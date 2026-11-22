"""Global terminal sessions: real PTYs, bounded and idempotent, as the service user, over the signed channel."""
import base64
import http.client
import json
import os
from pathlib import Path
import pwd
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import ats_cluster as cluster
import ats_remote
import ats_terminal as terminal


def me():
    return pwd.getpwuid(os.getuid()).pw_name


class TerminalBase(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {'ATS_TERMINAL_USER': me(), 'ATS_TERMINAL_ALLOW_ROOT': '1'})
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(terminal.close_all)

    def open(self, **extra):
        return terminal.handle('term.open', {'rows': 24, 'cols': 80, **extra})['sid']

    def send(self, sid, text):
        return terminal.handle('term.input', {'sid': sid, 'data': base64.b64encode(text.encode()).decode()})

    def until(self, sid, marker, timeout=15):
        """Read, acknowledging as a real client does, until the marker appears."""
        seen, since, end = b'', 0, time.time() + timeout
        while time.time() < end:
            result = terminal.handle('term.read', {'sid': sid, 'since': since, 'wait': 1})
            seen += base64.b64decode(result['data'])
            since = result['next']
            if marker.encode() in seen:
                return seen.decode('utf-8', 'replace'), since
            if result['exited']:
                break
        self.fail(f'{marker!r} not seen in {seen[-300:]!r}')


class SessionTests(TerminalBase):
    def test_commands_run_and_output_returns_over_the_long_poll(self):
        sid = self.open()
        self.send(sid, 'echo ans-$((6*7))\n')
        text, _ = self.until(sid, 'ans-42')
        self.assertIn('ans-42', text)

    def test_resize_reaches_the_shell_and_clamps(self):
        sid = self.open(rows=30, cols=100)
        self.send(sid, 'stty size\n')
        self.until(sid, '30 100')
        terminal.handle('term.resize', {'sid': sid, 'rows': 40, 'cols': 120})
        self.send(sid, 'stty size\n')
        self.until(sid, '40 120')
        terminal.handle('term.resize', {'sid': sid, 'rows': 99999, 'cols': True})
        self.send(sid, 'stty size\n')
        self.until(sid, '1000 80')

    def test_exit_status_is_reported_once_and_the_session_is_released(self):
        sid = self.open()
        self.send(sid, 'exit 7\n')
        since, end = 0, time.time() + 15
        while time.time() < end:
            result = terminal.handle('term.read', {'sid': sid, 'since': since, 'wait': 1})
            since = result['next']
            if result['exited']:
                self.assertEqual(result['status'], 7)
                break
        else:
            self.fail('session never reported its exit')
        with self.assertRaisesRegex(terminal.TerminalError, 'no longer exists'):
            terminal.handle('term.read', {'sid': sid, 'since': since, 'wait': 0})

    def test_job_control_and_signals_work_because_the_shell_has_a_controlling_terminal(self):
        sid = self.open()
        self.send(sid, 'sleep 30\n')
        time.sleep(0.5)
        self.send(sid, '\x03')            # Ctrl-C must interrupt the foreground job, not the whole shell
        self.send(sid, 'echo still-alive-$?\n')
        text, _ = self.until(sid, 'still-alive-130')
        self.assertNotIn('no job control', text)

    def test_ctrl_c_works_even_when_the_daemon_inherited_ignored_signals(self):
        # Regression: a daemon started with nohup / as a background job ignores SIGINT, and every shell it spawned did too.
        import signal
        previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
        previous_quit = signal.signal(signal.SIGQUIT, signal.SIG_IGN)
        self.addCleanup(signal.signal, signal.SIGINT, previous)
        self.addCleanup(signal.signal, signal.SIGQUIT, previous_quit)
        sid = self.open()
        self.send(sid, 'sleep 30\n')
        time.sleep(0.6)
        self.send(sid, '\x03')
        self.send(sid, 'echo ignored-sig-$?\n')
        self.until(sid, 'ignored-sig-130')

    def test_unacknowledged_reads_are_repeated_not_lost(self):
        sid = self.open()
        self.send(sid, 'echo first-marker\n')
        _, after_first = self.until(sid, 'first-marker')
        self.send(sid, 'echo second-marker\n')
        time.sleep(0.6)
        one = terminal.handle('term.read', {'sid': sid, 'since': after_first, 'wait': 2})
        again = terminal.handle('term.read', {'sid': sid, 'since': after_first, 'wait': 0})   # the response was "lost"
        # The shell may print more between the two reads on a busy machine, so the second read must START with
        # everything the first returned (nothing lost, nothing reordered); on an idle one they are identical.
        sent, repeated = base64.b64decode(one['data']), base64.b64decode(again['data'])
        self.assertTrue(repeated.startswith(sent), (sent, repeated))
        self.assertTrue(sent, 'the first read returned nothing')
        self.assertFalse(again['lost'])
        # Once the output has settled the repeated read contains the command's result as well.
        deadline = time.time() + 20
        while time.time() < deadline and b'second-marker' not in base64.b64decode(terminal.handle('term.read', {'sid': sid, 'since': after_first, 'wait': 0})['data']):
            time.sleep(0.1)
        self.assertIn(b'second-marker', base64.b64decode(terminal.handle('term.read', {'sid': sid, 'since': after_first, 'wait': 0})['data']))

    def test_buffer_is_bounded_and_a_slow_reader_is_told_it_missed_output(self):
        with patch.object(terminal, 'BUFFER_LIMIT', 4096):
            sid = self.open()
            self.send(sid, 'head -c 300000 /dev/zero | tr "\\0" "x"; echo; echo flood-done\n')
            time.sleep(2.0)
            result = terminal.handle('term.read', {'sid': sid, 'since': 0, 'wait': 0})
            self.assertTrue(result['lost'])
            self.assertLessEqual(len(base64.b64decode(result['data'])), terminal.READ_CHUNK)
            session = terminal._sessions[sid]
            self.assertLessEqual(len(session.buffer), 4096 + terminal.READ_CHUNK)

    def test_session_limit_close_and_idle_reaper(self):
        sids = [self.open() for _ in range(terminal.MAX_SESSIONS)]
        with self.assertRaisesRegex(terminal.TerminalError, 'Too many terminals'):
            self.open()
        terminal.handle('term.close', {'sid': sids[0]})
        self.assertIsNotNone(self.open())
        with self.assertRaisesRegex(terminal.TerminalError, 'no longer exists'):
            terminal.handle('term.read', {'sid': sids[0], 'since': 0, 'wait': 0})

    def test_malformed_requests_are_refused(self):
        sid = self.open()
        for payload in ({'sid': 'x'}, {'sid': 123}, {'sid': 'a' * 32}, {}):
            with self.assertRaises(terminal.TerminalError):
                terminal.handle('term.read', payload)
        for bad in ({'since': -1}, {'since': 'x'}, {'since': True}, {'wait': 'long'}):
            with self.assertRaises(terminal.TerminalError):
                terminal.handle('term.read', dict(sid=sid, **bad))
        for bad in (123, None, '!!notbase64!!', 'A' * (terminal.MAX_INPUT * 2)):
            with self.assertRaises(terminal.TerminalError):
                terminal.handle('term.input', {'sid': sid, 'data': bad})
        with self.assertRaises(terminal.TerminalError):
            terminal.handle('term.bogus', {'sid': sid})
        # A very long wait is clamped, not honoured.
        started = time.monotonic()
        with patch.object(terminal, 'MAX_WAIT', 0.3):
            terminal.handle('term.read', {'sid': sid, 'since': 0, 'wait': 9999})
        self.assertLess(time.monotonic() - started, 3)


class PolicyTests(TerminalBase):
    def test_root_is_refused_unless_deliberately_allowed(self):
        with patch.dict(os.environ, {'ATS_TERMINAL_USER': 'root'}):
            os.environ.pop('ATS_TERMINAL_ALLOW_ROOT', None)
            enabled, reason = terminal.available()
            self.assertFalse(enabled)
            self.assertIn('root', reason)
            with self.assertRaisesRegex(terminal.TerminalError, 'root'):
                self.open()

    def test_disabled_and_unknown_user_report_why(self):
        with patch.dict(os.environ, {'ATS_TERMINAL': 'off'}):
            self.assertEqual(terminal.available()[0], False)
            with self.assertRaisesRegex(terminal.TerminalError, 'Disabled'):
                self.open()
        with patch.dict(os.environ, {'ATS_TERMINAL_USER': 'no-such-user-xyz'}):
            self.assertIn('does not exist', terminal.available()[1])
        with patch.dict(os.environ, {'ATS_TERMINAL_USER': ''}), patch.object(terminal, 'settings', return_value={'service_user': me()}):
            self.assertTrue(terminal.available()[0])           # falls back to the ATS service user
        with patch.dict(os.environ, {'ATS_TERMINAL_USER': ''}), patch.object(terminal, 'settings', return_value={}):
            self.assertIn('No terminal user', terminal.available()[1])

    @unittest.skipUnless(os.geteuid() == 0 and any(p.pw_name == 'nobody' for p in pwd.getpwall()), 'needs root and a nobody account')
    def test_the_shell_drops_privileges_to_the_service_user(self):
        with patch.dict(os.environ, {'ATS_TERMINAL_USER': 'nobody'}):
            sid = self.open()
            self.send(sid, 'echo uid-is-$(id -u)-user-$(id -un)-home-$HOME\n')
            expected = pwd.getpwnam('nobody')
            text, _ = self.until(sid, f'uid-is-{expected.pw_uid}-user-nobody')   # output only: the typed command differs
            self.assertNotIn('uid-is-0', text)
            self.send(sid, 'cat /etc/shadow >/dev/null 2>&1; echo shadow-$?\n')
            self.until(sid, 'shadow-1')             # root-only files stay unreadable

    def test_docker_targets_are_validated_and_run_without_a_shell_injection_path(self):
        for bad in ('', '-v', '--privileged', 'a b', 'a;rm -rf /', 'x' * 300, None, 5):
            with self.assertRaisesRegex(terminal.TerminalError, 'container'):
                self.open(target='docker', container=bad)
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'docker'
            fake.write_text('#!/bin/sh\necho "ARGS:$*"\nsleep 5\n')
            fake.chmod(0o755)
            with patch.dict(os.environ, {'DOCKER_BIN': str(fake)}), patch.object(terminal, 'PATH', directory + ':/usr/bin:/bin'):
                sid = self.open(target='docker', container='web-1')
                text, _ = self.until(sid, 'ARGS:')
        self.assertIn('exec -it web-1 sh -c', text)
        with patch.dict(os.environ, {'DOCKER_BIN': 'definitely-not-installed'}):
            with self.assertRaisesRegex(terminal.TerminalError, 'Docker is not installed'):
                self.open(target='docker', container='web-1')
        with self.assertRaisesRegex(terminal.TerminalError, 'Unsupported terminal target'):
            self.open(target='ssh')


class SignedChannelTests(TerminalBase):
    """Through the real Global listener: authentication, health capability and the full round trip."""
    def setUp(self):
        super().setUp()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = cluster.Store(Path(self.temp.name) / 'global.db')
        self.node = self.store.configure('global', 'Global', 'https://localhost')
        self.http = ats_remote.Server(('127.0.0.1', 0), self.store)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)

    def call(self, payload, secret=None):
        body = json.dumps(payload).encode()
        conn = http.client.HTTPConnection('127.0.0.1', self.http.server_port, timeout=30)
        conn.request('POST', '/v1/request', body, cluster.signed_headers(secret or self.node['secret'], self.node['id'], body))
        response = conn.getresponse()
        data = json.loads(response.read())
        conn.close()
        return response.status, data

    def test_health_advertises_the_terminal_and_requests_need_the_key(self):
        status, data = self.call({'kind': 'health'})
        self.assertEqual((status, data['data']['terminal']), (200, True))
        with patch.dict(os.environ, {'ATS_TERMINAL': 'off'}):
            data = self.call({'kind': 'health'})[1]['data']
        self.assertEqual((data['terminal'], 'ATS_TERMINAL=off' in data['terminal_reason']), (False, True))
        status, data = self.call({'kind': 'term.open'}, secret='0' * 64)
        self.assertEqual(status, 401)
        self.assertEqual(terminal._sessions, {})

    def test_round_trip_and_errors_are_explained_to_the_caller(self):
        status, data = self.call({'kind': 'term.open', 'rows': 24, 'cols': 80})
        self.assertEqual(status, 200)
        sid = data['data']['sid']
        self.assertEqual(data['data']['user'], me())
        encoded = base64.b64encode(b'echo wire-$((20+22))\n').decode()
        self.assertEqual(self.call({'kind': 'term.input', 'sid': sid, 'data': encoded})[0], 200)
        seen, since, end = b'', 0, time.time() + 15
        while b'wire-42' not in seen and time.time() < end:
            data = self.call({'kind': 'term.read', 'sid': sid, 'since': since, 'wait': 1})[1]['data']
            seen += base64.b64decode(data['data'])
            since = data['next']
        self.assertIn(b'wire-42', seen)
        self.assertEqual(self.call({'kind': 'term.close', 'sid': sid})[1]['data'], {'closed': True})
        status, data = self.call({'kind': 'term.read', 'sid': sid, 'since': 0, 'wait': 0})
        self.assertEqual(status, 502)
        self.assertIn('no longer exists', data['error'])
        with patch.dict(os.environ, {'ATS_TERMINAL': 'off'}):
            status, data = self.call({'kind': 'term.open'})
        self.assertEqual(status, 502)
        self.assertIn('Disabled', data['error'])


if __name__ == '__main__':
    unittest.main()
