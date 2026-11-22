"""Fleet status and safe self-update, using real git repositories in temporary directories."""
import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

import ats_cluster as cluster
import ats_remote
import ats_status
import ats_update

GIT = {'GIT_AUTHOR_NAME': 't', 'GIT_AUTHOR_EMAIL': 't@example.com', 'GIT_COMMITTER_NAME': 't', 'GIT_COMMITTER_EMAIL': 't@example.com'}


def git(directory, *args):
    return subprocess.run(['git', '-C', str(directory), *args], check=True, capture_output=True, text=True, env=dict(os.environ, **GIT)).stdout.strip()


class Repos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.origin = self.root / 'origin'
        self.origin.mkdir()
        git(self.origin, 'init', '-q', '-b', 'main')
        self.commit(self.origin, 'first')
        self.clone = self.root / 'clone'
        subprocess.run(['git', 'clone', '-q', str(self.origin), str(self.clone)], check=True, env=dict(os.environ, **GIT))
        ats_status.forget()

    def commit(self, directory, message, name='file.py', body=None):
        (Path(directory) / name).write_text(body if body is not None else message + '\n')
        git(directory, 'add', '-A')
        git(directory, 'commit', '-q', '-m', message)
        return git(directory, 'rev-parse', 'HEAD')


class StatusTests(Repos):
    def test_repo_info_reports_commit_branch_and_detached_state(self):
        info = ats_status.repo_info(self.clone, ttl=0)
        self.assertEqual((info['available'], info['branch'], info['detached'], info['subject']), (True, 'main', False, 'first'))
        self.assertEqual(info['commit'], git(self.clone, 'rev-parse', 'HEAD'))
        git(self.clone, 'checkout', '-q', '--detach')
        info = ats_status.repo_info(self.clone, ttl=0)
        self.assertEqual((info['detached'], info['branch']), (True, None))
        self.assertEqual(ats_status.repo_info(self.root / 'nowhere', ttl=0), {'available': False})

    def test_repo_info_is_cached_briefly(self):
        first = ats_status.repo_info(self.clone, ttl=60)
        self.commit(self.clone, 'second')
        self.assertEqual(ats_status.repo_info(self.clone, ttl=60), first)
        self.assertEqual(ats_status.repo_info(self.clone, ttl=0)['subject'], 'second')

    def test_metrics_have_sane_ranges_and_no_secrets(self):
        data = ats_status.collect(adapter=None)
        metrics = data['metrics']
        self.assertTrue(0 <= metrics['cpu_percent'] <= 100)
        self.assertTrue(0 < metrics['memory']['used_percent'] <= 100)
        self.assertTrue(metrics['disks'] and all(0 <= d['used_percent'] <= 100 for d in metrics['disks']))
        self.assertEqual(len(metrics['load']), 3)
        self.assertEqual(data['companion'], {'available': False})
        text = json.dumps(data)
        for private in ('secret', 'password', 'token', 'ATS_CLUSTER_DB'):
            self.assertNotIn(private, text)

    def test_cpu_percent_is_a_delta_between_calls(self):
        ats_status.cpu_percent()                      # takes its own short sample and remembers the totals
        import time as real_time
        real_time.sleep(0.6)                          # long enough to reuse the remembered totals
        with mock.patch.object(ats_status.time, 'sleep') as slept:
            value = ats_status.cpu_percent()
        slept.assert_not_called()
        self.assertTrue(0 <= value <= 100)
        with mock.patch.object(ats_status, '_cpu_times', return_value=None):
            self.assertIsNone(ats_status.cpu_percent())


class UpdateTests(Repos):
    def update(self, **kwargs):
        with mock.patch.object(ats_update, 'check_code', kwargs.pop('check', lambda name, directory: None)):
            return ats_update.update_one('companion', self.clone, **kwargs)

    def test_fast_forward_on_a_branch(self):
        head = self.commit(self.origin, 'second')
        self.commit(self.origin, 'third')
        result = self.update()
        self.assertEqual((result['changed'], result['commits']), (True, ['third', 'second']))
        self.assertEqual(git(self.clone, 'rev-parse', '--abbrev-ref', 'HEAD'), 'main')
        self.assertEqual(git(self.clone, 'log', '-1', '--format=%s'), 'third')
        self.assertEqual(self.update()['changed'], False)

    def test_detached_checkout_is_advanced_without_attaching(self):
        git(self.clone, 'checkout', '-q', '--detach')
        self.commit(self.origin, 'second')
        result = self.update(branch='main')
        self.assertTrue(result['changed'] and result['detached'])
        self.assertEqual(git(self.clone, 'rev-parse', '--abbrev-ref', 'HEAD'), 'HEAD')
        self.assertEqual(git(self.clone, 'log', '-1', '--format=%s'), 'second')

    def test_local_changes_and_diverged_history_are_refused_and_nothing_moves(self):
        self.commit(self.origin, 'second')
        (self.clone / 'file.py').write_text('edited locally\n')
        before = git(self.clone, 'rev-parse', 'HEAD')
        with self.assertRaisesRegex(ats_update.UpdateError, 'local changes'):
            self.update()
        git(self.clone, 'checkout', '--', 'file.py')
        self.commit(self.clone, 'local only', name='other.py')
        before = git(self.clone, 'rev-parse', 'HEAD')
        with self.assertRaisesRegex(ats_update.UpdateError, 'cannot be fast-forwarded'):
            self.update()
        self.assertEqual(git(self.clone, 'rev-parse', 'HEAD'), before)

    def test_new_code_that_fails_its_check_is_rolled_back(self):
        before = git(self.clone, 'rev-parse', 'HEAD')
        self.commit(self.origin, 'broken release')

        def failing(name, directory):
            raise ats_update.UpdateError('the new code failed its check: SyntaxError')
        with self.assertRaisesRegex(ats_update.UpdateError, 'previous version was restored'):
            self.update(check=failing)
        self.assertEqual(git(self.clone, 'rev-parse', 'HEAD'), before)
        self.assertEqual(git(self.clone, 'rev-parse', '--abbrev-ref', 'HEAD'), 'main')
        self.assertEqual(git(self.clone, 'status', '--porcelain'), '')

    def test_detached_rollback_restores_the_exact_commit(self):
        git(self.clone, 'checkout', '-q', '--detach')
        before = git(self.clone, 'rev-parse', 'HEAD')
        self.commit(self.origin, 'broken')
        with self.assertRaises(ats_update.UpdateError):
            self.update(branch='main', check=mock.Mock(side_effect=ats_update.UpdateError('bad')))
        self.assertEqual(git(self.clone, 'rev-parse', 'HEAD'), before)

    def test_unreachable_remote_and_non_repositories_are_explained(self):
        git(self.clone, 'remote', 'set-url', 'origin', str(self.root / 'gone'))
        with self.assertRaisesRegex(ats_update.UpdateError, 'git fetch failed'):
            self.update()
        with self.assertRaisesRegex(ats_update.UpdateError, 'not a git checkout'):
            ats_update.update_one('ats', self.root)

    def test_the_real_ats_checkout_passes_its_own_import_check(self):
        ats_update.check_code('ats', Path(ats_update.__file__).parent)
        broken = self.root / 'broken'
        broken.mkdir()
        with self.assertRaisesRegex(ats_update.UpdateError, 'failed its check'):
            ats_update.check_code('ats', broken)

    def test_update_requests_are_validated_and_restart_only_when_ats_changed(self):
        restarts = []
        dirs = {'ats': self.clone}
        with mock.patch.object(ats_update, 'check_code', lambda *a: None):
            idle = ats_update.update('ats', dirs=dirs, restarter=lambda: restarts.append(1))
            self.assertEqual((idle['restart'], restarts), (False, []))
            self.commit(self.origin, 'second')
            done = ats_update.update('ats', dirs=dirs, restarter=lambda: restarts.append(1))
            self.assertEqual((done['restart'], restarts), (True, [1]))
            self.commit(self.origin, 'third')
            quiet = ats_update.update('ats', restart=False, dirs=dirs, restarter=lambda: restarts.append(1))
            self.assertEqual((quiet['ats']['changed'], quiet['restart'], restarts), (True, False, [1]))
        for bad in ('everything', None, 'ats; rm -rf /'):
            with self.assertRaises(ats_update.UpdateError):
                ats_update.update(bad, dirs=dirs)
        with self.assertRaisesRegex(ats_update.UpdateError, 'companion is not installed'):
            ats_update.update('companion', dirs=dirs)
        self.assertNotIn('companion', ats_update.update('both', dirs=dirs, restarter=lambda: None))

    def test_two_updates_cannot_run_at_once(self):
        self.assertTrue(ats_update.LOCK.acquire(blocking=False))
        try:
            with self.assertRaisesRegex(ats_update.UpdateError, 'already running'):
                ats_update.update('ats', dirs={'ats': self.clone})
        finally:
            ats_update.LOCK.release()

    def test_restart_reexecutes_the_original_command_line(self):
        with mock.patch.object(ats_update.os, 'execv') as execv, mock.patch.object(ats_update.time, 'sleep'), \
                mock.patch.object(ats_update.sys, 'orig_argv', ['python3', '/opt/ats/app.py', '--daemon'], create=True):
            ats_update.schedule_restart(0)
            for thread in threading.enumerate():
                if thread is not threading.current_thread() and thread.daemon:
                    thread.join(2)
        execv.assert_called_once_with(ats_update.sys.executable, ['python3', '/opt/ats/app.py', '--daemon'])


class SignedChannelTests(Repos):
    def setUp(self):
        super().setUp()
        self.store = cluster.Store(self.root / 'global.db')
        self.node = self.store.configure('global', 'Global', 'https://localhost')
        self.http = ats_remote.Server(('127.0.0.1', 0), self.store)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)

    def call(self, payload, secret=None):
        body = json.dumps(payload).encode()
        conn = http.client.HTTPConnection('127.0.0.1', self.http.server_port, timeout=60)
        conn.request('POST', '/v1/request', body, cluster.signed_headers(secret or self.node['secret'], self.node['id'], body))
        response = conn.getresponse()
        data = json.loads(response.read())
        conn.close()
        return response.status, data

    def test_status_is_available_to_the_signed_caller_only(self):
        status, data = self.call({'kind': 'status'})
        self.assertEqual(status, 200)
        self.assertIn('metrics', data['data'])
        self.assertTrue(data['data']['ats']['available'])
        self.assertEqual(self.call({'kind': 'status'}, secret='0' * 64)[0], 401)

    def test_update_errors_reach_the_caller_as_plain_messages(self):
        status, data = self.call({'kind': 'update', 'targets': 'everything'})
        self.assertEqual(status, 502)
        self.assertIn('Choose ats, companion or both', data['error'])
        status, data = self.call({'kind': 'update', 'restart': 'yes'})
        self.assertEqual((status, data['error']), (502, 'restart must be true or false'))
        with mock.patch.object(ats_update, 'update', side_effect=ats_update.UpdateError('ats: the checkout has local changes; commit or discard them first')):
            status, data = self.call({'kind': 'update'})
        self.assertIn('local changes', data['error'])


if __name__ == '__main__':
    unittest.main()
