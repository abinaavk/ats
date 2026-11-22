"""server doctor: every failure names its cause and fix, and nothing secret is printed."""
import contextlib
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import yaml

import ats_cluster as c
import ats_doctor as doctor
import ats_global_setup as setup
import ats_remote
import ats_server_cli as cli

STUB = '''import json, sys
if "--check" in sys.argv:
    print(json.dumps({"ok": True}))
else:
    json.load(sys.stdin)
    print(json.dumps({"status": 200, "body": {"ok": True, "data": {"services": []}}}))
'''


def isolate(case):
    """Doctor's host-tool probes must never touch the machine running the tests (it may have a real Docker)."""
    probe = patch.object(doctor, 'tool_checks', lambda report: None)
    probe.start()
    case.addCleanup(probe.stop)


def levels(report):
    return {item['title']: item['level'] for item in report.items}


class LocalDoctorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        cert, key = self.root / 'cert.pem', self.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert),
                        '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, capture_output=True)
        adapter = self.root / 'remote_host.py'
        adapter.write_text(STUB)
        env = patch.dict(os.environ, {'SSL_CERT_FILE': str(cert), 'ATS_MONITOR_ADAPTER': str(adapter)})
        env.start()
        self.addCleanup(env.stop)
        pairing = patch.object(cli, 'default_pairing_path', return_value=self.root / 'files' / 'pairing.json')
        pairing.start()
        self.addCleanup(pairing.stop)
        isolate(self)
        self.global_store = c.Store(self.root / 'global.db')
        self.node = self.global_store.configure('global', 'Build', 'https://localhost')
        self.http = ats_remote.Server(('127.0.0.1', 0), self.global_store)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.http.socket = ctx.wrap_socket(self.http.socket, server_side=True)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)
        self.origin = 'https://localhost:%d' % self.http.server_port
        self.local = c.Store(self.root / 'local.db')
        self.local.configure('local', 'Primary', webhook='hooks.example.com')

    def pair(self):
        self.local.pair(self.node['id'], 'Build', self.origin, self.node['secret'])

    def test_healthy_global_passes_signed_health_and_a_service_read(self):
        self.pair()
        report = doctor.run(self.local)
        self.assertFalse(report.failed, report.text())
        self.assertEqual(levels(report)['Global “Build” (%s)' % self.origin], 'ok')
        self.assertNotIn(self.node['secret'], report.text() + json.dumps(report.items))

    def test_no_servers_and_wrong_key_and_disconnected_and_revoked_are_each_explained(self):
        self.assertIn('none paired yet', doctor.run(self.local).text())
        self.pair()
        label = 'Global “Build” (%s)' % self.origin
        self.local.connection(self.node['id'], 'disconnect')
        report = doctor.run(self.local)
        self.assertEqual(levels(report)[label], 'warn')
        self.local.connection(self.node['id'], 'reconnect')
        # The Global rotates its key (e.g. server rotate): Local's saved key is now wrong.
        with self.global_store.db() as db:
            db.execute('UPDATE node SET secret=?', ('f' * 64,))
        report = doctor.run(self.local)
        self.assertTrue(report.failed)
        text = report.text()
        self.assertIn('rejected the server ID or passkey', text)
        self.assertIn('replace-credentials', text)
        self.assertNotIn(self.node['secret'], text)

    def test_missing_adapter_is_reported_with_the_setup_command(self):
        self.pair()
        with patch.dict(os.environ, {'ATS_MONITOR_ADAPTER': str(self.root / 'absent.py')}):
            text = doctor.run(self.local).text()
        self.assertIn('Monitor adapter is not configured', text)
        self.assertIn('server setup --apply', text)

    def test_unreachable_global_names_the_network_cause(self):
        self.pair()
        self.http.shutdown()
        self.http.server_close()
        text = doctor.run(self.local).text()
        self.assertIn('refused the connection', text)

    def test_registry_permissions_are_checked(self):
        os.chmod(self.local.path, 0o644)
        report = doctor.run(self.local)
        self.assertEqual(levels(report)['Cluster registry permissions'], 'fail')
        os.chmod(self.local.path, 0o600)
        os.chmod(Path(self.local.path).parent, 0o755)
        try:
            # The default /etc/ats is usually 0755; with a 0600 key file that is a warning only.
            self.assertEqual(levels(doctor.run(self.local))['Cluster registry directory'], 'warn')
        finally:
            os.chmod(Path(self.local.path).parent, 0o700)

    def test_unconfigured_instance(self):
        report = doctor.run(c.Store(self.root / 'empty.db'))
        self.assertTrue(report.failed)
        self.assertIn('not configured', report.text())


class GlobalDoctorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        home = self.root / 'home'
        home.mkdir()
        (home / 'ats.db').touch()
        self.cf = self.root / 'cloudflared.yml'
        self.config = {'tunnel': 't', 'credentials-file': '/x.json',
                       'ingress': [{'hostname': 'app.example.com', 'service': 'http://localhost:8000'}, {'service': 'http_status:404'}]}
        self.cf.write_text(yaml.safe_dump(self.config))
        settings = self.root / 'ats.yml'
        settings.write_text(yaml.safe_dump({'ats_home': str(home), 'cloudflare_config': str(self.cf)}))
        self.adapter = self.root / 'remote_host.py'
        self.adapter.write_text(STUB)
        self.units = self.root / 'units'
        self.units.mkdir()
        env = patch.dict(os.environ, {'ATS_CONFIG_FILE': str(settings), 'ATS_CLUSTER_DB': str(self.root / 'registry.db'),
                                      'ATS_MONITOR_ADAPTER': str(self.adapter), 'PATH': os.environ['PATH']}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.pairing = self.root / 'files' / 'pairing.json'
        pairing = patch.object(cli, 'default_pairing_path', return_value=self.pairing)
        pairing.start()
        self.addCleanup(pairing.stop)
        isolate(self)
        self.store = c.Store()
        self.node = self.store.configure('global', 'Build', 'https://api.example.com')
        self.http = ats_remote.Server(('127.0.0.1', 0), self.store)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)
        self.unit = {'LoadState': 'loaded', 'ActiveState': 'active', 'UnitFileState': 'enabled',
                     'ExecStart': str(Path(cli.__file__).parent / 'app.py') + ' --daemon',
                     'Environment': 'ATS_CLUSTER_DB=' + self.store.path}
        self.tunnel_route = False

    def run_doctor(self, **extra):
        def runner(argv, **kwargs):
            out, code = '', 0
            if argv[:2] == ['systemctl', 'list-unit-files']:
                out, code = ('ats-global.service enabled', 0) if self.unit else ('', 1)
            elif argv[:2] == ['systemctl', 'show']:
                if argv[2] == 'cloudflared.service':
                    props = {'ActiveState': 'active', 'User': 'root', 'ExecStart': 'cloudflared --config %s tunnel run' % self.cf}
                elif self.unit and argv[2] == 'ats-global.service':
                    props = self.unit
                else:
                    props = {'LoadState': 'not-found'}
                out = '\n'.join(k + '=' + v for k, v in props.items())
            elif len(argv) == 3 and argv[2] == '--check':
                return subprocess.run(argv, capture_output=True, text=True, env=kwargs.get('env'))
            return subprocess.CompletedProcess(argv, code, out, '')
        options = dict(runner=runner, monitor_adapter=str(self.adapter), unit_dir=str(self.units),
                       port=self.http.server_port, unit='ats-global.service')
        options.update(extra)
        with patch.object(doctor.gs, 'verify_health', side_effect=self.verify):
            return doctor.run(self.store, **options)

    def verify(self, plan, *, public=False, management=False):
        if public:
            raise ValueError('public HTTPS not reachable in this test')
        payload = {'kind': 'http', 'method': 'GET', 'path': '/api/manage/services'} if management else {'kind': 'health'}
        body = json.dumps(payload, separators=(',', ':')).encode()
        import http.client
        conn = http.client.HTTPConnection('127.0.0.1', plan['port'], timeout=10)
        conn.request('POST', '/v1/request', body, c.signed_headers(self.node['secret'], self.node['id'], body))
        if conn.getresponse().status != 200:
            raise ValueError('rejected')

    def add_route(self):
        self.config['ingress'].insert(1, {'hostname': 'api.example.com', 'path': '^/v1/request$',
                                          'service': 'http://127.0.0.1:%d' % self.http.server_port})
        self.cf.write_text(yaml.safe_dump(self.config))

    def test_missing_route_pairing_file_and_service_are_all_reported(self):
        self.unit = None
        report = self.run_doctor()
        text = report.text()
        self.assertTrue(report.failed)
        self.assertIn('not installed', text)
        self.assertIn('server setup --apply', text)

    def test_fully_configured_global_passes_loopback_checks(self):
        self.add_route()
        cli.save_pairing(self.store)
        report = self.run_doctor()
        result = levels(report)
        self.assertEqual(result['Tunnel route'], 'ok', report.text())
        self.assertEqual(result['Pairing file'], 'ok')
        self.assertEqual(result['Monitor adapter'], 'ok')
        self.assertEqual(result['Signed health (loopback)'], 'ok')
        self.assertEqual(result['Adapter service read (loopback)'], 'ok')
        self.assertEqual(result['API port'], 'ok')
        # Public reachability can lag DNS: a warning, never a hard failure.
        self.assertEqual(result['Signed health (public HTTPS)'], 'warn')
        self.assertNotIn(self.node['secret'], report.text())

    def test_stale_pairing_file_after_key_change_is_flagged(self):
        self.add_route()
        cli.save_pairing(self.store)
        with self.store.db() as db:
            db.execute('UPDATE node SET secret=?', ('e' * 64,))
        report = self.run_doctor()
        self.assertEqual(levels(report)['Pairing file'], 'fail')
        self.assertIn('server export', report.text())

    def test_daemon_not_listening_is_reported_with_the_journal_command(self):
        self.add_route()
        self.http.shutdown()
        self.http.server_close()
        report = self.run_doctor()
        self.assertEqual(levels(report)['API port'], 'fail')
        self.assertIn('journalctl -u', report.text())

    def test_missing_python_module_in_adapter_is_named(self):
        self.add_route()
        self.adapter.write_text('import json, sys\nprint(json.dumps({"ok": False, "problems": ["Python module \'flask\' is missing for /usr/bin/python3"]}))\n')
        text = self.run_doctor().text()
        self.assertIn("module 'flask' is missing", text)

    def test_cli_runs_doctor_and_exits_nonzero_on_failure(self):
        with patch.object(sys, 'argv', ['ats', 'doctor', '--json']), patch('ats_doctor.run') as run, \
                contextlib.redirect_stdout(io.StringIO()) as out:
            report = doctor.Report()
            report.add(doctor.FAIL, 'x', 'broken', 'fix it')
            run.return_value = report
            with self.assertRaises(SystemExit) as caught:
                cli.main()
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(json.loads(out.getvalue())[0]['fix'], 'fix it')



class FleetChecksTests(unittest.TestCase):
    """Docker, rclone, terminal, version, backup and alert checks, with fake tools only."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        env = patch.dict(os.environ, {'PATH': str(self.bin)})
        env.start()
        self.addCleanup(env.stop)
        self.assertEqual(__import__('shutil').which('docker'), None)          # the host's real tools are out of reach
        self.store = c.Store(self.root / 'registry.db')

    def tool(self, name, script):
        path = self.bin / name
        path.write_text('#!/bin/sh\n' + script + '\n')
        path.chmod(0o755)

    def checks(self):
        report = doctor.Report()
        with patch('ats_terminal.available', return_value=(True, '')):
            doctor.tool_checks(report)
        return {i['title']: i for i in report.items}

    def test_missing_tools_are_warnings_that_say_how_to_install_them(self):
        found = self.checks()
        self.assertEqual((found['Docker']['level'], found['rclone']['level']), ('warn', 'warn'))
        self.assertIn('Install Docker', found['Docker']['fix'])
        self.assertIn('Install rclone', found['rclone']['fix'])

    def test_working_tools_pass_and_broken_ones_name_the_next_step(self):
        self.tool('docker', 'echo 27.0.1')
        self.tool('rclone', 'echo gdrive:; echo s3:')
        found = self.checks()
        self.assertEqual((found['Docker']['level'], found['rclone']['level']), ('ok', 'ok'))
        self.assertIn('27.0.1', found['Docker']['detail'])
        self.assertIn('2 remote', found['rclone']['detail'])
        self.tool('docker', 'echo "Cannot connect to the Docker daemon" >&2; exit 1')
        self.tool('rclone', 'exit 0')
        found = self.checks()
        self.assertEqual(found['Docker']['level'], 'fail')
        self.assertIn('systemctl enable --now docker', found['Docker']['fix'])
        self.assertEqual((found['rclone']['level'], found['rclone']['fix']), ('warn', 'run: rclone config'))
        self.tool('rclone', 'exit 4')
        self.assertEqual(self.checks()['rclone']['level'], 'fail')

    def test_a_hanging_tool_cannot_hang_the_doctor(self):
        self.tool('docker', 'sleep 30')
        with patch.object(doctor.subprocess, 'run', side_effect=doctor.subprocess.TimeoutExpired('docker', 10)):
            self.assertEqual(self.checks()['Docker']['level'], 'fail')

    def test_terminal_availability_on_this_server_and_on_a_global(self):
        report = doctor.Report()
        with patch('ats_terminal.available', return_value=(False, 'no PTY for the service user')):
            doctor.tool_checks(report)
        item = [i for i in report.items if i['title'] == 'Terminal'][0]
        self.assertEqual((item['level'], item['detail']), ('warn', 'no PTY for the service user'))
        for health, level in (({'terminal': True}, 'ok'), ({'terminal': False, 'terminal_reason': 'no shell'}, 'warn'), ({}, 'warn')):
            report = doctor.Report()
            doctor.terminal_line(report, 'Global “B”', health)
            self.assertEqual(report.items[0]['level'], level)
        self.assertIn('older ATS', report.items[0]['detail'])

    def test_version_differences_and_old_globals_are_reported(self):
        import ats_status
        mine = ats_status.repo_info(Path(doctor.__file__).resolve().parent, ttl=0).get('commit') or 'a' * 40
        cases = [({'ats': {'available': True, 'commit': mine, 'short': mine[:7]}}, 'ok'),
                 ({'ats': {'available': True, 'commit': 'b' * 40, 'short': 'bbbbbbb'}}, 'warn'),
                 ({'ats': {'available': False}}, 'warn')]
        for payload, level in cases:
            report = doctor.Report()
            with patch.object(doctor.ats_cluster, 'remote', return_value=payload), \
                    patch.object(ats_status, 'repo_info', return_value={'commit': mine}):
                doctor.version_line(report, 'Global', {})
            self.assertEqual(report.items[0]['level'], level, payload)
        report = doctor.Report()
        with patch.object(doctor.ats_cluster, 'remote', side_effect=c.TransportError('Unsupported request kind', 'adapter')):
            doctor.version_line(report, 'Global', {})
        self.assertIn('older ATS', report.items[0]['detail'])

    def test_backup_and_alert_checks_report_age_failures_and_delivery_problems(self):
        import ats_notify
        import ats_registry_backup as backups
        node = self.store.configure('local', 'Primary', webhook='hooks.example.com')

        def run():
            report = doctor.Report()
            doctor.backup_and_alert_checks(report, self.store, self.store.node())
            return {i['title']: i for i in report.items}
        found = run()
        self.assertFalse((self.root / 'registry-backups').exists())               # doctor never creates anything
        self.assertEqual((found['Registry backup']['level'], found['Alerts']['level']), ('warn', 'warn'))
        backups.create(self.store)
        found = run()
        self.assertEqual(found['Registry backup']['level'], 'ok')
        newest = Path(backups.listing(self.store)[0]['path'])
        os.utime(newest, (time.time() - 5 * 86400, time.time() - 5 * 86400))
        self.assertIn('5 days old', run()['Registry backup']['detail'])
        ats_notify.save(self.store, {'webhook': {'url': 'https://hooks.example.com/x'}, 'enabled': {'webhook': True}})
        self.store.kv_set('fleet_notify', {'at': 1, 'outcome': {'webhook': {'ok': False, 'error': 'HTTP 404'}}})
        found = run()
        self.assertEqual(found['Alerts']['level'], 'warn')
        self.assertIn('webhook', found['Alerts']['detail'])
        self.assertNotIn('hooks.example.com', json.dumps(found))


if __name__ == '__main__':
    unittest.main()
