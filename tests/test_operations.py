"""Operations behavior on a disposable host, including real Git rollback."""
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import types
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_manage_integration import HostAPI
import ats_operations as ops
import ats_api
import ats_manage_runtime as runtime


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.host = HostAPI('test_complete_service_and_backup_flow')
        self.host.setUp()
        self.a = self.host.a
        self.host.deploy()
        self.s = runtime.row(self.a, 'demo')
        ops.init(self.a)

    def tearDown(self):
        self.host.tearDown()

    def test_config_limits_and_legacy_override(self):
        self.assertTrue(ops.get(self.a, {'name': 'demo'})['schedule']['legacy_midnight'])
        self.assertTrue(ops.get(self.a, {})['collector']['stale'])
        for args in ({'timeout_seconds': True}, {'retain_count': 0}, {'interval_hours': 721},
                     {'health_path': '//elsewhere'}, {'health_path': '/a\r\nHost: attacker'},
                     {'health_enabled': 'yes'}, {'unknown': 1}):
            with self.subTest(args=args), self.assertRaises(ValueError):
                ops.set_config(self.a, dict(args, name='demo'))
        ops.set_config(self.a, {'name': 'demo', 'backup_enabled': False})
        self.assertIsNone(ops.get(self.a, {'name': 'demo'})['schedule']['next_backup'])

    def test_local_http_checks_do_not_follow_redirects_and_alert_recovery(self):
        class Handler(BaseHTTPRequestHandler):
            code = 302
            def do_GET(self):
                self.send_response(self.code)
                self.send_header('Location', 'http://must-not-follow.invalid/')
                self.end_headers()
            def log_message(self, *args): pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            service = dict(self.s, port=server.server_port)
            ops.set_config(self.a, {'name': 'demo', 'health_enabled': True, 'failure_threshold': 2})
            ops.sample(self.a, service, time.time())
            self.assertFalse(ops.get(self.a, {'name': 'demo'})['alerts'])
            ops.sample(self.a, service, time.time() + 1)
            alert = ops.get(self.a, {'name': 'demo'})['alerts'][0]
            self.assertTrue(alert['active']); self.assertIn('HTTP 302', alert['message'])
            ops.run(self.a, 'alerts.ack', {'id': alert['id']})
            ops.sample(self.a, service, time.time() + 2)
            self.assertTrue(ops.get(self.a, {'name': 'demo'})['alerts'][0]['acknowledged'])
            Handler.code = 200
            ops.sample(self.a, service, time.time() + 3)
            self.assertFalse(ops.get(self.a, {'name': 'demo'})['alerts'][0]['active'])
            self.assertEqual(ops.get(self.a, {'name': 'demo'})['health']['failure_streak'], 0)
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_resource_delta_and_missing_measurements(self):
        def metrics(ns, memory):
            return types.SimpleNamespace(returncode=0, stdout=f'ActiveState=active\nCPUUsageNSec={ns}\nMemoryCurrent={memory}\n')
        with mock.patch.object(ats_api, 'command', side_effect=[metrics(1000000000, 1048576), metrics(2000000000, 2097152), metrics('[not set]', '[not set]')]):
            ops.sample(self.a, self.s, 100)
            ops.sample(self.a, self.s, 110)
            ops.sample(self.a, self.s, 120)
        samples = ops.get(self.a, {'name': 'demo'})['samples']
        self.assertIsNone(samples[0]['cpu_percent'])
        self.assertEqual(samples[1]['cpu_percent'], 10)
        self.assertEqual(samples[1]['memory_mb'], 2)
        self.assertIsNone(samples[2]['memory_mb'])
        self.assertIsNone(samples[2]['cpu_percent'])

    def test_scheduled_retention_preserves_manual_backups_and_disabling(self):
        database = Path(self.host.env.storage) / 'database' / 'demo' / 'db.sqlite'
        database.write_text('original')
        manual = ats_api.backup_create(self.a, {'name': 'demo'})
        ops.set_config(self.a, {'name': 'demo', 'backup_enabled': True, 'interval_hours': 1, 'retain_count': 1})
        for _ in range(2):
            with ops.connection(self.a) as c: c.execute('UPDATE ops_config SET next_backup=0 WHERE name=?', ('demo',))
            ops.collect(self.a)
        backups = ats_api.backup_list(self.a, {'name': 'demo'})['backups']
        self.assertEqual(len(backups), 2)
        self.assertIn(manual['filename'], [x['filename'] for x in backups])
        self.assertEqual(database.read_text(), 'original')
        d = ops.get(self.a, {'name': 'demo'})
        self.assertIsNotNone(d['schedule']['verified_at'])
        self.assertFalse(d['collector']['stale'])
        ops.set_config(self.a, {'name': 'demo', 'backup_enabled': False})
        ops.collect(self.a)
        self.assertEqual(len(ats_api.backup_list(self.a, {'name': 'demo'})['backups']), 2)

    def test_verification_failure_keeps_existing_backups_and_sets_alert(self):
        database = Path(self.host.env.storage) / 'database' / 'demo' / 'db.sqlite'
        database.write_text('data')
        ops.set_config(self.a, {'name': 'demo', 'backup_enabled': True, 'retain_count': 1})
        for fail in (False, True):
            with ops.connection(self.a) as c: c.execute('UPDATE ops_config SET next_backup=0 WHERE name=?', ('demo',))
            if fail:
                with mock.patch.object(ops, 'verify_backup', side_effect=ValueError('corrupt archive')): ops.collect(self.a)
            else: ops.collect(self.a)
        self.assertEqual(len(ats_api.backup_list(self.a, {'name': 'demo'})['backups']), 2)
        self.assertTrue(any(x['kind'] == 'backup' and x['active'] for x in ops.get(self.a, {'name': 'demo'})['alerts']))

    def test_activity_never_returns_secret_metadata(self):
        self.a.audit_log('CONFIG', 'demo', {'env': {'TOKEN': 'never-display'}, 'webhook_secret': 'hidden'})
        payload = json.dumps(ops.get(self.a, {'name': 'demo'}))
        self.assertNotIn('never-display', payload)
        self.assertNotIn('hidden', payload)
        self.assertIn('CONFIG', payload)

    def test_real_git_rollback_and_failed_health_recovery(self):
        directory = Path(runtime.paths(self.a, self.s)[0])
        git = '/usr/bin/git'
        def command(*args):
            return subprocess.check_output([git, *args], cwd=directory, text=True).strip()
        command('init', '-b', 'main');command('config', 'user.name', 'Test');command('config', 'user.email', 'test@example.invalid')
        code = directory / 'code.txt'; code.write_text('first')
        command('add', 'code.txt');command('commit', '-m', 'first')
        first = command('rev-parse', 'HEAD')
        record = ops.begin(self.a, self.s, 'deploy');ops.finish(self.a, record, 'success', first)
        code.write_text('second');command('commit', '-am', 'second')
        second = command('rev-parse', 'HEAD')
        events = []
        def as_user(argv, cwd=None, timeout=None, capture=None):
            r = subprocess.run([git, *argv[1:]], cwd=cwd, text=True, capture_output=True)
            return r.returncode, r.stdout, r.stderr
        db = Path(self.host.env.storage) / 'database' / 'demo' / 'db.sqlite';db.write_text('preserved')
        with mock.patch.object(self.a, 'run_as_gaia', side_effect=as_user), mock.patch.object(runtime, 'dependencies'), mock.patch.object(self.a, '_systemctl_and_verify'), mock.patch.object(self.a, 'health_check_deployment', return_value=True), mock.patch.object(self.a, 'api_emit', events.append, create=True):
            result = ops.rollback(self.a, {'name': 'demo', 'deployment_id': record, 'confirm': 'demo'})
            self.assertEqual(result['commit'], first);self.assertEqual(code.read_text(), 'first')
            self.assertEqual(db.read_text(), 'preserved')
            self.assertIn({'t': 'step', 'id': 'health', 'state': 'done'}, events)
            newer = ops.begin(self.a, self.s, 'deploy');ops.finish(self.a, newer, 'success', second)
            code.write_text('dirty')
            with self.assertRaises(self.a.ServiceOpError):ops.rollback(self.a, {'name':'demo','deployment_id':newer,'confirm':'demo'})
            command('restore', 'code.txt')
            with mock.patch.object(self.a, 'health_check_deployment', return_value=False):
                with self.assertRaisesRegex(self.a.ServiceOpError, 'previous code restored'):
                    ops.rollback(self.a, {'name':'demo','deployment_id':newer,'confirm':'demo'})
            self.assertEqual(command('rev-parse', 'HEAD'), first)
            self.assertEqual(code.read_text(), 'first')
            self.assertEqual(db.read_text(), 'preserved')
            with ops.connection(self.a) as c:c.execute('UPDATE ops_deployments SET repository=? WHERE id=?', ('other-repo', newer))
            with self.assertRaises(ValueError):ops.rollback(self.a, {'name':'demo','deployment_id':newer,'confirm':'demo'})


if __name__ == '__main__': unittest.main()
