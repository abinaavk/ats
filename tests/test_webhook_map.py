"""server map: legacy per-service secrets keep working, generated secrets are shown once, failures say why."""
import asyncio
import contextlib
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import yaml

import ats_cluster as cluster
import ats_routing
import ats_server_cli as cli


class MapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        home = self.root / 'home'
        home.mkdir()
        self.legacy = secrets.token_hex(32)
        with sqlite3.connect(home / 'ats.db') as db:
            db.execute('CREATE TABLE services(name TEXT, repo_url TEXT, branch TEXT, webhook_secret TEXT)')
            db.execute("INSERT INTO services VALUES('site','https://github.com/owner/site.git','release',?)", (self.legacy,))
            db.execute("INSERT INTO services VALUES('ssh','git@github.com:owner/ssh-site.git','main',?)", (self.legacy[::-1],))
            db.execute("INSERT INTO services VALUES('gitlab','https://gitlab.com/owner/x.git','main',?)", (secrets.token_hex(32),))
            db.execute("INSERT INTO services VALUES('nosecret','https://github.com/owner/none','main',NULL)")
        config = self.root / 'ats.yml'
        config.write_text(yaml.safe_dump({'ats_home': str(home)}))
        env = patch.dict(os.environ, {'ATS_CONFIG_FILE': str(config), 'ATS_CLUSTER_DB': str(self.root / 'cluster.db')}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.store = cluster.Store()
        self.local = self.store.configure('local', 'Primary', webhook='hooks.example.com')
        self.remote = secrets.token_hex(16)
        with self.store.db() as db:
            db.execute("INSERT INTO servers(id,name,domain,secret,connected,local) VALUES(?,?,?,?,1,0)",
                       (self.remote, 'Build', 'https://build.example.com', '1' * 64))

    def run_map(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', ['ats', 'map', *argv]), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                cli.main()
                code = 0
            except SystemExit as exit_:
                code = exit_.code
        return code, out.getvalue(), err.getvalue()

    def mapping(self, repository):
        with self.store.db() as db:
            row = db.execute('SELECT * FROM routes WHERE repository=?', (repository.lower(),)).fetchone()
            return dict(row) if row else None

    def test_from_service_reuses_the_existing_secret_repository_and_branch(self):
        code, out, err = self.run_map('--from-service', 'site')
        self.assertEqual(code, 0, err)
        row = self.mapping('owner/site')
        self.assertEqual((row['server_id'], row['service'], row['branch'], row['secret']), (self.local['id'], 'site', 'release', self.legacy))
        self.assertIn('https://hooks.example.com/webhook/site', out)
        self.assertIn('needs no change', out)
        self.assertNotIn(self.legacy, out + err)
        # An existing GitHub webhook signed with the old secret now authenticates at the central receiver.
        body = json.dumps({'repository': {'full_name': 'owner/site'}, 'ref': 'refs/heads/release', 'after': 'a' * 40}).encode()
        headers = {'x-github-event': 'push', 'x-github-delivery': 'd1',
                   'x-hub-signature-256': 'sha256=' + hmac.new(self.legacy.encode(), body, hashlib.sha256).hexdigest()}
        mapped, _, delivery = ats_routing.route(self.store, '/webhook/site', headers, body)
        self.assertEqual((mapped['service'], delivery), ('site', 'd1'))

    def test_from_service_handles_ssh_urls_and_explicit_overrides(self):
        self.assertEqual(self.run_map('--from-service', 'ssh')[0], 0)
        self.assertIsNotNone(self.mapping('owner/ssh-site'))
        code, _, err = self.run_map('--from-service', 'ssh', '--repository', 'owner/other', '--branch', 'dev', '--replace-mapping')
        self.assertEqual(code, 1)
        self.assertIn('No existing mapping to replace', err)
        self.assertEqual(self.run_map('--from-service', 'site', '--repository', 'owner/renamed', '--branch', 'dev')[0], 0)
        self.assertEqual(self.mapping('owner/renamed')['branch'], 'dev')

    def test_from_service_refuses_what_it_cannot_map_safely(self):
        for service, message in (('missing', 'No Local service'), ('gitlab', 'not a github.com URL'), ('nosecret', 'no usable webhook secret')):
            code, _, err = self.run_map('--from-service', service)
            self.assertEqual(code, 1, service)
            self.assertIn(message, err)
        self.assertEqual(self.run_map('--from-service', 'site', '--generate-secret')[0], 2)
        self.assertEqual(self.run_map('--from-service', 'site', '--service', 'x')[0], 2)

    def test_generate_secret_is_shown_once_and_stored_only_in_the_registry(self):
        code, out, err = self.run_map('--repository', 'owner/build', '--server-id', self.remote, '--service', 'web', '--generate-secret')
        self.assertEqual(code, 0, err)
        shown = re.search(r'Secret\s*: ([0-9a-f]{64})', out).group(1)
        self.assertEqual(self.mapping('owner/build')['secret'], shown)
        self.assertIn('shown once', out)
        self.assertIn('https://hooks.example.com/webhook/web', out)
        self.assertIn('Build', out)
        # A second generation is a different secret, and a duplicate mapping is refused.
        self.assertEqual(self.run_map('--repository', 'owner/build', '--server-id', self.remote, '--service', 'web2', '--generate-secret')[0], 1)

    def test_secret_file_still_works_and_exactly_one_secret_source_is_required(self):
        secret_file = self.root / 'secret'
        secret_file.write_text(secrets.token_hex(32))
        args = ('--repository', 'owner/file', '--server-id', self.remote, '--service', 'file')
        self.assertEqual(self.run_map(*args)[0], 2)
        self.assertEqual(self.run_map(*args, '--secret-file', str(secret_file), '--generate-secret')[0], 2)
        code, out, err = self.run_map(*args, '--secret-file', str(secret_file))
        self.assertEqual(code, 0, err)
        self.assertNotIn(secret_file.read_text().strip(), out)

    def test_unknown_server_is_refused_before_anything_is_saved(self):
        code, _, err = self.run_map('--repository', 'owner/x', '--server-id', 'f' * 32, '--service', 'x', '--generate-secret')
        self.assertEqual(code, 1)
        self.assertIn('Unknown server', err)
        self.assertIsNone(self.mapping('owner/x'))


class FailureReasonTests(unittest.TestCase):
    def app(self):
        a = MagicMock()
        a.redact_repo_url = lambda text: re.sub(r'(https?://)[^/\s@]+@', r'\1***@', text)
        return a

    def test_own_errors_are_shown_and_foreign_errors_are_typed_and_redacted(self):
        a = self.app()
        text = ats_routing.failure_reason(a, ValueError('Local service/branch no longer matches mapping'))
        self.assertIn('no longer matches mapping', text)
        self.assertIn('inspect the destination before a manual retry', text)
        transport = ats_routing.failure_reason(a, cluster.TransportError('build.example.com rejected the server ID or passkey.', 'auth'))
        self.assertIn('rejected the server ID or passkey', transport)
        foreign = ats_routing.failure_reason(a, RuntimeError('git failed for https://user:token@github.com/o/r.git'))
        self.assertTrue(foreign.startswith('RuntimeError: '))
        self.assertNotIn('token', foreign)
        self.assertLessEqual(len(ats_routing.failure_reason(a, ValueError('x' * 5000))), 240 + 60)
        self.assertEqual(ats_routing.failure_reason(a, KeyError()).split(' (')[0], 'KeyError')

    def test_process_records_the_reason_and_logs_it(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        with patch.dict(os.environ, {'ATS_CLUSTER_DB': tmp.name + '/c.db'}):
            store = cluster.Store()
            store.configure('local', 'Primary', webhook='hooks.example.com')
            local = store.node()['id']
            store.mapping('owner/r', local, 'svc', 'main', secrets.token_hex(32))
            a = self.app()
            a.get_service_by_name = lambda name: None  # the Local service vanished since the mapping was made
            events = []
            a.record_webhook_event = lambda *args, **kwargs: events.append(args)
            with store.db() as db:
                row = dict(db.execute('SELECT * FROM routes').fetchone())
                data = json.dumps({'route': row, 'payload': {'ref': 'refs/heads/main', 'after': 'a' * 40}, 'delivery': 'd1'})
                db.execute("INSERT INTO seen VALUES('webhook','d1',0,'pending',?)", (data,))
            asyncio.run(ats_routing.process(a, store, 'd1'))
            self.assertEqual(events[0][4], 'failed')
            self.assertIn('no longer matches mapping', events[0][5])
            a.logger.warning.assert_called_once()


class MappedStatusTests(unittest.TestCase):
    def test_webhook_operation_reports_whether_a_service_is_mapped(self):
        import ats_api
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = patch.dict(os.environ, {'ATS_CLUSTER_DB': tmp.name + '/c.db'})
        env.start()
        self.addCleanup(env.stop)
        store = cluster.Store()
        local = store.configure('local', 'Primary', webhook='hooks.example.com')['id']
        mapping_secret = secrets.token_hex(32)
        store.mapping('Owner/Site', local, 'site', 'main', mapping_secret)
        a = MagicMock()
        a.WEBHOOK_PORT = 9999
        a.webhook_bind_address.return_value = '127.0.0.1'
        a.check_port_listening.return_value = True
        a.get_webhook_info.return_value = {'url': 'https://hooks.example.com/webhook/x', 'secret': 's', 'branch': 'main', 'auto_update': True}
        a.list_webhook_events.return_value = []
        with patch.object(ats_api, 'settings', return_value={'webhook': {'domain': 'hooks.example.com'}}), patch.object(ats_api, 'routes', return_value=[]):
            with patch.object(ats_api, 'service', return_value={'name': 'site'}):
                mapped = ats_api.webhook(a, {'name': 'site'})['service']
            with patch.object(ats_api, 'service', return_value={'name': 'unmapped'}):
                unmapped = ats_api.webhook(a, {'name': 'unmapped'})['service']
            with patch.object(ats_api, 'service', return_value={'name': 'site'}), patch('ats_cluster.Store', side_effect=OSError('unreadable')):
                unknown = ats_api.webhook(a, {'name': 'site'})['service']
        self.assertEqual((mapped['mapped'], mapped['mapped_repository']), (True, 'owner/site'))
        self.assertEqual((unmapped['mapped'], unmapped['mapped_repository']), (False, None))
        self.assertIsNone(unknown['mapped'])
        self.assertNotIn(mapping_secret, json.dumps([mapped, unmapped, unknown]))  # the registry's secret is never reported


if __name__ == '__main__':
    unittest.main()
