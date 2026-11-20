"""Upgrade/startup setup runs before background tasks; all storage is temporary."""
import asyncio
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ats_cluster import Store
from ats_server_cli import ensure_startup_configuration as ready


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'cluster.db')
        self.cf = self.root / 'tunnel.yml'
        self.cf.write_text('ingress: []\n')
        self.env = patch.dict(os.environ, {'ATS_CONFIG_FILE': str(self.root / 'config.yml')})
        self.export = patch('ats_server_cli.default_pairing_path', return_value=self.root / 'files' / 'pairing.json')
        self.export.start()
        self.addCleanup(self.export.stop)
        self.env.start()
        self.addCleanup(self.env.stop)

    def launch(self, answers):
        with patch('builtins.input', side_effect=answers):
            return ready(interactive=True, cloudflare_config=str(self.cf), store=self.store)

    def test_upgrade_prompts_on_first_launch_then_reuses_identity(self):
        node = self.launch(['local', 'Primary', 'hooks.example.com'])
        with patch('builtins.input', side_effect=AssertionError('must not prompt')):
            self.assertEqual(ready(interactive=True, store=self.store), node)
            self.assertEqual(ready(interactive=False, store=self.store), node)

    def test_missing_field_preserves_identity_secret_and_existing_name(self):
        old = self.store.configure('local', 'Existing', webhook='hooks.example.com')
        with self.store.db() as db:
            db.execute('UPDATE node SET webhook=NULL')
        node = self.launch(['new-hooks.example.com'])
        for key in ('id', 'secret', 'name', 'role'):
            self.assertEqual(old[key], node[key])
        self.assertEqual(node['webhook'], 'new-hooks.example.com')

    def test_invalid_entry_retries_before_persisting(self):
        node = self.launch(['wrong', 'Name', 'local', 'Name', 'bad/host',
                            'local', 'Name', 'hooks.example.com'])
        self.assertEqual(node['role'], 'local')

    def test_noninteractive_missing_config_never_prompts(self):
        with patch('builtins.input', side_effect=AssertionError('must not prompt')):
            with self.assertRaisesRegex(ValueError, 'ATS_CLUSTER_DB'):
                ready(interactive=False, store=self.store)
        self.assertIsNone(self.store.node())

    def test_cancel_leaves_no_node(self):
        with self.assertRaisesRegex(ValueError, 'cancelled'):
            self.launch([EOFError])
        self.assertIsNone(self.store.node())

    def test_existing_route_needs_confirmation_and_never_changes_tunnel(self):
        config = 'ingress:\n- hostname: hooks.example.com\n  service: http://localhost:9999\n'
        self.cf.write_text(config)
        node = self.launch(['local', 'Primary', 'hooks.example.com', 'yes'])
        self.assertEqual(node['webhook'], 'hooks.example.com')
        self.assertEqual(self.cf.read_text(), config)

    def test_route_reuse_declined_and_then_new_hostname_selected(self):
        config = 'ingress:\n- hostname: hooks.example.com\n  service: http://localhost:9999\n'
        self.cf.write_text(config)
        node = self.launch(['local', 'Primary', 'hooks.example.com', 'no',
                            'local', 'Primary', 'new.example.com'])
        self.assertEqual(node['webhook'], 'new.example.com')
        self.assertEqual(self.cf.read_text(), config)

    def test_wildcard_reuse_requires_explicit_confirmation(self):
        self.cf.write_text('ingress:\n- hostname: "*.example.com"\n  service: http://localhost:9999\n')
        node = self.launch(['local', 'Primary', 'hooks.example.com', 'yes'])
        self.assertEqual(node['webhook'], 'hooks.example.com')

    def test_duplicate_route_rejected_before_save(self):
        self.cf.write_text('ingress:\n- hostname: hooks.example.com\n- hostname: hooks.example.com\n')
        with self.assertRaisesRegex(ValueError, 'cancelled'):
            self.launch(['local', 'Primary', 'hooks.example.com', EOFError])
        self.assertIsNone(self.store.node())

    def test_global_automatically_exports_without_webhook(self):
        path = self.root / 'files' / 'pairing.json'
        node = self.launch(['global', 'Remote', 'https://remote.example.com'])
        self.assertIsNone(node['webhook'])
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        import json
        self.assertEqual(json.loads(path.read_text()), node)

    def test_unsafe_pairing_directory_does_not_persist_global(self):
        (self.root / 'files').mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, 'cancelled'):
            self.launch(['global', 'Remote', 'https://remote.example.com', EOFError])
        self.assertIsNone(self.store.node())

    def test_corrupt_credentials_are_not_silently_regenerated(self):
        self.store.configure('local', 'Primary', webhook='hooks.example.com')
        with self.store.db() as db:
            db.execute("UPDATE node SET secret='' ")
        with self.assertRaisesRegex(ValueError, 'restore the private'):
            self.launch([])

    def test_startup_checks_precede_menu_and_daemon_workers(self):
        # Harness prevents any real service, database or config access.
        from harness import load_app
        env = load_app()
        self.addCleanup(env.close)
        app = env.app
        with patch('ats_server_cli.ensure_startup_configuration', side_effect=ValueError('incomplete')):
            with patch('asyncio.create_task', side_effect=AssertionError('worker started')):
                for entry in (app.mainmenu, app.run_daemon):
                    with self.assertRaisesRegex(ValueError, 'incomplete'):
                        asyncio.run(entry())

    def test_global_webhook_menu_returns_without_task(self):
        from harness import load_app
        node = self.store.configure('global', 'Remote', 'https://remote.example.com')
        env = load_app()
        self.addCleanup(env.close)
        app = env.app
        with patch('ats_cluster.Store', return_value=self.store), patch('ats_server_cli.ensure_startup_configuration', return_value=node):
            with patch('asyncio.create_task', side_effect=AssertionError('webhook task started')):
                asyncio.run(app.run_webhook_listener())


if __name__ == '__main__':
    unittest.main()
