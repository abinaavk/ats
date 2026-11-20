"""Private automatic export and option 12 behavior; no real service operations."""
import argparse
import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, AsyncMock

from ats_cluster import Store
import ats_server_cli as cli


class PairingFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / 'root' / '.json'
        self.store = Store(self.root / 'cluster.db')
        self.node = self.store.configure('global', 'Remote', 'https://remote.example.com')
        self.actual_default = cli.default_pairing_path
        export = patch.object(cli, 'default_pairing_path', return_value=self.path)
        export.start()
        self.addCleanup(export.stop)

    def test_missing_export_recreated_on_unattended_startup_without_rotating(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            cli.ensure_startup_configuration(interactive=False, store=self.store)
            self.path.unlink()
            cli.ensure_startup_configuration(interactive=False, store=self.store)
        self.assertEqual(json.loads(self.path.read_text()), self.node)
        self.assertEqual(self.store.node(), self.node)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(self.node['secret'], output.getvalue())

    def test_reconfiguration_updates_export_preserving_credentials(self):
        cli.save_pairing(self.store)
        args = argparse.Namespace(role='global', name='Renamed', api_domain='https://new.example.com',
            webhook_host=None, pairing_file=None)
        cli.configure(self.store, args, False)
        bundle = json.loads(self.path.read_text())
        for key in ('id', 'secret'):
            self.assertEqual(bundle[key], self.node[key])
        self.assertEqual(bundle, self.store.node())
        self.assertEqual(bundle['domain'], args.api_domain)

    def test_rotation_refreshes_export_and_export_failure_preserves_key(self):
        cli.save_pairing(self.store)
        cli.rotate_pairing(self.store)
        rotated = self.store.node()
        self.assertNotEqual(rotated['secret'], self.node['secret'])
        self.assertEqual(rotated['id'], self.node['id'])
        self.assertEqual(json.loads(self.path.read_text()), rotated)
        with self.assertRaises(FileExistsError):
            cli.rotate_pairing(self.store, self.path)
        self.assertEqual(self.store.node(), rotated)

    def test_foreign_identity_malformed_and_public_file_rejected_without_overwrite(self):
        cli.save_pairing(self.store)
        for data in ('{broken', json.dumps(dict(self.node, id='f'*32))):
            self.path.write_text(data)
            with self.assertRaises(ValueError):
                cli.save_pairing(self.store)
            self.assertEqual(self.path.read_text(), data)
        self.path.write_text(json.dumps(self.node))
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):
            cli.save_pairing(self.store)
        self.assertEqual(self.store.node(), self.node)

    def test_symlink_directory_and_file_rejected_without_touching_target(self):
        other = self.root / 'other'
        other.mkdir(mode=0o700)
        self.path.parent.symlink_to(other, target_is_directory=True)
        with self.assertRaises(OSError):
            cli.save_pairing(self.store)
        self.assertFalse((other / '.json').exists())
        self.path.parent.unlink()
        self.path.parent.mkdir(mode=0o700)
        victim = self.root / 'victim'
        victim.write_text('unchanged')
        self.path.symlink_to(victim)
        with self.assertRaises(OSError):
            cli.save_pairing(self.store)
        self.assertEqual(victim.read_text(), 'unchanged')

    def test_explicit_exports_remain_exclusive(self):
        target = self.root / 'custom.json'
        cli.save_pairing(self.store, target)
        self.assertEqual(json.loads(target.read_text()), self.node)
        with self.assertRaises(FileExistsError):
            cli.save_pairing(self.store, target)

    def test_menu_export_rename_rotation_decline_and_back_never_print_key(self):
        with patch('builtins.input', side_effect=['2', '1', 'Renamed', 'https://new.example.com', '3', 'no', '0']):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                cli.menu(self.store)
        self.assertNotIn(self.node['secret'], output.getvalue())
        self.assertEqual(self.store.node()['secret'], self.node['secret'])
        self.assertEqual(self.store.node()['name'], 'Renamed')
        self.assertEqual(json.loads(self.path.read_text()), self.store.node())

    def test_local_export_rejected(self):
        local = Store(self.root / 'local.db')
        local.configure('local', 'Primary', webhook='hooks.example.com')
        with self.assertRaises(ValueError):
            cli.save_pairing(local)
        self.assertFalse(self.path.exists())

    def test_headless_default_configure_export_and_rotate(self):
        with patch.object(cli, 'Store', return_value=self.store):
            with patch('sys.argv', ['server', 'configure', '--role', 'global', '--name', 'Renamed', '--api-domain', 'https://new.example.com']):
                cli.main()
            self.path.unlink()
            with patch('sys.argv', ['server', 'export']):
                cli.main()
            self.assertEqual(json.loads(self.path.read_text())['secret'], self.node['secret'])
            with patch('sys.argv', ['server', 'rotate']):
                cli.main()
            self.assertEqual(json.loads(self.path.read_text()), self.store.node())
            self.assertNotEqual(self.store.node()['secret'], self.node['secret'])

    def test_option_12_dispatches_from_main_menu(self):
        from harness import load_app
        env = load_app()
        self.addCleanup(env.close)
        app = env.app
        def discard_worker(coro):
            coro.close()
        with patch.object(cli, 'ensure_startup_configuration'), patch.object(cli, 'menu') as menu:
            with patch.object(app, 'get_telemetry_async', new=AsyncMock(return_value=(0, '0', '0', 0))):
                with patch.object(app.db, 'query', return_value=[]), patch('asyncio.create_task', side_effect=discard_worker):
                    with patch('builtins.input', side_effect=['12', EOFError]), contextlib.redirect_stdout(io.StringIO()) as output:
                        asyncio.run(app.mainmenu())
        menu.assert_called_once_with()
        self.assertIn('Server Configuration', output.getvalue())

    def test_default_path_is_anchored_to_installation(self):
        self.assertEqual(self.actual_default(), Path(cli.__file__).resolve().parent / 'root' / '.json')
