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
        self.path = self.root / 'files' / 'pairing.json'
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

    def test_upgrade_reexports_registry_and_preserves_unnamed_private_file(self):
        old = self.root / 'files' / '.json'
        old.parent.mkdir(mode=0o700)
        old.write_text(json.dumps(dict(self.node, name='Previous name')))
        old.chmod(0o600)
        previous = old.read_bytes()
        cli.ensure_startup_configuration(interactive=False, store=self.store)
        cli.save_pairing(self.store)
        self.assertEqual(json.loads(self.path.read_text()), self.node)
        self.assertEqual(self.store.node(), self.node)
        self.assertEqual(old.read_bytes(), previous)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_styled_menu_uses_runtime_header_and_keeps_results_until_continue(self):
        from harness import load_app
        env = load_app()
        self.addCleanup(env.close)
        app = env.app
        prompts = []
        answers = iter(['10', '', 'invalid', '', '2', '', '0'])
        def answer(prompt):
            prompts.append(prompt)
            return next(answers)
        with patch.object(app, 'print_header') as header, patch('builtins.input', side_effect=answer), \
                patch('os.geteuid', return_value=self.root.stat().st_uid):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                cli.menu(self.store, ui=app)
        text = output.getvalue()
        self.assertEqual(header.call_count, 4)
        self.assertIn(app.C_CYAN + app.C_BOLD + '═══ SERVER CONFIGURATION ═══', text)
        self.assertIn(app.C_BOLD + '[0]' + app.C_RESET + ' Back', text)
        self.assertIn('Restart=always', text)
        self.assertNotIn('Disconnect Global', text)
        self.assertIn(app.C_YELLOW, text)
        self.assertEqual(sum('Press Enter to continue' in p for p in prompts), 3)
        self.assertEqual(json.loads(self.path.read_text()), self.node)
        self.assertNotIn(self.node['secret'], text)

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
        self.assertFalse((other / 'pairing.json').exists())
        self.path.parent.unlink()
        self.path.parent.mkdir(mode=0o700)
        victim = self.root / 'victim'
        victim.write_text('unchanged')
        self.path.symlink_to(victim)
        with self.assertRaises(OSError):
            cli.save_pairing(self.store)
        self.assertEqual(victim.read_text(), 'unchanged')

    def test_startup_secures_owned_directory_and_preserves_credentials_and_old_files(self):
        for mode in (0o755, 0o775, 0o777, 0o750, 0o1700):
            with self.subTest(mode=oct(mode)):
                self.path.parent.mkdir(exist_ok=True)
                self.path.parent.chmod(mode)
                old = self.path.parent / '.json'
                old.write_text('old private export')
                old.chmod(0o600)
                cli.ensure_startup_configuration(interactive=False, store=self.store)
                self.assertEqual(self.path.parent.stat().st_mode & 0o7777, 0o700)
                self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(json.loads(self.path.read_text()), self.node)
                self.assertEqual(self.store.node(), self.node)
                self.assertEqual(old.read_text(), 'old private export')

    def test_foreign_directory_is_not_chmodded_or_exported(self):
        self.path.parent.mkdir(mode=0o755)
        with patch.object(cli.os, 'geteuid', return_value=self.root.stat().st_uid + 1), \
                patch.object(cli.os, 'fchmod') as chmod:
            with self.assertRaisesRegex(ValueError, 'correct ownership'):
                cli.save_pairing(self.store)
        chmod.assert_not_called()
        self.assertFalse(self.path.exists())
        self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(self.store.node(), self.node)

    @contextlib.contextmanager
    def root_runtime(self, *, fail_chown=False):
        """Model root fchown on real temporary directory/file I/O."""
        original_fstat = os.fstat
        original_replace = os.replace
        root_files = set()
        def replace(*args, **kwargs):
            original_replace(*args, **kwargs)
            root_files.add(self.path.stat().st_ino)
        # Present a non-root login user as the owner even when the suite itself runs as root.
        login_uid = os.getuid() or 1000
        directory_uid = self.path.parent.stat().st_uid or login_uid
        def fstat(fd):
            info = original_fstat(fd)
            if info.st_ino in root_files:
                owner = 0
            elif info.st_ino == self.path.parent.stat().st_ino:
                owner = directory_uid
            else:
                owner = login_uid
            fields = list(info)
            fields[4] = owner
            return os.stat_result(fields)
        def fchown(fd, uid, gid):
            nonlocal directory_uid
            inode = original_fstat(fd).st_ino
            self.assertIn(inode, {self.path.parent.stat().st_ino, self.path.stat().st_ino} if self.path.exists() else {self.path.parent.stat().st_ino})
            self.assertEqual((uid, gid), (0, -1))
            if fail_chown:
                raise PermissionError('ownership repair denied')
            if inode == self.path.parent.stat().st_ino:
                directory_uid = uid
            else:
                root_files.add(inode)
        with patch.object(cli.os, 'geteuid', return_value=0), \
                patch.object(cli.os, 'replace', side_effect=replace), \
                patch.object(cli.os, 'fstat', side_effect=fstat), \
                patch.object(cli.os, 'fchown', side_effect=fchown) as chown:
            yield chown

    def test_root_startup_adopts_user_directory_and_preserves_credentials(self):
        self.path.parent.mkdir(mode=0o755)
        old = self.path.parent / '.json'
        old.write_text('old private export')
        old.chmod(0o600)
        before = old.stat()
        for existing in (False, True):
            with self.subTest(existing=existing), self.root_runtime() as chown:
                cli.ensure_startup_configuration(interactive=False, store=self.store)
                cli.ensure_startup_configuration(interactive=False, store=self.store)
                self.assertEqual(chown.call_count, 2 if existing else 1)
            self.assertEqual(json.loads(self.path.read_text()), self.node)
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(self.path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(self.store.node(), self.node)
            self.assertEqual(old.read_text(), 'old private export')
            self.assertEqual(old.stat().st_uid, before.st_uid)

    def test_root_repair_failure_preserves_export_and_registry(self):
        cli.save_pairing(self.store)
        previous = self.path.read_bytes()
        with self.root_runtime(fail_chown=True):
            with self.assertRaisesRegex(ValueError, 'Cannot secure pairing directory'):
                cli.ensure_startup_configuration(interactive=False, store=self.store)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(self.store.node(), self.node)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_root_validates_existing_export_before_taking_ownership(self):
        cli.save_pairing(self.store)
        for data in ('{broken', json.dumps(dict(self.node, id='f'*32))):
            self.path.write_text(data)
            with self.root_runtime() as chown:
                with self.assertRaises(ValueError):
                    cli.save_pairing(self.store)
                chown.assert_not_called()
            self.assertEqual(self.path.read_text(), data)
        self.path.write_text(json.dumps(self.node))
        self.path.chmod(0o644)
        with self.root_runtime() as chown:
            with self.assertRaises(ValueError):
                cli.save_pairing(self.store)
            chown.assert_not_called()

    def test_root_rejects_unrelated_file_owner_and_hardlinks(self):
        cli.save_pairing(self.store)
        original_fstat = os.fstat
        def unrelated_owner(fd):
            info = original_fstat(fd)
            if info.st_ino == self.path.stat().st_ino:
                fields = list(info)
                fields[4] = self.root.stat().st_uid + 42
                return os.stat_result(fields)
            return info
        with patch.object(cli.os, 'geteuid', return_value=0), \
                patch.object(cli.os, 'fstat', side_effect=unrelated_owner), \
                patch.object(cli.os, 'fchown') as chown:
            with self.assertRaisesRegex(ValueError, 'private, owned'):
                cli.save_pairing(self.store)
            chown.assert_not_called()
        backup = self.root / 'linked.json'
        os.link(self.path, backup)
        with self.root_runtime() as chown:
            with self.assertRaisesRegex(ValueError, 'private, owned'):
                cli.save_pairing(self.store)
            chown.assert_not_called()
        self.assertEqual(json.loads(backup.read_text()), self.node)

    def test_permission_repair_failure_preserves_existing_export_and_registry(self):
        cli.save_pairing(self.store)
        previous = self.path.read_bytes()
        self.path.parent.chmod(0o755)
        with patch.object(cli.os, 'fchmod', side_effect=PermissionError('read only')):
            with self.assertRaisesRegex(ValueError, 'Cannot secure pairing directory'):
                cli.ensure_startup_configuration(interactive=False, store=self.store)
        self.assertEqual(self.path.read_bytes(), previous)
        self.assertEqual(self.store.node(), self.node)
        self.assertEqual(list(self.path.parent.iterdir()), [self.path])

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
        menu.assert_called_once_with(ui=app)
        self.assertIn('Server Configuration', output.getvalue())

    def test_default_path_is_anchored_to_installation(self):
        self.assertEqual(self.actual_default(), Path(cli.__file__).resolve().parent / 'files' / 'pairing.json')
