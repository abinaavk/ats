"""Deleting services reliably, editing the Cloudflare tunnel config safely, installing Docker/rclone on demand."""
import hashlib
import os
import re
from pathlib import Path
import shutil
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import harness
import ats_manage_runtime as runtime

SYSTEMCTL = '''#!/bin/sh
echo "systemctl $*" >> "$FAKE_STATE/calls.log"
case ",$GONE_ACTIONS," in *",$1,"*) echo "Failed to $1 $2: Unit $2 not loaded." >&2; exit 5;; esac
if [ "$FAIL_ACTION" = "$1" ]; then echo "injected failure" >&2; exit 1; fi
case "$1" in
stop) echo inactive > "$FAKE_STATE/active_$2";;
start|restart) echo active > "$FAKE_STATE/active_$2";;
is-active) if [ -f "$FAKE_STATE/active_$2" ]; then cat "$FAKE_STATE/active_$2"; else echo inactive; fi;;
esac
exit 0
'''

APT = '''#!/bin/sh
echo "apt-get $*" >> "$FAKE_STATE/calls.log"
if [ "$FAKE_APT_FAIL" = lock ]; then echo "E: Could not get lock /var/lib/dpkg/lock-frontend" >&2; exit 100; fi
if [ "$FAKE_APT_FAIL" = net ]; then echo "E: Failed to fetch http://deb.example/pool" >&2; exit 100; fi
if [ "$1" = install ]; then
  for pkg in "$@"; do
    case "$pkg" in
      docker.io) printf '#!/bin/sh\\necho "Docker version 27.0.0"\\n' > "$FAKE_BIN/docker"; chmod +x "$FAKE_BIN/docker";;
      rclone) printf '#!/bin/sh\\necho "rclone v1.60"\\n' > "$FAKE_BIN/rclone"; chmod +x "$FAKE_BIN/rclone";;
    esac
  done
fi
echo "Setting up packages..."
exit 0
'''

CLOUDFLARED = '''#!/bin/sh
echo "cloudflared $*" >> "$FAKE_STATE/calls.log"
if grep -q REJECT "$3" 2>/dev/null; then echo "error parsing ingress: REJECT rule is invalid" >&2; exit 1; fi
exit 0
'''


class Base(unittest.TestCase):
    def setUp(self):
        self.env = harness.load_app()
        self.addCleanup(self.env.close)
        self.a, self.root = self.env.app, Path(self.env.root)
        self.bin = Path(self.env.bin)
        # ISOLATION: these tests exercise installers and service control, so nothing outside the fake bin directory
        # (plus a few harmless utilities the fake scripts call) may ever be reachable through PATH.
        safe = self.root / 'safe'
        safe.mkdir()
        for utility in ('cat', 'grep', 'chmod', 'python3', 'sh'):
            real = shutil.which(utility, path='/usr/bin:/bin')
            if real:
                os.symlink(real, safe / utility)
        for name, body in (('systemctl', SYSTEMCTL), ('apt-get', APT), ('cloudflared', CLOUDFLARED),
                           ('usermod', '#!/bin/sh\necho "usermod $*" >> "$FAKE_STATE/calls.log"\n'),
                           ('dnf', '#!/bin/sh\necho "dnf $*" >> "$FAKE_STATE/calls.log"\nexit 1\n'),
                           ('docker', '#!/bin/sh\nexit 0\n'), ('rclone', '#!/bin/sh\nexit 0\n')):
            self.put(name, body)
        isolated = f'{self.bin}:{safe}'
        mock.patch.dict(os.environ, {'FAKE_BIN': str(self.bin), 'PATH': isolated}).start()
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(runtime, 'SAFE_PATH', isolated).start()
        for dangerous in ('systemctl', 'apt-get', 'dnf', 'usermod', 'docker', 'rclone', 'cloudflared'):
            self.assertEqual(shutil.which(dangerous, path=os.environ['PATH']), str(self.bin / dangerous), f'tests must never reach the host {dangerous}')
        # Start from "nothing optional is installed"; individual tests install or remove what they need.
        for name in ('docker', 'rclone', 'dnf'):
            (self.bin / name).unlink()
        self.a.SYSTEMD_DIR, self.a.LOGROTATE_DIR = str(self.root / 'systemd'), str(self.root / 'rotate')
        (self.root / 'systemd').mkdir()
        (self.root / 'rotate').mkdir()
        self.events, self.logs = [], []
        self.a.api_emit = self.events.append
        self.a.api_log = lambda message, level='info': self.logs.append((level, message))
        # "Installed" means the executable exists in the fake bin directory, whatever the real host has.
        mock.patch.object(runtime.shutil, 'which', lambda name, **k: str(self.bin / name) if (self.bin / name).exists() else None).start()

    def put(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(0o755)

    def steps(self):
        return [(e['id'], e['state']) for e in self.events if e['t'] == 'step']


class DeleteTests(Base):
    def service(self, name='demo', kind='node'):
        runtime.sql(self.a, 'INSERT INTO services(name,port,domain,storage_path,repo_url,runtime,branch) VALUES(?,?,?,?,?,?,?)',
                    (name, 18080, name + '.example.com', self.env.storage, 'https://github.com/o/r.git', kind, 'main'))
        s = runtime.row(self.a, name)
        directory, database = runtime.paths(self.a, s)
        os.makedirs(directory)
        os.makedirs(database)
        Path(self.a._unit_path(name)).write_text('[Unit]\n')
        self.a.cloudflare.add_route = lambda *a: None
        return s

    def remaining(self, name='demo'):
        return self.a.db.query('SELECT 1 FROM services WHERE name=?', (name,), fetch_one=True)

    def delete(self, **extra):
        with mock.patch.object(self.a, 'restart_cloudflared_resilient', lambda *a, **k: None):
            return runtime.delete(self.a, dict(name='demo', confirm='demo', **extra))

    def test_every_step_is_reported_in_order_and_the_service_is_gone(self):
        s = self.service()
        result = self.delete()
        self.assertEqual(result, {'deleted': True, 'warnings': []})
        ids = [i for i, state in self.steps() if state == 'start']
        self.assertEqual(ids, ['stop', 'disable', 'cloudflare', 'unit', 'files', 'record', 'reload'])
        self.assertEqual([state for _, state in self.steps()], ['start', 'done'] * len(ids))
        self.assertIsNone(self.remaining())
        self.assertFalse(Path(self.a._unit_path('demo')).exists())
        self.assertFalse(Path(runtime.paths(self.a, s)[0]).exists())

    def test_optional_steps_appear_only_when_requested(self):
        self.service(kind='docker')
        self.put('docker', '#!/bin/sh\nexit 0\n')
        self.a.create_local_backup = lambda s: True
        self.delete(backup_first=True, delete_backups=True)
        ids = [i for i, state in self.steps() if state == 'start']
        self.assertEqual(ids, ['backup', 'stop', 'disable', 'cloudflare', 'container', 'unit', 'files', 'backups', 'record', 'reload'])

    def test_a_service_whose_unit_never_existed_can_still_be_deleted(self):
        # Regression: a half-deployed service could never be deleted because systemctl stop/disable failed on a missing unit.
        self.service()
        Path(self.a._unit_path('demo')).unlink()
        with mock.patch.dict(os.environ, {'GONE_ACTIONS': 'stop,disable'}):
            self.assertEqual(self.delete()['deleted'], True)
        self.assertIsNone(self.remaining())

    def test_a_genuine_stop_failure_aborts_before_anything_is_deleted(self):
        s = self.service()
        with mock.patch.dict(os.environ, {'FAIL_ACTION': 'stop'}):
            with self.assertRaisesRegex(self.a.ServiceOpError, 'injected failure'):
                self.delete()
        self.assertIsNotNone(self.remaining())
        self.assertTrue(Path(runtime.paths(self.a, s)[0]).exists())
        self.assertIn(('stop', 'fail'), self.steps())

    def test_an_interrupted_delete_is_finished_by_running_it_again(self):
        s = self.service()
        real = shutil.rmtree
        calls = []

        def broken(path, *a, **k):
            calls.append(path)
            raise PermissionError(13, 'Permission denied')
        with mock.patch.object(runtime.shutil, 'rmtree', broken):
            with self.assertRaisesRegex(self.a.ServiceOpError, 'Could not delete .*Permission denied.*run the delete again'):
                self.delete()
        self.assertIsNotNone(self.remaining())                        # nothing is lost: it can be retried
        self.assertFalse(Path(self.a._unit_path('demo')).exists())    # the unit step already completed
        self.events.clear()
        with mock.patch.dict(os.environ, {'GONE_ACTIONS': 'stop,disable'}):  # the unit is gone now, as systemd would say
            self.assertEqual(self.delete()['deleted'], True)
        self.assertIsNone(self.remaining())
        self.assertFalse(Path(runtime.paths(self.a, s)[0]).exists())

    def test_a_cloudflare_problem_is_a_warning_not_a_blocker(self):
        self.service()
        with mock.patch.object(self.a.cloudflare, 'remove_route', side_effect=RuntimeError('cloudflared did not become active\nlong journal')):
            with mock.patch.object(self.a, 'restart_cloudflared_resilient', lambda *a, **k: None):
                result = runtime.delete(self.a, dict(name='demo', confirm='demo'))
        self.assertTrue(result['deleted'])
        self.assertEqual(len(result['warnings']), 1)
        self.assertIn('Cloudflare route for demo.example.com was not removed', result['warnings'][0])
        self.assertNotIn('long journal', result['warnings'][0])
        self.assertIsNone(self.remaining())
        self.assertIn(('warn', result['warnings'][0]), self.logs)

    def test_missing_docker_does_not_crash_a_docker_service_delete(self):
        self.service(kind='docker')
        result = self.delete()
        self.assertTrue(result['deleted'])
        self.assertIn('Docker is not installed', result['warnings'][0])
        self.put('docker', '#!/bin/sh\necho "Error: No such container: ats-demo" >&2\nexit 1\n')   # "already gone" is success
        self.service(kind='docker')
        self.assertEqual(self.delete()['warnings'], [])

    def test_drive_backups_need_rclone_and_already_deleted_ones_do_not_block(self):
        self.service()
        for name in ('one.zip', 'two.zip'):
            runtime.sql(self.a, "INSERT INTO backups(service_name,filename,size_bytes,checksum,location,local_path) VALUES('demo',?,1,'x','gdrive',NULL)", (name,))
        result = self.delete(delete_backups=True)             # rclone is not installed
        self.assertEqual(len(result['warnings']), 2)
        self.assertTrue(all('rclone is not installed' in w for w in result['warnings']))
        self.assertEqual(self.a.db.query("SELECT count(*) AS n FROM backups WHERE service_name='demo'", fetch_one=True)['n'], 2)   # kept for later
        self.service()
        self.put('rclone', '#!/bin/sh\necho "Failed to deletefile: object not found" >&2\nexit 3\n')
        result = self.delete(delete_backups=True)
        self.assertEqual(result['warnings'], [])
        self.assertEqual(self.a.db.query("SELECT count(*) AS n FROM backups WHERE service_name='demo'", fetch_one=True)['n'], 0)

    def test_confirmation_and_symlinks_are_still_enforced(self):
        s = self.service()
        with self.assertRaisesRegex(ValueError, 'Type the service name'):
            runtime.delete(self.a, dict(name='demo', confirm='nope'))
        directory = runtime.paths(self.a, s)[0]
        decoy = self.root / 'decoy'
        decoy.mkdir()
        (decoy / 'precious.txt').write_text('keep')
        shutil.rmtree(directory)
        os.symlink(decoy, directory)
        with self.assertRaisesRegex(ValueError, 'symlinked'):
            self.delete()
        self.assertEqual((decoy / 'precious.txt').read_text(), 'keep')     # the link target was never touched
        self.assertIsNotNone(self.remaining())


class CloudflareFileTests(Base):
    GOOD = 'tunnel: test\ncredentials-file: /x.json\ningress:\n  - hostname: a.example.com\n    service: http://localhost:8000\n  - service: http_status:404\n'

    def setUp(self):
        super().setUp()
        self.path = Path(self.env.cf_config)
        self.path.write_text(self.GOOD)
        self.path.chmod(0o640)
        self.restarts = []
        mock.patch.object(self.a, 'restart_cloudflared_resilient', lambda *a, **k: self.restarts.append(k)).start()
        mock.patch.object(self.a, 'check_systemd_active', lambda name: True).start()

    def get(self):
        return runtime.cloudflare_file(self.a, 'cloudflare.config.get', {})

    def set(self, content, **extra):
        return runtime.cloudflare_file(self.a, 'cloudflare.config.set', dict(content=content, base_sha256=self.get()['sha256'], **extra))

    def test_get_returns_the_file_and_its_fingerprint(self):
        data = self.get()
        self.assertEqual(data['content'], self.GOOD)
        self.assertEqual(data['sha256'], hashlib.sha256(self.GOOD.encode()).hexdigest())
        self.assertEqual((data['exists'], data['validator'], data['active']), (True, True, True))

    def test_a_valid_edit_is_backed_up_written_atomically_and_applied(self):
        edited = self.GOOD.replace('  - service: http_status:404', '  - hostname: b.example.com\n    service: http://localhost:9000\n  - service: http_status:404')
        result = self.set(edited)
        self.assertEqual(self.path.read_text(), edited)
        self.assertEqual(oct(self.path.stat().st_mode & 0o777), '0o640')           # mode preserved
        self.assertEqual(Path(result['backup']).read_text(), self.GOOD)
        self.assertTrue((result['saved'], result['restarted']) == (True, True) and len(self.restarts) == 1)
        self.assertEqual([i for i, st in self.steps() if st == 'start'], ['validate', 'backup', 'write', 'restart'])
        self.assertNotIn('b.example.com', ' '.join(self.logs[0:0]))
        self.assertEqual(self.get()['sha256'], result['sha256'])

    def test_bad_files_are_refused_and_nothing_changes(self):
        for bad, reason in (('ingress: [', 'Not valid YAML'), ('- just\n- a list\n', 'YAML mapping'), ('tunnel: t\ncredentials-file: /x\ningress: []\n', 'non-empty list'),
                            ('tunnel: t\ncredentials-file: /x\ningress:\n  - hostname: a.example.com\n    service: http://localhost:1\n', 'catch-all'),
                            ('credentials-file: /x\ningress:\n  - service: http_status:404\n', '"tunnel" must not be removed'),
                            ('tunnel: test\ningress:\n  - service: http_status:404\n', '"credentials-file" must not be removed'),
                            (self.GOOD + '# REJECT\n', 'cloudflared rejected the config')):
            with self.assertRaisesRegex(ValueError, reason):
                self.set(bad)
        with self.assertRaises(ValueError):
            self.set('x\x00y')
        with self.assertRaises(ValueError):
            runtime.cloudflare_file(self.a, 'cloudflare.config.set', dict(content=self.GOOD, base_sha256='short'))
        self.assertEqual(self.path.read_text(), self.GOOD)
        self.assertEqual(self.restarts, [])
        self.assertEqual([p.name for p in self.path.parent.glob('*.bak-*')], [])

    def test_a_concurrent_change_is_detected_instead_of_overwritten(self):
        seen = self.get()['sha256']
        self.path.write_text(self.GOOD + '# edited by ATS meanwhile\n')
        with self.assertRaisesRegex(self.a.ServiceOpError, 'changed on the server'):
            runtime.cloudflare_file(self.a, 'cloudflare.config.set', dict(content=self.GOOD, base_sha256=seen))
        self.assertIn('edited by ATS meanwhile', self.path.read_text())

    def test_if_cloudflared_will_not_start_the_previous_file_is_restored(self):
        calls = []

        def restart(*a, **k):
            calls.append(k)
            if len(calls) == 1:
                raise RuntimeError('cloudflared did not become active after 3 attempts\njournal...')
        with mock.patch.object(self.a, 'restart_cloudflared_resilient', restart):
            with self.assertRaisesRegex(self.a.ServiceOpError, 'previous file was restored.*cloudflared did not become active'):
                self.set(self.GOOD.replace('a.example.com', 'c.example.com'))
        self.assertEqual(self.path.read_text(), self.GOOD)
        self.assertEqual(len(calls), 2)                       # one failed start, one start with the restored file
        self.assertIn(('restart', 'fail'), self.steps())

    def test_saving_without_restart_says_the_tunnel_still_runs_the_old_routes(self):
        result = self.set(self.GOOD.replace('a.example.com', 'd.example.com'), restart=False)
        self.assertFalse(result['restarted'])
        self.assertEqual(self.restarts, [])
        self.assertIn('not restarted', result['warnings'][0])

    def test_routes_of_deployed_services_that_were_removed_are_reported(self):
        runtime.sql(self.a, 'INSERT INTO services(name,port,domain,storage_path,repo_url,runtime,branch) VALUES(?,?,?,?,?,?,?)',
                    ('site', 18090, 'site.example.com', self.env.storage, 'https://github.com/o/r.git', 'node', 'main'))
        result = self.set(self.GOOD)
        self.assertEqual(result['missing_routes'], ['site.example.com'])

    def test_without_cloudflared_only_the_structure_is_checked(self):
        (self.bin / 'cloudflared').unlink()
        self.assertFalse(self.get()['validator'])
        result = self.set(self.GOOD + '# comment\n')
        self.assertIn('cloudflared is not installed', result['warnings'][0])

    def test_unknown_options_and_the_hostile_path_cannot_redirect_the_write(self):
        other = self.root / 'elsewhere.yml'
        runtime.cloudflare_file(self.a, 'cloudflare.config.set', dict(content=self.GOOD, base_sha256=self.get()['sha256'], path=str(other)))
        self.assertFalse(other.exists())


    def backups(self):
        return runtime.cloudflare_file(self.a, 'cloudflare.config.backups', {})['backups']

    def restore(self, name, **extra):
        return runtime.cloudflare_file(self.a, 'cloudflare.config.restore', dict(name=name, base_sha256=self.get()['sha256'], **extra))

    def two_edits(self):
        first = self.GOOD.replace('a.example.com', 'one.example.com')
        self.set(first)
        time.sleep(1.1)                                # backup names carry second resolution
        self.set(first.replace('one.example.com', 'two.example.com'))
        return first

    def test_backups_are_listed_newest_first_with_the_hostnames_they_route(self):
        self.assertEqual(self.backups(), [])
        self.two_edits()
        listed = self.backups()
        self.assertEqual([b['hostnames'] for b in listed], [['one.example.com'], ['a.example.com']])
        self.assertTrue(all(re.fullmatch(r'[0-9a-f]{64}', b['sha256']) and b['size'] > 0 for b in listed))
        (self.path.parent / (self.path.name + '.bak-20200101-000000')).symlink_to(self.path)
        (self.path.parent / 'other.yml.bak-20200101-000000').write_text(self.GOOD)
        (self.path.parent / (self.path.name + '.bak-notadate')).write_text(self.GOOD)
        self.assertEqual(len(self.backups()), 2)       # symlinks, other files' backups and odd names are never offered

    def test_restoring_validates_backs_up_the_current_file_and_restarts(self):
        self.two_edits()
        target = self.backups()[1]
        before = self.path.read_text()
        result = self.restore(target['name'])
        self.assertEqual(self.path.read_text(), self.GOOD)
        self.assertEqual((result['restored'], result['restarted']), (target['name'], True))
        self.assertEqual(Path(result['backup']).read_text(), before)         # restoring is itself undoable
        self.assertEqual(len(self.restarts), 3)
        self.assertEqual(self.backups()[0]['hostnames'], ['two.example.com'])

    def test_a_backup_that_is_no_longer_valid_is_refused_and_nothing_changes(self):
        self.two_edits()
        name = self.backups()[0]['name']
        (self.path.parent / name).write_text(self.GOOD + '# REJECT\n')
        before, restarts = self.path.read_text(), len(self.restarts)
        with self.assertRaisesRegex(ValueError, 'cloudflared rejected'):
            self.restore(name)
        self.assertEqual((self.path.read_text(), len(self.restarts)), (before, restarts))

    def test_restore_rejects_names_outside_the_listed_pattern_and_stale_pages(self):
        self.two_edits()
        outside = self.root / 'secret.txt'
        outside.write_text('x')
        for bad in ('../secret.txt', str(outside), self.path.name, self.path.name + '.bak-20200101-000000/../../x', 'other.yml.bak-20200101-000000', None, 5, ['a']):
            with self.assertRaises(ValueError, msg=bad):
                self.restore(bad)
        with self.assertRaisesRegex(self.a.ServiceOpError, 'no longer exists'):
            self.restore(self.path.name + '.bak-20200101-000000')
        link = self.path.parent / (self.path.name + '.bak-20200101-000001')
        link.symlink_to(outside)
        with self.assertRaises(self.a.ServiceOpError):
            self.restore(link.name)                    # a symlink named like a backup is never followed
        self.assertNotIn('x', self.path.read_text().split())
        seen = self.get()['sha256']
        self.path.write_text(self.GOOD + '# changed meanwhile\n')
        with self.assertRaisesRegex(self.a.ServiceOpError, 'changed on the server'):
            runtime.cloudflare_file(self.a, 'cloudflare.config.restore', dict(name=self.backups()[0]['name'], base_sha256=seen))

    def test_a_restore_that_cannot_start_cloudflared_puts_the_previous_file_back(self):
        self.two_edits()
        calls = []

        def restart(*a, **k):
            calls.append(k)
            if len(calls) == 1:
                raise RuntimeError('cloudflared did not become active')
        before = self.path.read_text()
        with mock.patch.object(self.a, 'restart_cloudflared_resilient', restart):
            with self.assertRaisesRegex(self.a.ServiceOpError, 'previous file was restored'):
                self.restore(self.backups()[1]['name'])
        self.assertEqual(self.path.read_text(), before)


class InstallTests(Base):
    def install(self, name, **env):
        with mock.patch.dict(os.environ, env):
            return runtime.install_dependency(self.a, {'name': name})

    def test_docker_is_installed_enabled_and_given_to_the_service_user(self):
        self.put('usermod', '#!/bin/sh\necho "usermod $*" >> "$FAKE_STATE/calls.log"\n')
        result = self.install('docker')
        self.assertEqual((result['installed'], result['version']), (True, 'Docker version 27.0.0'))
        calls = self.env.calls()
        self.assertIn('apt-get update -qq', calls)
        self.assertIn('apt-get install -y --no-install-recommends docker.io', calls)
        self.assertIn('systemctl enable --now docker', calls)
        self.assertIn(f'usermod -aG docker {self.a.SERVICE_USER}', calls)
        self.assertEqual([i for i, s in self.steps() if s == 'start'], ['prepare', 'install', 'enable', 'access', 'verify'])
        self.assertIn(self.a.SERVICE_USER, result['next'])

    def test_rclone_install_points_at_the_next_manual_step(self):
        result = self.install('rclone')
        self.assertTrue(result['installed'])
        self.assertIn('rclone config', result['next'])
        self.assertNotIn('docker', self.env.calls())

    def test_already_installed_is_a_no_op(self):
        self.put('docker', '#!/bin/sh\necho docker\n')
        result = self.install('docker')
        self.assertEqual((result['installed'], result['already']), (False, True))
        self.assertNotIn('apt-get', self.env.calls())

    def test_only_docker_and_rclone_with_fixed_packages_can_be_installed(self):
        for bad in ('git', 'docker.io', 'docker; rm -rf /', '', None, ['docker']):
            with self.assertRaisesRegex(ValueError, 'Only docker and rclone'):
                runtime.install_dependency(self.a, {'name': bad})
        self.assertNotIn('apt-get', self.env.calls())

    def test_busy_package_manager_and_network_failures_are_explained(self):
        with self.assertRaisesRegex(self.a.ServiceOpError, 'package manager is busy'):
            self.install('docker', FAKE_APT_FAIL='lock')
        with self.assertRaisesRegex(self.a.ServiceOpError, 'Failed to fetch'):
            self.install('rclone', FAKE_APT_FAIL='net')
        self.assertFalse((self.bin / 'docker').exists())

    def test_an_unsupported_system_says_to_install_manually(self):
        with mock.patch.object(runtime, 'package_manager', lambda: None):
            with self.assertRaisesRegex(self.a.ServiceOpError, 'No supported package manager.*manually'):
                runtime.install_dependency(self.a, {'name': 'docker'})

    def test_dnf_systems_use_dnf(self):
        (self.bin / 'apt-get').unlink()
        self.put('dnf', '#!/bin/sh\necho "dnf $*" >> "$FAKE_STATE/calls.log"\nprintf \'#!/bin/sh\\necho rclone v1\\n\' > "$FAKE_BIN/rclone"; chmod +x "$FAKE_BIN/rclone"\n')
        self.assertTrue(self.install('rclone')['installed'])
        self.assertIn('dnf install -y rclone', self.env.calls())

    def test_missing_tools_are_reported_as_installable_with_the_package_manager(self):
        import ats_api
        deps = ats_api.dependencies(self.a)
        for key in ('docker', 'rclone'):
            self.assertFalse(deps[key]['ok'])
            self.assertEqual((deps[key]['installable'], deps[key]['package_manager']), (True, 'apt'))
        self.assertNotIn('installable', deps['git'])
        with mock.patch.object(runtime, 'package_manager', lambda: None):
            self.assertFalse(ats_api.dependencies(self.a)['docker']['installable'])


if __name__ == '__main__':
    unittest.main()
