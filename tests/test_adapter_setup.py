"""Adapter previews use the configured instance and leave runtime state untouched."""
import contextlib
import io
import os
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
from ats_cluster import Store
from ats_server_cli import adapter_drop_in, adapter_environment, main, service_unit


class AdapterSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / 'ATS data'
        self.home.mkdir()
        (self.home / 'ats.db').touch()
        self.config = self.root / 'config.yml'
        self.config.write_text(yaml.safe_dump({'ats_home': str(self.home)}))
        self.adapter = self.root / 'Monitor space' / 'remote_host.py'
        self.adapter.parent.mkdir()
        self.adapter.write_text('raise AssertionError("Preview must never import Monitor")\n')
        self.state = self.root / 'private state'
        self.env = patch.dict(os.environ, {
            'ATS_CONFIG_FILE': str(self.config),
            'ATS_CLUSTER_DB': str(self.root / 'cluster.db'),
        }, clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.store = Store()
        self.node = self.store.configure('global', 'Remote', 'https://remote.example.com')

    def prepare(self):
        return adapter_environment(self.store, str(self.adapter), str(self.state))

    def test_complete_environment_uses_existing_instance_without_creating_state(self):
        env = self.prepare()
        self.assertEqual(env['ATS_HOME'], str(self.home))
        self.assertEqual(env['ATS_MONITOR_ADAPTER'], str(self.adapter))
        self.assertEqual(env['ATS_SECURITY_DB'], str(self.state / 'security.sqlite3'))
        self.assertEqual(env['ATS_MONITOR_JOBS_DIR'], str(self.state / 'jobs'))
        self.assertEqual(shlex.split(env['ATS_CLI']),
                         [sys.executable, str(Path(env['ATS_MODULE_DIR']) / 'app.py')])
        self.assertFalse(self.state.exists())
        self.assertEqual(self.store.node(), self.node)

    def test_drop_in_keeps_service_command_and_identity(self):
        unit = adapter_drop_in(self.store, str(self.adapter), str(self.state))
        self.assertTrue(unit.startswith('[Service]\nUMask=0077\n'))
        self.assertIn('ExecStartPre=/usr/bin/test -d "'+str(self.state / 'jobs')+'"', unit)
        for forbidden in ('ExecStart=', 'ATS_CONFIG_FILE=', 'ATS_CLUSTER_DB=', self.node['secret']):
            self.assertNotIn(forbidden, unit)
        self.assertEqual(self.store.node(), self.node)

    def test_full_service_explicit_setup_and_inherited_state(self):
        env = self.prepare()
        unit = service_unit(self.store, monitor_adapter=str(self.adapter),
                            adapter_state_dir=str(self.state))
        self.assertIn('UMask=0077', unit)
        self.assertIn(' --daemon', unit)
        with patch.dict(os.environ, env):
            inherited = service_unit(self.store)
            for key, value in env.items():
                self.assertIn(key+'='+value, inherited)
            self.assertEqual(adapter_environment(self.store), env)

    def test_health_only_service_preview_explains_missing_adapter(self):
        unit = service_unit(self.store)
        self.assertIn('# Global management adapter is not configured', unit)
        self.assertIn('server adapter --monitor-adapter', unit)

    def test_explicit_cli_and_home_overrides_are_preserved(self):
        other_home = self.root / 'other'
        other_home.mkdir()
        (other_home / 'ats.db').touch()
        with patch.dict(os.environ, {'ATS_CLI': '/opt/ats-launcher', 'ATS_HOME': str(other_home)}):
            env = self.prepare()
        self.assertEqual(env['ATS_HOME'], str(other_home))
        self.assertEqual(env['ATS_CLI'], '/opt/ats-launcher')

    def test_invalid_adapter_state_config_and_cli_fail_before_output(self):
        for adapter, state in [('relative.py', str(self.state)),
                               (str(self.root / 'missing.py'), str(self.state)),
                               (str(self.adapter), 'relative'), (str(self.adapter), '/')]:
            with self.subTest(adapter=adapter, state=state), self.assertRaises(ValueError):
                adapter_drop_in(self.store, adapter, state)
        for settings in ([], {'ats_home': 42}, {'ats_home': '/nonexistent'}):
            self.config.write_text(yaml.safe_dump(settings))
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                self.prepare()
        self.config.write_text(yaml.safe_dump({'ats_home': str(self.home)}))
        for cli in (' ', '"unterminated', '/opt/launcher\nInjected=true'):
            with patch.dict(os.environ, {'ATS_CLI': cli}), self.assertRaises(ValueError):
                self.prepare()
        with self.assertRaises(ValueError):
            adapter_environment(self.store, str(self.adapter))

    def test_local_cannot_prepare_global_adapter(self):
        local = Store(self.root / 'local.db')
        local.configure('local', 'Local', webhook='hooks.example.com')
        with self.assertRaisesRegex(ValueError, 'Global'):
            adapter_environment(local, str(self.adapter), str(self.state))

    def test_missing_transport_or_database_is_rejected(self):
        with patch.dict(os.environ, {'ATS_MODULE_DIR': str(self.root)}):
            with self.assertRaisesRegex(ValueError, 'ats_cluster.py'):
                self.prepare()
        (self.home / 'ats.db').unlink()
        with self.assertRaisesRegex(ValueError, 'ats.db'):
            self.prepare()

    def test_cli_outputs_only_reviewable_drop_in(self):
        output = io.StringIO()
        argv = ['ats_server_cli.py', 'adapter', '--monitor-adapter', str(self.adapter),
                '--adapter-state-dir', str(self.state)]
        with patch.object(sys, 'argv', argv), contextlib.redirect_stdout(output):
            main()
        self.assertTrue(output.getvalue().startswith('[Service]\n'))
        self.assertFalse(self.state.exists())
        self.assertEqual(self.store.node(), self.node)

    def test_cli_invalid_yaml_has_actionable_error_without_partial_unit(self):
        self.config.write_text('ats_home: [')
        output, errors = io.StringIO(), io.StringIO()
        argv = ['ats_server_cli.py', 'adapter', '--monitor-adapter', str(self.adapter),
                '--adapter-state-dir', str(self.state)]
        with patch.object(sys, 'argv', argv), contextlib.redirect_stdout(output), \
                contextlib.redirect_stderr(errors), self.assertRaises(SystemExit) as raised:
            main()
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(output.getvalue(), '')
        self.assertIn('Service preview failed', errors.getvalue())

    def test_special_paths_survive_systemd_and_shell_command_quoting(self):
        # Generated ATS_CLI is interpreted by shlex in Monitor, never by a shell.
        from ats_server_cli import unit_quote
        self.assertEqual(unit_quote('/opt/100%/a"b'), '"/opt/100%%/a\\"b"')
        odd = self.root / 'private%$state'
        unit = adapter_drop_in(self.store, str(self.adapter), str(odd))
        self.assertIn('private%%$state/security.sqlite3', unit)
        self.assertIn('private%%$$state/jobs', unit)

    def test_generated_environment_runs_adapter_subprocess(self):
        # Exercise the actual subprocess boundary and its inherited six settings.
        # The fixture has no host dependencies or service mutations.
        self.adapter.write_text('''import json, os, pathlib, shlex, sys
request = json.load(sys.stdin)
assert request == {"kind": "http", "method": "GET", "path": "/api/manage/services"}
assert pathlib.Path(os.environ['ATS_HOME'], 'ats.db').is_file()
assert pathlib.Path(os.environ['ATS_MODULE_DIR'], 'ats_cluster.py').is_file()
assert shlex.split(os.environ['ATS_CLI'])[0] == sys.executable
assert os.environ['ATS_SECURITY_DB'].endswith('/security.sqlite3')
assert os.environ['ATS_MONITOR_JOBS_DIR'].endswith('/jobs')
print(json.dumps({'status': 200, 'body': {'ok': True, 'data': {'services': []}}}))
''')
        import ats_remote
        with patch.dict(os.environ, self.prepare()):
            result = ats_remote.dispatch(self.store, {'kind': 'http', 'method': 'GET',
                                                      'path': '/api/manage/services'})
        self.assertEqual(result['status'], 200)
        self.assertEqual(result['body']['data']['services'], [])


if __name__ == '__main__':
    unittest.main()
