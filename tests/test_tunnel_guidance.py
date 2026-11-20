"""Global API route guidance uses temporary configs and never edits tunnel files."""
import contextlib
import io
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch
import yaml
from ats_cluster import Store
from ats_server_cli import tunnel_guidance, menu


class TunnelGuidanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'registry.db')
        self.node = self.store.configure('global', 'server2', 'https://server2.gaiasentinel.online')
        self.config = self.root / 'config.yml'

    def check(self, routes):
        self.config.write_text(yaml.safe_dump({'tunnel': 'preserved', 'credentials-file': '/private/tunnel.json', 'ingress': routes}))
        before = self.config.read_bytes()
        with contextlib.redirect_stdout(io.StringIO()) as output:
            route = tunnel_guidance(self.store, self.config)
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(self.store.node(), self.node)
        self.assertNotIn(self.node['secret'], output.getvalue())
        return route, output.getvalue()

    def test_missing_domain_outputs_correct_api_only_route_without_edit(self):
        route, output = self.check([{'hostname': 'app.example.com', 'service': 'http://localhost:8080'}, {'service': 'http_status:404'}])
        self.assertIn('missing, conflicting', output)
        self.assertEqual(route, {'hostname': 'server2.gaiasentinel.online', 'path': '^/v1/request$', 'service': 'http://127.0.0.1:9997'})
        self.assertNotIn('/webhook', output)

    def test_matching_route_and_shadowed_route(self):
        route = {'hostname': 'server2.gaiasentinel.online', 'path': '^/v1/request$', 'service': 'http://127.0.0.1:9997'}
        _, output = self.check([route, {'service': 'http_status:404'}])
        self.assertIn('API route matches', output)
        for shadow in ({'service': 'http_status:404'}, {'hostname': '*.gaiasentinel.online', 'service': 'http://localhost:9999'}, dict(route, path=None)):
            with self.subTest(shadow=shadow):
                _, output = self.check([shadow, route])
                self.assertIn('potentially shadowed', output)

    def test_duplicate_and_wrong_port_are_not_ready(self):
        route = {'hostname': 'server2.gaiasentinel.online', 'path': '^/v1/request$', 'service': 'http://127.0.0.1:9997'}
        for routes in ([route, route], [dict(route, service='http://localhost:9999')]):
            _, output = self.check(routes)
            self.assertNotIn('API route matches', output)

    def test_nondefault_port_and_no_config(self):
        with patch.dict(os.environ, {'ATS_REMOTE_PORT': '10001'}), contextlib.redirect_stdout(io.StringIO()) as output:
            route = tunnel_guidance(self.store)
        self.assertEqual(route['service'], 'http://127.0.0.1:10001')
        self.assertNotIn('API route matches', output.getvalue())
        with self.assertRaises(ValueError):
            tunnel_guidance(self.store, port=70000)

    def test_local_refused_and_invalid_yaml_rejected(self):
        local = Store(self.root / 'local.db')
        local.configure('local', 'Primary', webhook='hooks.example.com')
        with self.assertRaisesRegex(ValueError, 'Global'):
            tunnel_guidance(local)
        for text in ('[]', 'ingress: wrong', 'ingress: [null]'):
            self.config.write_text(text)
            with self.assertRaisesRegex(ValueError, 'ingress list'):
                tunnel_guidance(self.store, self.config)

    def test_headless_command_uses_environment_port_and_reports_bad_yaml(self):
        self.config.write_text('ingress: []\n')
        command = [sys.executable, str(Path(__file__).resolve().parents[1] / 'app.py'),
                   'server', 'tunnel', '--cloudflare-config', str(self.config)]
        env = dict(os.environ, ATS_CLUSTER_DB=str(self.root / 'registry.db'), ATS_REMOTE_PORT='10002')
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('http://127.0.0.1:10002', result.stdout)
        self.assertNotIn(self.node['secret'], result.stdout + result.stderr)
        self.config.write_text('ingress: [invalid')
        result = subprocess.run(command, env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Server setup failed:', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual(self.config.read_text(), 'ingress: [invalid')

    def test_option_12_submenu_checks_route(self):
        self.config.write_text('ingress: []\n')
        with patch('builtins.input', side_effect=['9', str(self.config), '0']), contextlib.redirect_stdout(io.StringIO()) as output:
            menu(self.store)
        self.assertIn('[9] Check Global API tunnel route', output.getvalue())
        self.assertIn('server2.gaiasentinel.online', output.getvalue())
        self.assertNotIn(self.node['secret'], output.getvalue())
