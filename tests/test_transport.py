"""Operators must be told *why* a Global is unreachable, without leaking secrets."""
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import ats_cluster as c
import ats_remote


class Scripted(BaseHTTPRequestHandler):
    """A stand-in origin or edge that answers with whatever the test scripted."""
    protocol_version = 'HTTP/1.1'
    seen = []

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        type(self).seen.append(dict(self.headers))
        status, headers, payload = self.server.script
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)
        self.close_connection = True


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        cert, key = self.root / 'cert.pem', self.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(key), '-out', str(cert),
                        '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, capture_output=True)
        env = patch.dict(os.environ, {'SSL_CERT_FILE': str(cert)})
        env.start()
        self.addCleanup(env.stop)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Scripted)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.server.script = (200, {}, {})
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        Scripted.seen = []
        self.sid = 'a' * 32
        self.entry = dict(id=self.sid, secret='b' * 64, local=0, connected=1,
                          domain='https://localhost:%d' % self.server.server_port)

    def fail(self, status, payload=None, headers=None):
        self.server.script = (status, headers or {}, payload if payload is not None else {})
        with self.assertRaises(c.TransportError) as caught:
            c.remote(self.entry, {'kind': 'health'})
        return caught.exception

    def test_user_agent_is_sent_and_credentials_never_appear_in_errors(self):
        self.server.script = (200, {}, {'ok': True, 'server_id': self.sid, 'data': {'role': 'global'}})
        self.assertEqual(c.remote(self.entry, {'kind': 'health'}), {'role': 'global'})
        self.assertTrue(Scripted.seen[0]['User-Agent'].startswith('ATS-Cluster/'))
        for error in (self.fail(401), self.fail(404), self.fail(502, {'ok': False, 'error': 'boom'})):
            self.assertNotIn(self.entry['secret'], str(error))

    def test_wrong_key_and_clock_skew_are_distinguished(self):
        wrong = self.fail(401, {'ok': False, 'error': 'unauthorized', 'server_time': int(time.time())})
        self.assertEqual(wrong.code, 'auth')
        self.assertIn('passkey', str(wrong))
        skewed = self.fail(401, {'ok': False, 'error': 'unauthorized', 'server_time': int(time.time()) - 900})
        self.assertEqual(skewed.code, 'clock')
        self.assertRegex(str(skewed), r'9\d\d s behind')
        # A hostile non-integer time must not break classification.
        self.assertEqual(self.fail(401, {'server_time': 'soon'}).code, 'auth')
        self.assertEqual(self.fail(401, {'server_time': True}).code, 'auth')

    def test_tunnel_and_proxy_failures_name_the_fix(self):
        self.assertEqual(self.fail(404).code, 'route')
        self.assertIn('server setup --apply', str(self.fail(404)))
        blocked = self.fail(403, b'<html>1010</html>', {'Server': 'cloudflare', 'CF-Ray': 'x'})
        self.assertEqual(blocked.code, 'blocked')
        self.assertEqual(self.fail(530, b'error code: 1033').code, 'unavailable')
        self.assertEqual(self.fail(502).code, 'unavailable')
        self.assertEqual(self.fail(418).code, 'protocol')

    def test_global_supplied_message_is_relayed_but_only_when_short_and_printable(self):
        error = self.fail(502, {'ok': False, 'error': 'Monitor host adapter is not configured on this Global server'})
        self.assertEqual(error.code, 'adapter')
        self.assertIn('adapter is not configured', str(error))
        self.assertNotIn('\x1b', str(self.fail(502, {'ok': False, 'error': '\x1b[31m' + 'x' * 50})))
        self.assertNotIn('x' * 301, str(self.fail(502, {'ok': False, 'error': 'x' * 301})))

    def test_identity_mismatch_and_garbage_are_protocol_errors(self):
        self.server.script = (200, {}, {'ok': True, 'server_id': 'c' * 32, 'data': {}})
        with self.assertRaises(c.TransportError) as caught:
            c.remote(self.entry, {'kind': 'health'})
        self.assertEqual(caught.exception.code, 'auth')
        self.server.script = (200, {}, b'<html>not json</html>')
        with self.assertRaises(c.TransportError):
            c.remote(self.entry, {'kind': 'health'})

    def test_network_failures_are_classified(self):
        with patch('socket.getaddrinfo', side_effect=socket.gaierror('nope')), self.assertRaises(c.TransportError) as caught:
            c.remote(dict(self.entry, domain='https://missing.example.com'), {'kind': 'health'})
        self.assertEqual(caught.exception.code, 'dns')
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            closed = probe.getsockname()[1]
        with self.assertRaises(c.TransportError) as caught:
            c.remote(dict(self.entry, domain='https://localhost:%d' % closed), {'kind': 'health'})
        self.assertEqual(caught.exception.code, 'refused')
        with patch('ats_cluster.http.client.HTTPSConnection') as conn:
            conn.return_value.request.side_effect = socket.timeout()
            with self.assertRaises(c.TransportError) as caught:
                c.remote(self.entry, {'kind': 'health'})
        self.assertEqual(caught.exception.code, 'timeout')

    def test_disconnected_server_has_clear_code(self):
        with self.assertRaises(c.TransportError) as caught:
            c.remote(dict(self.entry, connected=0), {'kind': 'health'})
        self.assertEqual(caught.exception.code, 'disabled')


class GlobalListenerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = c.Store(self.root / 'global.db')
        self.node = self.store.configure('global', 'Global', 'https://localhost')
        self.http = ats_remote.Server(('127.0.0.1', 0), self.store)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)

    def post(self, headers, body=b'{"kind":"health"}'):
        import http.client
        conn = http.client.HTTPConnection('127.0.0.1', self.http.server_port, timeout=5)
        conn.request('POST', '/v1/request', body, headers)
        response = conn.getresponse()
        data = json.loads(response.read())
        conn.close()
        return response.status, data

    def test_unauthorized_reply_carries_server_time_only(self):
        status, data = self.post({'Content-Length': '16'})
        self.assertEqual(status, 401)
        self.assertEqual(set(data), {'ok', 'error', 'server_time'})
        self.assertLess(abs(data['server_time'] - time.time()), 5)
        body = b'{"kind":"health"}'
        headers = c.signed_headers('0' * 64, self.node['id'], body)
        status, data = self.post(headers, body)
        self.assertEqual((status, data['error']), (401, 'unauthorized'))

    def test_missing_adapter_module_is_named_without_leaking_stderr(self):
        adapter = self.root / 'remote_host.py'
        adapter.write_text('import secret_missing_module_xyz\n')
        body = json.dumps({'kind': 'http', 'method': 'GET', 'path': '/api/manage/services'}).encode()
        with patch.dict(os.environ, {'ATS_MONITOR_ADAPTER': str(adapter)}):
            status, data = self.post(c.signed_headers(self.node['secret'], self.node['id'], body), body)
        self.assertEqual(status, 502)
        self.assertIn("'secret_missing_module_xyz'", data['error'])
        self.assertNotIn('Traceback', data['error'])
        self.assertNotIn(self.node['secret'], json.dumps(data))

    def test_unknown_adapter_failure_is_generic_and_adapter_absence_is_actionable(self):
        adapter = self.root / 'remote_host.py'
        adapter.write_text('import sys\nsys.stderr.write("password=hunter2\\n")\nsys.exit(3)\n')
        body = json.dumps({'kind': 'http', 'method': 'GET', 'path': '/api/manage/services'}).encode()
        with patch.dict(os.environ, {'ATS_MONITOR_ADAPTER': str(adapter)}):
            status, data = self.post(c.signed_headers(self.node['secret'], self.node['id'], body), body)
        self.assertEqual(status, 502)
        self.assertNotIn('hunter2', json.dumps(data))
        with patch.dict(os.environ, {'ATS_MONITOR_ADAPTER': str(self.root / 'absent.py')}):
            status, data = self.post(c.signed_headers(self.node['secret'], self.node['id'], body), body)
        self.assertIn('server setup --apply', data['error'])


if __name__ == '__main__':
    unittest.main()
