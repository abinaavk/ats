"""Global management listener. Bind loopback behind an operator-managed TLS proxy."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import socket
import secrets
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ats_cluster as cluster

SLOTS = threading.BoundedSemaphore(8)
MISSING_MODULE = re.compile(r"No module named '([A-Za-z0-9_.]+)'")


class PublicError(ValueError):
    """A failure whose message is written here and safe to return to the signed caller."""


def adapter_failure(stderr_text):
    """Explain an adapter exit without relaying its stderr (which could hold secrets)."""
    match = MISSING_MODULE.search(stderr_text or '')
    if match:
        return PublicError(f"Monitor adapter cannot start: Python module '{match.group(1)}' is missing for the ATS "
                           f"interpreter {sys.executable}. Install the Monitor requirements for that interpreter "
                           "and retry; run \"server doctor\" on the Global for the full check.")
    return PublicError('Monitor adapter failed; run "server doctor" on the Global and inspect its journal.')


def execute(argv, value, timeout=60):
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=out, stderr=err)
        deadline = time.monotonic()+timeout
        first = True
        try:
            while True:
                try:
                    process.communicate(json.dumps(value).encode() if first else None, timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    first = False
                    if time.monotonic() >= deadline or os.fstat(out.fileno()).st_size > cluster.MAX_OUTPUT or os.fstat(err.fileno()).st_size > cluster.MAX_OUTPUT:
                        raise PublicError('Operation exceeded time or output limit; inspect the originating server before retrying')
        except Exception:
            process.kill(); process.wait()
            raise
        out.seek(0)
        data = out.read(cluster.MAX_OUTPUT+1)
        if len(data) > cluster.MAX_OUTPUT:
            raise PublicError('Operation output exceeded limit')
        # stderr may contain credentials; only a recognised module name is relayed.
        if process.returncode:
            err.seek(max(0, os.fstat(err.fileno()).st_size - 8192))
            raise adapter_failure(err.read(8192).decode('utf-8', 'replace'))
        return json.loads(data)


def dispatch(store, data, authenticated=None):
    if not isinstance(data, dict):
        raise ValueError('JSON object required')
    kind = data.get('kind')
    if kind == 'health':
        return {'server_id': store.node()['id'], 'role': 'global', 'terminal': False,
                'management_ready': Path(os.environ.get('ATS_MONITOR_ADAPTER', '')).is_file()}
    if kind == 'revoke':
        with store.db() as db:
            current = authenticated or store.node()
            if db.execute('UPDATE node SET secret=? WHERE id=? AND secret=?',
                          (secrets.token_hex(32), current['id'], current['secret'])).rowcount != 1:
                raise ValueError('Credential changed before revocation; authenticate again')
        # The exported pairing file must carry the replacement key, never the revoked one.
        try:
            import ats_server_cli
            ats_server_cli.save_pairing(store)
        except Exception:
            pass
        return {'revoked': True}
    if kind == 'http':
        adapter = os.environ.get('ATS_MONITOR_ADAPTER')
        if not adapter or not Path(adapter).is_file():
            raise PublicError('Monitor host adapter is not configured on this Global server; '
                              'run "server setup --apply" on it')
        return execute([sys.executable, adapter], data)
    raise ValueError('Unsupported request kind')


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(10)
        self.read_deadline = threading.Timer(10, self.expire_read)
        self.read_deadline.daemon = True
        self.read_deadline.start()

    def expire_read(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        self.read_deadline.cancel()
        super().finish()

    def log_message(self, *_):
        pass  # Do not log request payloads, credentials or URLs.

    def unauthorized(self):
        # The time is not secret and lets the caller tell clock skew from a wrong key.
        return self.reply(401, {'ok': False, 'error': 'unauthorized', 'server_time': int(time.time())})

    def reply(self, code, data):
        payload = json.dumps(data).encode()
        if len(payload) > cluster.MAX_OUTPUT:
            code, payload = 502, b'{"ok":false,"error":"Response too large"}'
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(payload)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    def do_POST(self):
        acquired = False
        try:
            if self.path != '/v1/request' or self.headers.get('Transfer-Encoding'):
                return self.reply(400, {'ok': False})
            lengths = self.headers.get_all('Content-Length', [])
            if len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= cluster.MAX_BODY:
                return self.reply(413, {'ok': False})
            for key in ('X-ATS-Server', 'X-ATS-Time', 'X-ATS-Nonce', 'X-ATS-Signature'):
                if len(self.headers.get_all(key, [])) != 1:
                    return self.unauthorized()
            body = self.rfile.read(int(lengths[0]))
            self.read_deadline.cancel()
            if len(body) != int(lengths[0]):
                return self.reply(400, {'ok': False})
            try:
                authenticated = cluster.authenticate(self.server.store, 'POST', self.path, body, self.headers)
            except ValueError:
                return self.unauthorized()
            acquired = SLOTS.acquire(blocking=False)
            if not acquired:
                return self.reply(503, {'ok': False})
            result = dispatch(self.server.store, json.loads(body), authenticated)
            return self.reply(200, {'ok': True, 'server_id': self.server.store.node()['id'], 'data': result})
        except PublicError as exc:
            self.reply(502, {'ok': False, 'error': str(exc)})
        except (ValueError, OSError, subprocess.SubprocessError):
            self.reply(502, {'ok': False, 'error': 'Global operation failed'})
        finally:
            if acquired:
                SLOTS.release()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def process_request(self, request, address):
        if not self.connections.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, address)
        except Exception:
            self.connections.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.connections.release()

    def __init__(self, address, store):
        if not store.node() or store.node()['role'] != 'global':
            raise ValueError('Configure this instance as Global first')
        self.connections = threading.BoundedSemaphore(16)
        self.store = store
        super().__init__(address, Handler)


def serve(store, port=9997):
    Server(('127.0.0.1', port), store).serve_forever()
