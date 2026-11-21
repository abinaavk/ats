#!/usr/bin/python3
"""Stand-in for cloudflared+Cloudflare edge: TLS on 443, routes only what the tunnel YAML allows."""
import http.client, os, re, ssl, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import yaml

CF, CERT, KEY, PORT = os.environ['E2E_CF'], os.environ['E2E_CERT'], os.environ['E2E_KEY'], int(os.environ.get('E2E_TLS_PORT', '443'))

def route(host, path):
    for rule in (yaml.safe_load(open(CF)) or {}).get('ingress', []):
        if rule.get('hostname') and rule['hostname'] != host: continue
        if rule.get('path') and not re.search(rule['path'], path): continue
        return rule.get('service')
    return None

class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        host = (self.headers.get('Host') or '').split(':')[0]
        service = route(host, self.path)
        if service is None or service.startswith('http_status:'):
            data = b'cloudflared: no ingress rule matched'
            self.send_response(404); self.send_header('Content-Length', str(len(data))); self.send_header('Connection', 'close')
            self.send_header('Server', 'cloudflare'); self.end_headers(); self.wfile.write(data); self.close_connection = True; return
        u = urlsplit(service)
        c = http.client.HTTPConnection(u.hostname, u.port, timeout=70)
        try:
            c.request('POST', self.path, body, {k: v for k, v in self.headers.items() if k.lower() not in ('host', 'connection')})
            r = c.getresponse(); data = r.read()
            self.send_response(r.status); self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data))); self.send_header('Connection', 'close'); self.end_headers(); self.wfile.write(data)
        except OSError:
            data = b'error code: 1033'
            self.send_response(530); self.send_header('Content-Length', str(len(data))); self.send_header('Connection', 'close'); self.send_header('Server', 'cloudflare'); self.end_headers(); self.wfile.write(data)
        finally:
            c.close(); self.close_connection = True

class S(ThreadingHTTPServer):
    daemon_threads = True

srv = S(('127.0.0.1', PORT), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(CERT, KEY)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print('tunnel sim on', PORT, flush=True)
srv.serve_forever()
