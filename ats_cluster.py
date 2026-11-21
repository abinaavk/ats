"""Persistent server identities, explicit webhook routes, and signed HTTPS transport.

The database contains credentials: keep it private, outside the served tree.
"""
import contextlib
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import ssl
import time
from urllib.parse import urlsplit
import uuid

MAX_BODY = 262144
MAX_OUTPUT = 4 * 1024 * 1024
WINDOW = 120
ID = re.compile(r'^[0-9a-f]{32}$')
NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$')
REPO = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
# Cloudflare's Browser Integrity Check can drop requests that carry no User-Agent.
USER_AGENT = 'ATS-Cluster/1 (+https://github.com/abinaavk/ats)'


class TransportError(ValueError):
    """A failure whose message is written by ATS and safe to show an operator.

    It never contains credentials, signatures or remote response bodies. It is a
    ValueError so every existing handler keeps working; ``code`` names the failure
    class (tls, dns, refused, timeout, network, auth, clock, blocked, route,
    unavailable, adapter, protocol) for UI and doctor output.
    """

    def __init__(self, message, code='transport'):
        super().__init__(message)
        self.code = code


def domain(value):
    if not isinstance(value, str) or value != value.strip():
        raise ValueError('HTTPS API origin required')
    u = urlsplit(value)
    if (u.scheme != 'https' or not u.hostname or u.username or u.password or
            u.path not in ('', '/') or u.query or u.fragment or
            len(u.hostname) > 253 or any(not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label) for label in u.hostname.split('.'))):
        raise ValueError('Use an HTTPS origin without credentials, path, query or fragment')
    port = u.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError('HTTPS port must be between 1 and 65535')
    return 'https://'+u.hostname.lower()+(':'+str(port) if port and port != 443 else '')


def name(value):
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError('Name must be 1–64 letters, numbers, spaces, dots, underscores or hyphens')
    return value


class Store:
    def __init__(self, path=None):
        self.path = str(path or os.environ.get('ATS_CLUSTER_DB', '/etc/ats/cluster.sqlite3'))
        p = Path(self.path)
        p.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fd = os.open(p, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(p, 0o600)
        with self.db() as db:
            db.executescript('''
              CREATE TABLE IF NOT EXISTS node(id TEXT PRIMARY KEY, role TEXT NOT NULL,
                name TEXT NOT NULL, domain TEXT, secret TEXT, webhook TEXT);
              CREATE UNIQUE INDEX IF NOT EXISTS one_node ON node((1));
              CREATE TABLE IF NOT EXISTS servers(id TEXT PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                domain TEXT UNIQUE, secret TEXT, connected INTEGER NOT NULL DEFAULT 1,
                local INTEGER NOT NULL DEFAULT 0 CHECK(local IN (0,1)));
              CREATE UNIQUE INDEX IF NOT EXISTS one_local ON servers(local) WHERE local=1;
              CREATE TABLE IF NOT EXISTS routes(repository TEXT PRIMARY KEY COLLATE NOCASE,
                server_id TEXT NOT NULL REFERENCES servers(id), service TEXT NOT NULL,
                branch TEXT NOT NULL, secret TEXT NOT NULL, UNIQUE(server_id,service));
              CREATE UNIQUE INDEX IF NOT EXISTS route_secret_unique ON routes(secret);
              CREATE TABLE IF NOT EXISTS seen(scope TEXT, nonce TEXT, created REAL,
                state TEXT, result TEXT, PRIMARY KEY(scope,nonce));
            ''')
            db.execute('BEGIN IMMEDIATE')
            columns = {row['name'] for row in db.execute('PRAGMA table_info(servers)')}
            for column in ('revision', 'revocation_pending'):
                if column not in columns:
                    db.execute('ALTER TABLE servers ADD COLUMN '+column+' INTEGER NOT NULL DEFAULT 0')

    @contextlib.contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys=ON')
        try:
            with db:
                yield db
        finally:
            db.close()

    def node(self):
        with self.db() as db:
            r = db.execute('SELECT * FROM node').fetchone()
            return dict(r) if r else None

    def configure(self, role, label, api_domain=None, webhook=None):
        if role not in ('local', 'global'):
            raise ValueError('Choose local or global')
        name(label)
        if role == 'global':
            api_domain = domain(api_domain)
            if webhook:
                raise ValueError('Global servers cannot host webhooks')
        elif not webhook or not re.fullmatch(r'(?=.{1,253}$)[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?', webhook) or '..' in webhook:
            raise ValueError('Local requires a valid webhook hostname')
        if role == 'local':
            domain('https://'+webhook)
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old = db.execute('SELECT * FROM node').fetchone()
            if old and old['role'] != role:
                raise ValueError('Changing the role requires a separate installation')
            sid = old['id'] if old else uuid.uuid4().hex
            secret = old['secret'] if old else secrets.token_hex(32)
            db.execute('INSERT OR REPLACE INTO node VALUES(?,?,?,?,?,?)',
                       (sid, role, label, api_domain, secret, webhook))
            if role == 'local':
                db.execute('INSERT INTO servers(id,name,local) VALUES(?,?,1) ON CONFLICT(id) DO UPDATE SET name=excluded.name', (sid, label))
        return self.node()

    def servers(self):
        with self.db() as db:
            return [dict(r) for r in db.execute('SELECT id,name,domain,connected,local,revocation_pending,(secret IS NOT NULL) AS paired FROM servers ORDER BY local DESC,name')]

    def server(self, sid):
        if not isinstance(sid, str) or not ID.fullmatch(sid):
            raise ValueError('Explicit server identity required')
        with self.db() as db:
            r = db.execute('SELECT * FROM servers WHERE id=?', (sid,)).fetchone()
            if not r:
                raise ValueError('Unknown server')
            return dict(r)

    def _local(self):
        node = self.node()
        if not node or node['role'] != 'local':
            raise ValueError('Only the primary Local can manage servers')
        return node

    def _candidate(self, sid, label, origin, secret):
        node = self._local()
        if not isinstance(sid, str) or not ID.fullmatch(sid) or sid == node['id']:
            raise ValueError('Invalid Global identity')
        name(label); origin = domain(origin)
        if not isinstance(secret, str) or not re.fullmatch('[0-9a-f]{64}', secret):
            raise ValueError('Invalid pairing secret')
        return dict(id=sid, name=label, domain=origin, secret=secret, connected=1, local=0)

    @staticmethod
    def _verified(candidate):
        health = remote(candidate, {'kind': 'health'})
        if not isinstance(health, dict) or health.get('server_id') != candidate['id'] or health.get('role') != 'global':
            raise ValueError('Pairing identity or role mismatch')
        return health

    def _unique_secret(self, db, secret, sid):
        if (db.execute('SELECT 1 FROM servers WHERE secret=? AND id!=?', (secret, sid)).fetchone()
                or db.execute('SELECT 1 FROM node WHERE secret=?', (secret,)).fetchone()):
            raise ValueError('Credentials already used by another server')

    @staticmethod
    def _unchanged(db, server):
        row = db.execute('SELECT * FROM servers WHERE id=?', (server['id'],)).fetchone()
        if not row or dict(row) != server:
            raise ValueError('Server changed during verification; refresh and retry')

    def pair(self, sid, label, origin, secret):
        candidate = self._candidate(sid, label, origin, secret)
        with self.db() as db:
            row = db.execute('SELECT * FROM servers WHERE id=?', (sid,)).fetchone()
            previous = dict(row) if row else None
        if previous and previous['revocation_pending'] and previous['secret'] == secret:
            raise ValueError('Rotate credentials on Global before pairing again')
        health = self._verified(candidate)
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            self._unique_secret(db, secret, sid)
            if previous:
                self._unchanged(db, previous)
                db.execute('UPDATE servers SET name=?,domain=?,secret=?,connected=1,revocation_pending=0,revision=revision+1 WHERE id=?',
                           (label, candidate['domain'], secret, sid))
            else:
                db.execute('INSERT INTO servers(id,name,domain,secret,connected,local) VALUES(?,?,?,?,1,0)',
                           (sid, label, candidate['domain'], secret))
        return health

    def replace_credentials(self, sid, new_id, label, origin, secret):
        """Verify first, then atomically replace the entry and its explicit routes.

        Connection state is retained. Old jobs keep their originating identity.
        No request is sent with the old key and no Global key is changed here.
        """
        previous = self.server(sid)
        if previous['local']:
            raise ValueError('Cannot replace the primary Local identity')
        candidate = self._candidate(new_id, label, origin, secret)
        if previous['revocation_pending'] and previous['secret'] == secret:
            raise ValueError('Rotate credentials on Global before replacing this pairing')
        health = self._verified(candidate)
        # Connection state is deliberately preserved: re-enabling a disconnected or revoked
        # server stays an explicit operator action (Reconnect).
        connected = previous['connected']
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            self._unchanged(db, previous)
            self._unique_secret(db, secret, sid)
            if new_id != sid:
                # Insert before migrating FKs; never merge two saved servers.
                # Temporarily free this entry's unique name/domain inside the transaction.
                db.execute('UPDATE servers SET name=?,domain=NULL WHERE id=?', ('replacement-'+secrets.token_hex(16), sid))
                db.execute('INSERT INTO servers(id,name,domain,secret,connected,local,revision) VALUES(?,?,?,?,?,0,?)',
                           (new_id, label, candidate['domain'], secret, connected, previous['revision']+1))
                db.execute('UPDATE routes SET server_id=? WHERE server_id=?', (new_id, sid))
                db.execute('DELETE FROM servers WHERE id=?', (sid,))
            else:
                db.execute('UPDATE servers SET name=?,domain=?,secret=?,connected=?,revocation_pending=0,revision=revision+1 WHERE id=?',
                           (label, candidate['domain'], secret, connected, sid))
        return health

    def find_server(self, bundle):
        """The saved Global a pairing bundle refers to: same ID, else same HTTPS origin, else same name."""
        if not isinstance(bundle, dict):
            raise ValueError('Pairing bundle must be a JSON object')
        self._local()
        saved = [s for s in self.servers() if not s['local']]
        try:
            origin = domain(bundle.get('domain'))
        except ValueError:
            origin = None
        for key, wanted in (('id', bundle.get('id')), ('domain', origin),
                            ('name', (bundle.get('name') or '').lower() if isinstance(bundle.get('name'), str) else None)):
            if not wanted:
                continue
            # ID, address and name are each unique in the registry, so a hit is never ambiguous.
            for saved_server in saved:
                if (saved_server[key].lower() if key == 'name' else saved_server[key]) == wanted:
                    return saved_server['id']
        raise ValueError('No saved Global matches this pairing file (ID, address or name); pair it as a new server instead')

    def connection(self, sid, action):
        self._local()
        server = self.server(sid)
        if server['local']:
            raise ValueError('The primary Local cannot be disconnected or revoked')
        if action == 'disconnect':
            with self.db() as db:
                db.execute('UPDATE servers SET connected=0,revision=revision+1 WHERE id=?', (sid,))
            return
        if action == 'reconnect':
            if server['revocation_pending']:
                raise ValueError('Revocation is unconfirmed; replace with a fresh Global credential first')
            self._verified(dict(server, connected=1))
        elif action == 'revoke':
            with self.db() as db:
                db.execute('BEGIN IMMEDIATE')
                self._unchanged(db, server)
                db.execute('UPDATE servers SET connected=0,revocation_pending=1,revision=revision+1 WHERE id=?', (sid,))
            server.update(connected=0, revocation_pending=1, revision=server['revision']+1)
            result = remote(dict(server, connected=1), {'kind': 'revoke'})
            if not isinstance(result, dict) or result.get('revoked') is not True:
                raise ValueError('Global did not confirm revocation')
        else:
            raise ValueError('Invalid connection action')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            self._unchanged(db, server)
            if action == 'reconnect':
                db.execute('UPDATE servers SET connected=1,revision=revision+1 WHERE id=?', (sid,))
            else:
                db.execute('UPDATE servers SET connected=0,secret=NULL,revocation_pending=0,revision=revision+1 WHERE id=?', (sid,))

    def update_server(self, sid, label, origin):
        self._local()
        server = self.server(sid)
        if server['local']:
            raise ValueError('Configure the primary Local from its ATS CLI')
        name(label); origin = domain(origin)
        self._verified(dict(server, name=label, domain=origin, connected=1))
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            self._unchanged(db, server)
            db.execute('UPDATE servers SET name=?,domain=?,revision=revision+1 WHERE id=?', (label, origin, sid))

    def mapping(self, repository, sid, service, branch, secret, replace=False):
        if not isinstance(repository, str) or not REPO.fullmatch(repository):
            raise ValueError('Explicit owner/repository required')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', service or ''):
            raise ValueError('Invalid service')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,99}', branch or '') or '..' in branch:
            raise ValueError('Invalid branch')
        if not isinstance(secret, str) or not re.fullmatch('[0-9a-f]{64}', secret):
            raise ValueError('A unique 32-byte hex GitHub webhook secret is required')
        self.server(sid)
        with self.db() as db:
            if replace:
                if not db.execute('SELECT 1 FROM routes WHERE repository=?', (repository.lower(),)).fetchone():
                    raise ValueError('No existing mapping to replace')
                db.execute('UPDATE routes SET server_id=?,service=?,branch=?,secret=? WHERE repository=?', (sid,service,branch,secret,repository.lower()))
            else:
                db.execute('INSERT INTO routes VALUES(?,?,?,?,?)', (repository.lower(), sid, service, branch, secret))

    def claim(self, scope, nonce):
        with self.db() as db:
            # Auth nonces expire outside the accepted timestamp window; deliveries do not.
            if scope == 'auth':
                db.execute('DELETE FROM seen WHERE scope=? AND created<?', (scope, time.time()-2*WINDOW))
            return db.execute('INSERT OR IGNORE INTO seen VALUES(?,?,?,\'accepted\',NULL)',
                              (scope, nonce, time.time())).rowcount == 1


def canonical(method, path, body, sid, timestamp, nonce):
    return '\n'.join((method, path, sid, timestamp, nonce, hashlib.sha256(body).hexdigest())).encode()


def signed_headers(secret, sid, body, method='POST', path='/v1/request', timestamp=None, nonce=None):
    timestamp = str(int(time.time())) if timestamp is None else str(timestamp)
    nonce = nonce or secrets.token_hex(24)
    signature = hmac.new(secret.encode(), canonical(method, path, body, sid, timestamp, nonce), hashlib.sha256).hexdigest()
    return {'X-ATS-Server': sid, 'X-ATS-Time': timestamp, 'X-ATS-Nonce': nonce,
            'X-ATS-Signature': signature, 'Content-Type': 'application/json'}


def authenticate(store, method, path, body, headers):
    n = store.node()
    sid, ts, nonce, sig = (headers.get(k, '') for k in ('X-ATS-Server', 'X-ATS-Time', 'X-ATS-Nonce', 'X-ATS-Signature'))
    if not n or n['role'] != 'global' or not n['secret'] or sid != n['id']:
        raise ValueError('Unauthorized')
    if not re.fullmatch('[0-9]{1,12}', ts) or abs(time.time()-int(ts)) > WINDOW or not re.fullmatch('[0-9a-f]{48}', nonce):
        raise ValueError('Unauthorized')
    if not re.fullmatch('[0-9a-f]{64}', sig):
        raise ValueError('Unauthorized')
    expected = hmac.new(n['secret'].encode(), canonical(method, path, body, sid, ts, nonce), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig) or not store.claim('auth', nonce):
        raise ValueError('Unauthorized')
    return n


def _safe_json(data):
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError):
        return None
    return value if isinstance(value, dict) else None


def _public_error(value):
    """Keep only a short printable message written by the Global itself."""
    if isinstance(value, str) and 0 < len(value) <= 300 and value.isprintable():
        return value
    return None


def _http_failure(host, status, headers, data):
    """Explain a non-200 reply without echoing any remote body or credential."""
    body = _safe_json(data)
    detail = _public_error((body or {}).get('error'))
    behind_cloudflare = 'cloudflare' in (headers.get('Server') or '').lower() or bool(headers.get('CF-Ray'))
    if status == 401:
        server_time = (body or {}).get('server_time')
        if isinstance(server_time, int) and not isinstance(server_time, bool) and abs(server_time - time.time()) > WINDOW // 2:
            skew = int(server_time - time.time())
            return TransportError(
                f'Clock mismatch: {host} reports a time {abs(skew)} s {"ahead of" if skew > 0 else "behind"} this server '
                f'(requests are accepted within {WINDOW} s). Enable time sync on both servers, e.g. '
                '"timedatectl set-ntp true", then retry.', 'clock')
        return TransportError(
            f'{host} rejected the server ID or passkey. Check they match that Global\'s current pairing file '
            '("server export" on that Global), then pair again or use Update ID and passkey.', 'auth')
    if status in (403, 429) and behind_cloudflare and not detail:
        return TransportError(
            f'Cloudflare blocked the request before it reached {host} (HTTP {status}). Allow this server in '
            'Cloudflare security rules (WAF / Bot Fight Mode / rate limiting) for /v1/request.', 'blocked')
    if status == 404:
        return TransportError(
            f'{host} has no /v1/request route. On that Global run "server setup --apply" so the Cloudflare '
            'tunnel forwards /v1/request to the ATS API.', 'route')
    if status in (502, 503, 504) or 520 <= status <= 530:
        if detail:
            return TransportError(f'{host}: {detail}', 'adapter' if 'adapter' in detail.lower() else 'unavailable')
        return TransportError(
            f'{host} is unreachable through its tunnel (HTTP {status}). Check that the Global ATS API service and '
            'cloudflared are running ("server doctor" on that Global).', 'unavailable')
    if detail:
        return TransportError(f'{host}: {detail} (HTTP {status})', 'protocol')
    return TransportError(f'{host} answered HTTP {status}; expected a signed ATS response. '
                          'Check the hostname points at the ATS API tunnel route.', 'protocol')


def remote(server, payload, *, timeout=None):
    if server['local'] or not server['connected'] or not server['secret']:
        raise TransportError('Selected Global server is disconnected or revoked', 'disabled')
    u = urlsplit(domain(server['domain']))
    host = u.hostname + (':' + str(u.port) if u.port and u.port != 443 else '')
    body = json.dumps(payload, separators=(',', ':')).encode()
    if len(body) > MAX_BODY:
        raise ValueError('Request too large')
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout or (5 if payload.get('kind') == 'health' else 10 if payload.get('kind') == 'revoke' else 65))
    headers = signed_headers(server['secret'], server['id'], body)
    headers['User-Agent'] = USER_AGENT
    headers['Accept'] = 'application/json'
    try:
        try:
            conn.request('POST', '/v1/request', body, headers)
            r = conn.getresponse()
            data = r.read(MAX_OUTPUT + 1)
        except ssl.SSLCertVerificationError as exc:
            raise TransportError(f'The HTTPS certificate for {host} could not be verified ({exc.verify_message}). '
                                 'Use the real Cloudflare hostname; certificate checks are never disabled.', 'tls') from None
        except ssl.SSLError:
            raise TransportError(f'TLS handshake with {host} failed. Check the hostname is proxied by Cloudflare '
                                 'and served over HTTPS.', 'tls') from None
        except socket.gaierror:
            raise TransportError(f'Cannot resolve {host}. Create the tunnel DNS record for this hostname '
                                 '(cloudflared tunnel route dns) and check this server\'s DNS.', 'dns') from None
        except (socket.timeout, TimeoutError):
            raise TransportError(f'Timed out waiting for {host}. The Global may be busy or its tunnel may be down.', 'timeout') from None
        except ConnectionRefusedError:
            raise TransportError(f'{host} refused the connection.', 'refused') from None
        except OSError as exc:
            raise TransportError(f'Network error contacting {host}: {exc.strerror or type(exc).__name__}', 'network') from None
        except (http.client.HTTPException, UnicodeError):
            raise TransportError('Global transport returned an invalid or incomplete response', 'protocol') from None
        if len(data) > MAX_OUTPUT:
            raise TransportError(f'{host} returned an oversized response', 'protocol')
        if r.status != 200:
            raise _http_failure(host, r.status, r.headers, data)
        result = _safe_json(data)
        if result is None or result.get('server_id') != server['id']:
            raise TransportError('Global response identity mismatch: the hostname answers for a different server ID', 'auth')
        if result.get('ok') is not True:
            raise TransportError(_public_error(result.get('error')) or 'Global operation failed', 'adapter')
        if not isinstance(result.get('data'), dict):
            raise TransportError('Invalid Global response payload', 'protocol')
        return result['data']
    finally:
        conn.close()
