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
import sqlite3
import time
from urllib.parse import urlsplit
import uuid

MAX_BODY = 262144
MAX_OUTPUT = 4 * 1024 * 1024
WINDOW = 120
ID = re.compile(r'^[0-9a-f]{32}$')
NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$')
REPO = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')


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
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            self._unchanged(db, previous)
            self._unique_secret(db, secret, sid)
            if new_id != sid:
                # Insert before migrating FKs; never merge two saved servers.
                # Temporarily free this entry's unique name/domain inside the transaction.
                db.execute('UPDATE servers SET name=?,domain=NULL WHERE id=?', ('replacement-'+secrets.token_hex(16), sid))
                db.execute('INSERT INTO servers(id,name,domain,secret,connected,local,revision) VALUES(?,?,?,?,?,0,?)',
                           (new_id, label, candidate['domain'], secret, previous['connected'], previous['revision']+1))
                db.execute('UPDATE routes SET server_id=? WHERE server_id=?', (new_id, sid))
                db.execute('DELETE FROM servers WHERE id=?', (sid,))
            else:
                db.execute('UPDATE servers SET name=?,domain=?,secret=?,revocation_pending=0,revision=revision+1 WHERE id=?',
                           (label, candidate['domain'], secret, sid))
        return health

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


def remote(server, payload, *, timeout=None):
    if server['local'] or not server['connected'] or not server['secret']:
        raise ValueError('Selected Global server is disconnected or revoked')
    u = urlsplit(domain(server['domain']))
    body = json.dumps(payload, separators=(',', ':')).encode()
    if len(body) > MAX_BODY:
        raise ValueError('Request too large')
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout or (5 if payload.get('kind') == 'health' else 10 if payload.get('kind') == 'revoke' else 65))
    try:
        conn.request('POST', '/v1/request', body, signed_headers(server['secret'], server['id'], body))
        r = conn.getresponse()
        data = r.read(MAX_OUTPUT+1)
        if len(data) > MAX_OUTPUT or r.status != 200:
            raise ValueError('Global API rejected request or returned an oversized response (HTTP %s)' % r.status)
        result = json.loads(data)
        if not isinstance(result, dict) or result.get('server_id') != server['id']:
            raise ValueError('Global response identity mismatch')
        if result.get('ok') is not True:
            raise ValueError(result.get('error', 'Global operation failed'))
        if not isinstance(result.get('data'), dict):
            raise ValueError('Invalid Global response payload')
        return result['data']
    except (http.client.HTTPException, UnicodeError) as exc:
        raise ValueError('Global transport returned an invalid or incomplete response') from exc
    finally:
        conn.close()
