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
            return [dict(r) for r in db.execute('SELECT id,name,domain,connected,local FROM servers ORDER BY local DESC,name')]

    def server(self, sid):
        if not isinstance(sid, str) or not ID.fullmatch(sid):
            raise ValueError('Explicit server identity required')
        with self.db() as db:
            r = db.execute('SELECT * FROM servers WHERE id=?', (sid,)).fetchone()
            if not r:
                raise ValueError('Unknown server')
            return dict(r)

    def pair(self, sid, label, origin, secret):
        node = self.node()
        if not node or node['role'] != 'local':
            raise ValueError('Only the primary Local can pair servers')
        if not isinstance(sid, str) or not ID.fullmatch(sid) or sid == node['id']:
            raise ValueError('Invalid Global identity')
        name(label); origin = domain(origin)
        if not isinstance(secret, str) or not re.fullmatch('[0-9a-f]{64}', secret):
            raise ValueError('Invalid pairing secret')
        candidate = dict(id=sid, name=label, domain=origin, secret=secret, connected=1, local=0)
        health = remote(candidate, {'kind': 'health'})
        if health.get('server_id') != sid:
            raise ValueError('Pairing identity mismatch')
        with self.db() as db:
            # Different servers must never share credentials.
            if db.execute('SELECT 1 FROM servers WHERE secret=? AND id!=?', (secret, sid)).fetchone():
                raise ValueError('Credentials already used by another server')
            db.execute('INSERT INTO servers VALUES(?,?,?,?,1,0) ON CONFLICT(id) DO UPDATE SET name=excluded.name,domain=excluded.domain,secret=excluded.secret,connected=1',
                       (sid, label, origin, secret))
        return health

    def connection(self, sid, action):
        s = self.server(sid)
        if s['local']:
            raise ValueError('The primary Local cannot be disconnected or revoked')
        if action == 'reconnect':
            remote(dict(s, connected=1), {'kind': 'health'})
        elif action == 'revoke':
            remote(dict(s, connected=1), {'kind': 'revoke'})
        elif action != 'disconnect':
            raise ValueError('Invalid connection action')
        with self.db() as db:
            db.execute('UPDATE servers SET connected=?,secret=? WHERE id=?',
                       (int(action == 'reconnect'), None if action == 'revoke' else s['secret'], sid))

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
    expected = hmac.new(n['secret'].encode(), canonical(method, path, body, sid, ts, nonce), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig) or not store.claim('auth', nonce):
        raise ValueError('Unauthorized')


def remote(server, payload):
    if server['local'] or not server['connected'] or not server['secret']:
        raise ValueError('Selected Global server is disconnected or revoked')
    u = urlsplit(domain(server['domain']))
    body = json.dumps(payload, separators=(',', ':')).encode()
    if len(body) > MAX_BODY:
        raise ValueError('Request too large')
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=65)
    try:
        conn.request('POST', '/v1/request', body, signed_headers(server['secret'], server['id'], body))
        r = conn.getresponse()
        data = r.read(MAX_OUTPUT+1)
        if len(data) > MAX_OUTPUT or r.status != 200:
            raise ValueError('Global API rejected request or returned an oversized response (HTTP %s)' % r.status)
        result = json.loads(data)
        if not isinstance(result, dict) or result.get('server_id') != server['id']:
            raise ValueError('Global response identity mismatch')
        if not result.get('ok'):
            raise ValueError(result.get('error', 'Global operation failed'))
        return result['data']
    finally:
        conn.close()
