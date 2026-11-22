"""Backups of the cluster registry: identities, keys, webhook mappings and alert settings.

The registry cannot be recreated from anywhere else; losing it means re-pairing every server. Snapshots use
SQLite's online backup API, so they are consistent while ATS is running. A backup holds private keys, so files
are mode 0600 in a 0700 directory and can be encrypted with a passphrase (openssl, AES-256, PBKDF2).
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import threading
import time

MAGIC = b'Salted__'
OFFSITE_KEEP = 10
OFFSITE_MAX = 16 * 1024 * 1024
CHUNK = 120_000                  # raw bytes per request; base64 keeps the body well under the 256 KiB request limit
OFFSITE_NAME = re.compile(r'registry-\d{8}-\d{6}\.sqlite3\.enc\Z')
_receive_lock = threading.Lock()
KEEP = 7
INTERVAL = 24 * 3600
NAME = re.compile(r'registry-\d{8}-\d{6}\.sqlite3(\.enc)?\Z')
REQUIRED = ('node', 'servers', 'routes', 'seen')


def directory(store, create=True):
    path = Path(store.path).parent / 'registry-backups'
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    return path


def snapshot(store, destination):
    """A consistent copy of the live registry, written privately and atomically."""
    destination = Path(destination)
    temporary = destination.with_name('.' + destination.name + '.part')
    source = sqlite3.connect(store.path, timeout=30)
    target = sqlite3.connect(temporary)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()
    os.chmod(temporary, 0o600)
    os.replace(temporary, destination)
    return destination


def _openssl(decrypt, source, target, passphrase):
    command = ['openssl', 'enc', '-d' if decrypt else '-e', '-aes-256-cbc', '-pbkdf2', '-iter', '200000', '-salt',
               '-in', str(source), '-out', str(target), '-pass', 'stdin']
    try:
        result = subprocess.run(command, input=passphrase + '\n', capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('openssl is not available to encrypt or decrypt the backup') from None
    if result.returncode:
        target_path = Path(target)
        if target_path.exists():
            target_path.unlink()
        raise ValueError('Wrong passphrase, or the backup is damaged' if decrypt else 'Encryption failed')


def is_encrypted(path):
    with open(path, 'rb') as stream:
        return stream.read(len(MAGIC)) == MAGIC


def create(store, output=None, passphrase=None):
    """Write one backup. Returns {'path', 'size', 'encrypted', 'at'}."""
    if passphrase is not None and not (isinstance(passphrase, str) and len(passphrase) >= 8):
        raise ValueError('The passphrase must be at least 8 characters')
    stamp = time.strftime('%Y%m%d-%H%M%S')
    final = Path(output) if output else directory(store) / (f'registry-{stamp}.sqlite3' + ('.enc' if passphrase else ''))
    if final.exists():
        raise ValueError(f'{final} already exists; choose another file name')
    final.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.ats-backup-', dir=final.parent) as scratch:
        plain = snapshot(store, Path(scratch) / 'registry.sqlite3')
        if passphrase:
            sealed = Path(scratch) / 'registry.enc'
            _openssl(False, plain, sealed, passphrase)
            os.chmod(sealed, 0o600)
            os.replace(sealed, final)
        else:
            os.replace(plain, final)
    os.chmod(final, 0o600)
    return {'path': str(final), 'size': final.stat().st_size, 'encrypted': bool(passphrase), 'at': int(time.time())}


def prune(store, keep=KEEP):
    files = sorted((p for p in directory(store, False).iterdir() if NAME.fullmatch(p.name)), key=lambda p: p.name) if directory(store, False).is_dir() else []
    for old in files[:-keep] if keep else files:
        old.unlink()
    return len(files[-keep:]) if keep else 0


def listing(store):
    result, folder = [], directory(store, False)
    if not folder.is_dir():
        return result
    for path in sorted(folder.iterdir(), key=lambda p: p.name, reverse=True):
        if NAME.fullmatch(path.name):
            info = path.stat()
            result.append({'name': path.name, 'path': str(path), 'size': info.st_size, 'at': int(info.st_mtime), 'encrypted': path.name.endswith('.enc')})
    return result


def describe(path, passphrase=None):
    """Open a backup read-only, check it, and say what it contains. Never changes the live registry."""
    path = Path(path)
    if not path.is_file():
        raise ValueError(f'{path} does not exist')
    with tempfile.TemporaryDirectory(prefix='.ats-restore-') as scratch:
        readable = path
        if is_encrypted(path):
            if not passphrase:
                raise ValueError('This backup is encrypted; a passphrase is required')
            readable = Path(scratch) / 'registry.sqlite3'
            _openssl(True, path, readable, passphrase)
        try:
            db = sqlite3.connect(f'file:{readable}?mode=ro', uri=True)
            db.row_factory = sqlite3.Row
            try:
                if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                    raise ValueError('The backup failed its integrity check')
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not set(REQUIRED) <= tables:
                    raise ValueError('This file is not an ATS registry backup')
                node = db.execute('SELECT id,role,name,domain FROM node').fetchone()
                servers = [r['name'] for r in db.execute('SELECT name FROM servers WHERE local=0 ORDER BY name')]
                routes = db.execute('SELECT count(*) FROM routes').fetchone()[0]
            finally:
                db.close()
        except sqlite3.DatabaseError:
            raise ValueError('This file is not a readable ATS registry backup') from None
    return {'id': node['id'] if node else None, 'role': node['role'] if node else None, 'name': node['name'] if node else None,
            'domain': node['domain'] if node else None, 'servers': servers, 'mappings': routes, 'encrypted': is_encrypted(path),
            'at': int(path.stat().st_mtime)}


def restore(store, path, passphrase=None, force=False):
    """Replace the live registry with a backup, after a safety copy of the current one."""
    summary = describe(path, passphrase)
    current = store.node()
    if current and not force and (current['id'] != summary['id'] or current['role'] != summary['role']):
        raise ValueError(f"This backup belongs to a different server ({summary['role']} “{summary['name']}”), not this one "
                         f"({current['role']} “{current['name']}”). Restoring would replace this server's identity; use --force only if that is the intent")
    safety = snapshot(store, directory(store) / f'pre-restore-{time.strftime("%Y%m%d-%H%M%S")}.sqlite3')
    with tempfile.TemporaryDirectory(prefix='.ats-restore-') as scratch:
        readable = Path(path)
        if is_encrypted(path):
            readable = Path(scratch) / 'registry.sqlite3'
            _openssl(True, path, readable, passphrase)
        source = sqlite3.connect(f'file:{readable}?mode=ro', uri=True)
        target = sqlite3.connect(store.path, timeout=30)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
    os.chmod(store.path, 0o600)
    type(store)(store.path)          # re-run schema migrations against the restored file
    return dict(summary, safety_copy=str(safety))


def status(store):
    """What the daemon last did, for doctor and the Monitor. Reads only registry state."""
    last = store.kv_get('registry_backup')
    items = listing(store)
    return {'last': last, 'count': len(items), 'newest': items[0] if items else None}


def run_scheduled(store, now=None):
    """Called by the daemon: make a backup when the newest one is older than INTERVAL."""
    now = now or time.time()
    items = listing(store)
    if items and now - items[0]['at'] < INTERVAL:
        return None
    passphrase = None
    secret_file = os.environ.get('ATS_REGISTRY_BACKUP_PASSPHRASE_FILE')
    if secret_file:
        passphrase = Path(secret_file).read_text().strip()
    try:
        made = create(store, passphrase=passphrase)
        prune(store)
        record = {'at': made['at'], 'path': made['path'], 'size': made['size'], 'encrypted': made['encrypted'], 'error': None}
        if made['encrypted'] and store.node() and store.node()['role'] == 'local':
            try:
                push_file(store, made['path'])
            except ValueError:
                pass            # no connected Global, or none reachable: recorded per server, shown in doctor
    except (OSError, ValueError, sqlite3.Error) as exc:
        record = {'at': int(now), 'error': str(exc)[:200]}
    store.kv_set('registry_backup', record)
    return record


# ── off-host copies: the Local pushes encrypted backups to a paired Global over the signed channel ──
def offsite_dir(store, create=True):
    path = Path(store.path).parent / 'offsite-backups'
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
        os.chmod(path, 0o700)
    return path


def _digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def _sequence(value, low, high, label):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f'{label} is not valid')
    return value


def receive(store, data):
    """Global side: accept one chunk of an encrypted registry backup. Plaintext is refused; the file appears only once complete and verified."""
    node = store.node()
    if not node or node['role'] != 'global':
        raise ValueError('Only a Global stores off-host backups')
    name = data.get('name')
    if not isinstance(name, str) or not OFFSITE_NAME.fullmatch(name):
        raise ValueError('Not a registry backup name')
    index, total = _sequence(data.get('index'), 0, 10_000, 'index'), _sequence(data.get('total'), 1, 10_000, 'total')
    if index >= total or total * CHUNK > OFFSITE_MAX + CHUNK:
        raise ValueError('The backup is larger than this server accepts')
    try:
        raw = base64.b64decode(data.get('data') or '', validate=True)
    except (ValueError, TypeError):
        raise ValueError('The backup data is not valid base64') from None
    if len(raw) > CHUNK or (index < total - 1 and len(raw) != CHUNK):
        raise ValueError('Unexpected chunk size')
    folder = offsite_dir(store)
    part, marker = folder / f'.incoming-{name}', folder / f'.incoming-{name}.next'
    with _receive_lock:
        for old in folder.glob('.incoming-*'):
            if time.time() - old.stat().st_mtime > 3600:
                old.unlink(missing_ok=True)
        expected = int(marker.read_text()) if marker.exists() else 0
        if index == 0:
            part.write_bytes(b'')
            expected = 0
        if index != expected or not part.exists():
            raise ValueError('Chunks must arrive in order; start again from the first one')
        if index == 0 and not raw.startswith(MAGIC):
            part.unlink(missing_ok=True)
            raise ValueError('Only encrypted backups are accepted here (this one is not)')
        with open(part, 'ab') as stream:
            stream.write(raw)
        os.chmod(part, 0o600)
        marker.write_text(str(index + 1))
        if index < total - 1:
            return {'stored': False, 'next': index + 1}
        size = part.stat().st_size
        if size > OFFSITE_MAX or _digest(part) != data.get('sha256'):
            part.unlink(missing_ok=True); marker.unlink(missing_ok=True)
            raise ValueError('The received backup did not match its checksum; nothing was stored')
        os.replace(part, folder / name)
        marker.unlink(missing_ok=True)
        os.chmod(folder / name, 0o600)
        kept = sorted(p for p in folder.iterdir() if OFFSITE_NAME.fullmatch(p.name))
        for old in kept[:-OFFSITE_KEEP]:
            old.unlink()
    return {'stored': True, 'name': name, 'size': size}


def list_offsite(store):
    folder = offsite_dir(store, False)
    if not folder.is_dir():
        return []
    return [{'name': p.name, 'size': p.stat().st_size, 'at': int(p.stat().st_mtime)}
            for p in sorted(folder.iterdir(), key=lambda p: p.name, reverse=True) if OFFSITE_NAME.fullmatch(p.name)]


def read_part(store, name, index):
    """Global side: one chunk of a stored backup, so the Local can fetch it back."""
    if not isinstance(name, str) or not OFFSITE_NAME.fullmatch(name):
        raise ValueError('Not a registry backup name')
    path = offsite_dir(store, False) / name
    if not path.is_file() or path.is_symlink():
        raise ValueError('No such backup on this server')
    size = path.stat().st_size
    total = max(1, -(-size // CHUNK))
    _sequence(index, 0, total - 1, 'index')
    with open(path, 'rb') as stream:
        stream.seek(index * CHUNK)
        raw = stream.read(CHUNK)
    return {'index': index, 'total': total, 'data': base64.b64encode(raw).decode(), 'sha256': _digest(path), 'size': size}


def push_file(store, path, call=None):
    """Local side: send one encrypted backup to every connected Global. Failures are per server and recorded."""
    import ats_cluster as cluster
    call = call or cluster.remote
    path = Path(path)
    if not path.is_file() or not is_encrypted(path):
        raise ValueError('Only an encrypted backup can leave this server')
    if path.stat().st_size > OFFSITE_MAX:
        raise ValueError('The backup is larger than the 16 MB off-host limit')
    if not OFFSITE_NAME.fullmatch(path.name):
        raise ValueError('Not a registry backup file name')
    checksum, size = _digest(path), path.stat().st_size
    total = max(1, -(-size // CHUNK))
    results = store.kv_get('registry_backup_offsite', {})
    targets = [store.server(s['id']) for s in store.servers() if not s['local'] and s['paired'] and s['connected'] and not s['revocation_pending']]
    if not targets:
        raise ValueError('No connected Global to send a copy to')
    with open(path, 'rb') as stream:
        blocks = [stream.read(CHUNK) for _ in range(total)]
    for server in targets:
        try:
            for index, block in enumerate(blocks):
                call(server, {'kind': 'backup.put', 'name': path.name, 'index': index, 'total': total,
                              'data': base64.b64encode(block).decode(), 'sha256': checksum}, timeout=60)
            results[server['id']] = {'ok': True, 'name': path.name, 'at': int(time.time()), 'size': size, 'error': None, 'server': server['name']}
        except (cluster.TransportError, ValueError) as exc:
            results[server['id']] = dict(results.get(server['id']) or {}, ok=False, at=int(time.time()), error=str(exc)[:200], server=server['name'])
    store.kv_set('registry_backup_offsite', results)
    return results


def push_offsite(store, passphrase=None, call=None):
    """Push now: with a passphrase, make a fresh encrypted backup to send; otherwise send the newest encrypted one that exists."""
    if passphrase is None and os.environ.get('ATS_REGISTRY_BACKUP_PASSPHRASE_FILE'):
        passphrase = Path(os.environ['ATS_REGISTRY_BACKUP_PASSPHRASE_FILE']).read_text().strip()
    if passphrase:
        with tempfile.TemporaryDirectory(prefix='.ats-offsite-') as scratch:
            stamp = time.strftime('%Y%m%d-%H%M%S')
            made = create(store, Path(scratch) / f'registry-{stamp}.sqlite3.enc', passphrase)
            return push_file(store, made['path'], call)
    newest = next((i for i in listing(store) if i['encrypted']), None)
    if not newest:
        raise ValueError('Off-host copies are always encrypted: enter a passphrase, or set ATS_REGISTRY_BACKUP_PASSPHRASE_FILE')
    return push_file(store, newest['path'], call)


def fetch_offsite(store, server, name, output, call=None):
    """Local side: bring a stored copy back from a Global (it stays encrypted until you restore it)."""
    import ats_cluster as cluster
    call = call or cluster.remote
    output = Path(output)
    if output.exists():
        raise ValueError(f'{output} already exists; choose another file name')
    if name is None:
        listed = call(server, {'kind': 'backup.list'}).get('backups') or []
        if not listed:
            raise ValueError('That server holds no copies of this registry yet')
        name = listed[0]['name']
    first = call(server, {'kind': 'backup.get', 'name': name, 'index': 0}, timeout=60)
    chunks = [base64.b64decode(first['data'])]
    for index in range(1, first['total']):
        chunks.append(base64.b64decode(call(server, {'kind': 'backup.get', 'name': name, 'index': index}, timeout=60)['data']))
    blob = b''.join(chunks)
    if hashlib.sha256(blob).hexdigest() != first['sha256'] or not blob.startswith(MAGIC):
        raise ValueError('The fetched copy did not match its checksum; nothing was written')
    output.write_bytes(blob)
    os.chmod(output, 0o600)
    return {'name': name, 'size': len(blob), 'path': str(output)}


def offsite_status(store):
    """Per paired Global: when the last copy went and whether it worked. Reads only registry state."""
    return store.kv_get('registry_backup_offsite', {})
