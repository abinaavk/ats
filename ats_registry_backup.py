"""Backups of the cluster registry: identities, keys, webhook mappings and alert settings.

The registry cannot be recreated from anywhere else; losing it means re-pairing every server. Snapshots use
SQLite's online backup API, so they are consistent while ATS is running. A backup holds private keys, so files
are mode 0600 in a 0700 directory and can be encrypted with a passphrase (openssl, AES-256, PBKDF2).
"""
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import tempfile
import time

MAGIC = b'Salted__'
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
    except (OSError, ValueError, sqlite3.Error) as exc:
        record = {'at': int(now), 'error': str(exc)[:200]}
    store.kv_set('registry_backup', record)
    return record
