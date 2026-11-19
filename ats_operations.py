"""Persistent operations history and the daemon's bounded monitoring cycle."""
import asyncio
import contextlib
import hashlib
import http.client
import json
import os
import re
import sqlite3
import time
import zipfile

import ats_manage_runtime as runtime

DEFAULTS = dict(health_enabled=False, health_path='/', expected_status=200,
                timeout_seconds=3, failure_threshold=3, backup_enabled=False,
                interval_hours=24, retain_count=7)


@contextlib.contextmanager
def connection(a):
    with contextlib.closing(sqlite3.connect(a.DB_FILE, timeout=30)) as c:
        c.row_factory = sqlite3.Row
        with c:
            yield c


def init(a):
    with connection(a) as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS ops_deployments (
          id INTEGER PRIMARY KEY, name TEXT, repository TEXT, branch TEXT,
          action TEXT, commit_sha TEXT, before_sha TEXT, status TEXT,
          started REAL, finished REAL, error TEXT);
        CREATE INDEX IF NOT EXISTS ops_deploy_name ON ops_deployments(name,id);
        CREATE TABLE IF NOT EXISTS ops_config (name TEXT PRIMARY KEY, config TEXT,
          next_backup REAL, last_backup REAL, last_error TEXT, verified_at REAL);
        CREATE TABLE IF NOT EXISTS ops_samples (id INTEGER PRIMARY KEY, name TEXT,
          at REAL, status TEXT, health_ok INTEGER, latency_ms REAL, error TEXT,
          cpu_ns REAL, cpu_percent REAL, memory_mb REAL);
        CREATE INDEX IF NOT EXISTS ops_sample_name ON ops_samples(name,id);
        CREATE TABLE IF NOT EXISTS ops_alerts (id INTEGER PRIMARY KEY, alert_key TEXT UNIQUE,
          name TEXT, kind TEXT, message TEXT, active INTEGER, acknowledged INTEGER,
          started REAL, last_seen REAL);
        CREATE TABLE IF NOT EXISTS ops_backups (id INTEGER PRIMARY KEY,
          name TEXT, backup_id INTEGER, created REAL, verified_at REAL);
        CREATE TABLE IF NOT EXISTS ops_state (key TEXT PRIMARY KEY, value TEXT);
        ''')


def repo_key(a, s):
    # Credentials never become history; changing repository invalidates rollback targets.
    return hashlib.sha256(a.redact_repo_url(s['repo_url']).encode()).hexdigest()


def begin(a, s, action, before=None):
    init(a)
    with connection(a) as c:
        return c.execute('INSERT INTO ops_deployments(name,repository,branch,action,before_sha,status,started) VALUES (?,?,?,?,?,?,?)',
                         (s['name'], repo_key(a, s), s.get('branch', 'main'), action, before, 'running', time.time())).lastrowid


def finish(a, ident, status, commit=None, error=None):
    with connection(a) as c:
        c.execute('UPDATE ops_deployments SET status=?,commit_sha=?,error=?,finished=? WHERE id=?',
                  (status, commit, a.redact_repo_url(str(error))[:1000] if error else None, time.time(), ident))
        c.execute('DELETE FROM ops_deployments WHERE id IN (SELECT id FROM ops_deployments WHERE status != ? ORDER BY id DESC LIMIT -1 OFFSET 5000)', ('running',))


def commit(a, s):
    try:
        return runtime.user(a, ['git', 'rev-parse', 'HEAD'], runtime.paths(a, s)[0], timeout=10)
    except Exception:
        return None


def history(a, s):
    with connection(a) as c:
        rows = [dict(r) for r in c.execute('SELECT * FROM ops_deployments WHERE name=? ORDER BY id DESC LIMIT 100', (s['name'],))]
    current = commit(a, s)
    for r in rows:
        r['rollback_available'] = (r['status'] == 'success' and bool(re.fullmatch(r'[0-9a-f]{40,64}', r['commit_sha'] or ''))
            and r['repository'] == repo_key(a, s) and r['branch'] == s.get('branch', 'main') and r['commit_sha'] != current)
        r.pop('repository', None)
    return {'deployments': rows, 'current_commit': current}


def rollback(a, args):
    init(a)
    s = runtime.row(a, args.get('name', ''))
    if args.get('confirm') != s['name']:
        raise ValueError('Type the service name to confirm rollback')
    ident = args.get('deployment_id')
    if isinstance(ident, bool) or not isinstance(ident, int) or ident < 1:
        raise ValueError('Invalid deployment id')
    with a.service_lock(s['name']):
        with connection(a) as c:
            target = c.execute('SELECT * FROM ops_deployments WHERE id=? AND name=? AND status=?', (ident, s['name'], 'success')).fetchone()
        if not target or target['repository'] != repo_key(a, s) or target['branch'] != s.get('branch', 'main'):
            raise ValueError('Choose a successful deployment from the current repository and branch')
        sha = target['commit_sha'] or ''
        if not re.fullmatch(r'[0-9a-f]{40,64}', sha):
            raise ValueError('This deployment has no usable commit')
        directory, _ = runtime.paths(a, s)
        if runtime.user(a, ['git', 'status', '--porcelain', '--untracked-files=no'], directory):
            raise a.ServiceOpError('Preserve local tracked changes before rollback', 'conflict')
        before = commit(a, s)
        if before == sha:
            raise ValueError('This commit is already checked out')
        record = begin(a, s, 'rollback', before)
        changed = False
        try:
            runtime.step(a, 'checkout', lambda: runtime.user(a, ['git', 'checkout', '--detach', sha], directory))
            changed = True
            runtime.step(a, 'build' if s['runtime'] == 'docker' else 'deps', lambda: runtime.dependencies(a, s))
            runtime.step(a, 'start', lambda: a._systemctl_and_verify('restart', s['name']))
            def health():
                if not a.health_check_deployment(s['name'], s['port']):
                    raise a.ServiceOpError('Rollback failed deployment health checks')
            runtime.step(a, 'health', health)
            finish(a, record, 'success', sha)
            a.audit_log('ROLLBACK', s['name'], {'deployment_id': ident, 'commit': sha})
            return {'name': s['name'], 'commit': sha, 'database_changed': False}
        except Exception as error:
            recovery = ''
            if changed and before:
                try:
                    runtime.step(a, 'recover', lambda: runtime.user(a, ['git', 'checkout', '--detach', before], directory))
                    runtime.dependencies(a, s)
                    a._systemctl_and_verify('restart', s['name'])
                    recovery = '; previous code restored'
                except Exception:
                    recovery = '; recovery failed, inspect service before retrying'
            finish(a, record, 'failed', commit(a, s), str(error) + recovery)
            a.audit_log('ROLLBACK_FAILED', s['name'], {'deployment_id': ident})
            raise a.ServiceOpError(a.redact_repo_url(str(error)) + recovery)


def config(a, name):
    with connection(a) as c:
        row = c.execute('SELECT * FROM ops_config WHERE name=?', (name,)).fetchone()
    return dict(DEFAULTS, **json.loads(row['config'])) if row else dict(DEFAULTS)


def set_config(a, args):
    s = runtime.row(a, args.get('name', ''))
    values = {k: v for k, v in args.items() if k != 'name'}
    if set(values) - set(DEFAULTS):
        raise ValueError('Unknown operations setting')
    cfg = dict(config(a, s['name']), **values)
    for k in ('health_enabled', 'backup_enabled'):
        if not isinstance(cfg[k], bool): raise ValueError(k + ' must be boolean')
    for k, lo, hi in (('expected_status', 100, 599), ('timeout_seconds', 1, 10), ('failure_threshold', 1, 20), ('interval_hours', 1, 720), ('retain_count', 1, 100)):
        if isinstance(cfg[k], bool) or not isinstance(cfg[k], int) or not lo <= cfg[k] <= hi:
            raise ValueError(k + ' is outside its allowed range')
    path = cfg['health_path']
    if not isinstance(path, str) or len(path) > 512 or not path.startswith('/') or path.startswith('//') or any(ord(x) < 33 or ord(x) > 126 for x in path) or '#' in path:
        raise ValueError('Health path must be a local HTTP path, for example /health')
    with a.service_lock(s['name']), connection(a) as c:
        old = c.execute('SELECT config,next_backup FROM ops_config WHERE name=?', (s['name'],)).fetchone()
        next_run = (old['next_backup'] if old and json.loads(old['config'])['backup_enabled'] and json.loads(old['config'])['interval_hours'] == cfg['interval_hours'] else time.time() + cfg['interval_hours'] * 3600) if cfg['backup_enabled'] else None
        c.execute('INSERT INTO ops_config(name,config,next_backup) VALUES (?,?,?) ON CONFLICT(name) DO UPDATE SET config=excluded.config,next_backup=excluded.next_backup', (s['name'], json.dumps(cfg), next_run))
    a.audit_log('OPERATIONS_CONFIG', s['name'], {'fields': sorted(values)})
    return {'config': cfg, 'next_backup': next_run}


def alert(a, key, name, kind, message, active):
    now = time.time()
    with connection(a) as c:
        old = c.execute('SELECT * FROM ops_alerts WHERE alert_key=?', (key,)).fetchone()
        if not active:
            c.execute('UPDATE ops_alerts SET active=0,last_seen=? WHERE alert_key=? AND active=1', (now, key))
        elif old:
            c.execute('UPDATE ops_alerts SET message=?,active=1,acknowledged=CASE WHEN active=0 THEN 0 ELSE acknowledged END,started=CASE WHEN active=0 THEN ? ELSE started END,last_seen=? WHERE alert_key=?', (message, now, now, key))
        else:
            c.execute('INSERT INTO ops_alerts(alert_key,name,kind,message,active,acknowledged,started,last_seen) VALUES (?,?,?,?,1,0,?,?)', (key, name, kind, message, now, now))


def verify_backup(a, args):
    import ats_api
    s = runtime.row(a, args.get('name', ''))
    backup = ats_api.find_backup(a, args)
    if backup['service_name'] != s['name'] or backup['location'] != 'local':
        raise ValueError('Choose a local backup belonging to this service')
    with a.service_lock(s['name']):
        path = ats_api.backup_path(a, backup['filename'])
        if backup.get('checksum') and a.calculate_file_hash(str(path)) != backup['checksum']:
            raise a.ServiceOpError('Backup checksum mismatch')
        with zipfile.ZipFile(path) as z:
            if len(z.infolist()) > 10000 or sum(x.file_size for x in z.infolist()) > 2 * 1024 ** 3:
                raise ValueError('Backup exceeds the 2 GiB verification limit')
            if any(x.compress_size and x.file_size / x.compress_size > 1000 for x in z.infolist()):
                raise ValueError('Backup compression ratio exceeds verification limit')
            a._plan_zip_extraction(z, str(path.parent / '.verify-unused'))
            if z.testzip(): raise a.ServiceOpError('Backup archive integrity check failed')
        now = time.time()
        with connection(a) as c:
            c.execute('UPDATE ops_config SET verified_at=? WHERE name=?', (now, s['name']))
            c.execute('UPDATE ops_backups SET verified_at=? WHERE backup_id=? AND name=?', (now, backup['id'], s['name']))
        a.audit_log('BACKUP_VERIFIED', s['name'], {'filename': backup['filename']})
        return {'verified_at': now, 'filename': backup['filename'], 'kind': 'archive_integrity', 'restore_tested': False}


def sample(a, s, now):
    cfg = config(a, s['name'])
    status = 'unknown'
    cpu_ns = memory = cpu = latency = ok = error = None
    try:
        from ats_api import command
        r = command(['systemctl', 'show', s['name'], '--property=ActiveState,CPUUsageNSec,MemoryCurrent'], timeout=10)
        if r.returncode: raise OSError('systemd metrics unavailable')
        fields = dict(line.split('=', 1) for line in r.stdout.splitlines() if '=' in line)
        status = fields.get('ActiveState', 'unknown')
        if fields.get('CPUUsageNSec', '').isdigit(): cpu_ns = float(fields['CPUUsageNSec'])
        if fields.get('MemoryCurrent', '').isdigit(): memory = int(fields['MemoryCurrent']) / 1024 ** 2
    except Exception:
        pass
    if cfg['health_enabled']:
        started = time.monotonic()
        conn = http.client.HTTPConnection('127.0.0.1', s['port'], timeout=cfg['timeout_seconds'])
        try:
            conn.request('GET', cfg['health_path'], headers={'Connection': 'close', 'User-Agent': 'ATS-health/1'})
            response = conn.getresponse()
            ok = response.status == cfg['expected_status']
            if not ok: error = 'HTTP ' + str(response.status)
        except (OSError, http.client.HTTPException) as e:
            ok = False
            error = str(e)[:200]
        finally:
            conn.close()
            latency = round((time.monotonic() - started) * 1000, 1)
    with connection(a) as c:
        previous = c.execute('SELECT * FROM ops_samples WHERE name=? ORDER BY id DESC LIMIT 1', (s['name'],)).fetchone()
        if previous and cpu_ns is not None and previous['cpu_ns'] is not None and now > previous['at'] and cpu_ns >= previous['cpu_ns']:
            cpu = round((cpu_ns - previous['cpu_ns']) / 1e9 / (now - previous['at']) * 100, 2)
        c.execute('INSERT INTO ops_samples(name,at,status,health_ok,latency_ms,error,cpu_ns,cpu_percent,memory_mb) VALUES (?,?,?,?,?,?,?,?,?)', (s['name'], now, status, ok, latency, error, cpu_ns, cpu, memory))
        recent = c.execute('SELECT health_ok FROM ops_samples WHERE name=? ORDER BY id DESC LIMIT ?', (s['name'], cfg['failure_threshold'])).fetchall()
        failures = 0
        for row in recent:
            if row['health_ok'] != 0: break
            failures += 1
        c.execute('DELETE FROM ops_samples WHERE name=? AND id NOT IN (SELECT id FROM ops_samples WHERE name=? ORDER BY id DESC LIMIT 1440)', (s['name'], s['name']))
    alert(a, s['name'] + ':health', s['name'], 'health', 'Health check failed ' + str(failures) + ' consecutive times: ' + (error or ''), cfg['health_enabled'] and failures >= cfg['failure_threshold'])
    if status != 'unknown': alert(a, s['name'] + ':service', s['name'], 'service', 'Service is ' + status, status not in ('active', 'activating'))


def collect(a):
    import ats_api
    init(a)
    # Global nonblocking lock prevents two daemons or manual cycles overlapping.
    import fcntl
    with open(os.path.join(a.ATS_HOME, '.operations-collector.lock'), 'a') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return {'busy': True}
        now = time.time()
        errors = []
        services = [dict(s) for s in a.db.query('SELECT * FROM services ORDER BY name', fetch_all=True)]
        for s in services:
            name = s['name']
            try:
                sample(a, s, now)
                with connection(a) as c:
                    scheduled = c.execute('SELECT * FROM ops_config WHERE name=?', (name,)).fetchone()
                if scheduled:
                    cfg = json.loads(scheduled['config'])
                    if cfg['backup_enabled'] and (scheduled['next_backup'] or 0) <= now:
                        # Advance before execution: a crash cannot cause rapid repeated backups.
                        with connection(a) as c: c.execute('UPDATE ops_config SET next_backup=? WHERE name=?', (now + cfg['interval_hours'] * 3600, name))
                        try:
                            b = ats_api.backup_create(a, {'name': name}, scheduled=True)
                            record = a.db.query("SELECT id FROM backups WHERE service_name=? AND filename=? AND location='local' ORDER BY id DESC LIMIT 1", (name, b['filename']), fetch_one=True)
                            with connection(a) as c:
                                c.execute('INSERT INTO ops_backups(name,backup_id,created) VALUES (?,?,?)', (name, record['id'], now))
                                c.execute('UPDATE ops_config SET last_backup=?,last_error=NULL WHERE name=?', (now, name))
                            verify_backup(a, {'name': name, 'id': record['id']})
                            with connection(a) as c:
                                expired = [dict(r) for r in c.execute('SELECT * FROM ops_backups WHERE name=? ORDER BY id DESC LIMIT -1 OFFSET ?', (name, cfg['retain_count']))]
                            for item in expired:
                                if a.db.query('SELECT id FROM backups WHERE id=?', (item['backup_id'],), fetch_one=True): ats_api.backup_delete(a, {'id': item['backup_id']})
                                with connection(a) as c: c.execute('DELETE FROM ops_backups WHERE id=?', (item['id'],))
                            alert(a, name + ':backup', name, 'backup', 'Scheduled backup failed', False)
                        except Exception as e:
                            message = a.redact_repo_url(str(e))[:400]
                            with connection(a) as c: c.execute('UPDATE ops_config SET last_error=? WHERE name=?', (message, name))
                            alert(a, name + ':backup', name, 'backup', message, True)
                            a.audit_log('SCHEDULED_BACKUP_FAILED', name)
                with connection(a) as c:
                    last = c.execute('SELECT status,error FROM ops_deployments WHERE name=? ORDER BY id DESC LIMIT 1', (name,)).fetchone()
                if last and last['status'] != 'running': alert(a, name + ':deployment', name, 'deployment', last['error'] or 'Deployment failed', last['status'] == 'failed')
            except Exception as e:
                errors.append({'name': name, 'error': a.redact_repo_url(str(e))[:200]})
        import shutil
        try:
            disk = shutil.disk_usage(a.DEFAULT_STORAGE)
            pct = round(disk.used / disk.total * 100, 1)
            alert(a, 'host:disk', 'SYSTEM', 'disk', 'Storage disk is ' + str(pct) + '% used', pct >= 90)
        except OSError: pass
        with connection(a) as c:
            c.execute('INSERT OR REPLACE INTO ops_state(key,value) VALUES (?,?)', ('collector', json.dumps({'at': time.time(), 'errors': errors, 'services': len(services)})))
            names = {s['name'] for s in services}
            for row in c.execute('SELECT name FROM ops_config').fetchall():
                if row['name'] not in names:
                    c.execute('DELETE FROM ops_config WHERE name=?', (row['name'],))
            c.execute('DELETE FROM ops_alerts WHERE active=0 AND last_seen<?', (now - 30 * 86400,))
        return {'collected_at': now, 'services': len(services), 'errors': errors}


def activity(a, name=None):
    entries = []
    try:
        with open(a.AUDIT_FILE, 'rb') as f:
            f.seek(max(0, os.fstat(f.fileno()).st_size - 1024 * 1024))
            if f.tell(): f.readline()
            for raw in f:
                try:
                    item = json.loads(raw)
                    if name and item.get('target') != name: continue
                    # Return event identity only. Arbitrary old metadata may contain secrets.
                    entries.append({k: str(item.get(k, ''))[:200] for k in ('timestamp', 'action', 'target', 'user')})
                except (ValueError, TypeError): pass
    except OSError: pass
    return entries[-100:][::-1]


def get(a, args):
    name = args.get('name')
    s = runtime.row(a, name) if name else None
    with connection(a) as c:
        collector = c.execute('SELECT value FROM ops_state WHERE key=?', ('collector',)).fetchone()
        alerts = [dict(r) for r in c.execute('SELECT * FROM ops_alerts' + (' WHERE name=?' if name else '') + ' ORDER BY active DESC,last_seen DESC LIMIT 100', (name,) if name else ())]
        samples = [dict(r) for r in c.execute('SELECT at,status,health_ok,latency_ms,error,cpu_percent,memory_mb FROM ops_samples WHERE name=? ORDER BY id DESC LIMIT 240', (name,))][::-1] if name else []
        schedule = c.execute('SELECT next_backup,last_backup,last_error,verified_at FROM ops_config WHERE name=?', (name,)).fetchone() if name else None
    state = json.loads(collector['value']) if collector else {'at': None, 'errors': []}
    state['stale'] = not state['at'] or time.time() - state['at'] > 180
    checked = [r for r in samples if r['health_ok'] is not None]
    streak = 0
    for row in reversed(checked):
        if row['health_ok'] != 0: break
        streak += 1
    data = {'collector': state, 'alerts': alerts, 'activity': activity(a, name), 'samples': samples,
            'health': {'observed_availability_pct': round(sum(r['health_ok'] for r in checked) / len(checked) * 100, 1) if checked else None, 'observations': len(checked), 'failure_streak': streak}}
    if s:
        data.update(history(a, s), config=config(a, name), schedule=dict(schedule) if schedule else {'legacy_midnight': True}, webhook_events=a.list_webhook_events(name, 100))
    return data


def run(a, op, args):
    init(a)
    if op == 'operations.get': return get(a, args)
    if op == 'operations.set': return set_config(a, args)
    if op == 'operations.collect': return collect(a)
    if op == 'deployments.rollback': return rollback(a, args)
    if op == 'backups.verify': return verify_backup(a, args)
    if op == 'alerts.ack':
        ident = args.get('id')
        if isinstance(ident, bool) or not isinstance(ident, int) or ident < 1: raise ValueError('Invalid alert id')
        with connection(a) as c:
            if not c.execute('UPDATE ops_alerts SET acknowledged=1 WHERE id=?', (ident,)).rowcount: raise a.ServiceOpError('Alert not found', 'notfound')
        a.audit_log('ALERT_ACKNOWLEDGED', 'SYSTEM', {'id': ident})
        return {'acknowledged': True}
    raise a.ServiceOpError('Unsupported operation', 'unsupported')


async def worker(a):
    while True:
        try:
            await asyncio.to_thread(collect, a)
        except Exception:
            a.logger.exception('Operations collection failed')
        await asyncio.sleep(60)
