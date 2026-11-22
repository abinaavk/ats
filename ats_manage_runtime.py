"""Noninteractive ATS service operations, shared with signed webhook updates."""
import collections
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import tempfile
import threading
import time


def row(a, name):
    a.validate_service_name(name)
    value = a.db.query('SELECT * FROM services WHERE name=?', (name,), fetch_one=True)
    if not value:
        raise a.ServiceOpError('Service not found', 'notfound')
    return dict(value)


def base(s):
    value = s['storage_path'].rstrip('/')
    return value[:-4] if value.endswith('/api') else value


def paths(a, s):
    return a.get_service_path(s['storage_path'], s['name']), os.path.join(base(s), 'database', s['name'])


def safe_path(path):
    if not isinstance(path, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', path) or '..' in path.split('/'):
        raise ValueError('Service storage paths must be absolute and contain only letters, digits, /, _, . and -')
    return path


def atomic(path, text, mode=0o600):
    fd, tmp = tempfile.mkstemp(prefix='.ats-', dir=os.path.dirname(path))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w') as out:
            out.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def environment(value):
    if not isinstance(value, dict) or len(value) > 200:
        raise ValueError('env must be an object with at most 200 entries')
    for key, val in value.items():
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', key):
            raise ValueError('Invalid environment variable name')
        if not isinstance(val, str) or len(val) > 4096 or any(c in val for c in '\0\r\n'):
            raise ValueError('Environment values must be single-line strings')
    return value


def write_env(a, s, env):
    directory, _ = paths(a, s)
    def quote(v):
        return '"' + v.replace('\\', '\\\\').replace('"', '\\"').replace('`', '\\`').replace('$', '\\$') + '"'
    atomic(os.path.join(directory, '.ats.env'), ''.join(k + '=' + quote(v) + '\n' for k, v in environment(env).items()))
    atomic(os.path.join(directory, '.ats.docker.env'), ''.join(k + '=' + v + '\n' for k, v in env.items()))
    for filename in ('.ats.env', '.ats.docker.env'):
        shutil.chown(os.path.join(directory, filename), user=a.SERVICE_USER, group=a.SERVICE_GROUP)


def unit(a, s):
    directory, database = paths(a, s)
    safe_path(directory); safe_path(database)
    logs = os.path.join(directory, 'logs')
    cfg = a.ServiceConfig(name=s['name'], port=s['port'], domain=s['domain'], storage_path=s['storage_path'],
                          repo_url=s['repo_url'], workers=s['workers'], max_memory_mb=s['max_memory_mb'],
                          cpu_quota=s['cpu_quota'], runtime=s['runtime'])
    if s['runtime'] != 'docker':
        content = a.generate_systemd_service(cfg, directory, logs, database)
        return content.replace('# Environment\n', f'# Environment\nEnvironmentFile=-{directory}/.ats.env\n')
    docker = shutil.which('docker')
    if not docker:
        raise a.ServiceOpError('Docker is not installed')
    docker = safe_path(docker)
    name = s['name']
    # systemd starts the Docker client as the service user; it needs socket access.
    return f'''[Unit]
Description={name} [ATS managed Docker]
After=network-online.target docker.service
Requires=docker.service
[Service]
Type=simple
User={a.SERVICE_USER}
Group={a.SERVICE_GROUP}
WorkingDirectory={directory}
ExecStartPre=-{docker} rm -f ats-{name}
ExecStart={docker} run --rm --name ats-{name} --publish 127.0.0.1:{s['port']}:{s['container_port']} --memory {s['max_memory_mb']}m --cpus {s['cpu_quota']/100:g} --restart no --env-file {directory}/.ats.docker.env --volume {database}:/data ats-{name}:latest
ExecStop={docker} stop -t 20 ats-{name}
StandardOutput=append:{logs}/stdout.log
StandardError=append:{logs}/stderr.log
Restart=on-failure
RestartSec=5
TimeoutStartSec=120
TimeoutStopSec=30
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
'''


def logrotate(a, s):
    directory, _ = paths(a, s)
    root = getattr(a, 'LOGROTATE_DIR', '/etc/logrotate.d')
    os.makedirs(root, exist_ok=True)
    atomic(os.path.join(root, 'ats-' + s['name']), f'''{directory}/logs/*.log {{
    weekly
    rotate 4
    compress
    copytruncate
    missingok
    notifempty
    su {a.SERVICE_USER} {a.SERVICE_GROUP}
}}
''', 0o644)


def step(a, name, fn):
    emit = getattr(a, 'api_emit', lambda event: None)
    emit({'t': 'step', 'id': name, 'state': 'start'})
    try:
        result = fn()
    except Exception:
        emit({'t': 'step', 'id': name, 'state': 'fail'})
        raise
    emit({'t': 'step', 'id': name, 'state': 'done'})
    return result


def user(a, argv, directory, timeout=600):
    rc, out, err = a.run_as_gaia(argv, cwd=directory, timeout=timeout, capture=True)
    if rc:
        # Commands may contain private repository URLs; redact before surfacing.
        raise a.ServiceOpError(a.redact_repo_url((err or out or 'Command failed')[-2000:]))
    return out.strip()


def dependencies(a, s, recreate=False):
    directory, _ = paths(a, s)
    if s['runtime'] == 'docker':
        if not os.path.isfile(os.path.join(directory, 'Dockerfile')):
            raise ValueError('Docker runtime requires a Dockerfile in the repository root; Compose is unsupported')
        argv = ['docker', 'build'] + (['--no-cache'] if recreate else []) + ['-t', 'ats-' + s['name'] + ':latest', '.']
        user(a, argv, directory, timeout=1800)
    elif s['runtime'] == 'node':
        if not os.path.isfile(os.path.join(directory, 'package.json')):
            raise ValueError('Node runtime requires package.json')
        user(a, ['npm', 'ci' if os.path.isfile(os.path.join(directory, 'package-lock.json')) else 'install', '--omit=dev'], directory)
    else:
        venv = os.path.join(directory, 'venv')
        if not os.path.isfile(os.path.join(venv, 'bin', 'python')):
            user(a, ['python3', '-m', 'venv', venv], directory)
        python = os.path.join(venv, 'bin', 'python')
        req = os.path.join(directory, 'requirements.txt')
        if os.path.isfile(req):
            user(a, [python, '-m', 'pip', 'install', '-r', req], directory)
        user(a, [python, '-m', 'pip', 'install', 'gunicorn', 'flask'], directory)


def sql(a, statement, values=()):
    with contextlib.closing(sqlite3.connect(a.DB_FILE, timeout=30)) as connection:
        with connection:
            connection.execute('PRAGMA foreign_keys=ON')
            connection.execute(statement, values)


@contextlib.contextmanager
def global_lock(a):
    # Domain/port uniqueness and Cloudflare writes must be serialized across services.
    with open(os.path.join(a.ATS_HOME, 'manage.lock'), 'a') as lock:
        os.chmod(lock.name, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise a.ServiceBusyError('Another deployment or configuration change is running')
        yield


def validate(a, args, current=None):
    import ats_api
    settings = ats_api.run(a, 'settings.get', {})
    s = dict(current or {})
    defaults = settings['defaults']
    for key in ('runtime', 'branch', 'workers', 'max_memory_mb', 'cpu_quota', 'container_port'):
        s.setdefault(key, defaults[key])
    s.update(args)
    s['name'] = a.validate_service_name(s.get('name', ''))
    s['repo_url'] = a.validate_git_url(s.get('repo_url', ''))
    s['branch'] = a.validate_branch(s['branch'])
    s['domain'] = a.validate_domain(s.get('domain', ''), exclude_name=s['name'] if current else None)
    if s['runtime'] not in ('python', 'node', 'docker'):
        raise ValueError('runtime must be python, node or docker')
    s['workers'] = a.validate_workers(s['workers'])
    s['max_memory_mb'] = a.validate_memory(s['max_memory_mb'])
    s['cpu_quota'] = a.validate_cpu(s['cpu_quota'])
    port = s.get('port') or ats_api.run(a, 'ports.suggest', {})['port']
    s['port'] = current['port'] if current and port == current['port'] else a.validate_port(str(port))
    cp = s.get('container_port') or 8000
    if isinstance(cp, bool) or not isinstance(cp, int) or not 1 <= cp <= 65535:
        raise ValueError('container_port must be between 1 and 65535')
    s['container_port'] = cp
    if not current:
        s['storage_path'] = a.validate_storage(s.get('storage_root') or settings['storage_root'])
    safe_path(s['storage_path'])
    if 'env' in s:
        environment(s['env'])
    if 'auto_update' in args and not isinstance(args['auto_update'], bool):
        raise ValueError('auto_update must be boolean')
    s['auto_update'] = bool(s.get('auto_update', True))
    return s


def deploy(a, args):
    started = time.time()
    name = a.validate_service_name(args.get('name', ''))
    with global_lock(a), a.service_lock(name):
        if a.db.query('SELECT id FROM services WHERE name=?', (name,), fetch_one=True):
            raise a.ServiceOpError('Service already exists', 'conflict')
        s = validate(a, args)
        directory, database = paths(a, s)
        log_path = os.path.join(getattr(a, 'LOGROTATE_DIR', '/etc/logrotate.d'), 'ats-' + name)
        locations = [directory, database, a._unit_path(name), log_path]
        if any(os.path.lexists(path) for path in locations):
            raise a.ServiceOpError('A service path already exists; resolve it before deploying', 'conflict')
        route_created = False
        import ats_operations as ops
        record = ops.begin(a, s, 'deploy')
        a.audit_log('DEPLOY_START', name, {'runtime': s['runtime']})
        try:
            for parent in (os.path.dirname(directory), os.path.dirname(database)):
                os.makedirs(parent, mode=0o755, exist_ok=True)
            os.makedirs(directory, mode=0o750)
            os.makedirs(database, mode=0o750)
            for path in (directory, database):
                shutil.chown(path, user=a.SERVICE_USER, group=a.SERVICE_GROUP)
            step(a, 'clone', lambda: user(a, ['git', 'clone', '--branch', s['branch'], '--single-branch', '--', s['repo_url'], directory], os.path.dirname(directory)))
            logs = os.path.join(directory, 'logs')
            if os.path.lexists(logs):
                if os.path.islink(logs) or not os.path.isdir(logs):
                    raise ValueError('Repository logs path must be a regular directory')
            else:
                os.mkdir(logs, 0o750)
            shutil.chown(logs, user=a.SERVICE_USER, group=a.SERVICE_GROUP)
            write_env(a, s, s.get('env', {}))
            step(a, 'build' if s['runtime'] == 'docker' else 'deps', lambda: dependencies(a, s))
            step(a, 'unit', lambda: atomic(a._unit_path(name), unit(a, s), 0o644))
            logrotate(a, s)
            a.run_root(['systemctl', 'daemon-reload'])
            step(a, 'cloudflare', lambda: a.cloudflare.add_route(s['domain'], s['port']))
            route_created = True
            def start():
                a.run_root(['systemctl', 'enable', name])
                a._systemctl_and_verify('start', name)
            step(a, 'start', start)
            def health():
                if not a.health_check_deployment(name, s['port']):
                    raise a.ServiceOpError('Service failed health checks')
            step(a, 'health', health)
            secret = a.generate_webhook_secret()
            sql(a, '''INSERT INTO services(name,port,domain,storage_path,repo_url,workers,max_memory_mb,cpu_quota,branch,runtime,container_port,auto_update,webhook_secret)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)''', tuple(s[k] for k in ('name','port','domain','storage_path','repo_url','workers','max_memory_mb','cpu_quota','branch','runtime','container_port')) + (int(s.get('auto_update', True)), secret))
            sql(a, 'INSERT INTO deployments(service_name,status,duration_seconds) VALUES (?,?,?)', (name, 'success', time.time()-started))
            ops.finish(a, record, 'success', ops.commit(a,s))
            a.audit_log('DEPLOY_SUCCESS', name)
            return {'name': name, 'url': 'https://' + s['domain'], 'port': s['port'], 'runtime': s['runtime'], 'webhook': {'url': a.webhook_url(name), 'secret': secret}}
        except Exception as error:
            ops.finish(a, record, 'failed', ops.commit(a,s), error)
            for command in (['systemctl','stop',name], ['systemctl','disable',name]):
                try: a.run_root(command)
                except Exception: pass
            if route_created:
                try: a.cloudflare.remove_route(s['domain'])
                except Exception: pass
            for path in locations:
                if os.path.isdir(path) and not os.path.islink(path): shutil.rmtree(path)
                elif os.path.lexists(path): os.unlink(path)
            if s['runtime'] == 'docker':
                for command in (['docker','rm','-f','ats-'+name], ['docker','rmi','ats-'+name+':latest']):
                    try: a.run_root(command)
                    except Exception: pass
            a.run_root(['systemctl','daemon-reload'])
            a.audit_log('DEPLOY_FAILED', name, {'error': a.redact_repo_url(str(error))})
            raise


def update(a, name, s, log=None, rebuild=False, reinstall=False):
    started = time.time()
    directory, _ = paths(a, s)
    with a.service_lock(name):
        import ats_operations as ops
        if user(a, ['git','status','--porcelain','--untracked-files=no'], directory):
            raise a.ServiceOpError('Preserve tracked local changes before updating','conflict')
        before = user(a, ['git', 'rev-parse', 'HEAD'], directory)
        ops.init(a)
        with ops.connection(a) as conn:
            known = conn.execute("SELECT id FROM ops_deployments WHERE name=? AND repository=? AND commit_sha=? AND status='success'",(name,ops.repo_key(a,s),before)).fetchone()
        if not known:
            baseline=ops.begin(a,s,'baseline');ops.finish(a,baseline,'success',before)
        record = ops.begin(a,s,'rebuild' if rebuild else 'dependencies' if reinstall else 'update',before)
        current_branch = user(a, ['git','branch','--show-current'],directory)
        a.audit_log('UPDATE_STARTED', name)
        try:
            # Fetch/reset is the same branch policy used by the webhook and manual updates.
            branch = s.get('branch') or 'main'
            if current_branch != branch:
                user(a,['git','fetch','origin',branch],directory)
                user(a,['git','checkout','-B',branch,'FETCH_HEAD'],directory)
            output = step(a, 'clone', lambda: user(a, ['git', 'pull', '--ff-only', 'origin', s.get('branch') or 'main'], directory))
            unchanged = 'Already up to date' in output or 'Already up-to-date' in output
            if unchanged and not rebuild and not reinstall and s.get('runtime') != 'docker':
                ops.finish(a,record,'success',ops.commit(a,s))
                return {'ok': True, 'status': 'active' if a.check_systemd_active(name) else 'inactive', 'message': 'Already up to date', 'updated': False}
            changed = user(a, ['git','diff','--name-only',before,'HEAD','--','requirements.txt','package.json','package-lock.json'], directory) if before else ''
            if s.get('runtime') == 'docker' or changed or reinstall or rebuild:
                step(a, 'build' if s.get('runtime') == 'docker' else 'deps', lambda: dependencies(a, s, recreate=reinstall))
            step(a, 'start', lambda: a._systemctl_and_verify('restart', name))
            def health():
                if not a.health_check_deployment(name, s['port']):
                    raise a.ServiceOpError('Service failed health checks after update')
            step(a,'health',health)
            ops.finish(a,record,'success',ops.commit(a,s))
            sql(a, 'INSERT INTO deployments(service_name,status,duration_seconds) VALUES (?,?,?)', (name,'success',time.time()-started))
            a.audit_log('UPDATE', name)
            return {'ok': True, 'status': 'active', 'message': 'Service restarted with new code', 'updated': True}
        except Exception as error:
            ops.finish(a,record,'failed',ops.commit(a,s),error)
            sql(a, 'INSERT INTO deployments(service_name,status,duration_seconds,error_message) VALUES (?,?,?,?)', (name,'failed',time.time()-started,a.redact_repo_url(str(error))))
            a.audit_log('UPDATE_FAILED', name, {'error': a.redact_repo_url(str(error))})
            raise


def configure(a, args):
    name = args['name']
    with global_lock(a), a.service_lock(name):
        old = row(a, name)
        if 'runtime' in args: raise a.ServiceOpError('Runtime cannot be changed in place', 'unsupported')
        allowed = {'name','domain','port','repo_url','branch','workers','max_memory_mb','cpu_quota','container_port','env','auto_update'}
        if set(args)-allowed: raise ValueError('Unknown configuration field')
        new = validate(a, args, old)
        directory, _ = paths(a, new)
        files = [a._unit_path(name), os.path.join(directory,'.ats.env'), os.path.join(directory,'.ats.docker.env')]
        snapshots = {p: open(p,'rb').read() if os.path.isfile(p) else None for p in files}
        with open(a.CLOUDFLARE_CONFIG,'rb') as stream: routes = stream.read()
        restart = any(k in args and args[k] != old.get(k) for k in ('port','workers','max_memory_mb','cpu_quota','container_port','env'))
        columns = ('domain','port','repo_url','branch','workers','max_memory_mb','cpu_quota','container_port','auto_update')
        active = a.check_systemd_active(name)
        try:
            if new['repo_url'] != old['repo_url']: user(a,['git','remote','set-url','origin',new['repo_url']],directory)
            if 'env' in args: write_env(a, new, args['env'])
            atomic(a._unit_path(name), unit(a,new), 0o644)
            if new['domain'] != old['domain']: a.cloudflare.remove_route(old['domain'])
            if new['domain'] != old['domain'] or new['port'] != old['port']: a.cloudflare.add_route(new['domain'],new['port'])
            a.run_root(['systemctl','daemon-reload'])
            if restart and active: a._systemctl_and_verify('restart',name)
            sql(a, 'UPDATE services SET '+','.join(k+'=?' for k in columns)+',updated_at=CURRENT_TIMESTAMP WHERE name=?', tuple(new[k] for k in columns)+(name,))
            a.audit_log('CONFIG_UPDATE', name, {'fields': sorted(set(args)-{'name'})})
        except Exception:
            if new['repo_url'] != old['repo_url']:
                try: user(a,['git','remote','set-url','origin',old['repo_url']],directory)
                except Exception: pass
            for path, data in snapshots.items():
                if data is None:
                    if os.path.lexists(path): os.unlink(path)
                else:
                    atomic(path, data.decode(), 0o644 if path.endswith('.service') else 0o600)
                    if not path.endswith('.service'): shutil.chown(path,user=a.SERVICE_USER,group=a.SERVICE_GROUP)
            atomic(a.CLOUDFLARE_CONFIG, routes.decode())
            try:
                a.restart_cloudflared_resilient()
                a.run_root(['systemctl','daemon-reload'])
                if active: a._systemctl_and_verify('restart',name)
            except Exception: pass
            raise
        import ats_api
        detail = ats_api.run(a,'services.get',{'name':name})
        detail['restarted'] = restart and active
        return detail


def cloudflare(a, op, args):
    with global_lock(a):
        with open(a.CLOUDFLARE_CONFIG) as stream: config = a.yaml.safe_load(stream)
        if not isinstance(config, dict) or not isinstance(config.get('ingress'), list): raise ValueError('Invalid Cloudflare ingress config')
        services = [dict(s) for s in a.db.query('SELECT * FROM services',fetch_all=True)]
        owners = {s['domain']:s for s in services}
        routes = []
        for entry in config['ingress']:
            owner = owners.get(entry.get('hostname'))
            routes.append(dict(entry, owner=owner['name'] if owner else None, ok=bool(owner and entry.get('service') in (f'http://localhost:{owner["port"]}',f'http://127.0.0.1:{owner["port"]}'))))
        if op == 'cloudflare.status':
            return {'service':a.CLOUDFLARED_SERVICE,'active':a.check_systemd_active(a.CLOUDFLARED_SERVICE),'config_path':a.CLOUDFLARE_CONFIG,'routes':routes,'missing':[s['name'] for s in services if not any(r.get('hostname')==s['domain'] for r in routes)],'orphans':[]}
        if op == 'cloudflare.restart':
            a.restart_cloudflared_resilient(); a.audit_log('CLOUDFLARE_RESTART','SYSTEM')
            return {'active':a.check_systemd_active(a.CLOUDFLARED_SERVICE)}
        if args.get('remove_orphans'):
            # Unowned routes cannot be distinguished from unrelated applications.
            raise a.ServiceOpError('Unowned routes need manual review; automatic removal is unavailable','unsupported')
        added, fixed = [], []
        for s in services:
            found = next((r for r in routes if r.get('hostname')==s['domain']),None)
            if not found or not found['ok']:
                a.cloudflare.add_route(s['domain'],s['port'])
                (fixed if found else added).append(s['domain'])
        a.audit_log('CLOUDFLARE_SYNC','SYSTEM',{'added':added,'fixed':fixed})
        return {'added':added,'fixed':fixed,'removed':[]}


GONE = re.compile(r'not loaded|not-found|not found|does not exist|no such (file|unit|container|image)|could not be found|unknown (unit|container)', re.I)
MISSING = object()


def tolerant(argv, what, timeout=60):
    """Run one cleanup command. Success and "already gone" both mean done.

    Returns None when done, MISSING when the program is not installed, otherwise a short reason.
    """
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f'{what} timed out after {timeout}s'
    except FileNotFoundError:
        return MISSING
    except OSError as exc:
        return f'{what} failed: {exc.strerror or exc}'
    if result.returncode == 0:
        return None
    text = (result.stderr or result.stdout or '').strip()
    return None if GONE.search(text) else f'{what} failed: {text[-300:]}'


def delete(a, args):
    """Delete a service as a series of idempotent steps.

    Every step may be repeated, so an interrupted or partly failed delete is finished by simply running it
    again. Cleanup that cannot matter for the outcome (a stopped container, a missing unit, a Cloudflare
    route that cannot be edited right now) is reported as a warning instead of blocking the delete.
    """
    name = a.validate_service_name(args['name'])
    if args.get('confirm') != name: raise ValueError('Type the service name to confirm deletion')
    warnings = []
    log = getattr(a, 'api_log', lambda message, level='info': None)

    def warn(message):
        warnings.append(message)
        log(message, 'warn')

    with global_lock(a), a.service_lock(name):
        s = row(a, name)
        directory, database = paths(a, s)
        if args.get('backup_first'):
            def backup():
                if not a.create_local_backup(s): raise a.ServiceOpError('Backup failed; nothing was deleted')
            step(a, 'backup', backup)

        def stop():
            problem = tolerant(['systemctl', 'stop', name], 'Stopping ' + name, 120)
            if problem is MISSING: raise a.ServiceOpError('systemctl is not available on this server')
            if problem: raise a.ServiceOpError(problem)
            if a.check_systemd_active(name): raise a.ServiceOpError(name + ' is still running after the stop request; nothing else was deleted')
        step(a, 'stop', stop)

        def disable():
            problem = tolerant(['systemctl', 'disable', name], 'Disabling ' + name)
            if problem and problem is not MISSING: warn(problem)
        step(a, 'disable', disable)

        def route():
            try:
                a.cloudflare.remove_route(s['domain'])
            except Exception as exc:
                warn(f"The Cloudflare route for {s['domain']} was not removed ({str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__}). "
                     'The service is deleted anyway; run Cloudflare sync or edit the tunnel config to drop the route.')
        step(a, 'cloudflare', route)

        if s['runtime'] == 'docker':
            def container():
                if not shutil.which('docker'):
                    warn('Docker is not installed on this server, so the container and image could not be removed (there is nothing to remove if it never ran).')
                    return
                for command in (['docker', 'rm', '-f', 'ats-' + name], ['docker', 'rmi', 'ats-' + name + ':latest']):
                    problem = tolerant(command, ' '.join(command[:2]), 120)
                    if problem and problem is not MISSING: warn(problem)
            step(a, 'container', container)

        def units():
            for path in (a._unit_path(name), os.path.join(getattr(a, 'LOGROTATE_DIR', '/etc/logrotate.d'), 'ats-' + name)):
                try:
                    if os.path.lexists(path): os.unlink(path)
                except OSError as exc:
                    raise a.ServiceOpError(f'Could not remove {path}: {exc.strerror}')
        step(a, 'unit', units)

        if args.get('delete_files', True):
            def files():
                for path in (directory, database):
                    if os.path.islink(path): raise ValueError('Refusing to delete a symlinked service path')
                    if os.path.isdir(path):
                        try:
                            shutil.rmtree(path)
                        except OSError as exc:
                            raise a.ServiceOpError(f'Could not delete {path}: {exc.strerror}. Fix the permissions or close what is using it, then run the delete again.')
            step(a, 'files', files)

        if args.get('delete_backups', False):
            def backups():
                for backup in a.db.query('SELECT * FROM backups WHERE service_name=?', (name,), fetch_all=True):
                    filename = backup['filename']
                    if os.path.basename(filename) != filename: raise ValueError('Invalid backup record')
                    done = True
                    if backup['location'] == 'gdrive':
                        problem = tolerant(['rclone', 'deletefile', a.GDRIVE_FOLDER + '/' + name + '/' + filename], 'Drive backup ' + filename, 120)
                        if problem is MISSING:
                            warn(f'rclone is not installed, so the Google Drive backup {filename} was kept (its record stays so you can delete it later).')
                            done = False
                        elif problem:
                            warn(problem + ' (record kept)')
                            done = False
                    else:
                        path = backup['local_path'] or os.path.join(a.BACKUP_DIR, filename)
                        if os.path.islink(path): raise ValueError('Refusing a symlinked backup')
                        try:
                            if os.path.isfile(path): os.unlink(path)
                        except OSError as exc:
                            warn(f'Could not delete backup {filename}: {exc.strerror} (record kept)')
                            done = False
                    if done: sql(a, 'DELETE FROM backups WHERE id=?', (backup['id'],))
            step(a, 'backups', backups)

        def record():
            # Backup records not deleted above are kept on purpose.
            with contextlib.closing(sqlite3.connect(a.DB_FILE)) as conn:
                with conn: conn.execute('DELETE FROM services WHERE name=?', (name,))
        step(a, 'record', record)

        def reload():
            problem = tolerant(['systemctl', 'daemon-reload'], 'systemctl daemon-reload')
            if problem and problem is not MISSING: warn(problem)
        step(a, 'reload', reload)
        a.audit_log('SERVICE_DELETE', name, {'warnings': len(warnings)})
        return {'deleted': True, 'warnings': warnings}



# ── Cloudflare tunnel config file: read and edit safely ──
CF_MAX = 512 * 1024
CF_BACKUP = re.compile(r'\.bak-\d{8}-\d{6}\Z')
CF_BACKUP_NAME = re.compile(r'[A-Za-z0-9._-]{1,120}\.bak-\d{8}-\d{6}\Z')


def cloudflare_backups(path, yaml):
    """Timestamped copies the editor made next to the config, newest first, with what each one routes."""
    folder, base, found = os.path.dirname(path), os.path.basename(path), []
    try: names = os.listdir(folder)
    except OSError: return []
    for name in sorted(names, reverse=True):
        if not (name.startswith(base + '.bak-') and CF_BACKUP.search(name)): continue
        full = os.path.join(folder, name)
        try:
            info = os.lstat(full)
            if not stat.S_ISREG(info.st_mode) or info.st_size > CF_MAX: continue
            with open(full, 'rb') as stream: data = stream.read()
        except OSError: continue
        hosts = []
        try:
            config = yaml.safe_load(data.decode('utf-8', 'replace')) or {}
            hosts = sorted({rule.get('hostname') for rule in config.get('ingress', []) if isinstance(rule, dict) and rule.get('hostname')})
        except Exception: pass
        found.append({'name': name, 'at': int(info.st_mtime), 'size': info.st_size, 'sha256': hashlib.sha256(data).hexdigest(), 'hostnames': hosts[:50]})
    return found


def cloudflare_file(a, op, args):
    """Read or replace the configured tunnel config. Only the path in ATS's own settings is ever touched.

    A change is validated (YAML shape plus `cloudflared ingress validate` when installed), the previous file is
    kept as a timestamped backup, the write is atomic and keeps owner and mode, and if cloudflared will not
    start with the new file the previous one is put back.
    """
    path = os.path.realpath(a.CLOUDFLARE_CONFIG)
    warnings = []
    with global_lock(a):
        try:
            with open(path, 'rb') as stream: raw = stream.read(CF_MAX + 1)
        except FileNotFoundError:
            raw = None
        except OSError as exc:
            raise a.ServiceOpError(f'Cannot read {path}: {exc.strerror}')
        if raw is not None and len(raw) > CF_MAX: raise ValueError('The Cloudflare config is larger than 512 KiB')
        digest = hashlib.sha256(raw or b'').hexdigest()
        services = [dict(x) for x in a.db.query('SELECT * FROM services', fetch_all=True)]
        if op == 'cloudflare.config.get':
            return {'path': a.CLOUDFLARE_CONFIG, 'exists': raw is not None, 'content': (raw or b'').decode('utf-8', 'replace'),
                    'sha256': digest, 'service': a.CLOUDFLARED_SERVICE, 'active': a.check_systemd_active(a.CLOUDFLARED_SERVICE),
                    'validator': bool(shutil.which('cloudflared'))}
        if op == 'cloudflare.config.backups':
            return {'path': a.CLOUDFLARE_CONFIG, 'backups': cloudflare_backups(path, a.yaml)}
        content, base, restart = args.get('content'), args.get('base_sha256'), args.get('restart', True)
        restored = None
        if op == 'cloudflare.config.restore':
            restored = args.get('name')
            if not isinstance(restored, str) or not CF_BACKUP_NAME.fullmatch(restored) or not restored.startswith(os.path.basename(path) + '.bak-'):
                raise ValueError('Choose one of the listed backups')
            try:
                descriptor = os.open(os.path.join(os.path.dirname(path), restored), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                with os.fdopen(descriptor, 'rb') as stream:
                    if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): raise ValueError('Choose one of the listed backups')
                    content = stream.read(CF_MAX + 1).decode('utf-8')
            except FileNotFoundError:
                raise a.ServiceOpError('That backup no longer exists. Reload the list.', 'conflict')
            except (OSError, UnicodeDecodeError) as exc:
                raise a.ServiceOpError('That backup cannot be read' + (f': {exc.strerror}' if isinstance(exc, OSError) else ' as text'))
        if not isinstance(content, str) or '\x00' in content: raise ValueError('content must be text')
        if not isinstance(base, str) or not re.fullmatch('[0-9a-f]{64}', base): raise ValueError('base_sha256 is required')
        if not isinstance(restart, bool): raise ValueError('restart must be true or false')
        text = content.replace('\r\n', '\n')
        text = text if text.endswith('\n') else text + '\n'
        if len(text.encode()) > CF_MAX: raise ValueError('The Cloudflare config is larger than 512 KiB')
        if base != digest:
            raise a.ServiceOpError('The file changed on the server after you opened it. Reload it and apply your edit again.', 'conflict')
        try:
            before = a.yaml.safe_load((raw or b'').decode('utf-8', 'replace')) or {}
        except a.yaml.YAMLError:
            before = {}

        def validate():
            try:
                config = a.yaml.safe_load(text)
            except a.yaml.YAMLError as exc:
                raise ValueError('Not valid YAML: ' + (str(exc).splitlines() or ['parse error'])[0][:200])
            if not isinstance(config, dict): raise ValueError('The file must be a YAML mapping')
            ingress = config.get('ingress')
            if not isinstance(ingress, list) or not ingress or any(not isinstance(rule, dict) for rule in ingress):
                raise ValueError('ingress must be a non-empty list of rules')
            last = ingress[-1]
            if last.get('hostname') or last.get('path') or not last.get('service'):
                raise ValueError('The last ingress rule must be a catch-all with only a service, for example "service: http_status:404"')
            if any(not rule.get('service') for rule in ingress[:-1]): raise ValueError('Every ingress rule needs a service')
            if isinstance(before, dict):
                for key in ('tunnel', 'credentials-file'):
                    if before.get(key) and not config.get(key): raise ValueError(f'"{key}" must not be removed: the tunnel could not start')
            if shutil.which('cloudflared'):
                with tempfile.TemporaryDirectory(prefix='ats-cf-') as scratch:
                    candidate = os.path.join(scratch, 'config.yml')
                    atomic(candidate, text)
                    result = subprocess.run(['cloudflared', 'tunnel', '--config', candidate, 'ingress', 'validate'], capture_output=True, text=True, timeout=30)
                    if result.returncode:
                        lines = [line for line in (result.stderr or result.stdout).strip().splitlines() if line.strip()]
                        raise ValueError('cloudflared rejected the config: ' + (lines[-1][:240] if lines else 'validation failed'))
            else:
                warnings.append('cloudflared is not installed here, so only the YAML structure was checked.')
            return config
        config = step(a, 'validate', validate)

        saved = {}

        def backup():
            if raw is None: return
            stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
            saved['backup'] = f'{path}.bak-{stamp}'
            atomic(saved['backup'], raw.decode('utf-8', 'replace'))
            old = sorted(name for name in os.listdir(os.path.dirname(path)) if name.startswith(os.path.basename(path)) and CF_BACKUP.search(name))
            for name in old[:-10]:
                try: os.unlink(os.path.join(os.path.dirname(path), name))
                except OSError: pass
        step(a, 'backup', backup)

        def replace(data):
            info = os.stat(path) if raw is not None else None
            handle, temporary = tempfile.mkstemp(prefix='.ats-cf-', dir=os.path.dirname(path))
            try:
                with os.fdopen(handle, 'wb') as stream:
                    os.fchmod(stream.fileno(), info.st_mode & 0o7777 if info else 0o600)
                    if info: os.fchown(stream.fileno(), info.st_uid, info.st_gid)
                    stream.write(data); stream.flush(); os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                if os.path.exists(temporary): os.unlink(temporary)
        try:
            step(a, 'write', lambda: replace(text.encode()))
        except OSError as exc:
            raise a.ServiceOpError(f'Could not write {path}: {exc.strerror}')

        restarted = False
        if restart:
            def bring_up():
                try:
                    a.restart_cloudflared_resilient()
                except Exception as exc:
                    try:
                        if raw is None: os.unlink(path)
                        else: replace(raw)
                        a.restart_cloudflared_resilient(max_attempts=1, poll_timeout=15)
                    except Exception:
                        pass
                    first = (str(exc).splitlines() or [type(exc).__name__])[0][:200]
                    raise a.ServiceOpError(f'cloudflared did not start with the new config, so the previous file was restored ({first})')
            step(a, 'restart', bring_up)
            restarted = True
        else:
            warnings.append('The file was saved but cloudflared was not restarted, so the running tunnel still uses the old routes.')
        routes = {rule.get('hostname') for rule in config['ingress'] if isinstance(rule, dict)}
        a.audit_log('CLOUDFLARE_CONFIG_RESTORE' if restored else 'CLOUDFLARE_CONFIG_EDIT', 'SYSTEM',
                    dict({'bytes': len(text.encode()), 'restarted': restarted}, **({'from': restored} if restored else {})))
        return {'saved': True, 'restored': restored, 'restarted': restarted, 'backup': saved.get('backup'), 'sha256': hashlib.sha256(text.encode()).hexdigest(),
                'missing_routes': sorted(x['domain'] for x in services if x['domain'] not in routes), 'warnings': warnings}


# ── installing the tools ATS can use but does not require ──
# The package manager never runs with an inherited PATH (ATS runs as root); tests point this at fakes.
SAFE_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
INSTALLABLE = {
    'docker': {'binary': 'docker', 'apt': ['docker.io'], 'dnf': ['docker'], 'label': 'Docker'},
    'rclone': {'binary': 'rclone', 'apt': ['rclone'], 'dnf': ['rclone'], 'label': 'rclone'},
}


def package_manager():
    for manager, binary in (('apt', 'apt-get'), ('dnf', 'dnf')):
        if shutil.which(binary): return manager
    return None


def install_dependency(a, args):
    """Install Docker or rclone from the distribution's own packages. Nothing is downloaded or run from the internet."""
    name = args.get('name')
    if not isinstance(name, str) or name not in INSTALLABLE: raise ValueError('Only docker and rclone can be installed from here')
    spec = INSTALLABLE[name]
    log = getattr(a, 'api_log', lambda message, level='info': None)
    warnings = []
    with global_lock(a):
        if shutil.which(spec['binary']):
            return {'installed': False, 'already': True, 'name': name, 'warnings': []}
        manager = package_manager()
        if not manager:
            raise a.ServiceOpError(f"No supported package manager (apt or dnf) was found. Install {spec['label']} on this server manually.", 'unsupported')
        packages = spec[manager]
        env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', LC_ALL='C', PATH=SAFE_PATH)

        def stream(argv, timeout):
            tail = collections.deque(maxlen=12)
            process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, env=env)
            timer = threading.Timer(timeout, process.kill)
            timer.start()
            try:
                for line in process.stdout:
                    line = line.rstrip()
                    if line:
                        tail.append(line[:200])
                        if not line.startswith(('Reading', 'Building', '(Reading')): log(line[:200])
                code = process.wait()
            finally:
                timer.cancel()
            if code:
                if any('lock' in line.lower() for line in tail):
                    raise a.ServiceOpError('The package manager is busy (another update is running). Try again in a few minutes.', 'busy')
                raise a.ServiceOpError(f'{argv[0]} failed (exit {code}): ' + ' | '.join(list(tail)[-3:]))

        if manager == 'apt':
            step(a, 'prepare', lambda: stream(['apt-get', 'update', '-qq'], 300))
        else:
            step(a, 'prepare', lambda: None)
        install = ['apt-get', 'install', '-y', '--no-install-recommends'] if manager == 'apt' else ['dnf', 'install', '-y']
        step(a, 'install', lambda: stream(install + packages, 1500))
        if name == 'docker':
            def enable():
                problem = tolerant(['systemctl', 'enable', '--now', 'docker'], 'Starting the Docker service', 120)
                if problem and problem is not MISSING: warnings.append(problem)
            step(a, 'enable', enable)

            def access():
                problem = tolerant(['usermod', '-aG', 'docker', a.SERVICE_USER], f'Giving {a.SERVICE_USER} access to Docker')
                if problem and problem is not MISSING: warnings.append(problem)
            step(a, 'access', access)

        def verify():
            if not shutil.which(spec['binary']): raise a.ServiceOpError(f"{spec['label']} was installed but is not on the PATH")
            result = subprocess.run([spec['binary'], '--version'], capture_output=True, text=True, timeout=20)
            return (result.stdout or result.stderr).strip().splitlines()[0][:200] if (result.stdout or result.stderr).strip() else ''
        version = step(a, 'verify', verify)
        a.audit_log('DEPENDENCY_INSTALL', 'SYSTEM', {'name': name, 'version': version})
        next_step = ("Configure the Google Drive remote on this server with `rclone config` (name it the remote ATS expects)."
                     if name == 'rclone' else f"Docker is running and {a.SERVICE_USER} was added to the docker group.")
        return {'installed': True, 'name': name, 'version': version, 'next': next_step, 'warnings': warnings}


def run(a, op, args):
    if op not in {'cloudflare.config.get','cloudflare.config.set','cloudflare.config.backups','cloudflare.config.restore','system.install','cloudflare.status','cloudflare.sync','cloudflare.restart','services.deploy','services.delete','services.config.set','services.resources','services.action','webhook.test','services.redeploy'}:
        raise a.ServiceOpError('Unsupported operation','unsupported')
    if op in ('cloudflare.config.get','cloudflare.config.set','cloudflare.config.backups','cloudflare.config.restore'): return cloudflare_file(a,op,args)
    if op=='system.install': return install_dependency(a,args)
    if op.startswith('cloudflare.'): return cloudflare(a,op,args)
    if op=='services.deploy': return deploy(a,args)
    if op=='services.delete': return delete(a,args)
    if op=='services.config.set': return configure(a,args)
    s=row(a,args.get('name','')); name=s['name']
    if op=='services.resources':
        usage=a.service_resource_usage(name,s)
        uptime = 0
        if usage.get('pid') and a.psutil:
            try: uptime = max(0,time.time()-a.psutil.Process(usage['pid']).create_time())
            except Exception: pass
        return {'cpu_pct':usage.get('cpu_percent',0),'mem_mb':usage.get('memory_mb',0),'mem_limit_mb':s['max_memory_mb'],'pids':1+usage.get('children',0) if usage.get('running') else 0,'uptime_s':uptime,'limits':{k:s[k] for k in ('workers','max_memory_mb','cpu_quota')}}
    if op=='services.action':
        action=args.get('action')
        if action in ('start','stop','restart'): return getattr(a,'service_'+action)(name,s,log=getattr(a,'api_log',a._logger_log))
        if action in ('update','rebuild','reinstall_deps'): return update(a,name,s,rebuild=action=='rebuild',reinstall=action=='reinstall_deps')
        raise ValueError('Invalid service action')
    if op=='webhook.test':
        event = a.record_webhook_event(name, 'test', 'refs/heads/'+s['branch'], None, 'accepted', 'Manual test')
        try:
            update(a,name,s)
            a.update_webhook_event(event, 'updated', 'Manual test completed')
        except Exception as error:
            a.update_webhook_event(event, 'failed', a.redact_repo_url(str(error)))
            raise
        return {'ok':True,'status':200,'message':'Service updated through the webhook update path'}
    if op=='services.redeploy':
        # Stage the replacement checkout; the old code is retained until the new
        # service has passed health checks, then removed.
        repo=a.validate_git_url(args.get('repo_url','')); branch=a.validate_branch(args.get('branch') or s['branch'])
        with global_lock(a), a.service_lock(name):
            directory,_=paths(a,s)
            staging=tempfile.mkdtemp(prefix='.ats-redeploy-',dir=os.path.dirname(directory))
            saved=staging+'-previous'
            moved=False
            import ats_operations as ops
            replacement=dict(s,repo_url=repo,branch=branch)
            record=ops.begin(a,replacement,'redeploy',ops.commit(a,s))
            try:
                shutil.chown(staging,user=a.SERVICE_USER,group=a.SERVICE_GROUP)
                user(a,['git','clone','--branch',branch,'--single-branch','--',repo,staging],os.path.dirname(directory))
                a._systemctl('stop',name)
                os.rename(directory,saved); moved=True
                os.rename(staging,directory)
                for filename in ('.ats.env','.ats.docker.env'):
                    src=os.path.join(saved,filename)
                    if os.path.isfile(src):
                        with open(src) as source: atomic(os.path.join(directory,filename),source.read())
                    else: atomic(os.path.join(directory,filename),'')
                    shutil.chown(os.path.join(directory,filename),user=a.SERVICE_USER,group=a.SERVICE_GROUP)
                logs=os.path.join(directory,'logs')
                if os.path.lexists(logs):
                    if os.path.islink(logs) or not os.path.isdir(logs): raise ValueError('Invalid repository logs directory')
                else: os.mkdir(logs,0o750)
                shutil.chown(logs,user=a.SERVICE_USER,group=a.SERVICE_GROUP)
                dependencies(a,s)
                a._systemctl_and_verify('start',name)
                if not a.health_check_deployment(name,s['port']): raise a.ServiceOpError('Replacement failed health check')
                sql(a,'UPDATE services SET repo_url=?,branch=?,updated_at=CURRENT_TIMESTAMP WHERE name=?',(repo,branch,name))
                previous_logs = os.path.join(saved, 'logs')
                if os.path.isdir(previous_logs): shutil.copytree(previous_logs, logs, dirs_exist_ok=True)
                shutil.rmtree(saved); moved=False
                ops.finish(a,record,'success',ops.commit(a,replacement))
                a.audit_log('REDEPLOY',name)
            except Exception as error:
                ops.finish(a,record,'failed',ops.commit(a,replacement),error)
                if moved:
                    if os.path.isdir(directory): shutil.rmtree(directory)
                    os.rename(saved,directory)
                    if s['runtime']=='docker': dependencies(a,s)
                    a._systemctl_and_verify('start',name)
                raise
            finally:
                if os.path.isdir(staging): shutil.rmtree(staging)
        return {'name':name,'url':'https://'+s['domain'],'port':s['port'],'runtime':s['runtime'],'webhook':{'url':a.webhook_url(name),'secret':s['webhook_secret']}}
    raise a.ServiceOpError('Unsupported operation','unsupported')
