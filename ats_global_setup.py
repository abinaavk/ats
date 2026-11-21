"""Explicit, repeatable Global installation using the existing ATS configuration.

Planning is read-only. Applying validates candidates, keeps private backups and
restores files/service state on failure. It never creates a tunnel or DNS record.
"""
import contextlib
import fcntl
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit

import yaml
import ats_cluster
import ats_server_cli as cli

UNIT = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.@-]*\.service\Z')
DEFAULT_MONITOR_DIR = '/opt/ats-monitor'
DEFAULT_MONITOR_REPO = 'https://github.com/abinaavk/ats-monitor.git'
REF = re.compile(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,99}\Z')
MANAGED = '# ATS managed Global setup\n'


def run(argv, *, check=True, env=None, timeout=45):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError('Could not complete '+argv[0]+' '+argv[1]+'; inspect the host locally') from exc
    if check and result.returncode:
        # Tool stderr/configuration can contain tokens. Keep it off the console.
        raise ValueError(argv[0]+' '+argv[1]+' failed; inspect the host locally')
    return result


def unit_name(value):
    value = value if value.endswith('.service') else value+'.service'
    if not UNIT.fullmatch(value):
        raise ValueError('Invalid systemd unit name')
    return value


def properties(unit, runner=run):
    fields = ['LoadState', 'ExecStart', 'Environment', 'EnvironmentFiles', 'FragmentPath',
              'ActiveState', 'UnitFileState', 'MainPID', 'User']
    result = runner(['systemctl', 'show', unit, '--no-pager'] + ['--property='+f for f in fields])
    return dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)


def ats_units(runner):
    """Installed ats*.service files. systemd exits 1 when none match, the normal first-install state."""
    result = runner(['systemctl', 'list-unit-files', 'ats*.service', '--no-legend', '--no-pager'], check=False)
    if result.returncode not in (0, 1) or (result.returncode == 1 and result.stdout.strip() == '' and
                                           'Failed' in (result.stderr or '')):
        raise ValueError('systemctl list-unit-files failed; is systemd running on this host?')
    return [line.split()[0] for line in result.stdout.splitlines() if line.split()]


def snapshot(path):
    path = Path(path)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('Expected an unlinked regular configuration file: '+str(path))
        if info.st_size > 2*1024*1024:
            raise ValueError('Configuration is too large: '+str(path))
        return (stream.read(), stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)


def absolute(value, label):
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError(label+' must be an absolute path')
    cli.unit_quote(value)
    path = Path(value)
    # Refuse symlink ancestors too, including a dangling final component.
    if any(p.is_symlink() for p in [path, *path.parents]):
        raise ValueError(label+' must not traverse symlinks')
    return path


def same_loopback_service(found, port):
    """ATS's own routes use http://localhost:PORT; accept any loopback spelling of the same listener."""
    try:
        parsed = urlsplit(str(found))
        return (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', 'localhost', '::1')
                and parsed.port == port and parsed.path in ('', '/') and not parsed.query)
    except ValueError:
        return False


def api_route(config, hostname, port):
    """Preserve unrelated rules and policy; refuse collisions instead of hijacking."""
    if not isinstance(config, dict) or not config.get('tunnel'):
        raise ValueError('Use an existing locally managed tunnel configuration with a tunnel ID')
    routes = config.get('ingress')
    if (not isinstance(routes, list) or not routes or any(not isinstance(r, dict) for r in routes)
            or routes[-1].get('hostname') or routes[-1].get('path') or not routes[-1].get('service')):
        raise ValueError('Tunnel ingress must end with a catch-all rule')
    desired = {'hostname': hostname, 'path': '^/v1/request$', 'service': f'http://127.0.0.1:{port}'}
    matches = [r for r in routes if str(r.get('hostname', '')).lower() == hostname]
    if len(matches) > 1:
        raise ValueError('Duplicate API hostname routes; resolve them before setup')
    if matches:
        found = matches[0]
        if not same_loopback_service(found.get('service'), port) or found.get('path') not in (None, '', desired['path']):
            raise ValueError('API hostname already routes elsewhere; existing route was preserved')
        # Preserve originRequest/access settings while narrowing an existing API route.
        desired = {**found, **desired}
        index = routes.index(found)
        covering = routes[:index]
    else:
        covering = routes[:-1]
    for rule in covering:
        host = str(rule.get('hostname', '')).lower()
        if not host or host == '*' or (host.startswith('*.') and hostname.endswith(host[1:])):
            raise ValueError('An earlier wildcard/catch-all may cover the API hostname; resolve route order first')
    result = dict(config)
    result['ingress'] = [desired if r is matches[0] else r for r in routes] if matches else routes[:-1]+[desired, routes[-1]]
    return result


def check_tunnel_config(tunnel_props, cf):
    """Confirm the running tunnel really reads the file ATS is about to edit."""
    start = tunnel_props.get('ExecStart', '')
    if '--token' in start or 'TUNNEL_TOKEN' in tunnel_props.get('Environment', ''):
        raise ValueError('Token-managed tunnels are configured in the Cloudflare dashboard; automatic route setup needs a locally managed tunnel with a config file')
    named = re.findall(r'--config[= ]+([^\s;]+)', start)
    if named:
        if not any(Path(item).absolute() == cf for item in named):
            raise ValueError('Cloudflare service reads a different config file ('+named[-1]+'); select it with --cloudflare-config')
        return
    # Without --config, cloudflared reads its default locations; accept only those.
    home = '/root'
    user = tunnel_props.get('User')
    if user:
        try:
            import pwd
            home = pwd.getpwnam(user).pw_dir
        except (KeyError, ImportError):
            pass
    defaults = {Path('/etc/cloudflared/config.yml'), Path('/usr/local/etc/cloudflared/config.yml'),
                Path(home)/'.cloudflared'/'config.yml'}
    if cf not in defaults:
        raise ValueError('Cloudflare service does not name a config file and '+str(cf)+' is not one of cloudflared\'s default locations; select the file the tunnel really reads with --cloudflare-config')


class MonitorMissing(ValueError):
    """No Monitor companion could be located; --install-monitor can supply one."""


def build_plan(store, *, port=None, config_path=None, monitor_adapter=None,
               state_dir=None, unit=None, unit_dir='/etc/systemd/system', runner=run):
    node = store.node()
    if cli.configuration_issues(node) or node['role'] != 'global':
        raise ValueError('Configure this instance as Global first')
    instance = os.environ.get('ATS_INSTANCE', '')
    if instance and not re.fullmatch('[A-Za-z0-9_-]+', instance):
        raise ValueError('Invalid ATS_INSTANCE')
    settings_path = absolute(os.environ.get('ATS_CONFIG_FILE') or
        ('/etc/ats/config-'+instance+'.yml' if instance else '/etc/ats/config.yml'), 'ATS_CONFIG_FILE')
    settings_snapshot = snapshot(settings_path)
    if not settings_snapshot:
        raise ValueError('ATS settings file is missing')
    settings = yaml.safe_load(settings_snapshot[0])
    if not isinstance(settings, dict):
        raise ValueError('ATS settings must contain a mapping')
    checkout = Path(cli.__file__).resolve().parent
    registry = absolute(str(Path(store.path).absolute()), 'ATS_CLUSTER_DB')
    units = [unit_name(unit)] if unit else ats_units(runner)
    candidates = []
    for selected in units:
        unit_name(selected)
        props = properties(selected, runner)
        start = props.get('ExecStart', '')
        if str(checkout/'app.py') in start and '--daemon' in start:
            if props.get('EnvironmentFiles'):
                raise ValueError('Existing daemon uses EnvironmentFile; provide its settings explicitly in the unit before automatic setup')
            env = dict(item.split('=', 1) for item in shlex.split(props.get('Environment', '')) if '=' in item)
            saved_db = env.get('ATS_CLUSTER_DB', '/etc/ats/cluster.sqlite3')
            if Path(saved_db).absolute() == registry:
                candidates.append((selected, props, env))
            elif unit:
                raise ValueError('Selected service uses a different cluster registry')
        elif unit and props.get('LoadState') != 'not-found':
            raise ValueError('Selected service is not this ATS daemon')
    if len(candidates) > 1:
        raise ValueError('Multiple ATS daemons use this registry; resolve duplicate services before setup')
    if candidates:
        selected, props, saved_env = candidates[0]
    else:
        selected = unit_name(unit or 'ats-global-'+node['id'])
        props, saved_env = properties(selected, runner), {}
        if props.get('LoadState') != 'not-found':
            raise ValueError('Destination service already exists and is not this daemon')
    active = props.get('ActiveState') == 'active'
    if props.get('ActiveState') in ('activating', 'deactivating', 'reloading'):
        raise ValueError('Wait for the existing service transition to finish')
    if props.get('UnitFileState') not in ('', None, 'enabled', 'disabled'):
        raise ValueError('Existing service must be enabled or disabled, not masked/static/linked')
    cf = absolute(config_path or os.environ.get('ATS_CLOUDFLARE_CONFIG') or settings.get('cloudflare_config') or
                  next((c for c in ('/etc/cloudflared/config.yml', '/root/.cloudflared/config.yml') if os.path.isfile(c)), None),
                  'Cloudflare config')
    before_cf = snapshot(cf)
    if before_cf is None:
        raise ValueError('Configured Cloudflare file is missing')
    tunnel_unit = unit_name(os.environ.get('ATS_CLOUDFLARED_SERVICE') or settings.get('cloudflared_service') or 'cloudflared')
    tunnel_props = properties(tunnel_unit, runner)
    if tunnel_props.get('ActiveState') != 'active':
        raise ValueError('Existing Cloudflare tunnel service must be active before adding the API route')
    check_tunnel_config(tunnel_props, cf)
    port = int(port if port is not None else os.environ.get('ATS_REMOTE_PORT') or saved_env.get('ATS_REMOTE_PORT') or 9997)
    if not 1 <= port <= 65535:
        raise ValueError('API port must be between 1 and 65535')
    origin = urlsplit(ats_cluster.domain(node['domain']))
    if origin.port not in (None, 443):
        raise ValueError('Automatic tunnel setup requires a standard HTTPS origin on port 443')
    configured_cf = yaml.safe_load(before_cf[0])
    updated_cf = api_route(configured_cf, origin.hostname, port)
    adapter = monitor_adapter or os.environ.get('ATS_MONITOR_ADAPTER') or saved_env.get('ATS_MONITOR_ADAPTER') or settings.get('monitor_adapter')
    if not adapter:
        known = [checkout.parent/'ats-monitor'/'remote_host.py', Path(DEFAULT_MONITOR_DIR)/'remote_host.py',
                 Path('/opt/api/monitor/remote_host.py'), Path('/opt/ats-monitor-server2/remote_host.py')]
        found = [str(p) for p in known if p.is_file()]
        if len(found) != 1:
            raise MonitorMissing('Monitor companion not found. Re-run with --install-monitor to install it into '+DEFAULT_MONITOR_DIR+
                             ', or select an existing copy with --monitor-adapter /absolute/path/remote_host.py')
        adapter = found[0]
    absolute(adapter, 'Monitor adapter')
    state = state_dir or settings.get('global_state_dir') or str(registry.parent/('global-'+node['id']))
    interpreter = sys.executable
    if candidates:
        match = re.search(r'(?:^|[ {])path=([^;]+?)\s*;', props.get('ExecStart', ''))
        if match:
            interpreter = match.group(1).strip()
            if not Path(interpreter).is_absolute() or not Path(interpreter).name.startswith('python'):
                raise ValueError('Existing daemon uses a wrapper; select its Python environment explicitly before setup')
        configured_path = saved_env.get('ATS_CONFIG_FILE')
        if configured_path and Path(configured_path).absolute() != settings_path:
            raise ValueError('Existing daemon uses a different ATS_CONFIG_FILE; run setup with that same file')
    environment = dict(saved_env)
    environment.update(os.environ)
    environment.setdefault('ATS_CLI', shlex.join([interpreter, str(checkout/'app.py')]))
    # Reuse persisted adapter directories on an existing service.
    inherited = state_dir is None and all(environment.get(k) for k in ('ATS_SECURITY_DB', 'ATS_MONITOR_JOBS_DIR'))
    with temporary_environment(environment):
        adapter_env = cli.adapter_environment(store, adapter, None if inherited else state)
        full_unit = cli.service_unit(store, port, monitor_adapter=adapter,
                                     adapter_state_dir=None if inherited else state)
    full_unit = full_unit.replace('ExecStart='+cli.unit_quote(sys.executable).replace('$', '$$')+' ',
                                  'ExecStart='+cli.unit_quote(interpreter).replace('$', '$$')+' ')
    for key in ('ATS_SECURITY_DB', 'ATS_MONITOR_JOBS_DIR'):
        absolute(adapter_env[key], key)
    # Pin tunnel settings too so service operations use the same selected config.
    extra_env = ''.join('Environment='+cli.unit_quote(k+'='+v)+'\n' for k,v in {
        'ATS_CLOUDFLARE_CONFIG':str(cf), 'ATS_CLOUDFLARED_SERVICE':tunnel_unit.removesuffix('.service')}.items())
    full_unit = MANAGED+full_unit.replace('[Service]\n', '[Service]\n'+extra_env)
    directory = absolute(unit_dir, 'systemd unit directory')
    own_unit = snapshot(directory/selected)
    if candidates and not (own_unit and own_unit[0].startswith(MANAGED.encode())):
        destination = directory/(selected+'.d')/'60-ats-global.conf'
        service_section = full_unit.split('[Service]\n', 1)[1].split('\n[Install]', 1)[0]
        unit_content = MANAGED+'[Unit]\nWants=network-online.target\nAfter=network-online.target\nStartLimitIntervalSec=0\n[Service]\nExecStart=\n'+service_section+'\n'
    else:
        destination, unit_content = directory/selected, full_unit+'\n'
    absolute(str(destination), 'Service destination')
    before_unit = snapshot(destination)
    if before_unit and not before_unit[0].startswith(MANAGED.encode()):
        raise ValueError('Managed destination is occupied; existing file was preserved')
    return dict(node=node, port=port, settings_path=settings_path, settings_snapshot=settings_snapshot,
                registry=registry, cf=cf, before_cf=before_cf,
                cf_content=(before_cf[0] if updated_cf == configured_cf else yaml.safe_dump(updated_cf, sort_keys=False).encode()),
                unit=selected, destination=destination, before_unit=before_unit,
                unit_content=unit_content.encode(), full_unit=full_unit,
                tunnel_unit=tunnel_unit, active=active, enabled=props.get('UnitFileState')=='enabled',
                adapter_env=adapter_env, existing=bool(candidates), interpreter=interpreter,
                daemon_env={k: v for k, v in {'ATS_CONFIG_FILE': str(settings_path), 'ATS_CLUSTER_DB': str(registry),
                                               'ATS_INSTANCE': instance, 'ATS_REMOTE_PORT': str(port)}.items() if v})


@contextlib.contextmanager
def temporary_environment(values):
    old = dict(os.environ)
    try:
        os.environ.clear(); os.environ.update(values)
        yield
    finally:
        os.environ.clear(); os.environ.update(old)


def public_plan(plan):
    return {'service':plan['unit'], 'reuse_existing_service':plan['existing'],
            'service_file':str(plan['destination']), 'cloudflare_config':str(plan['cf']),
            'cloudflare_service':plan['tunnel_unit'], 'api_origin':plan['node']['domain'],
            'loopback_port':plan['port'], 'adapter':plan['adapter_env']['ATS_MONITOR_ADAPTER'],
            'service_change':plan['before_unit'] is None or plan['before_unit'][0]!=plan['unit_content'],
            'route_change':plan['before_cf'][0]!=plan['cf_content']}


def private_directory(path):
    path = absolute(str(path), 'Private state directory')
    missing = []
    current = path
    while not current.exists():
        missing.append(current);current = current.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
    info = path.stat()
    if not path.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('Private state directory must be owned by root with mode 0700: '+str(path))


def replace_file(path, data, mode=0o600, owner=None):
    absolute(str(path), 'Configuration destination')
    fd, tmp = tempfile.mkstemp(prefix='.ats-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            if owner is not None:
                os.fchown(stream.fileno(), *owner)
            stream.write(data);stream.flush();os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


def verify_health(plan, *, public=False, management=False):
    payload = {'kind':'http', 'method':'GET', 'path':'/api/manage/services'} if management else {'kind':'health'}
    node = plan['node']
    if public:
        result = ats_cluster.remote(dict(node, local=0, connected=1), payload, timeout=65 if management else 8)
    else:
        body = json.dumps(payload, separators=(',', ':')).encode()
        connection = http.client.HTTPConnection('127.0.0.1', plan['port'], timeout=65 if management else 3)
        try:
            connection.request('POST', '/v1/request', body, ats_cluster.signed_headers(node['secret'],node['id'],body))
            response = connection.getresponse();raw = response.read(ats_cluster.MAX_OUTPUT+1)
            if response.status != 200 or len(raw)>ats_cluster.MAX_OUTPUT:
                raise ValueError('Signed loopback health failed')
            envelope = json.loads(raw)
            if envelope.get('ok') is not True or envelope.get('server_id') != node['id']:
                raise ValueError('Loopback identity mismatch')
            result = envelope.get('data', {})
        finally:
            connection.close()
    if not isinstance(result, dict):
        raise ValueError('Invalid signed response')
    if management:
        if result.get('status') != 200 or not isinstance(result.get('body'), dict) or result['body'].get('ok') is not True:
            raise ValueError('Global adapter service read failed')
        return
    if result.get('server_id') != node['id'] or result.get('role')!='global' or result.get('management_ready') is not True:
        raise ValueError('Global management readiness or identity check failed')


def adapter_check(plan, runner=run):
    """Run the companion's self-check exactly as the daemon will run it, in scratch state.

    Failing here means no file has been changed yet, and the operator is told the
    precise missing module or setting instead of an opaque HTTP 502 later.
    """
    adapter = plan['adapter_env']['ATS_MONITOR_ADAPTER']
    with tempfile.TemporaryDirectory(prefix='ats-adapter-check-') as scratch:
        env = {k: os.environ[k] for k in ('PATH', 'HOME', 'LANG', 'LC_ALL') if k in os.environ}
        env.update(plan['daemon_env'])
        env.update(plan['adapter_env'])
        env['ATS_SECURITY_DB'] = scratch+'/security.sqlite3'
        env['ATS_MONITOR_JOBS_DIR'] = scratch+'/jobs'
        result = runner([plan['interpreter'], adapter, '--check'], check=False, env=env, timeout=60)
    try:
        report = json.loads(result.stdout or '')
    except ValueError:
        report = None
    if not isinstance(report, dict):
        raise ValueError('The Monitor companion at '+adapter+' has no adapter self-check. Update it '
                         '(git pull in that directory) and run setup again')
    if report.get('ok') is not True:
        problems = [item[:240] for item in report.get('problems', []) if isinstance(item, str)][:8]
        raise ValueError('Monitor adapter self-check failed with '+plan['interpreter']+': '+('; '.join(problems) or 'unknown problem'))
    return report


def install_monitor(runner=run, repo=DEFAULT_MONITOR_REPO, ref='origin/main', destination=DEFAULT_MONITOR_DIR):
    """Opt-in install of the Monitor companion into a new root-owned directory.

    The destination must not exist, hooks are disabled, and the resulting revision
    is reported so the operator can verify it. Python packages are never installed.
    """
    dest = absolute(destination, 'Monitor install directory')
    if os.path.lexists(dest):
        raise ValueError(str(dest)+' already exists; select it with --monitor-adapter '+str(dest/'remote_host.py')+' or choose another --monitor-dir')
    if not isinstance(repo, str) or urlsplit(repo).scheme != 'https' or not urlsplit(repo).hostname:
        raise ValueError('The Monitor repository must be an https:// URL')
    if not REF.fullmatch(ref or '') or '..' in ref:
        raise ValueError('Invalid Monitor git ref')
    parent = dest.parent
    info = parent.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError('The parent of the Monitor directory must be root-owned and not group/world-writable: '+str(parent))
    env = dict(os.environ, GIT_TERMINAL_PROMPT='0')
    try:
        runner(['git', 'clone', '--no-checkout', repo, str(dest)], env=env, timeout=180)
        runner(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(dest), 'checkout', '--detach', ref], env=env, timeout=60)
        head = runner(['git', '-C', str(dest), 'rev-parse', 'HEAD'], env=env).stdout.strip()
        if not (dest/'remote_host.py').is_file():
            raise ValueError('The checked-out repository has no remote_host.py')
    except ValueError as exc:
        import shutil
        shutil.rmtree(dest, ignore_errors=True)
        raise ValueError(str(exc)+'. If the repository is private, give this server read access first '
                         '(deploy key or gh auth login) or copy it manually and use --monitor-adapter') from None
    return str(dest/'remote_host.py'), head


TUNNEL_RETRIES = 3
TUNNEL_BACKOFF = (5, 10)


def restart_tunnel(unit, runner=run):
    """Restart cloudflared, tolerating a slow start that systemd recovers by itself."""
    failure = None
    for attempt in range(TUNNEL_RETRIES):
        try:
            runner(['systemctl', 'restart', unit])
            return
        except ValueError as exc:
            failure = exc
        for _ in range(10):
            try:
                runner(['systemctl', 'is-active', unit])
                return
            except ValueError:
                time.sleep(1)
        if attempt < TUNNEL_RETRIES-1:
            time.sleep(TUNNEL_BACKOFF[min(attempt, len(TUNNEL_BACKOFF)-1)])
    raise failure


def require_root():
    if os.geteuid() != 0:
        raise ValueError('Run Global setup as root using the existing ATS environment')


def apply(store, *, runner=run, health=verify_health, install=False, monitor_repo=DEFAULT_MONITOR_REPO,
          monitor_ref='origin/main', monitor_dir=DEFAULT_MONITOR_DIR, **options):
    require_root()
    lock_path = absolute(str(Path(store.path).absolute())+'.setup.lock', 'Setup lock')
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        try:fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Another Global setup is running') from None
        installed = None
        try:
            plan = build_plan(store, runner=runner, **options)
        except MonitorMissing:
            if not install:
                raise
            adapter, head = install_monitor(runner, monitor_repo, monitor_ref, monitor_dir)
            installed = {'path': adapter, 'revision': head}
            options['monitor_adapter'] = adapter
            plan = build_plan(store, runner=runner, **options)
        summary = public_plan(plan)
        if installed:
            summary['monitor_installed'] = installed
        # Never compete with a terminal daemon or another listener.
        if not plan['active']:
            with socket.socket() as listener:
                try:listener.bind(('127.0.0.1', plan['port']))
                except OSError:raise ValueError('API port is occupied; stop the identified old daemon before setup') from None
        # Prove the adapter can start under the daemon's interpreter before any file changes.
        adapter_check(plan, runner)
        # Validate a candidate without writing to the active config or starting services.
        with tempfile.TemporaryDirectory(prefix='ats-global-validate-') as staging:
            candidate = Path(staging)/'cloudflared.yml'
            candidate.write_bytes(plan['cf_content']);candidate.chmod(0o600)
            runner(['cloudflared','tunnel','--config',str(candidate),'ingress','validate'])
            candidate_unit = Path(staging)/plan['unit'];candidate_unit.write_text(plan['full_unit'])
            runner(['systemd-analyze','verify',str(candidate_unit)])
        if (snapshot(plan['cf'])!=plan['before_cf'] or snapshot(plan['destination'])!=plan['before_unit']
                or snapshot(plan['settings_path'])!=plan['settings_snapshot'] or store.node()!=plan['node']):
            raise ValueError('Configuration changed during validation; retry')
        for directory in {Path(plan['adapter_env']['ATS_SECURITY_DB']).parent, Path(plan['adapter_env']['ATS_MONITOR_JOBS_DIR'])}:
            private_directory(directory)
        backup_root = plan['registry'].parent/('setup-backups-'+plan['node']['id'])
        private_directory(backup_root)
        backup = Path(tempfile.mkdtemp(prefix='run-', dir=backup_root))
        changed = []
        service_touched = tunnel_touched = False
        try:
            for label,path,old,data in [('tunnel',plan['cf'],plan['before_cf'],plan['cf_content']),
                                       ('service',plan['destination'],plan['before_unit'],plan['unit_content'])]:
                if old and old[0]==data:continue
                if old:replace_file(backup/(label+'.before'),old[0])
                path.parent.mkdir(parents=True, exist_ok=True)
                if snapshot(path)!=old:
                    raise ValueError('Configuration changed before installation')
                changed.append((path,old,data))
                replace_file(path,data,old[1] if old else 0o644,(old[2],old[3]) if old else None)
            runner(['systemctl','daemon-reload'])
            service_touched = True
            runner(['systemctl','enable',plan['unit']])
            if summary['service_change'] or not plan['active']:
                runner(['systemctl','restart' if plan['active'] else 'start',plan['unit']])
            # systemd active is not proof that Python has bound the socket.
            for attempt in range(10):
                try:health(plan);break
                except (ValueError,OSError,http.client.HTTPException):
                    if attempt==9:raise
                    time.sleep(1)
            health(plan, management=True)
            if summary['route_change']:
                tunnel_touched = True
                restart_tunnel(plan['tunnel_unit'], runner)
            runner(['systemctl','is-active',plan['unit']])
            runner(['systemctl','is-active',plan['tunnel_unit']])
        except Exception as exc:
            recovery_failed = False
            for path,old,data in reversed(changed):
                try:
                    current = snapshot(path)
                    if current==old:continue
                    if current is None or current[0]!=data:
                        recovery_failed=True;continue
                    if old:replace_file(path,old[0],old[1],(old[2],old[3]))
                    else:path.unlink()
                except (OSError, ValueError):recovery_failed=True
            for command in ([['systemctl','stop',plan['unit']]] if service_touched and not plan['active'] else []) + \
                    ([['systemctl','disable',plan['unit']]] if service_touched and not plan['enabled'] else []) + \
                    [['systemctl','daemon-reload']] + \
                    ([['systemctl','restart',plan['unit']]] if service_touched and plan['active'] else []) + \
                    ([['systemctl','restart',plan['tunnel_unit']]] if tunnel_touched else []):
                try:runner(command)
                except ValueError:recovery_failed=True
            raise ValueError('Global setup failed; '+('rollback needs operator attention' if recovery_failed else 'previous files and service state restored')+'. Private backups: '+str(backup)) from exc
        # DNS/edge propagation may lag; keep a verified working local service.
        try:
            health(plan, public=True)
            health(plan, public=True, management=True)
            summary['public_health']='verified'
        except (ValueError,OSError,http.client.HTTPException):
            summary['public_health']='unverified: check tunnel DNS and edge connectivity'
        summary.update(loopback_health='verified', adapter_check='verified', adapter_service_read='verified', backup_directory=str(backup))
        return summary
