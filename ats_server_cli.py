"""Interactive and headless server setup; never changes production tunnel routes."""
import argparse
import contextlib
import stat
import json
import os
from pathlib import Path
import secrets
import shlex
import sys
from urllib.parse import urlsplit
import yaml
from ats_cluster import Store


def main():
    parser = argparse.ArgumentParser(description='ATS multi-server configuration (operator-managed TLS, storage and GitHub)')
    parser.add_argument('action', choices=['configure', 'show', 'export', 'rotate', 'serve', 'map', 'unmap', 'pair', 'disconnect', 'reconnect', 'revoke', 'tunnel', 'service', 'adapter'])
    parser.add_argument('--role', choices=['local', 'global'])
    parser.add_argument('--name')
    parser.add_argument('--api-domain')
    parser.add_argument('--webhook-host')
    parser.add_argument('--cloudflare-config')
    parser.add_argument('--confirm-existing-route', action='store_true')
    parser.add_argument('--port', type=int, default=int(os.environ.get('ATS_REMOTE_PORT', '9997')))
    parser.add_argument('--pairing-file')
    parser.add_argument('--monitor-adapter', help='Installed Monitor remote_host.py (preview only)')
    parser.add_argument('--adapter-state-dir', help='Private absolute directory for adapter security/job state')
    parser.add_argument('--server-id')
    parser.add_argument('--repository')
    parser.add_argument('--service')
    parser.add_argument('--branch', default='main')
    parser.add_argument('--secret-file')
    parser.add_argument('--replace-mapping', action='store_true')
    args = parser.parse_args()
    if (args.monitor_adapter or args.adapter_state_dir) and args.action not in ('service', 'adapter'):
        parser.error('Adapter options require server service or server adapter')
    store = Store()
    if args.action == 'configure':
        try:
            configure(store, args, sys.stdin.isatty())
        except (ValueError, OSError, yaml.YAMLError, EOFError) as exc:
            parser.error('Server setup failed: ' + str(exc))
    elif args.action in ('service', 'adapter'):
        try:
            if args.action == 'adapter':
                print(adapter_drop_in(store, args.monitor_adapter, args.adapter_state_dir))
            else:
                print(service_unit(store, args.port, monitor_adapter=args.monitor_adapter,
                                   adapter_state_dir=args.adapter_state_dir))
        except (ValueError, OSError, yaml.YAMLError) as exc:
            parser.error('Service preview failed: ' + str(exc))
    elif args.action == 'tunnel':
        try:
            tunnel_guidance(store, args.cloudflare_config, args.port)
        except (ValueError, OSError, yaml.YAMLError) as exc:
            parser.error('Server setup failed: ' + str(exc))
    elif args.action == 'show':
        n = store.node()
        print(json.dumps({k: v for k, v in (n or {}).items() if k != 'secret'}))
    elif args.action == 'export':
        save_pairing(store, args.pairing_file)
    elif args.action == 'rotate':
        rotate_pairing(store, args.pairing_file)
    elif args.action == 'serve':
        try:
            ensure_startup_configuration(interactive=False, store=store)
        except ValueError as exc:
            parser.error(str(exc))
        if not store.node() or store.node()['role'] != 'global':
            parser.error('Configure this instance as Global first')
        os.environ['ATS_REMOTE_PORT'] = str(args.port)
        import asyncio
        import app as runtime
        asyncio.run(runtime.run_daemon())
    elif args.action == 'pair':
        with open(args.pairing_file) as f:
            bundle = json.load(f)
        store.pair(bundle['id'], args.name or bundle['name'], bundle['domain'], bundle['secret'])
        print('Global server paired and verified')
    elif args.action == 'map':
        with open(args.secret_file) as f:
            secret = f.read().strip()
        store.mapping(args.repository, args.server_id, args.service, args.branch, secret, replace=args.replace_mapping)
        print('Explicit webhook mapping saved')
    elif args.action == 'unmap':
        if not args.repository:
            parser.error('--repository is required')
        with store.db() as db:
            db.execute('DELETE FROM routes WHERE repository=?', (args.repository.lower(),))
        print('Mapping removed; future deliveries are rejected')
    else:
        store.connection(args.server_id, args.action)


def configure(store, args, interactive):
    """Shared setup for explicit configuration and launch-time upgrade checks."""
    role = args.role or (input('Role (local/global): ').strip() if interactive else None)
    label = args.name or (input('Server name: ').strip() if interactive else None)
    origin = args.api_domain
    host = args.webhook_host
    if role == 'global' and not origin and interactive:
        origin = input('HTTPS API origin (configure TLS manually): ').strip()
    if role == 'local':
        if not host and interactive:
            host = input('Central webhook hostname: ').strip()
        cf = args.cloudflare_config or os.environ.get('ATS_CLOUDFLARE_CONFIG')
        if not cf and interactive:
            cf = input('Cloudflare Tunnel config path: ').strip()
        if not cf:
            raise ValueError('--cloudflare-config is required to check actual Local tunnel routes')
        with open(cf) as f:
            config = yaml.safe_load(f) or {}
        if not isinstance(config, dict) or not isinstance(config.get('ingress', []), list) or any(
                not isinstance(route, dict) for route in config.get('ingress', [])):
            raise ValueError('Cloudflare config must contain an ingress list of routes')
        matches = [r for r in config.get('ingress', []) if r.get('hostname') == host]
        wildcard = [r for r in config.get('ingress', []) if str(r.get('hostname', '')).startswith('*.') and host and host.endswith(str(r['hostname'])[1:])]
        if wildcard and not args.confirm_existing_route:
            if not interactive or input('Wildcard route covers this hostname. Have you checked route order and confirm reuse? [yes/NO] ') != 'yes':
                raise ValueError('A wildcard tunnel route covers this hostname; inspect route order and explicitly confirm reuse')
        if len(matches) > 1:
            raise ValueError('Duplicate webhook hostname in actual tunnel configuration')
        if matches and not args.confirm_existing_route:
            if not interactive or input('Existing route found. Reuse this hostname without changing the route? [yes/NO] ') != 'yes':
                raise ValueError('Existing tunnel hostname requires explicit confirmation')
        # Detect configured services using the chosen hostname.
        instance = os.environ.get('ATS_INSTANCE', '')
        cfgpath = os.environ.get('ATS_CONFIG_FILE') or ('/etc/ats/config-'+instance+'.yml' if instance and all(ch.isalnum() or ch in '_-' for ch in instance) else '/etc/ats/config.yml')
        if Path(cfgpath).exists():
            import sqlite3
            with open(cfgpath) as f:
                cfg = yaml.safe_load(f) or {}
            dbpath = Path(cfg.get('ats_home', os.environ.get('ATS_HOME', '/home/gaia'))) / 'ats.db'
            if dbpath.exists():
                with sqlite3.connect(dbpath) as db:
                    if db.execute('SELECT 1 FROM services WHERE domain=?', (host,)).fetchone():
                        raise ValueError('Webhook hostname is already used by a service')
    if role == 'global':
        # Check/reserve the export destination before changing configuration.
        with pairing_destination(args.pairing_file, store.node()) as f:
            node = store.configure(role, label, origin, host)
            json.dump(node, f)
        print('Pairing file saved privately at ' + str(args.pairing_file or default_pairing_path()))
        tunnel_guidance(store)
    else:
        store.configure(role, label, origin, host)
    print('Configuration saved. Configure/validate TLS proxy, storage and GitHub manually; no services or tunnel routes were changed.')


def tunnel_guidance(store, config_path=None, port=None):
    """Preview the operator-managed API route without modifying/restarting anything."""
    from ats_cluster import domain
    node = store.node()
    if not node or node['role'] != 'global':
        raise ValueError('API tunnel guidance requires a configured Global server')
    hostname = urlsplit(domain(node['domain'])).hostname
    port = int(port if port is not None else os.environ.get('ATS_REMOTE_PORT', '9997'))
    if not 1 <= port <= 65535:
        raise ValueError('API port must be between 1 and 65535')
    route = {'hostname': hostname, 'path': '^/v1/request$',
             'service': f'http://127.0.0.1:{port}'}
    print('API domain is saved in the private cluster registry, not Cloudflare config.yml.')
    if config_path:
        with open(config_path) as f:
            config = yaml.safe_load(f)
        if not isinstance(config, dict) or not isinstance(config.get('ingress'), list) or any(
                not isinstance(item, dict) for item in config['ingress']):
            raise ValueError('Cloudflare config must contain an ingress list of routes')
        routes = config['ingress']
        # A preceding catch-all, wildcard or same-host rule can shadow this one.
        relevant = [item for item in routes if not item.get('hostname') or
                    str(item.get('hostname', '')).lower() == hostname or
                    (str(item.get('hostname', '')).startswith('*.') and
                     hostname.endswith(str(item['hostname'])[1:].lower()))]
        if relevant and relevant[0] == route and sum(item.get('hostname') == hostname for item in routes) == 1:
            print('API route matches the configured endpoint; DNS/TLS and live connectivity remain unverified.')
        else:
            print('API route is missing, conflicting or potentially shadowed. Inspect ingress order before editing.')
    print('Operator: place this rule before covering hostname/wildcard/catch-all rules in the active tunnel config:')
    print(yaml.safe_dump([route], sort_keys=False).rstrip())
    print('Keep the existing tunnel credentials, service routes and final catch-all. Forward only /v1/request; this is not a webhook route.')
    print('Configure tunnel DNS/TLS and validate ingress manually. Apply/restart only with operator authorization. No configuration was changed.')
    return route


def configuration_issues(node):
    """Validate persisted startup requirements without changing identity or keys."""
    import re
    from ats_cluster import domain, name, ID
    issues = []
    if not node:
        return ['Local/Global mode, server name and endpoint']
    if not ID.fullmatch(node.get('id') or ''):
        issues.append('server identity (restore the private cluster registry)')
    if not re.fullmatch('[0-9a-f]{64}', node.get('secret') or ''):
        issues.append('server credential (restore the private cluster registry)')
    try:
        name(node.get('name'))
    except ValueError:
        issues.append('server name')
    role = node.get('role')
    try:
        if role == 'local':
            domain('https://' + (node.get('webhook') or ''))
        elif role == 'global':
            domain(node.get('domain'))
            if node.get('webhook'):
                issues.append('Global must not have a webhook receiver')
        else:
            issues.append('Local/Global mode')
    except (ValueError, TypeError):
        issues.append('webhook hostname' if role == 'local' else 'HTTPS API origin')
    return issues


def ensure_startup_configuration(*, interactive, cloudflare_config=None, store=None):
    """Ask before starting tasks; unattended launches fail with an actionable error."""
    store = store or Store()
    while True:
        node = store.node()
        issues = configuration_issues(node)
        if not issues:
            if node['role'] == 'global':
                save_pairing(store)
            return node
        detail = 'ATS setup incomplete: ' + ', '.join(issues)
        if not interactive:
            raise ValueError(detail + '. Run sudo python3 app.py interactively once, '
                             'or use python3 app.py server configure with explicit settings; '
                             'use the same ATS_CONFIG_FILE and ATS_CLUSTER_DB as the service.')
        print(detail)
        # Do not invent a replacement for a damaged identity or credential.
        if node and (any('restore the private' in issue for issue in issues) or
                     node.get('role') not in ('local', 'global')):
            raise ValueError(detail)
        args = argparse.Namespace(role=(node or {}).get('role'),
            name=(node or {}).get('name'), api_domain=(node or {}).get('domain'),
            webhook_host=(node or {}).get('webhook'),
            cloudflare_config=cloudflare_config, confirm_existing_route=False,
            pairing_file=None)
        # Keep valid existing fields, ask again for invalid or missing values.
        if 'server name' in issues:
            args.name = None
        if 'webhook hostname' in issues:
            args.webhook_host = None
        if 'HTTPS API origin' in issues:
            args.api_domain = None
        if (node or {}).get('role') == 'global':
            args.webhook_host = None
        try:
            configure(store, args, True)
        except (EOFError, KeyboardInterrupt):
            raise ValueError('ATS setup cancelled; no background services were started') from None
        except (ValueError, OSError, yaml.YAMLError) as exc:
            if not configuration_issues(store.node()):
                raise ValueError('Configuration saved, but pairing export failed; fix private file permissions and use server export; existing credentials are preserved') from exc
            print('Setup could not be completed: ' + str(exc))
            if isinstance(exc, (OSError, yaml.YAMLError)):
                cloudflare_config = None

def default_pairing_path():
    """Relative to the installed app.py, never to the current working directory."""
    return Path(__file__).resolve().parent / 'files' / 'pairing.json'


@contextlib.contextmanager
def pairing_destination(path, node):
    """Explicit exports are exclusive; the managed file is privately replaced."""
    if path:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'w') as f:
                yield f
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            os.unlink(path)
            raise
        return
    target = default_pairing_path()
    target.parent.mkdir(mode=0o700, exist_ok=True)
    directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = '.pairing-' + secrets.token_hex(16)
    try:
        info = os.fstat(directory)
        runtime_uid = os.geteuid()
        directory_uid = info.st_uid
        if directory_uid != runtime_uid and runtime_uid != 0:
            raise ValueError(f'Pairing directory {target.parent} is owned by UID {directory_uid}, '
                             f'but ATS runs as UID {runtime_uid}. Have the operator correct '
                             'ownership for the ATS runtime user; existing credentials are preserved')
        try:
            fd = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        except FileNotFoundError:
            pass
        else:
            with os.fdopen(fd) as existing:
                info = os.fstat(existing.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid not in {runtime_uid, directory_uid} or info.st_mode & 0o077 or info.st_nlink != 1:
                    raise ValueError('Existing pairing file must be private, owned, regular and unlinked elsewhere')
                try:
                    previous = json.load(existing)
                except (ValueError, UnicodeError):
                    raise ValueError('Existing pairing file is invalid; preserve it privately before exporting') from None
                if not isinstance(previous, dict) or not node or previous.get('id') != node['id']:
                    raise ValueError('Existing pairing file belongs to another identity; use a separate ATS checkout')
                if info.st_uid != runtime_uid:
                    # Transfer the validated export first so interrupted directory
                    # adoption remains retryable with the existing credential.
                    try:
                        os.fchown(existing.fileno(), runtime_uid, -1)
                    except OSError as exc:
                        raise ValueError('Cannot secure pairing directory export ownership; existing credentials are preserved') from exc
        # ATS app.py requires root, even in a checkout owned by the sudo user.
        # Validate the old export first, then secure only the opened managed
        # directory. Atomic replacement gives the refreshed file to the runtime.
        try:
            if stat.S_IMODE(os.fstat(directory).st_mode) != 0o700:
                os.fchmod(directory, 0o700)
            if directory_uid != runtime_uid:
                os.fchown(directory, runtime_uid, -1)
        except OSError as exc:
            raise ValueError(f'Cannot secure pairing directory {target.parent} to runtime ownership and mode 0700; '
                             'have the operator correct permissions; existing credentials are preserved') from exc
        secured = os.fstat(directory)
        if secured.st_uid != runtime_uid or stat.S_IMODE(secured.st_mode) != 0o700:
            raise ValueError('Pairing directory could not be secured; existing credentials are preserved')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, 'w') as f:
                yield f
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, target.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
    finally:
        os.close(directory)


def save_pairing(store, path=None):
    node = store.node()
    if not node or node['role'] != 'global' or configuration_issues(node):
        raise ValueError('Configure a valid Global server before exporting pairing credentials')
    with pairing_destination(path, node) as f:
        json.dump(node, f)
    print('Pairing file saved privately at ' + str(path or default_pairing_path()))


def rotate_pairing(store, path=None):
    with store.db() as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM node').fetchone()
        node = dict(row) if row else None
        if not node or node['role'] != 'global' or configuration_issues(dict(node, secret=node['secret'] or '0'*64)):
            raise ValueError('Rotate pairing credentials on a valid Global server')
        with pairing_destination(path, node) as f:
            node['secret'] = secrets.token_hex(32)
            json.dump(node, f)
        db.execute('UPDATE node SET secret=?', (node['secret'],))
    print('Credentials rotated. Re-pair this Global on Local using the private file.')


def unit_quote(value):
    """Quote a systemd value, including literal specifiers; never shell-evaluate."""
    value = str(value)
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Invalid service path or environment')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'


def adapter_environment(store, monitor_adapter=None, state_dir=None):
    """Prepare an explicit Global adapter without importing it or changing state."""
    node = store.node()
    if configuration_issues(node) or node['role'] != 'global':
        raise ValueError('Adapter setup requires a configured Global server')

    def absolute(value, label):
        if not isinstance(value, str) or not value or not Path(value).is_absolute():
            raise ValueError(label + ' must be an absolute path')
        unit_quote(value)
        return str(Path(value).resolve())

    adapter = absolute(monitor_adapter or os.environ.get('ATS_MONITOR_ADAPTER'),
                       '--monitor-adapter')
    if not Path(adapter).is_file():
        raise ValueError('Install the reviewed Monitor remote_host.py before previewing the adapter')
    checkout = Path(__file__).resolve().parent
    instance = os.environ.get('ATS_INSTANCE', '')
    if instance and not all(c.isalnum() or c in '_-' for c in instance):
        raise ValueError('Invalid ATS_INSTANCE')
    config = absolute(os.environ.get('ATS_CONFIG_FILE') or
                      ('/etc/ats/config-'+instance+'.yml' if instance else '/etc/ats/config.yml'),
                      'ATS_CONFIG_FILE')
    with open(config) as f:
        settings = yaml.safe_load(f)
    if not isinstance(settings, dict):
        raise ValueError('ATS config must contain a settings mapping')
    home = absolute(os.environ.get('ATS_HOME') or settings.get('ats_home'), 'ATS_HOME / ats_home')
    if not (Path(home) / 'ats.db').is_file():
        raise ValueError('ATS_HOME must contain the existing ats.db')
    if state_dir is not None:
        state = Path(absolute(state_dir, '--adapter-state-dir'))
        if state == Path('/'):
            raise ValueError('--adapter-state-dir must be a private directory below /')
        security_db, jobs = str(state / 'security.sqlite3'), str(state / 'jobs')
    else:
        security_db = absolute(os.environ.get('ATS_SECURITY_DB'),
                               'ATS_SECURITY_DB (or supply --adapter-state-dir)')
        jobs = absolute(os.environ.get('ATS_MONITOR_JOBS_DIR'),
                        'ATS_MONITOR_JOBS_DIR (or supply --adapter-state-dir)')
    # Root runs the adapter with the same interpreter and intended ATS instance.
    # Explicit operator launchers are retained rather than silently replaced.
    cli = os.environ.get('ATS_CLI') or shlex.join([sys.executable, str(checkout / 'app.py')])
    if not shlex.split(cli):
        raise ValueError('ATS_CLI must contain a command')
    unit_quote(cli)
    module_dir = absolute(os.environ.get('ATS_MODULE_DIR') or str(checkout), 'ATS_MODULE_DIR')
    if not (Path(module_dir) / 'ats_cluster.py').is_file():
        raise ValueError('ATS_MODULE_DIR must contain ats_cluster.py')
    return {'ATS_MONITOR_ADAPTER': adapter, 'ATS_MODULE_DIR': module_dir,
            'ATS_CLI': cli, 'ATS_HOME': home, 'ATS_SECURITY_DB': security_db,
            'ATS_MONITOR_JOBS_DIR': jobs}


def adapter_preflight(env):
    # Creation/ownership is an explicit installation step. Importing Monitor in
    # a preview would initialize its private security database.
    checks = [('-f', env['ATS_MONITOR_ADAPTER']),
              ('-f', Path(env['ATS_MODULE_DIR']) / 'ats_cluster.py'),
              ('-f', Path(env['ATS_HOME']) / 'ats.db'),
              ('-d', Path(env['ATS_SECURITY_DB']).parent),
              ('-d', env['ATS_MONITOR_JOBS_DIR'])]
    return ['ExecStartPre=/usr/bin/test '+flag+' '+unit_quote(path).replace('$', '$$')
            for flag, path in checks]


def adapter_drop_in(store, monitor_adapter=None, state_dir=None):
    """Print a drop-in for an existing Global daemon; preserve its unit and keys."""
    env = adapter_environment(store, monitor_adapter, state_dir)
    return '\n'.join(['[Service]', 'UMask=0077'] +
                     ['Environment='+unit_quote(k+'='+v) for k, v in env.items()] +
                     adapter_preflight(env))


def service_unit(store, port=None, *, monitor_adapter=None, adapter_state_dir=None):
    """Print a reviewable unit for the current installation; never apply it."""
    node = store.node()
    if configuration_issues(node):
        raise ValueError('Complete server configuration before preparing a service')
    port = int(port if port is not None else os.environ.get('ATS_REMOTE_PORT', '9997'))
    if not 1 <= port <= 65535:
        raise ValueError('API port must be between 1 and 65535')
    checkout = Path(__file__).resolve().parent
    instance = os.environ.get('ATS_INSTANCE', '')
    if instance and not all(c.isalnum() or c in '_-' for c in instance):
        raise ValueError('Invalid ATS_INSTANCE')
    config = os.environ.get('ATS_CONFIG_FILE') or ('/etc/ats/config-'+instance+'.yml' if instance else '/etc/ats/config.yml')
    env = {'PYTHONUNBUFFERED': '1', 'ATS_CONFIG_FILE': str(Path(config).resolve()),
           'ATS_CLUSTER_DB': str(Path(store.path).resolve()), 'ATS_REMOTE_PORT': str(port)}
    for key in ('ATS_INSTANCE', 'ATS_HOME', 'ATS_MONITOR_ADAPTER', 'ATS_CLI', 'ATS_MODULE_DIR',
                'ATS_SECURITY_DB', 'ATS_MONITOR_JOBS_DIR'):
        if key in os.environ:
            env[key] = os.environ[key]
    explicit_adapter = monitor_adapter is not None or adapter_state_dir is not None
    if explicit_adapter:
        env.update(adapter_environment(store, monitor_adapter, adapter_state_dir))
    lines = ['[Unit]', 'Description=ATS persistent '+node['role'].title()+' daemon',
             'Wants=network-online.target', 'After=network-online.target', 'StartLimitIntervalSec=0',
             '', '[Service]', 'Type=simple', 'User=root', 'WorkingDirectory='+unit_quote(checkout)]
    if node['role'] == 'global' and not Path(env.get('ATS_MONITOR_ADAPTER', '')).is_file():
        lines += ['# Global management adapter is not configured; health alone can still pass.',
                  '# Preview its settings with server adapter --monitor-adapter /absolute/path/to/remote_host.py --adapter-state-dir /private/state/path']
    lines += ['Environment='+unit_quote(k+'='+v) for k, v in env.items()]
    if explicit_adapter:
        lines += ['UMask=0077'] + adapter_preflight(env)
    lines += ['ExecStartPre=/usr/bin/test -f '+unit_quote(env['ATS_CONFIG_FILE']).replace('$', '$$'),
              'ExecStartPre=/usr/bin/test -f '+unit_quote(env['ATS_CLUSTER_DB']).replace('$', '$$'),
              'ExecStart='+unit_quote(sys.executable).replace('$', '$$')+' '+unit_quote(checkout / 'app.py').replace('$', '$$')+' --daemon',
              'Restart=always', 'RestartSec=10', '', '[Install]', 'WantedBy=multi-user.target']
    return '\n'.join(lines)


def menu(store=None, ui=None):
    """Option 12 uses the same setup, pairing and credential operations as headless CLI."""
    store = store or Store()
    # Receive the running CLI so its header and palette stay consistent, without
    # importing app.py again (which would initialize another runtime/database).
    cyan = ui.C_CYAN if ui else ''
    bold = ui.C_BOLD if ui else ''
    reset = ui.C_RESET if ui else ''
    def status(message, level='info'):
        if ui:
            ui.print_status(message, level)
        else:
            print(message)
    while True:
        node = store.node() or {}
        if ui:
            ui.print_header()
        print(f'{cyan}{bold}═══ SERVER CONFIGURATION ═══{reset}\n')
        for label, value in (
                ('Server', node.get('name', 'Not configured')),
                ('Role', node.get('role', 'Not configured').title()),
                ('Endpoint', node.get('domain') or node.get('webhook') or 'Not configured')):
            print(f'  {bold}{label + ":":<15}{reset} {value}')
        if node.get('role') == 'global':
            print(f'  {bold}{"Pairing file:":<15}{reset} {default_pairing_path()}')
        print()
        options = (
                ('1', 'Configure name / endpoint'), ('2', 'Export pairing file'),
                ('3', 'Rotate Global credentials'), ('4', 'List servers'),
                ('5', 'Pair Global from private file'), ('6', 'Disconnect Global'),
                ('7', 'Reconnect Global'), ('8', 'Revoke Global'),
                ('9', 'Check Global API tunnel route'), ('10', 'Preview automatic startup service'), ('0', 'Back'))
        allowed = {'1', '10', '0'} | ({'2', '3', '9'} if node.get('role') == 'global' else {'4', '5', '6', '7', '8'})
        for number, label in options:
            if number not in allowed:
                continue
            print(f'  {bold}[{number}]{reset} {label}')
        print()
        try:
            choice = input(f'  {bold}Select:{reset} ').strip()
            if choice == '0' or not choice:
                return
            if choice not in allowed:
                status('This action is unavailable for this server role', 'warning')
            elif choice == '10':
                print(service_unit(store))
            elif choice == '1':
                args = argparse.Namespace(role=node.get('role'), name=None,
                    api_domain=None, webhook_host=None, cloudflare_config=None,
                    confirm_existing_route=False, pairing_file=None)
                configure(store, args, True)
            elif choice == '2':
                save_pairing(store)
            elif choice == '3':
                if input('Invalidate the current key and require re-pairing? [yes/NO] ') == 'yes':
                    rotate_pairing(store)
            elif choice == '9':
                path = input('Active Cloudflare Tunnel config path (blank for example only): ').strip()
                tunnel_guidance(store, path or None)
            elif choice == '4':
                servers = store.servers()
                if not servers:
                    status('No servers configured')
                for server in servers:
                    role = 'Local' if server['local'] else 'Global'
                    state = 'Connected' if server['connected'] else 'Disconnected'
                    print(f"\n  {bold}{server['name']}{reset} — {role} | {state}")
                    print(f"    ID: {server['id']}")
                    print(f"    Endpoint: {server['domain'] or 'Local'}")
            elif choice == '5':
                with open(input('Private pairing file path: ').strip()) as f:
                    bundle = json.load(f)
                store.pair(bundle['id'], bundle['name'], bundle['domain'], bundle['secret'])
                status('Global paired and verified', 'success')
            elif choice in ('6', '7', '8'):
                action = {'6': 'disconnect', '7': 'reconnect', '8': 'revoke'}[choice]
                sid = input('Global server ID: ').strip()
                if action != 'revoke' or input('Revoke this Global credential? [yes/NO] ') == 'yes':
                    store.connection(sid, action)
                    status('Server ' + action + ' completed', 'success')
            else:
                status('Invalid choice', 'warning')
        except (EOFError, KeyboardInterrupt):
            return
        except (ValueError, OSError, KeyError, yaml.YAMLError) as exc:
            status('Server setup failed: ' + str(exc), 'error')
        if ui:
            try:
                input(f'\n{cyan}Press Enter to continue...{reset}')
            except (EOFError, KeyboardInterrupt):
                return


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError) as e:
        print('Server setup failed: ' + str(e), file=sys.stderr)
        sys.exit(1)
