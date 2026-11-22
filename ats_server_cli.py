"""Interactive and headless server configuration and explicit Global setup."""
import argparse
import contextlib
import stat
import json
import os
from pathlib import Path
import secrets
import shlex
import sys
import sqlite3
from urllib.parse import urlsplit
import yaml
from ats_cluster import Store


def _main():
    parser = argparse.ArgumentParser(description='ATS multi-server configuration (signed HTTPS management and automatic Global setup)')
    parser.add_argument('action', choices=['configure', 'show', 'export', 'rotate', 'serve', 'map', 'unmap', 'pair', 'disconnect', 'reconnect', 'revoke', 'tunnel', 'service', 'adapter', 'setup', 'replace-credentials', 'doctor', 'pair-code', 'rotate-global', 'backup', 'backups', 'restore'])
    parser.add_argument('--role', choices=['local', 'global'])
    parser.add_argument('--name')
    parser.add_argument('--api-domain')
    parser.add_argument('--webhook-host')
    parser.add_argument('--cloudflare-config')
    parser.add_argument('--confirm-existing-route', action='store_true')
    parser.add_argument('--port', type=int, default=None)
    parser.add_argument('--pairing-file')
    parser.add_argument('--apply', action='store_true', help='Install and start the Global service and add its API tunnel route')
    parser.add_argument('--unit', help='Existing ATS daemon systemd unit (auto-detected by default)')
    parser.add_argument('--monitor-adapter', help='Installed Monitor remote_host.py')
    parser.add_argument('--install-monitor', action='store_true',
                        help='With --apply: clone the Monitor companion into a new root-owned directory if none is installed')
    parser.add_argument('--monitor-repo', help='HTTPS git URL of the Monitor companion (default: the ats-monitor repository)')
    parser.add_argument('--monitor-ref', default='origin/main', help='Git ref to check out for --install-monitor')
    parser.add_argument('--monitor-dir', help='New directory for --install-monitor (default /opt/ats-monitor)')
    parser.add_argument('--adapter-state-dir', help='Private absolute directory for adapter security/job state')
    parser.add_argument('--server-id', help='Saved Global ID (replace-credentials: detected from the pairing file when omitted)')
    parser.add_argument('--repository')
    parser.add_argument('--service')
    parser.add_argument('--branch', help='Branch to track (default: the service\'s branch with --from-service, else main)')
    parser.add_argument('--secret-file')
    parser.add_argument('--from-service', metavar='NAME', help='map: map a Local service using its existing repository, branch and webhook secret')
    parser.add_argument('--generate-secret', action='store_true', help='map: create a fresh webhook secret and show it once')
    parser.add_argument('--replace-mapping', action='store_true')
    parser.add_argument('--json', action='store_true', help='doctor: machine-readable output')
    parser.add_argument('--domain', help='pair: the Global\'s HTTPS address, used with --code')
    parser.add_argument('--code', help='pair: a one-time pairing code made with "server pair-code" on that Global')
    parser.add_argument('--minutes', type=int, help='pair-code: how long the code works (default 10)')
    parser.add_argument('--output', help='backup: write the backup to this new file (default: the registry-backups directory)')
    parser.add_argument('--input', help='restore: the backup file to restore')
    parser.add_argument('--encrypt', action='store_true', help='backup: encrypt with a passphrase you are asked for (or --passphrase-file)')
    parser.add_argument('--passphrase-file', help='backup/restore: file whose first line is the passphrase')
    parser.add_argument('--force', action='store_true', help='restore: allow a backup from a different server identity')
    parser.add_argument('--yes', action='store_true', help='restore: do not ask for confirmation')
    args = parser.parse_args()
    if (args.monitor_adapter or args.adapter_state_dir) and args.action not in ('service', 'adapter', 'setup', 'configure'):
        parser.error('Adapter options require server service or server adapter')
    if args.apply and args.action not in ('configure', 'setup'):
        parser.error('--apply requires server configure or server setup')
    if args.install_monitor and (not args.apply or args.action not in ('configure', 'setup')):
        parser.error('--install-monitor requires --apply with server setup or server configure')
    if args.action == 'replace-credentials' and not args.pairing_file:
        parser.error('--pairing-file is required')
    if args.action == 'pair' and not args.pairing_file and not (args.domain and args.code):
        parser.error('--pairing-file is required (or --domain and --code for a one-time pairing code)')
    if args.action in ('disconnect', 'reconnect', 'revoke') and not args.server_id:
        parser.error('--server-id is required')
    if args.action == 'map':
        if args.from_service:
            if args.secret_file or args.generate_secret or args.service or (args.server_id and args.server_id != ''):
                parser.error('--from-service maps that Local service with its own secret; do not combine it with --secret-file, --generate-secret, --service or --server-id')
        elif not (args.repository and args.server_id and args.service):
            parser.error('map requires --repository, --server-id and --service (or --from-service NAME for a Local service)')
        elif bool(args.secret_file) == bool(args.generate_secret):
            parser.error('map needs exactly one of --secret-file or --generate-secret')
    store = Store()
    if args.action == 'configure':
        try:
            configure(store, args, sys.stdin.isatty())
        except (ValueError, OSError, yaml.YAMLError, EOFError) as exc:
            parser.error('Server setup failed: ' + str(exc))
    elif args.action == 'doctor':
        import ats_doctor
        report = ats_doctor.run(store, port=args.port, cloudflare_config=args.cloudflare_config)
        print(json.dumps(report.items, indent=2) if args.json else report.text())
        if report.failed:
            raise SystemExit(1)
    elif args.action == 'setup':
        try:
            setup_global(store, args)
        except (ValueError, OSError, yaml.YAMLError) as exc:
            parser.error('Global setup failed: '+str(exc))
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
        os.environ['ATS_REMOTE_PORT'] = str(args.port or os.environ.get('ATS_REMOTE_PORT', '9997'))
        import asyncio
        import app as runtime
        asyncio.run(runtime.run_daemon())
    elif args.action in ('backup', 'backups', 'restore'):
        registry_backup_command(store, args, parser)
    elif args.action == 'pair-code':
        code, expires = store.make_pair_code(args.minutes or 10)
        print_pair_code(store, code, expires)
    elif args.action == 'rotate-global':
        sid = args.server_id
        if not sid:
            candidates = [x for x in store.servers() if not x['local']]
            if len(candidates) != 1:
                parser.error('--server-id is required when there is not exactly one Global')
            sid = candidates[0]['id']
        result = store.rotate_global(sid)
        print(f"Key rotated and verified. The old key keeps working for {result['grace_seconds'] // 60} more minutes; nothing needs to be copied.")
    elif args.action == 'pair' and args.code:
        store.pair_by_code(args.domain, args.code, args.name)
        print('Global server paired and verified')
    elif args.action in ('pair', 'replace-credentials'):
        with open(args.pairing_file) as f:
            bundle = json.load(f)
        if not isinstance(bundle, dict):
            parser.error('Pairing file must contain a JSON object')
        if args.action == 'replace-credentials':
            sid = args.server_id or store.find_server(bundle)
            store.replace_credentials(sid, bundle['id'], args.name or bundle['name'], bundle['domain'], bundle['secret'])
            print('Credentials verified and replaced; connection state and webhook mappings preserved')
        else:
            store.pair(bundle['id'], args.name or bundle['name'], bundle['domain'], bundle['secret'])
            print('Global server paired and verified')
    elif args.action == 'map':
        map_repository(store, args)
    elif args.action == 'unmap':
        if not args.repository:
            parser.error('--repository is required')
        with store.db() as db:
            db.execute('DELETE FROM routes WHERE repository=?', (args.repository.lower(),))
        print('Mapping removed; future deliveries are rejected')
    else:
        store.connection(args.server_id, args.action)


def main():
    try:
        _main()
    except (ValueError, OSError, KeyError, sqlite3.Error) as exc:
        print('Server setup failed: '+str(exc), file=sys.stderr)
        raise SystemExit(1) from None


def configure(store, args, interactive):
    """Shared setup for explicit configuration and launch-time upgrade checks."""
    if getattr(args, 'apply', False) and args.role == 'local':
        raise ValueError('--apply is only supported for Global setup')
    role = args.role or (input('Role (local/global): ').strip() if interactive else None)
    if getattr(args, 'apply', False) and role != 'global':
        raise ValueError('--apply is only supported for Global setup')
    label = args.name or (input('Server name: ').strip() if interactive else None)
    origin = args.api_domain
    host = args.webhook_host
    if role == 'global' and not origin and interactive:
        origin = input('HTTPS API origin: ').strip()
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
        print('Global identity saved; existing credentials preserved.')
        if getattr(args, 'apply', False):
            setup_global(store, args)
        elif interactive:
            if input('Install/update the Global API service and configured tunnel route now? [yes/NO] ') == 'yes':
                args.apply = True
                setup_global(store, args)
        else:
            print('Run server setup to inspect automatic setup, then server setup --apply to install it.')
    else:
        store.configure(role, label, origin, host)
        print('Local configuration saved. Existing webhook routes were preserved.')


def ats_settings():
    """This instance's ATS settings file, found the same way the daemon finds it."""
    instance = os.environ.get('ATS_INSTANCE', '')
    path = os.environ.get('ATS_CONFIG_FILE') or ('/etc/ats/config-' + instance + '.yml' if instance and all(c.isalnum() or c in '_-' for c in instance) else '/etc/ats/config.yml')
    with open(path) as f:
        settings = yaml.safe_load(f) or {}
    return settings if isinstance(settings, dict) else {}


def ats_database():
    """This instance's service database."""
    return Path(ats_settings().get('ats_home') or os.environ.get('ATS_HOME') or '/home/gaia') / 'ats.db'


def github_repository(url):
    """owner/repository from an https or ssh GitHub URL."""
    import re
    match = re.fullmatch(r'(?:https://(?:[^/@\s]+@)?github\.com/|git@github\.com:|ssh://git@github\.com/)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?', (url or '').strip())
    if not match:
        raise ValueError('The service repository is not a github.com URL; pass --repository owner/repository')
    return match.group(1)


def map_repository(store, args):
    """Create an explicit webhook mapping, then say exactly what GitHub needs."""
    import re
    node = store._local()
    generated = None
    if args.from_service:
        path = ats_database()
        if not path.is_file():
            raise ValueError('ATS database not found at ' + str(path))
        with sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True) as db:
            row = db.execute('SELECT name,repo_url,branch,webhook_secret FROM services WHERE name=?', (args.from_service,)).fetchone()
        if not row:
            raise ValueError('No Local service named ' + args.from_service)
        repository = args.repository or github_repository(row[1])
        secret = row[3]
        if not re.fullmatch('[0-9a-f]{64}', secret or ''):
            raise ValueError('That service has no usable webhook secret; map it with --generate-secret instead')
        server_id, service, branch = node['id'], row[0], args.branch or row[2] or 'main'
    else:
        repository, server_id, service, branch = args.repository, args.server_id, args.service, args.branch or 'main'
        if args.generate_secret:
            secret = generated = secrets.token_hex(32)
        else:
            with open(args.secret_file) as f:
                secret = f.read().strip()
    target = store.server(server_id)
    store.mapping(repository, server_id, service, branch, secret, replace=args.replace_mapping)
    print(f"Explicit webhook mapping saved: {repository} -> {service} on {target['name']} (branch {branch})")
    print('In GitHub: Settings -> Webhooks -> Add webhook')
    print(f"  Payload URL : https://{node['webhook']}/webhook/{service}")
    print('  Content type: application/json    Events: just the push event    SSL verification: on')
    if generated:
        print('  Secret      : ' + generated)
        print('  (shown once; paste it into GitHub now. It is stored only in the private cluster registry.)')
    elif args.from_service:
        print("  Secret      : the service's existing webhook secret. A GitHub webhook that already uses this URL and secret needs no change.")
    else:
        print('  Secret      : the one in your secret file')


def registry_backup_command(store, args, parser):
    import ats_registry_backup as backups
    import getpass
    import time

    def passphrase(confirm):
        if args.passphrase_file:
            return Path(args.passphrase_file).read_text().strip()
        if not sys.stdin.isatty():
            return None
        value = getpass.getpass('Passphrase: ')
        if confirm and value != getpass.getpass('Repeat passphrase: '):
            raise ValueError('The passphrases do not match')
        return value
    if args.action == 'backup':
        made = backups.create(store, args.output, passphrase(True) if (args.encrypt or args.passphrase_file) else None)
        print(f"Registry backed up to {made['path']} ({made['size']} bytes, {'encrypted' if made['encrypted'] else 'NOT encrypted'}, mode 0600).")
        if not made['encrypted']:
            print('It contains private keys: keep it out of repositories and shared storage, or use --encrypt.')
    elif args.action == 'backups':
        items = backups.listing(store)
        for item in items:
            print(f"{item['name']}  {time.strftime('%Y-%m-%d %H:%M', time.localtime(item['at']))}  {item['size']} bytes  {'encrypted' if item['encrypted'] else 'plain'}")
        print(f'{len(items)} backup(s) in {backups.directory(store)}' if items else 'No automatic backups yet; the daemon makes one daily, or run "server backup".')
    else:
        if not args.input:
            parser.error('--input is required')
        key = passphrase(False) if backups.is_encrypted(args.input) else None
        info = backups.describe(args.input, key)
        print(f"Backup of {info['role']} “{info['name']}” ({info['id'][:8]}…), {len(info['servers'])} paired server(s), {info['mappings']} webhook mapping(s), "
              f"made {time.strftime('%Y-%m-%d %H:%M', time.localtime(info['at']))}.")
        if not args.yes and (not sys.stdin.isatty() or input('Replace this server\'s registry with it? A safety copy is made first. [yes/NO] ') != 'yes'):
            raise ValueError('Nothing was changed. Run again with --yes to restore.')
        done = backups.restore(store, args.input, key, force=args.force)
        print('Restored. Safety copy of the previous registry: ' + done['safety_copy'])
        print('Restart the ATS daemon (and the Monitor on a Local) so they use the restored registry.')


def print_pair_code(store, code, expires):
    import time
    node = store.node() or {}
    minutes = max(1, round((expires - time.time()) / 60))
    print(f'One-time pairing code: {code}')
    print(f'  Valid for about {minutes} minutes, works once, and can be created again at any time.')
    print(f"  In Monitor: Settings -> Servers -> Add a Global server -> address {node.get('domain')} and this code.")
    print(f"  Or on the Local server: server pair --domain {node.get('domain')} --code {code}")


def setup_global(store, args):
    import ats_global_setup as gs
    options = dict(port=getattr(args, 'port', None), config_path=getattr(args, 'cloudflare_config', None),
                   monitor_adapter=getattr(args, 'monitor_adapter', None), state_dir=getattr(args, 'adapter_state_dir', None),
                   unit=getattr(args, 'unit', None))
    if getattr(args, 'apply', False):
        install = dict(install=bool(getattr(args, 'install_monitor', False)))
        if getattr(args, 'monitor_repo', None):
            install['monitor_repo'] = args.monitor_repo
        if getattr(args, 'monitor_ref', None):
            install['monitor_ref'] = args.monitor_ref
        if getattr(args, 'monitor_dir', None):
            install['monitor_dir'] = args.monitor_dir
        result = gs.apply(store, **options, **install)
        print(json.dumps(result, indent=2))
        print_setup_summary(store, result)
        return result
    plan = gs.build_plan(store, **options)
    result = gs.public_plan(plan)
    try:
        gs.adapter_check(plan)
        result['adapter_check'] = 'ok'
    except ValueError as exc:
        result['adapter_check'] = 'FAILED: ' + str(exc)
    print(json.dumps(result, indent=2))
    print('Preview only. Use server setup --apply to install, enable and verify. Existing DNS/tunnel credentials are reused.')
    return result


def print_setup_summary(store, result):
    """A short plain-language result, so the next step is never a guess."""
    try:
        save_pairing(store)
    except (ValueError, OSError):
        pass
    node = store.node() or {}
    print()
    print('Global setup complete')
    print(f"  API service      : {result.get('service')} (enabled, running)")
    print(f"  Tunnel route     : {node.get('domain')}/v1/request -> http://127.0.0.1:{result.get('loopback_port')}"
          f" ({'added' if result.get('route_change') else 'already present'})")
    print('  Verified         : adapter self-check, signed loopback health, adapter service read')
    print(f"  Public HTTPS     : {result.get('public_health')}")
    if result.get('monitor_installed'):
        print(f"  Monitor installed: {result['monitor_installed']['path']} @ {result['monitor_installed']['revision'][:12]}")
    print(f"Next: on the Local server open Monitor -> Settings -> Servers and pair this Global using {default_pairing_path()}")
    print('      (the private file holds this Global\'s ID and passkey; copy it over a secure channel and delete it afterwards)')


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
        store.clear_previous_key(db)
    print('Credentials rotated. Re-pair this Global on Local using the private file.')


def unit_quote(value):
    """Quote a systemd value, including literal specifiers; never shell-evaluate."""
    value = str(value)
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Invalid service path or environment')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%') + '"'


def unit_path(value):
    """A systemd path setting such as WorkingDirectory=.

    These are not command lines: systemd takes the text literally, so surrounding
    quotes make the unit invalid ("path is not absolute"). Only specifiers need escaping.
    """
    value = str(value)
    if not value.startswith('/') or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Invalid service path')
    return value.replace('%', '%%')


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
             '', '[Service]', 'Type=simple', 'User=root', 'WorkingDirectory='+unit_path(checkout)]
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
                ('9', 'Check Global API tunnel route'), ('10', 'Preview automatic startup service'),
                ('11', 'Set up Global API service and tunnel'), ('12', 'Update saved Global ID / passkey'),
                ('13', 'Run health check (doctor)'), ('14', 'Create a one-time pairing code'),
                ('15', 'Pair a Global with a one-time code'), ('16', "Rotate a Global's key from here"), ('0', 'Back'))
        allowed = {'1', '10', '13', '0'} | ({'2', '3', '9', '11', '14'} if node.get('role') == 'global' else {'4', '5', '6', '7', '8', '12', '15', '16'})
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
            elif choice == '11':
                import ats_global_setup as gs
                args = argparse.Namespace(apply=False, install_monitor=False)
                try:
                    setup_global(store, args)
                    proceed = input('Apply this service/tunnel setup and restart affected services? [yes/NO] ') == 'yes'
                except gs.MonitorMissing as exc:
                    status(str(exc), 'warning')
                    args.install_monitor = proceed = input(
                        f'Install the Monitor companion from {gs.DEFAULT_MONITOR_REPO} into {gs.DEFAULT_MONITOR_DIR} '
                        'and apply setup now? [yes/NO] ') == 'yes'
                if proceed:
                    args.apply = True
                    setup_global(store, args)
            elif choice == '14':
                code, expires = store.make_pair_code(10)
                print_pair_code(store, code, expires)
            elif choice == '15':
                origin = input('Global HTTPS address (for example https://api.example.com): ').strip()
                store.pair_by_code(origin, input('One-time pairing code: ').strip())
                status('Global paired and verified', 'success')
            elif choice == '16':
                sid = input('Global server ID: ').strip()
                if input('Rotate this Global\'s key now? The new key is verified before it is saved. [yes/NO] ') == 'yes':
                    store.rotate_global(sid)
                    status('Key rotated and verified; nothing needs to be copied', 'success')
            elif choice == '13':
                import ats_doctor
                print(ats_doctor.run(store).text())
            elif choice == '12':
                with open(input('New private pairing file path: ').strip()) as f:
                    bundle = json.load(f)
                sid = store.find_server(bundle)
                saved = store.server(sid)
                if input(f"Replace the saved ID/passkey of {saved['name']} ({saved['id'][:8]}…)? [yes/NO] ") != 'yes':
                    raise ValueError('Cancelled; nothing was changed')
                store.replace_credentials(sid, bundle['id'], bundle['name'], bundle['domain'], bundle['secret'])
                status('Credentials verified and updated; connection state preserved (use Reconnect if it was disconnected)', 'success')
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
        except (ValueError, OSError, KeyError, sqlite3.Error, yaml.YAMLError) as exc:
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
