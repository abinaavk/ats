"""Interactive and headless server setup; never changes production tunnel routes."""
import argparse
import json
import os
from pathlib import Path
import secrets
import sys
import yaml
from ats_cluster import Store


def main():
    parser = argparse.ArgumentParser(description='ATS multi-server configuration (operator-managed TLS, storage and GitHub)')
    parser.add_argument('action', choices=['configure', 'show', 'rotate', 'serve', 'map', 'unmap', 'pair', 'disconnect', 'reconnect', 'revoke'])
    parser.add_argument('--role', choices=['local', 'global'])
    parser.add_argument('--name')
    parser.add_argument('--api-domain')
    parser.add_argument('--webhook-host')
    parser.add_argument('--cloudflare-config')
    parser.add_argument('--confirm-existing-route', action='store_true')
    parser.add_argument('--port', type=int, default=9997)
    parser.add_argument('--pairing-file')
    parser.add_argument('--server-id')
    parser.add_argument('--repository')
    parser.add_argument('--service')
    parser.add_argument('--branch', default='main')
    parser.add_argument('--secret-file')
    parser.add_argument('--replace-mapping', action='store_true')
    args = parser.parse_args()
    store = Store()
    if args.action == 'configure':
        try:
            configure(store, args, sys.stdin.isatty())
        except (ValueError, OSError, yaml.YAMLError, EOFError) as exc:
            parser.error('Server setup failed: ' + str(exc))
    elif args.action == 'show':
        n = store.node()
        print(json.dumps({k: v for k, v in (n or {}).items() if k != 'secret'}))
    elif args.action == 'rotate':
        if not store.node() or store.node()['role'] != 'global':
            parser.error('Rotate pairing credentials on a Global server')
        with store.db() as db:
            db.execute('UPDATE node SET secret=?', (secrets.token_hex(32),))
        save_pairing(store, args.pairing_file)
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
    if role == 'global' and not args.pairing_file and interactive:
        args.pairing_file = input('New private pairing file path (must not exist): ').strip()
    if role == 'global' and not args.pairing_file:
        raise ValueError('--pairing-file is required for Global setup')
    if role == 'global':
        # Reserve the private destination before persisting a new identity.
        fd = os.open(args.pairing_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'w') as f:
                store.configure(role, label, origin, host)
                json.dump(store.node(), f)
        except Exception:
            os.unlink(args.pairing_file)
            raise
        print('Pairing file saved privately. Transfer it securely to the Local operator.')
    else:
        store.configure(role, label, origin, host)
    print('Configuration saved. Configure/validate TLS proxy, storage and GitHub manually; no services or tunnel routes were changed.')


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
                raise ValueError('Configuration saved, but pairing export failed; use server rotate --pairing-file with a new private path') from exc
            print('Setup could not be completed: ' + str(exc))
            if isinstance(exc, (OSError, yaml.YAMLError)):
                cloudflare_config = None

def save_pairing(store, path):
    if not path:
        raise ValueError('--pairing-file is required; transfer this private file to the Local operator securely')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(store.node(), f)
    print('Pairing file saved privately. Do not paste it into logs or public artifacts.')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError) as e:
        print('Server setup failed: ' + str(e), file=sys.stderr)
        sys.exit(1)
