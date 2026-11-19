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
        interactive = sys.stdin.isatty()
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
            if not cf:
                parser.error('--cloudflare-config is required to check actual Local tunnel routes')
            with open(cf) as f:
                config = yaml.safe_load(f) or {}
            matches = [r for r in config.get('ingress', []) if r.get('hostname') == host]
            wildcard = [r for r in config.get('ingress', []) if str(r.get('hostname', '')).startswith('*.') and host and host.endswith(str(r['hostname'])[1:])]
            if wildcard and not args.confirm_existing_route:
                parser.error('A wildcard tunnel route covers this hostname; inspect route order and explicitly confirm reuse')
            if len(matches) > 1:
                parser.error('Duplicate webhook hostname in actual tunnel configuration')
            if matches and not args.confirm_existing_route:
                if not interactive or input('Existing route found. Reuse this hostname without changing the route? [yes/NO] ') != 'yes':
                    parser.error('Existing tunnel hostname requires explicit confirmation')
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
                            parser.error('Webhook hostname is already used by a service')
        if role == 'global' and not args.pairing_file:
            parser.error('--pairing-file is required for Global setup')
        n = store.configure(role, label, origin, host)
        if role == 'global':
            save_pairing(store, args.pairing_file)
        print('Configuration saved. Configure/validate TLS proxy, storage and GitHub manually; no services or tunnel routes were changed.')
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
