"""Read-only multi-server health check with plain-language fixes.

Run ``server doctor`` on a Local to test every paired Global end to end, or on a
Global to test its API service, tunnel route, Monitor adapter and pairing file.
It changes nothing and never prints a key, signature or remote response body.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import time

import ats_cluster
import ats_global_setup as gs
import ats_server_cli as cli

OK, WARN, FAIL = 'ok', 'warn', 'fail'
MARK = {OK: '✔', WARN: '!', FAIL: '✖'}


class Report:
    def __init__(self):
        self.items = []

    def add(self, level, title, detail='', fix=''):
        self.items.append({'level': level, 'title': title, 'detail': detail, 'fix': fix})

    @property
    def failed(self):
        return any(item['level'] == FAIL for item in self.items)

    def text(self):
        lines = []
        for item in self.items:
            lines.append(f"  {MARK[item['level']]} {item['title']}" + (f" — {item['detail']}" if item['detail'] else ''))
            if item['fix'] and item['level'] != OK:
                lines.append(f"      fix: {item['fix']}")
        problems = sum(item['level'] == FAIL for item in self.items)
        warnings = sum(item['level'] == WARN for item in self.items)
        lines.append('')
        lines.append('All checks passed.' if not problems and not warnings else
                     f'{problems} problem(s), {warnings} warning(s).')
        return '\n'.join(lines)


def timed(function, *args, **kwargs):
    started = time.monotonic()
    try:
        return function(*args, **kwargs), int((time.monotonic()-started)*1000), None
    except (ValueError, OSError) as exc:
        return None, int((time.monotonic()-started)*1000), exc


def registry_checks(report, store):
    path = Path(store.path)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        parent = stat.S_IMODE(path.parent.stat().st_mode)
    except OSError as exc:
        report.add(FAIL, 'Cluster registry', f'cannot read {path}: {exc.strerror}', 'check ATS_CLUSTER_DB and its permissions')
        return
    if mode & 0o077:
        report.add(FAIL, 'Cluster registry permissions', f'{path} is {oct(mode)}; it holds private keys',
                   f'run: chmod 600 {path}')
    elif parent & 0o077:
        report.add(WARN, 'Cluster registry directory', f'{path.parent} is {oct(parent)}; the file itself is private (0600)',
                   f'run: chmod 700 {path.parent} if that directory is used only by ATS')
    else:
        report.add(OK, 'Cluster registry', f'{path} is private (0600 in a 0700 directory)')


def check_local(report, store, node):
    issues = cli.configuration_issues(node)
    if issues:
        report.add(FAIL, 'Local configuration', ', '.join(issues), 'run: sudo python3 app.py server configure --role local')
        return
    report.add(OK, 'Local identity', f"{node['name']} ({node['id'][:8]}…), webhook host {node['webhook']}")
    globals_ = [s for s in store.servers() if not s['local']]
    if not globals_:
        report.add(WARN, 'Global servers', 'none paired yet', 'on a Global run "server export", then pair its file in Monitor → Settings → Servers')
    for summary in globals_:
        label = f"Global “{summary['name']}” ({summary['domain']})"
        server = store.server(summary['id'])
        if summary['revocation_pending']:
            report.add(FAIL, label, 'revocation was never confirmed; the old key may still work',
                       'export a fresh pairing file on that Global and use "server replace-credentials --pairing-file FILE"')
            continue
        if not summary['paired']:
            report.add(FAIL, label, 'revoked: no key is saved', 'export a fresh pairing file on that Global and pair it again')
            continue
        if not summary['connected']:
            report.add(WARN, label, 'disconnected by an operator; no requests are sent', 'use "server reconnect --server-id ID" when ready')
            continue
        health, ms, error = timed(ats_cluster.remote, server, {'kind': 'health'})
        if error:
            code = getattr(error, 'code', 'transport')
            report.add(FAIL, label, f'{error} [{code}]',
                       'after fixing the cause, retry; if the key changed use "server replace-credentials --pairing-file FILE"')
            continue
        if health.get('server_id') != server['id'] or health.get('role') != 'global':
            report.add(FAIL, label, 'answered, but not as this Global identity', 'check the hostname and ID')
            continue
        if health.get('management_ready') is not True:
            report.add(FAIL, label, f'reachable in {ms} ms, but its Monitor adapter is not configured',
                       'on that Global run: sudo python3 app.py server setup --apply')
            continue
        terminal_line(report, label, health)
        version_line(report, label, server)
        read, ms2, error = timed(ats_cluster.remote, server, {'kind': 'http', 'method': 'GET', 'path': '/api/manage/services'})
        if error:
            report.add(FAIL, label, f'signed health passed, but a service read failed: {error}',
                       'on that Global run "server doctor" for the adapter details')
        elif read.get('status') != 200:
            report.add(FAIL, label, f"service read returned HTTP {read.get('status')}", 'on that Global run "server doctor"')
        else:
            report.add(OK, label, f'signed health {ms} ms, service read {ms2} ms')


def clock_check(report):
    try:
        out = subprocess.run(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'],
                             capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return
    if out == 'yes':
        report.add(OK, 'Clock', 'synchronized with NTP (requests are rejected beyond a 120 s skew)')
    elif out == 'no':
        report.add(WARN, 'Clock', 'not synchronized', 'run: timedatectl set-ntp true — a skewed clock makes signed requests fail')


def check_global(report, store, node, port=None, cloudflare_config=None, **plan_options):
    issues = cli.configuration_issues(node)
    if issues:
        report.add(FAIL, 'Global configuration', ', '.join(issues), 'run: sudo python3 app.py server configure --role global')
        return
    report.add(OK, 'Global identity', f"{node['name']} ({node['id'][:8]}…), API origin {node['domain']}")
    pairing = cli.default_pairing_path()
    try:
        info = pairing.stat()
        data = json.loads(pairing.read_text())
        if info.st_mode & 0o077:
            report.add(FAIL, 'Pairing file', f'{pairing} is readable by others', 'chmod 600 it, then run "server export"')
        elif data.get('id') != node['id'] or data.get('secret') != node['secret']:
            report.add(FAIL, 'Pairing file', f'{pairing} holds an outdated ID or key', 'run "server export" to refresh it before pairing')
        else:
            report.add(OK, 'Pairing file', f'{pairing} matches the saved ID and key')
    except FileNotFoundError:
        report.add(WARN, 'Pairing file', f'{pairing} is missing', 'run "server export"')
    except (OSError, ValueError):
        report.add(FAIL, 'Pairing file', f'{pairing} is unreadable or malformed', 'run "server export" after moving the old file aside')
    clock_check(report)
    options = dict(port=port, config_path=cloudflare_config, **plan_options)
    try:
        plan = gs.build_plan(store, **options)
    except gs.MonitorMissing as exc:
        report.add(FAIL, 'Global API service', str(exc), 'run: sudo python3 app.py server setup --apply --install-monitor')
        return
    except (ValueError, OSError) as exc:
        report.add(FAIL, 'Global API service and tunnel', str(exc), 'fix the item above, then run: sudo python3 app.py server setup --apply')
        return
    unit = plan['unit']
    if plan['existing'] or plan['before_unit'] is not None:
        state = ('active' if plan['active'] else 'INACTIVE') + (', enabled at boot' if plan['enabled'] else ', NOT enabled at boot')
        level = OK if plan['active'] and plan['enabled'] else FAIL
        report.add(level, 'Global API service', f'{unit}: {state}', 'run: sudo python3 app.py server setup --apply')
        if plan['before_unit'] is not None and plan['before_unit'][0] != plan['unit_content']:
            report.add(WARN, 'Service file', 'differs from what setup would write', 'run: sudo python3 app.py server setup --apply to refresh it')
    else:
        report.add(FAIL, 'Global API service', 'not installed', 'run: sudo python3 app.py server setup --apply')
    host = gs.urlsplit(node['domain']).hostname
    if plan['before_cf'][0] != plan['cf_content']:
        report.add(FAIL, 'Tunnel route', f"{host} → http://127.0.0.1:{plan['port']} is missing from {plan['cf']}",
                   'run: sudo python3 app.py server setup --apply')
    else:
        report.add(OK, 'Tunnel route', f"{host}/v1/request → 127.0.0.1:{plan['port']} is in {plan['cf']}")
    try:
        with socket.create_connection(('127.0.0.1', plan['port']), timeout=3):
            report.add(OK, 'API port', f"something is listening on 127.0.0.1:{plan['port']}")
    except OSError:
        report.add(FAIL, 'API port', f"nothing is listening on 127.0.0.1:{plan['port']}",
                   f'start the service: sudo systemctl start {unit}; read its log with journalctl -u {unit} -n 50')
        return
    try:
        gs.adapter_check(plan, plan_options.get('runner', gs.run))
        report.add(OK, 'Monitor adapter', plan['adapter_env']['ATS_MONITOR_ADAPTER'])
    except ValueError as exc:
        report.add(FAIL, 'Monitor adapter', str(exc), 'install the missing Python modules for the interpreter named above, then retry')
    for label, public in (('Signed health (loopback)', False), ('Signed health (public HTTPS)', True)):
        _, ms, error = timed(gs.verify_health, plan, public=public)
        if error:
            code = getattr(error, 'code', '')
            report.add(FAIL if not public else WARN, label, f'{error}' + (f' [{code}]' if code else ''),
                       'restart the daemon and read its journal' if not public else
                       'check the tunnel DNS record and that cloudflared is running')
        else:
            report.add(OK, label, f'{ms} ms')
    _, ms, error = timed(gs.verify_health, plan, management=True)
    report.add(FAIL if error else OK, 'Adapter service read (loopback)', f'{error}' if error else f'{ms} ms',
               'run "server doctor" again after fixing the adapter' if error else '')


def terminal_line(report, label, health):
    """Whether a Global can open terminals for Monitor. Older Globals do not report it at all."""
    if 'terminal' not in health:
        report.add(WARN, f'{label}: terminal', 'this Global runs an older ATS that cannot report terminal support',
                   'update it: Monitor → Settings → Servers → Update, or git pull on that server and restart ATS')
    elif health['terminal']:
        report.add(OK, f'{label}: terminal', 'available (Monitor can open a shell on it)')
    else:
        report.add(WARN, f'{label}: terminal', health.get('terminal_reason') or 'not available',
                   'a terminal needs a PTY and a login shell for the service user; see the reason above')


def version_line(report, label, server):
    """Compare the Global's code to this Local's. Differences are a warning, not a failure: mixed versions usually work."""
    import ats_status
    try:
        remote_info = ats_cluster.remote(server, {'kind': 'status'}, timeout=15)
    except ats_cluster.TransportError:
        report.add(WARN, f'{label}: version', 'this Global does not report its version (older ATS)',
                   'update it: Monitor → Settings → Servers → Update, or git pull on that server and restart ATS')
        return
    mine = ats_status.repo_info(Path(__file__).resolve().parent).get('commit')
    theirs = (remote_info.get('ats') or {})
    if not theirs.get('available'):
        report.add(WARN, f'{label}: version', 'the ATS folder on that Global is not a git checkout, so it cannot be compared or updated remotely')
    elif mine and theirs.get('commit') != mine:
        report.add(WARN, f'{label}: version', f"ATS {theirs.get('short')} on the Global, {mine[:7]} here",
                   'update the older one: Monitor → Settings → Servers → Update')
    else:
        report.add(OK, f'{label}: version', f"ATS {theirs.get('short')} (same as this Local)")


def tool_checks(report):
    """Docker and rclone are optional, but deployments and backups need them; say what is missing and how to add it."""
    def run_quiet(argv, timeout=10):
        try:
            return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return None
    if not shutil.which('docker'):
        report.add(WARN, 'Docker', 'not installed (needed by Docker-based services)',
                   'Monitor → Settings → Servers → Install Docker, or: sudo apt-get install docker.io')
    else:
        result = run_quiet(['docker', 'version', '--format', '{{.Server.Version}}'])
        if result and result.returncode == 0 and result.stdout.strip():
            report.add(OK, 'Docker', f'version {result.stdout.strip()}, daemon reachable')
        else:
            report.add(FAIL, 'Docker', 'installed but the daemon does not answer',
                       'start it: sudo systemctl enable --now docker; check with: sudo docker info')
    if not shutil.which('rclone'):
        report.add(WARN, 'rclone', 'not installed (needed for cloud backups)',
                   'Monitor → Settings → Servers → Install rclone, or: sudo apt-get install rclone')
    else:
        result = run_quiet(['rclone', 'listremotes'])
        remotes = [x for x in (result.stdout.split() if result and result.returncode == 0 else [])]
        if result is None or result.returncode:
            report.add(FAIL, 'rclone', 'installed but "rclone listremotes" failed', 'run it by hand to see why')
        elif remotes:
            report.add(OK, 'rclone', f'{len(remotes)} remote(s) configured')
        else:
            report.add(WARN, 'rclone', 'installed but no remote is configured', 'run: rclone config')
    import ats_terminal
    ok, reason = ats_terminal.available()
    report.add(OK if ok else WARN, 'Terminal', 'this server can open terminals for Monitor' if ok else (reason or 'not available'),
               '' if ok else 'a terminal needs a PTY and a login shell for the service user')


def backup_and_alert_checks(report, store, node):
    import ats_notify
    import ats_registry_backup as backups
    last = backups.status(store)
    newest = last['newest']
    if not newest:
        report.add(WARN, 'Registry backup', 'no backup exists yet; the registry holds every key',
                   'the daemon makes one daily; make one now with: sudo python3 app.py server backup --encrypt')
    elif time.time() - newest['at'] > 3 * backups.INTERVAL:
        report.add(WARN, 'Registry backup', f"newest backup is {int((time.time() - newest['at']) / 86400)} days old",
                   'check the daemon is running and its journal; or run: sudo python3 app.py server backup')
    elif last['last'] and last['last'].get('error'):
        report.add(WARN, 'Registry backup', 'last scheduled backup failed: ' + last['last']['error'], 'fix the cause, or run: sudo python3 app.py server backup')
    else:
        report.add(OK, 'Registry backup', f"{last['count']} kept, newest {int((time.time() - newest['at']) / 3600)} h old" + (', encrypted' if newest['encrypted'] else ', not encrypted'))
    if node['role'] == 'local':
        config = ats_notify.load(store)
        if not any(config['enabled'].values()):
            report.add(WARN, 'Alerts', 'no alert channel is turned on, so a server going down is only visible in Monitor',
                       'Monitor → Settings → Servers → Alerts: add ntfy, Telegram or a webhook')
        else:
            note = store.kv_get('fleet_notify')
            failed = [k for k, v in ((note or {}).get('outcome') or {}).items() if not v.get('ok')]
            report.add(WARN if failed else OK, 'Alerts', ('last delivery failed for ' + ', '.join(failed)) if failed else
                       'on for ' + ', '.join(k for k, v in config['enabled'].items() if v), 'check the address or token under Alerts' if failed else '')


def run(store, *, port=None, cloudflare_config=None, **plan_options):
    report = Report()
    node = store.node()
    if not node:
        report.add(FAIL, 'ATS setup', 'this instance is not configured', 'run: sudo python3 app.py (interactive) or server configure')
        return report
    registry_checks(report, store)
    backup_and_alert_checks(report, store, node)
    tool_checks(report)
    if node['role'] == 'local':
        check_local(report, store, node)
    else:
        check_global(report, store, node, port, cloudflare_config, **plan_options)
    return report
