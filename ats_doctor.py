"""Read-only multi-server health check with plain-language fixes.

Run ``server doctor`` on a Local to test every paired Global end to end, or on a
Global to test its API service, tunnel route, Monitor adapter and pairing file.
It changes nothing and never prints a key, signature or remote response body.
"""
import json
import os
from pathlib import Path
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


def run(store, *, port=None, cloudflare_config=None, **plan_options):
    report = Report()
    node = store.node()
    if not node:
        report.add(FAIL, 'ATS setup', 'this instance is not configured', 'run: sudo python3 app.py (interactive) or server configure')
        return report
    registry_checks(report, store)
    if node['role'] == 'local':
        check_local(report, store, node)
    else:
        check_global(report, store, node, port, cloudflare_config, **plan_options)
    return report
