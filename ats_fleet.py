"""The Local's fleet watcher: probes every connected Global, records what happened, and alerts on change.

State lives in the private registry, so the Monitor can show it without talking to any Global. A server is
declared down only after several consecutive failed checks (no alerts for one dropped packet), recovery is
announced once, and a server that stays down is mentioned again every six hours rather than every minute.
"""
import asyncio
import logging
import time

import ats_cluster as cluster
import ats_notify
import ats_registry_backup
import ats_status

INTERVAL = 60
REPEAT_DOWN = 6 * 3600
MAX_EVENTS = 200
log = logging.getLogger('ats.fleet')


def probe(server):
    """(ok, data, error). A Global that predates the status request is still checked with a plain health request."""
    try:
        return True, cluster.remote(server, {'kind': 'status'}, timeout=10), None
    except cluster.TransportError as status_error:
        try:
            return True, dict(cluster.remote(server, {'kind': 'health'}, timeout=8), legacy=True), None
        except cluster.TransportError as health_error:
            return False, None, str(health_error if health_error.code != 'unavailable' else status_error)


def compact(data, now):
    metrics = (data or {}).get('metrics') or {}
    disks = metrics.get('disks') or []
    memory = metrics.get('memory') or {}
    return {'at': now, 'cpu': metrics.get('cpu_percent'), 'memory': memory.get('used_percent'),
            'disk': max((d['used_percent'] for d in disks), default=None), 'uptime': (data or {}).get('host', {}).get('uptime'),
            'ats': ((data or {}).get('ats') or {}).get('short'), 'companion': ((data or {}).get('companion') or {}).get('short'),
            'legacy': bool((data or {}).get('legacy'))}


def resources(entry, name, data, thresholds):
    """Alerts for crossing the disk or memory threshold (once), and for dropping back under it."""
    metrics = (data or {}).get('metrics') or {}
    found, flags = [], entry.setdefault('flags', {})
    disk = max((d['used_percent'] for d in metrics.get('disks') or []), default=0)
    memory = (metrics.get('memory') or {}).get('used_percent') or 0
    for key, value, limit, label in (('disk', disk, thresholds['disk'], 'disk'), ('memory', memory, thresholds['memory'], 'memory')):
        if value >= limit and not flags.get(key):
            flags[key] = True
            found.append(('warn', f'{name}: {label} is {value:.0f}% full (alert threshold {limit}%)'))
        elif value < limit - 5 and flags.get(key):
            flags[key] = False
            found.append(('recovered', f'{name}: {label} is back down to {value:.0f}%'))
    return found


def cycle(store, now=None, probe=probe, send=ats_notify.send, local=ats_status.collect):
    now = int(now or time.time())
    config = ats_notify.load(store)
    thresholds = config['thresholds']
    state = store.kv_get('fleet_state', {})
    events = store.kv_get('fleet_events', [])
    announcements = []

    def record(kind, server_id, name, message):
        events.append({'at': now, 'server_id': server_id, 'name': name, 'kind': kind, 'message': message})
        announcements.append((kind, name, message))

    seen = set()
    for summary in store.servers():
        sid, name = summary['id'], summary['name']
        seen.add(sid)
        entry = state.setdefault(sid, {'status': 'unknown', 'fails': 0, 'since': now, 'last_alert': 0})
        entry['name'] = name
        if summary['local']:
            try:
                data = local()
            except Exception:
                continue
            entry.update(status='up', fails=0, last_ok=now, error=None, metrics=compact(data, now))
            for kind, message in resources(entry, name, data, thresholds):
                record(kind, sid, name, message)
            continue
        if not summary['paired'] or not summary['connected'] or summary['revocation_pending']:
            entry.update(status='disabled', fails=0, error=None)
            continue
        ok, data, error = probe(store.server(sid))
        if ok:
            was = entry['status']
            entry.update(fails=0, last_ok=now, error=None, metrics=compact(data, now))
            if was != 'up':
                entry.update(status='up', since=now)
            if was == 'down':
                record('recovered', sid, name, f'{name} is reachable again')
            for kind, message in resources(entry, name, data, thresholds):
                record(kind, sid, name, message)
        else:
            entry['fails'] += 1
            entry['error'] = error
            if entry['fails'] >= thresholds['failures'] and entry['status'] != 'down':
                entry.update(status='down', since=now, last_alert=now)
                record('down', sid, name, f"{name} is unreachable after {entry['fails']} failed checks: {error}")
            elif entry['status'] == 'down' and now - entry.get('last_alert', 0) >= REPEAT_DOWN:
                entry['last_alert'] = now
                record('still_down', sid, name, f"{name} has been down since {time.strftime('%Y-%m-%d %H:%M', time.localtime(entry['since']))}: {error}")
    for gone in set(state) - seen:
        del state[gone]
    store.kv_set('fleet_state', state)
    store.kv_set('fleet_events', events[-MAX_EVENTS:])
    if announcements and any(config['enabled'].values()):
        worst = 'down' if any(k in ('down', 'still_down') for k, _, _ in announcements) else 'warn' if any(k == 'warn' for k, _, _ in announcements) else 'recovered'
        title = 'ATS: ' + (announcements[0][1] if len(announcements) == 1 else f'{len(announcements)} fleet changes')
        outcome = send(config, title, '\n'.join(m for _, _, m in announcements), worst)
        store.kv_set('fleet_notify', {'at': now, 'outcome': outcome})
    return announcements


async def worker(store=None):
    store = store or cluster.Store()
    while True:
        try:
            await asyncio.to_thread(cycle, store)
        except Exception:
            log.exception('Fleet check failed')
        await asyncio.sleep(INTERVAL)


async def backup_worker(store=None):
    store = store or cluster.Store()
    while True:
        try:
            await asyncio.to_thread(ats_registry_backup.run_scheduled, store)
        except Exception:
            log.exception('Registry backup failed')
        await asyncio.sleep(3600)
