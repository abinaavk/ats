"""Light host status for fleet views: code versions and CPU, memory, disk, load, uptime.

Standard library only, read from /proc and git, cheap enough to ask every few seconds without starting
the Monitor adapter. Nothing here is secret: no keys, paths of credentials, environment or service data.
"""
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import time

_cache = {}
_cpu_last = None


def _git(directory, *args, timeout=5):
    try:
        result = subprocess.run(['git', '-C', str(directory), *args], capture_output=True, text=True, timeout=timeout,
                                stdin=subprocess.DEVNULL, env={'PATH': '/usr/local/bin:/usr/bin:/bin', 'GIT_TERMINAL_PROMPT': '0',
                                                              'HOME': os.environ.get('HOME', '/root'), 'LC_ALL': 'C'})
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def repo_info(directory, ttl=30):
    """Commit, branch and subject of a checkout; cached briefly because git is the slow part."""
    key = str(directory)
    cached = _cache.get(key)
    if cached and time.monotonic() - cached[0] < ttl:
        return cached[1]
    commit = _git(directory, 'rev-parse', 'HEAD')
    if not commit:
        info = {'available': False}
    else:
        branch = _git(directory, 'rev-parse', '--abbrev-ref', 'HEAD')
        info = {'available': True, 'commit': commit, 'short': commit[:7], 'detached': branch == 'HEAD',
                'branch': None if branch in (None, 'HEAD') else branch,
                'subject': (_git(directory, 'log', '-1', '--format=%s') or '')[:120],
                'date': _git(directory, 'log', '-1', '--format=%cI') or ''}
    _cache[key] = (time.monotonic(), info)
    return info


def forget():
    """Drop cached git facts (after an update)."""
    _cache.clear()


def _cpu_times():
    try:
        with open('/proc/stat') as stream:
            fields = [int(x) for x in stream.readline().split()[1:]]
    except (OSError, ValueError):
        return None
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)       # idle + iowait
    return idle, sum(fields[:8])


def cpu_percent():
    """Busy percentage since the previous call; with no recent previous call, over a short 0.25 s sample."""
    global _cpu_last
    now = _cpu_times()
    if now is None:
        return None
    if _cpu_last and 0.5 <= time.monotonic() - _cpu_last[2] <= 120:
        base = _cpu_last[:2]
    else:
        base = now
        time.sleep(0.25)
        now = _cpu_times() or now
    _cpu_last = (now[0], now[1], time.monotonic())
    total = now[1] - base[1]
    return round(100.0 * (1 - (now[0] - base[0]) / total), 1) if total > 0 else 0.0


def memory():
    try:
        values = {}
        with open('/proc/meminfo') as stream:
            for line in stream:
                key, _, rest = line.partition(':')
                values[key] = int(rest.split()[0]) * 1024
        total, available = values['MemTotal'], values.get('MemAvailable', values.get('MemFree', 0))
        return {'total': total, 'available': available, 'used_percent': round(100.0 * (total - available) / total, 1),
                'swap_total': values.get('SwapTotal', 0), 'swap_free': values.get('SwapFree', 0)}
    except (OSError, KeyError, ValueError, ZeroDivisionError):
        return None


def disks(extra=()):
    seen, result = set(), []
    for path in ('/', *extra):
        try:
            device = os.stat(path).st_dev
            if device in seen:
                continue
            seen.add(device)
            usage = shutil.disk_usage(path)
            result.append({'path': path, 'total': usage.total, 'free': usage.free, 'used_percent': round(100.0 * (usage.total - usage.free) / usage.total, 1)})
        except (OSError, ZeroDivisionError):
            continue
    return result


def temperature():
    try:
        return round(int(Path('/sys/class/thermal/thermal_zone0/temp').read_text()) / 1000.0, 1)
    except (OSError, ValueError):
        return None


def uptime():
    try:
        return int(float(Path('/proc/uptime').read_text().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


UNIT = __import__('re').compile(r'[A-Za-z0-9@_.:-]{1,100}\.(service|socket|timer|mount)\Z')


def failed_units(runner=subprocess.run, limit=20):
    """Names of failed systemd units on this host (read-only; empty when systemd is not available)."""
    try:
        result = runner(['systemctl', 'list-units', '--state=failed', '--no-legend', '--plain', '--no-pager', '--full'],
                        capture_output=True, text=True, timeout=8, stdin=subprocess.DEVNULL,
                        env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    names = [line.split()[0] for line in result.stdout.splitlines() if line.split()]
    return [name for name in names if UNIT.match(name)][:limit]


def ops_alerts(path, limit=50):
    """Active, unacknowledged alerts the ATS collector raised (deployment, service, health, backup, disk). Read-only."""
    if not path or not os.path.isfile(path):
        return []
    import sqlite3
    try:
        db = sqlite3.connect(f'file:{path}?mode=ro', uri=True, timeout=3)
        try:
            rows = db.execute('SELECT alert_key,name,kind,message FROM ops_alerts WHERE active=1 AND acknowledged=0 ORDER BY id LIMIT ?', (limit,)).fetchall()
        finally:
            db.close()
    except sqlite3.Error:
        return []
    return [{'key': str(key)[:150], 'name': str(name)[:80], 'kind': str(kind)[:20], 'message': str(message or '')[:200]} for key, name, kind, message in rows]


def collect(adapter=None, storage=(), ops_db=None):
    """Everything a fleet view needs about this host, in one small JSON-safe dict."""
    checkout = Path(__file__).resolve().parent
    companion = Path(adapter).resolve().parent if adapter and Path(adapter).is_file() else None
    try:
        load = [round(x, 2) for x in os.getloadavg()]
    except OSError:
        load = None
    return {'collected_at': int(time.time()), 'host': {'name': socket.gethostname(), 'kernel': platform.release(), 'python': sys.version.split()[0],
                                                       'cpus': os.cpu_count(), 'uptime': uptime(), 'failed_units': failed_units()},
            'alerts': ops_alerts(ops_db),
            'ats': repo_info(checkout), 'companion': repo_info(companion) if companion else {'available': False},
            'metrics': {'cpu_percent': cpu_percent(), 'load': load, 'memory': memory(), 'disks': disks(storage), 'temperature_c': temperature()}}
