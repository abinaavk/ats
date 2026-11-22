"""Update this Global's ATS checkout and Monitor companion from their git remotes, safely.

Only a fast-forward is ever applied, a checkout with local changes is refused, the new code must import
(or compile) before it is kept, and a failed check puts the previous commit back. The daemon then re-executes
itself in place so the new code runs without a unit name, a reboot or an operator.
"""
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import ats_status

LOCK = threading.Lock()
ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'GIT_TERMINAL_PROMPT': '0', 'LC_ALL': 'C'}


class UpdateError(ValueError):
    """A failure whose message is written here and safe to return to the signed caller."""


def git(directory, *args, timeout=60, check=True):
    try:
        result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(directory), *args], capture_output=True, text=True,
                                timeout=timeout, stdin=subprocess.DEVNULL, env=dict(ENV, HOME=os.environ.get('HOME', '/root')))
    except subprocess.TimeoutExpired:
        raise UpdateError(f'git {args[0]} timed out') from None
    except OSError:
        raise UpdateError('git is not installed on this server') from None
    if check and result.returncode:
        lines = [x for x in (result.stderr or result.stdout).strip().splitlines() if x.strip()]
        raise UpdateError(f'git {args[0]} failed: ' + (lines[-1][:200] if lines else 'no details'))
    return result.stdout.strip()


def git_ok(directory, *args):
    """True when the git command exits 0 (used for yes/no questions such as merge-base --is-ancestor)."""
    return subprocess.run(['git', '-C', str(directory), *args], capture_output=True, env=dict(ENV, HOME=os.environ.get('HOME', '/root')),
                          stdin=subprocess.DEVNULL, timeout=30).returncode == 0


def directories(adapter=None):
    """The two checkouts this daemon runs: ATS itself and, if installed, the Monitor companion."""
    adapter = adapter or os.environ.get('ATS_MONITOR_ADAPTER')
    result = {'ats': Path(__file__).resolve().parent}
    if adapter and Path(adapter).is_file():
        result['companion'] = Path(adapter).resolve().parent
    return result


def check_code(name, directory):
    if name == 'ats':
        code = ('import sys; sys.path.insert(0, sys.argv[1]); import ats_cluster, ats_remote, ats_terminal, ats_server_cli, ats_update, ats_status')
        argv = [sys.executable, '-I', '-c', code, str(directory)]
    else:
        files = [str(p) for p in (Path(directory) / 'remote_host.py', Path(directory) / 'app.py', Path(directory) / 'manage_api.py') if p.is_file()]
        argv = [sys.executable, '-I', '-m', 'py_compile', *files]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL, cwd=str(directory))
    if result.returncode:
        raise UpdateError('the new code failed its check: ' + ((result.stderr or '').strip().splitlines() or ['no details'])[-1][:200])


def update_one(name, directory, branch=None):
    """Fast-forward one checkout. Returns what changed; raises UpdateError and leaves the checkout as it was."""
    directory = Path(directory)
    if git(directory, 'rev-parse', '--is-inside-work-tree', check=False) != 'true':
        raise UpdateError(f'{name}: {directory} is not a git checkout')
    if git(directory, 'status', '--porcelain', '--untracked-files=no'):
        raise UpdateError(f'{name}: the checkout has local changes; commit or discard them first')
    before = git(directory, 'rev-parse', 'HEAD')
    current = git(directory, 'rev-parse', '--abbrev-ref', 'HEAD')
    detached = current == 'HEAD'
    target = branch or os.environ.get('ATS_UPDATE_BRANCH') or (None if detached else current) or 'main'
    git(directory, 'fetch', '--quiet', 'origin', target, timeout=180)
    incoming = git(directory, 'rev-parse', 'FETCH_HEAD')
    if incoming == before:
        return {'changed': False, 'before': before[:7], 'after': before[:7], 'commits': [], 'detached': detached}
    if not git_ok(directory, 'merge-base', '--is-ancestor', before, incoming):
        raise UpdateError(f'{name}: this checkout has commits that {target} does not; it cannot be fast-forwarded')
    commits = git(directory, 'log', '--format=%s', f'{before}..{incoming}', '-n', '10').splitlines()
    git(directory, 'checkout', '--quiet', '--detach', incoming) if detached else git(directory, 'merge', '--ff-only', '--quiet', incoming)
    try:
        check_code(name, directory)
    except (UpdateError, subprocess.SubprocessError) as exc:
        git(directory, 'checkout', '--quiet', '--detach', before) if detached else git(directory, 'reset', '--quiet', '--hard', before)
        raise UpdateError(f'{name}: {exc}; the previous version was restored') from None
    ats_status.forget()
    return {'changed': True, 'before': before[:7], 'after': incoming[:7], 'commits': commits, 'detached': detached}


def schedule_restart(delay=1.5):
    """Re-execute this daemon in place after the reply has been sent. The PID, environment and arguments stay the same."""
    def restart():
        time.sleep(delay)
        argv = list(getattr(sys, 'orig_argv', None) or [sys.executable, *sys.argv])
        os.execv(sys.executable, argv)
    threading.Thread(target=restart, daemon=True).start()


def update(targets='both', restart=True, dirs=None, restarter=schedule_restart):
    if targets not in ('ats', 'companion', 'both'):
        raise UpdateError('Choose ats, companion or both')
    if not LOCK.acquire(blocking=False):
        raise UpdateError('An update is already running')
    try:
        dirs = dirs or directories()
        wanted = [name for name in ('ats', 'companion') if targets in ('both', name)]
        if 'companion' in wanted and 'companion' not in dirs:
            if targets == 'companion':
                raise UpdateError('The Monitor companion is not installed on this server')
            wanted.remove('companion')
        result = {name: update_one(name, dirs[name]) for name in wanted}
        result['restart'] = bool(restart and result.get('ats', {}).get('changed'))
        if result['restart']:
            restarter()
        return result
    finally:
        LOCK.release()
