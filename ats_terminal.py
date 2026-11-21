"""Interactive terminal sessions on a Global, served over the signed request channel.

A Local Monitor relays a browser terminal to a Global with five signed calls: ``term.open``,
``term.read`` (long poll), ``term.input``, ``term.resize`` and ``term.close``. They travel through the
same authenticated HTTPS route as every other call, so no new tunnel route or port is needed.

Safety properties:
* The shell runs as the ATS service user, never as root, unless the operator sets ATS_TERMINAL_ALLOW_ROOT=1.
* At most MAX_SESSIONS sessions exist at once; idle sessions are closed after IDLE_SECONDS.
* Output is buffered in memory only (bounded); keystrokes and output are never logged or stored.
* ATS_TERMINAL=off disables the feature entirely.
* Reads are idempotent: the caller acknowledges what it received by asking for the next offset, so a
  lost response is simply requested again.
"""
import base64
import fcntl
import json
import os
import pwd
import re
import secrets
import select
import shutil
import struct
import subprocess
import sys
import termios
import threading
import time

SID = re.compile(r'[0-9a-f]{32}\Z')
REF = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:@/\-]{0,254}\Z')
MAX_SESSIONS = 3
IDLE_SECONDS = 600
BUFFER_LIMIT = 256 * 1024
READ_CHUNK = 64 * 1024
MAX_INPUT = 64 * 1024
MAX_WAIT = 20.0
COALESCE = 0.03
PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

HELPER = r'''
import fcntl, json, os, sys, termios
spec = json.loads(sys.argv[1])
os.setsid()
fcntl.ioctl(0, termios.TIOCSCTTY, 1)
if os.geteuid() == 0 and spec['uid'] != 0:
    os.initgroups(spec['name'], spec['gid'])
    os.setgid(spec['gid'])
    os.setuid(spec['uid'])
try:
    os.chdir(spec['home'])
except OSError:
    os.chdir('/')
os.execvpe(spec['argv'][0], spec['argv'], spec['env'])
'''


class TerminalError(ValueError):
    """A failure whose message is written here and safe to return to the signed caller."""


def settings():
    try:
        import ats_server_cli
        return ats_server_cli.ats_settings()
    except (ImportError, OSError, ValueError):
        return {}


def terminal_user():
    """The account the shell runs as: ATS_TERMINAL_USER, else the ATS service user."""
    name = os.environ.get('ATS_TERMINAL_USER') or settings().get('service_user')
    if not name:
        raise TerminalError('No terminal user is configured; set ATS_TERMINAL_USER or the ATS service user')
    try:
        entry = pwd.getpwnam(name)
    except KeyError:
        raise TerminalError('The terminal user does not exist on this server') from None
    if entry.pw_uid == 0 and os.environ.get('ATS_TERMINAL_ALLOW_ROOT') != '1':
        raise TerminalError('The terminal would run as root. Set ATS_TERMINAL_USER to a normal account '
                            '(or ATS_TERMINAL_ALLOW_ROOT=1 to allow root deliberately)')
    return entry


def available():
    """(enabled, reason). The reason is empty when enabled and safe to show an operator."""
    if os.environ.get('ATS_TERMINAL', '').lower() in ('off', '0', 'false', 'no'):
        return False, 'Disabled on this server (ATS_TERMINAL=off)'
    try:
        terminal_user()
    except TerminalError as exc:
        return False, str(exc)
    return True, ''


def _size(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))


def _dimension(value, default, low=1, high=1000):
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(low, min(high, value))


class Session:
    def __init__(self, process, master, owner, kind):
        self.process, self.master, self.owner, self.kind = process, master, owner, kind
        self.cond = threading.Condition()
        self.buffer = bytearray()
        self.base = 0              # absolute offset of buffer[0]
        self.exited = False
        self.status = None
        self.touched = time.monotonic()
        self.closing = False
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        while True:
            try:
                ready, _, _ = select.select([self.master], [], [], 0.5)
                if ready:
                    data = os.read(self.master, 65536)
                    if not data:
                        break
                elif self.process.poll() is not None:
                    break
                else:
                    continue
            except OSError:
                break
            with self.cond:
                self.buffer += data
                if len(self.buffer) > BUFFER_LIMIT:
                    drop = len(self.buffer) - BUFFER_LIMIT
                    del self.buffer[:drop]
                    self.base += drop
                self.cond.notify_all()
        try:
            status = self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.kill()
            status = self.process.wait()
        with self.cond:
            self.exited, self.status = True, status
            self.cond.notify_all()

    def read(self, since, wait):
        deadline = time.monotonic() + wait
        with self.cond:
            self.touched = time.monotonic()
            lost = since < self.base
            since = max(since, self.base)
            since = min(since, self.base + len(self.buffer))
            if since > self.base:                       # the caller has received everything below `since`
                del self.buffer[:since - self.base]
                self.base = since
            while not self.buffer and not self.exited:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.cond.wait(remaining)
            if self.buffer and not self.exited:
                self.cond.wait(COALESCE)                # let a burst of output arrive together
            chunk = bytes(self.buffer[:READ_CHUNK])
            finished = self.exited and not self.buffer
            return {'data': base64.b64encode(chunk).decode(), 'next': self.base + len(chunk), 'lost': lost,
                    'exited': finished, 'status': self.status if finished else None}

    def write(self, data):
        self.touched = time.monotonic()
        view, deadline = memoryview(data), time.monotonic() + 2
        while view:
            try:
                view = view[os.write(self.master, view):]
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise TerminalError('The terminal is not accepting input')
                select.select([], [self.master], [], 0.1)
            except OSError:
                raise TerminalError('The terminal has ended') from None

    def resize(self, rows, cols):
        self.touched = time.monotonic()
        try:
            _size(self.master, rows, cols)
        except OSError:
            raise TerminalError('The terminal has ended') from None

    def close(self):
        if self.closing:
            return
        self.closing = True
        import signal
        try:
            os.killpg(self.process.pid, signal.SIGHUP)
        except (ProcessLookupError, PermissionError, OSError):
            pass

        def finish():
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    self.process.kill()
                self.process.wait()
            try:
                os.close(self.master)
            except OSError:
                pass
        threading.Thread(target=finish, daemon=True).start()


_sessions = {}
_lock = threading.Lock()
_reaper = None


def _reap_loop():
    while True:
        time.sleep(15)
        cutoff = time.monotonic() - IDLE_SECONDS
        with _lock:
            stale = [sid for sid, s in _sessions.items() if s.touched < cutoff]
            for sid in stale:
                session = _sessions.pop(sid)
                session.close()
                print(f'terminal {sid[:8]} closed after {IDLE_SECONDS} s idle', flush=True)


def _session(sid):
    if not isinstance(sid, str) or not SID.match(sid):
        raise TerminalError('Invalid terminal session')
    with _lock:
        session = _sessions.get(sid)
    if session is None:
        raise TerminalError('The terminal session no longer exists')
    return session


def open_session(data):
    global _reaper
    enabled, reason = available()
    if not enabled:
        raise TerminalError(reason)
    entry = terminal_user()
    kind = data.get('target', 'shell')
    env = {'HOME': entry.pw_dir, 'USER': entry.pw_name, 'LOGNAME': entry.pw_name, 'TERM': 'xterm-256color',
           'COLORTERM': 'truecolor', 'LANG': os.environ.get('LANG') or 'C.UTF-8', 'PATH': PATH}
    if kind == 'shell':
        shell = '/bin/bash' if os.path.exists('/bin/bash') else (entry.pw_shell or '/bin/sh')
        env['SHELL'] = shell
        argv = [shell] + (['--login'] if shell.endswith('bash') else [])
        label = 'shell'
    elif kind == 'docker':
        container = data.get('container')
        if not isinstance(container, str) or not REF.match(container):
            raise TerminalError('Invalid container reference')
        docker = shutil.which(os.environ.get('DOCKER_BIN', 'docker'), path=PATH)
        if not docker:
            raise TerminalError('Docker is not installed on this server')
        argv = [docker, 'exec', '-it', container, 'sh', '-c', 'command -v bash >/dev/null 2>&1 && exec bash || exec sh']
        label = 'docker ' + container[:40]
    else:
        raise TerminalError('Unsupported terminal target')
    with _lock:
        live = [s for s in _sessions.values() if not s.exited and not s.closing]
        if len(live) >= MAX_SESSIONS:
            raise TerminalError(f'Too many terminals are open on this server (limit {MAX_SESSIONS}); close one first')
        import pty
        master, slave = pty.openpty()
        try:
            _size(master, _dimension(data.get('rows'), 24), _dimension(data.get('cols'), 80))
            spec = {'uid': entry.pw_uid, 'gid': entry.pw_gid, 'name': entry.pw_name, 'home': entry.pw_dir, 'argv': argv, 'env': env}
            process = subprocess.Popen([sys.executable, '-I', '-c', HELPER, json.dumps(spec)], stdin=slave, stdout=slave,
                                       stderr=slave, close_fds=True, env={'PATH': PATH})
        except OSError:
            os.close(master)
            raise TerminalError('The terminal could not be started') from None
        finally:
            os.close(slave)
        flags = fcntl.fcntl(master, fcntl.F_GETFL)
        fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)
        sid = secrets.token_hex(16)
        _sessions[sid] = Session(process, master, entry.pw_name, label)
        if _reaper is None:
            _reaper = threading.Thread(target=_reap_loop, daemon=True)
            _reaper.start()
    print(f'terminal {sid[:8]} opened ({label}) as {entry.pw_name}', flush=True)
    return {'sid': sid, 'user': entry.pw_name}


def handle(kind, data):
    action = kind.split('.', 1)[1] if '.' in kind else ''
    if action == 'open':
        return open_session(data)
    session = _session(data.get('sid'))
    if action == 'read':
        since, wait = data.get('since', 0), data.get('wait', MAX_WAIT)
        if isinstance(since, bool) or not isinstance(since, int) or since < 0:
            raise TerminalError('Invalid read offset')
        if isinstance(wait, bool) or not isinstance(wait, (int, float)):
            raise TerminalError('Invalid wait')
        result = session.read(since, max(0.0, min(float(wait), MAX_WAIT)))
        if result['exited']:
            with _lock:
                _sessions.pop(data['sid'], None)
            session.close()
        return result
    if action == 'input':
        text = data.get('data')
        if not isinstance(text, str) or len(text) > MAX_INPUT * 4 // 3 + 8:
            raise TerminalError('Invalid input')
        try:
            raw = base64.b64decode(text, validate=True)
        except ValueError:
            raise TerminalError('Invalid input encoding') from None
        if len(raw) > MAX_INPUT:
            raise TerminalError('Input too large')
        session.write(raw)
        return {'written': len(raw)}
    if action == 'resize':
        session.resize(_dimension(data.get('rows'), 24), _dimension(data.get('cols'), 80))
        return {'ok': True}
    if action == 'close':
        with _lock:
            _sessions.pop(data['sid'], None)
        session.close()
        print(f"terminal {data['sid'][:8]} closed", flush=True)
        return {'closed': True}
    raise TerminalError('Unsupported terminal request')


def close_all():
    """For tests and shutdown: end every session."""
    with _lock:
        sessions = list(_sessions.values())
        _sessions.clear()
    for session in sessions:
        session.close()
