"""
Test harness: load app.py against a throw-away ATS_HOME with fake executables.

app.py is a root-only CLI that reads its config and opens its database at
import time. This helper:

  * builds a temp tree (ATS_HOME, storage root, a cloudflared config),
  * writes a config yaml and points ATS_CONFIG_FILE at it,
  * puts fake `systemctl`, `sudo`, `git`, `openssl`, `rclone`, `journalctl`,
    `npm`, `node` executables first on PATH,
  * patches os.geteuid -> 0 while the module is imported,
  * imports a *fresh* copy of app.py and returns it.

PyYAML is needed by app.py; if it is not installed, put a directory that has
it on PYTHONPATH (e.g. `pip install --target /tmp/ats-pydeps pyyaml`).
"""
import grp
import importlib.util
import logging
import os
import pwd
import shutil
import stat
import sys
import tempfile
from unittest import mock

APP_PY = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")

_FAKES = {}

_FAKES["systemctl"] = r'''#!/bin/sh
echo "systemctl $*" >> "$FAKE_STATE/calls.log"
action="$1"
if [ -n "$FAKE_SYSTEMCTL_FAIL" ] && [ "$FAKE_SYSTEMCTL_FAIL" = "$action" ]; then
    echo "Job failed" >&2
    exit 1
fi
case "$action" in
    is-active)
        f="$FAKE_STATE/active_$2"
        if [ -f "$f" ]; then cat "$f"; else echo active; fi
        [ "$(cat "$f" 2>/dev/null || echo active)" = "active" ] && exit 0 || exit 3
        ;;
    show) echo 0 ;;
    status) echo "* $2.service - fake unit"; echo "   Active: active (running)" ;;
esac
exit 0
'''

_FAKES["sudo"] = r'''#!/bin/sh
# fake sudo: `sudo -u <user> cmd...` just runs cmd
if [ "$1" = "-u" ]; then shift 2; fi
exec "$@"
'''

_FAKES["git"] = r'''#!/bin/sh
echo "git $*" >> "$FAKE_STATE/calls.log"
if [ -n "$FAKE_GIT_SLEEP" ]; then sleep "$FAKE_GIT_SLEEP"; fi
case "$1" in
    pull)
        if [ "$FAKE_GIT_FAIL" = "1" ]; then echo "fatal: could not read from remote" >&2; exit 1; fi
        if [ "$FAKE_GIT_UPTODATE" = "1" ]; then echo "Already up to date."; else echo "Updating abc..def"; echo " 1 file changed"; fi
        ;;
    clone)
        # git clone -b <branch> <url> <dir>
        dir=""; for a in "$@"; do dir="$a"; done
        mkdir -p "$dir"; echo "print('hi')" > "$dir/app.py"; echo "flask" > "$dir/requirements.txt"
        ;;
esac
exit 0
'''

_FAKES["openssl"] = r'''#!/usr/bin/env python3
import os, sys
state = os.environ["FAKE_STATE"]
with open(os.path.join(state, "openssl_argv.log"), "a") as f:
    f.write(" ".join(sys.argv[1:]) + "\n")
args = sys.argv[1:]
if args[:1] == ["rand"]:
    if os.environ.get("FAKE_OPENSSL_RAND_FAIL"):
        sys.stderr.write("rand failed\n"); sys.exit(1)
    if os.environ.get("FAKE_OPENSSL_RAND_EMPTY"):
        sys.exit(0)
    print("ab" * 32); sys.exit(0)
if args[:1] == ["enc"]:
    if os.environ.get("FAKE_OPENSSL_ENC_FAIL"):
        sys.stderr.write("enc failed\n"); sys.exit(1)
    dec = "-d" in args
    src = args[args.index("-in") + 1]
    dst = args[args.index("-out") + 1]
    data = open(src, "rb").read()
    if dec:
        if not data.startswith(b"ENCRYPTED:"):
            sys.exit(1)
        data = data[len(b"ENCRYPTED:"):]
    else:
        data = b"ENCRYPTED:" + data
    open(dst, "wb").write(data)
    sys.exit(0)
sys.exit(0)
'''

_FAKES["rclone"] = r'''#!/usr/bin/env python3
import os, shutil, sys
state = os.environ["FAKE_STATE"]
remote_root = os.path.join(state, "remote")
args = sys.argv[1:]
with open(os.path.join(state, "rclone_argv.log"), "a") as f:
    f.write(" ".join(args) + "\n")

def remote_dir(spec):
    # gdrive:backups/<name>  ->  <state>/remote/<name>
    path = spec.split(":", 1)[1] if ":" in spec else spec
    return os.path.join(remote_root, path)

cmd = args[0] if args else ""
if cmd == "copy":
    src, dst = args[1], args[2]
    if ":" in src and not os.path.exists(src):          # download: remote file -> local dir
        shutil.copy(remote_dir(src), os.path.join(dst, os.path.basename(src)))
    else:                                              # upload: local file -> remote dir
        if os.environ.get("FAKE_RCLONE_FAIL"):
            sys.stderr.write("upload failed\n"); sys.exit(1)
        d = remote_dir(dst)
        os.makedirs(d, exist_ok=True)
        shutil.copy(src, os.path.join(d, os.path.basename(src)))
elif cmd == "lsf":
    d = remote_dir(args[1])
    if os.path.isdir(d):
        for n in sorted(os.listdir(d)):
            print(n)
    for extra in os.environ.get("FAKE_RCLONE_LSF_EXTRA", "").split(","):
        if extra:
            print(extra)
elif cmd == "size":
    print('{"count": 1, "bytes": 1024}')
sys.exit(0)
'''

_FAKES["journalctl"] = "#!/bin/sh\necho 'fake journal'\n"
_FAKES["npm"] = "#!/bin/sh\necho \"npm $*\" >> \"$FAKE_STATE/calls.log\"\nexit 0\n"
_FAKES["node"] = "#!/bin/sh\necho v20.0.0\n"


class AppEnv:
    """A loaded copy of app.py plus the temp tree it runs against."""

    def __init__(self, root: str, app, env_patch, euid_patch):
        self.root = root
        self.app = app
        self.home = os.path.join(root, "ats_home")
        self.storage = os.path.join(root, "storage")
        self.state = os.path.join(root, "state")
        self.bin = os.path.join(root, "bin")
        self.cf_config = os.path.join(root, "cloudflared.yml")
        self._env_patch = env_patch
        self._euid_patch = euid_patch
        self._handlers = []

    def calls(self) -> str:
        path = os.path.join(self.state, "calls.log")
        if not os.path.exists(path):
            return ""
        with open(path) as f:
            return f.read()

    def argv_log(self, tool: str) -> str:
        path = os.path.join(self.state, f"{tool}_argv.log")
        if not os.path.exists(path):
            return ""
        with open(path) as f:
            return f.read()

    def close(self):
        root_logger = logging.getLogger()
        for h in list(root_logger.handlers):
            if getattr(h, "_ats_test", False):
                root_logger.removeHandler(h)
                try:
                    h.close()
                except Exception:
                    pass
        self._env_patch.stop()
        self._euid_patch.stop()
        shutil.rmtree(self.root, ignore_errors=True)


def load_app(extra_env=None) -> AppEnv:
    """Create the temp tree and import a fresh app.py. Call .close() when done."""
    import yaml  # noqa: F401  (fail early with a clear error if PyYAML is missing)

    root = tempfile.mkdtemp(prefix="ats-test-")
    home = os.path.join(root, "ats_home")
    storage = os.path.join(root, "storage")
    state = os.path.join(root, "state")
    bindir = os.path.join(root, "bin")
    for d in (home, storage, state, bindir):
        os.makedirs(d, exist_ok=True)

    for name, body in _FAKES.items():
        path = os.path.join(bindir, name)
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    cf_config = os.path.join(root, "cloudflared.yml")
    with open(cf_config, "w") as f:
        f.write("tunnel: test\ningress:\n  - service: http_status:404\n")

    user = pwd.getpwuid(os.getuid()).pw_name
    cfg_path = os.path.join(root, "config.yml")
    import yaml
    with open(cfg_path, "w") as f:
        yaml.safe_dump({
            "service_user": user,
            "service_group": grp.getgrgid(os.getgid()).gr_name,
            "main_domain": "example.com",
            "default_storage": storage,
            "cloudflare_config": cf_config,
            "ats_home": home,
        }, f)

    env = {
        "ATS_CONFIG_FILE": cfg_path,
        "ATS_HOME": home,
        "FAKE_STATE": state,
        "PATH": bindir + os.pathsep + os.environ.get("PATH", ""),
    }
    env.update(extra_env or {})
    env_patch = mock.patch.dict(os.environ, env)
    env_patch.start()
    euid_patch = mock.patch("os.geteuid", return_value=0)
    euid_patch.start()

    before = set(logging.getLogger().handlers)
    spec = importlib.util.spec_from_file_location(f"ats_app_{os.path.basename(root)}", APP_PY)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    old_argv = sys.argv
    sys.argv = ["app.py"]
    try:
        spec.loader.exec_module(module)
    except BaseException:
        env_patch.stop()
        euid_patch.stop()
        raise
    finally:
        sys.argv = old_argv
    env_obj = AppEnv(root, module, env_patch, euid_patch)
    for h in logging.getLogger().handlers:
        if h not in before:
            h._ats_test = True
            if type(h) is logging.StreamHandler:
                h.setLevel(logging.CRITICAL)      # keep test output readable; the log file still gets everything
    return env_obj
