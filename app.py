import os
import sys

# Headless entry must run before config, logging, database or interactive setup.
if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "--api":
    from ats_headless import main as _headless_main
    sys.exit(_headless_main(__file__))
if __name__ == "__main__" and len(sys.argv) > 1 and sys.argv[1] == "server":
    from ats_server_cli import main as _server_main
    del sys.argv[1]
    _server_main()
    sys.exit(0)
import subprocess
import sqlite3
import shutil
import time
import re
import logging
import fcntl
import socket
import atexit
import datetime
import asyncio
import json
import hashlib
import getpass
import hmac
import secrets
import tempfile
import contextlib
import functools
import errno
import zipfile
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Callable
from dataclasses import dataclass
import threading

# --- DEPENDENCY SAFEGUARD ---
try:
    import yaml
except ImportError:
    print("CRITICAL: 'python3-yaml' missing. Run: sudo apt install python3-yaml")
    sys.exit(1)

try:
    import psutil
except ImportError:
    psutil = None

try:
    from prometheus_client import Counter, Gauge, Histogram, generate_latest, REGISTRY

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

# --- ROOT PRIVILEGE CHECK ---
# Must happen before any config loading below: the first-run config wizard
# writes to /etc/ats/config.yml, and DatabaseManager (further down) opens a
# database file under ATS_HOME. Both need root. Checking here, before either
# runs, means a non-root user gets the clear error immediately instead of
# being walked through the entire interactive wizard only to hit a raw
# PermissionError crash at the very end.
if os.geteuid() != 0:
    print("ERROR: ATS requires root privileges.")
    print(f"Run: sudo python3 {sys.argv[0] if len(sys.argv) else 'ats.py'}")
    sys.exit(1)

# ==============================================================================
#   CONFIGURATION KERNEL  (universal / auto-detecting)
# ==============================================================================
#
# All server-specific values below are resolved in this priority order:
#   1. /etc/ats/config.yml         (persisted after first run on this box,
#                                    or wherever ATS_CONFIG_FILE points)
#   2. Environment variables       (ATS_SERVICE_USER, ATS_MAIN_DOMAIN, etc.)
#   3. Auto-detection              (sudo user, existing cloudflared config, disk)
#   4. Interactive first-run wizard (only for values with no safe default,
#      e.g. the primary domain)
#
# This means the same script file can be copied to any server and will adapt
# itself instead of needing constants hand-edited per-deployment.
#
# Running multiple independent instances of ATS on the same box (e.g. one
# clone per project) requires each to have its own config file -- otherwise
# every clone silently shares one ATS_HOME, one database, one set of logs,
# regardless of which copy of the code actually gets run. Two ways to select
# which instance a given run uses, in priority order:
#   1. ATS_CONFIG_FILE=/path/to/config.yml   (explicit full path)
#   2. ATS_INSTANCE=btgr                     (short name -> /etc/ats/config-btgr.yml)
# Neither set -> the default single-instance path, /etc/ats/config.yml.
# First-run setup (below) will also offer to pick an instance name
# interactively and create a launcher shortcut for it, so this doesn't need
# to be known/typed in advance.

_ATS_CONFIG_DIR = "/etc/ats"

def _ats_resolve_config_file() -> str:
    explicit = os.environ.get("ATS_CONFIG_FILE")
    if explicit:
        return explicit
    instance = os.environ.get("ATS_INSTANCE")
    if instance:
        safe = re.sub(r"[^a-zA-Z0-9_-]", "", instance)
        if safe:
            return os.path.join(_ATS_CONFIG_DIR, f"config-{safe}.yml")
    return os.path.join(_ATS_CONFIG_DIR, "config.yml")

CONFIG_FILE = _ats_resolve_config_file()

_ATS_ENV_MAP = {
    "service_user": "ATS_SERVICE_USER",
    "main_domain": "ATS_MAIN_DOMAIN",
    "default_storage": "ATS_DEFAULT_STORAGE",
    "cloudflare_config": "ATS_CLOUDFLARE_CONFIG",
    "ats_home": "ATS_HOME",
    "cloudflared_service": "ATS_CLOUDFLARED_SERVICE",
}

# Bare ANSI codes (duplicated here, not imported from the VISUAL STYLING
# block below) so the wizard can run before that block is defined.
_W_RESET = "\033[0m"
_W_BOLD = "\033[1m"
_W_CYAN = "\033[96m"
_W_YELLOW = "\033[93m"
_W_GREEN = "\033[92m"


def _ats_detect_service_user() -> str:
    """Best-effort guess at the non-root user that should own deployed services."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        return sudo_user
    try:
        import pwd
        candidates = [p.pw_name for p in pwd.getpwall() if 1000 <= p.pw_uid < 60000]
        if candidates:
            return sorted(candidates)[0]
    except Exception:
        pass
    return "gaia"


def _ats_detect_cloudflare_config() -> Optional[str]:
    for candidate in ("/etc/cloudflared/config.yml", "/root/.cloudflared/config.yml"):
        if os.path.exists(candidate):
            return candidate
    return None


def _ats_detect_default_storage() -> str:
    for candidate in ("/opt", "/srv", "/data"):
        if os.path.exists(candidate) and os.access(candidate, os.W_OK):
            return candidate
    return "/opt"


def _ats_load_config_file() -> Dict:
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"WARNING: Could not read {CONFIG_FILE}: {e}")
    return {}


def _ats_save_config_file(cfg: Dict):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(cfg, f, sort_keys=False, default_flow_style=False)
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except Exception:
        pass


def _ats_resolve_value(key: str, cfg: Dict):
    """config file > env var > None"""
    if cfg.get(key):
        return cfg[key]
    env_key = _ATS_ENV_MAP.get(key)
    if env_key and os.environ.get(env_key):
        return os.environ[env_key]
    return None


_DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")   # used with fullmatch (never "$": it matches before a trailing newline)


def _check_domain_format(domain: str) -> str:
    """
    Pure format check for a fully-qualified domain name; returns it lowercased.

    Rejects empty labels ('a..b.com'), leading/trailing dots or hyphens, labels
    longer than 63 chars, totals longer than 253 chars, and a non-alphabetic TLD.
    Defined this early so the first-run wizard (which runs at import time) can
    share it with validate_domain().
    """
    if not domain or not isinstance(domain, str):
        raise ValueError("Domain cannot be empty")
    d = domain.lower()
    if len(d) > 253:
        raise ValueError("Invalid domain format (longer than 253 characters).")
    labels = d.split(".")
    if len(labels) < 2:
        raise ValueError("Invalid domain format.")
    for label in labels:
        if not label or len(label) > 63 or not _DOMAIN_LABEL_RE.fullmatch(label):
            raise ValueError("Invalid domain format.")
    if not re.fullmatch(r"[a-z]{2,}", labels[-1]):
        raise ValueError("Invalid domain format.")
    return d


def _ats_first_run_wizard(cfg: Dict) -> Dict:
    """Interactively fill in anything still missing, save, and return the config."""
    global CONFIG_FILE

    print(f"{_W_CYAN}{_W_BOLD}")
    print("=" * 70)
    print("  ATS FIRST-RUN SETUP -- this server has no /etc/ats/config.yml yet")
    print("=" * 70)
    print(f"{_W_RESET}")

    instance_name = None
    env_instance = os.environ.get("ATS_INSTANCE")
    try:
        # Only ask if the caller hasn't already picked an instance via
        # ATS_CONFIG_FILE or ATS_INSTANCE -- e.g. a second clone of this
        # script on the same box (a separate ~/ats-btgr checkout) needs its
        # own isolated config/database/logs, not the shared default one.
        # Naming it here means future launches just need
        # 'ATS_INSTANCE=<name> sudo python3 ats.py' -- no need to have known
        # about that env var in advance.
        if not os.environ.get("ATS_CONFIG_FILE") and not env_instance:
            print(f"  {_W_CYAN}Running more than one independent ATS instance on this box?{_W_RESET}")
            print(f"  {_W_CYAN}(e.g. one per project -- each gets its own database, logs, and config){_W_RESET}\n")
            name_input = input("  Instance name (leave blank for a single default instance): ").strip()
            if name_input:
                safe_name = re.sub(r"[^a-zA-Z0-9_-]", "", name_input)
                if safe_name:
                    instance_name = safe_name
                    CONFIG_FILE = os.path.join(_ATS_CONFIG_DIR, f"config-{safe_name}.yml")
                    print(f"  {_W_GREEN}This instance will use {CONFIG_FILE}{_W_RESET}\n")
                else:
                    print(f"  {_W_YELLOW}No usable characters in that name -- continuing as the default instance.{_W_RESET}\n")
        elif env_instance:
            # Instance already chosen via env var -- don't ask again, but
            # still offer the same relaunch reminder / shortcut convenience
            # at the end, since this may still be this instance's first run.
            instance_name = re.sub(r"[^a-zA-Z0-9_-]", "", env_instance) or None

        detected_user = cfg.get("service_user") or _ats_detect_service_user()
        service_user = input(f"  Service user to run apps as [{detected_user}]: ").strip() or detected_user

        existing_domain = cfg.get("main_domain")
        while True:
            prompt = (f"  Primary domain for subdomain deployments [{existing_domain}]: "
                      if existing_domain else
                      "  Primary domain for subdomain deployments (e.g. example.com): ")
            main_domain = input(prompt).strip() or existing_domain or ""
            try:
                main_domain = _check_domain_format(main_domain)
                break
            except ValueError:
                pass
            print(f"  {_W_YELLOW}Invalid domain format, try again.{_W_RESET}")

        detected_storage = cfg.get("default_storage") or _ats_detect_default_storage()
        default_storage = input(f"  Default storage root for deployed apps [{detected_storage}]: ").strip() or detected_storage

        detected_cf = cfg.get("cloudflare_config") or _ats_detect_cloudflare_config() or "/etc/cloudflared/config.yml"
        cloudflare_config = input(f"  Cloudflare Tunnel config path [{detected_cf}]: ").strip() or detected_cf

        # Only asked for a named instance -- a single default instance has
        # no reason to think about this and gets the safe 'cloudflared'
        # default automatically. Only matters if this instance manages a
        # genuinely separate Cloudflare Tunnel with its own systemd unit
        # (not just a separate ingress config for the same tunnel).
        default_cf_service = cfg.get("cloudflared_service") or "cloudflared"
        if instance_name:
            print(f"\n  {_W_CYAN}If this instance manages its own separate Cloudflare Tunnel{_W_RESET}")
            print(f"  {_W_CYAN}(its own systemd service, not just its own config file), name it here.{_W_RESET}")
            print(f"  {_W_CYAN}Leave blank if it shares the same tunnel/service as another instance.{_W_RESET}")
            cloudflared_service = input(
                f"  Cloudflared systemd service name [{default_cf_service}]: "
            ).strip() or default_cf_service
        else:
            cloudflared_service = default_cf_service

        default_ats_home = cfg.get("ats_home") or f"/home/{service_user}/ats{('-' + instance_name) if instance_name else ''}"
        ats_home_input = input(f"  ATS home directory (db/logs) [{default_ats_home}]: ").strip()
        ats_home = ats_home_input or default_ats_home

        make_wrapper = False
        if instance_name:
            make_wrapper_input = input(
                f"  Create a shortcut command 'ats-{instance_name}' to launch this instance in future? (y/n): "
            ).strip().lower()
            make_wrapper = make_wrapper_input == 'y'
    except EOFError:
        print(
            f"\n{_W_YELLOW}No interactive terminal available to complete first-run setup.{_W_RESET}\n"
            f"Run 'sudo python3 {sys.argv[0] if sys.argv else 'ats.py'}' manually once, interactively, "
            f"to create {CONFIG_FILE} -- then --daemon/systemd/cron runs will use it automatically.\n"
        )
        sys.exit(1)

    resolved = {
        "service_user": service_user,
        "service_group": service_user,
        "main_domain": main_domain,
        "default_storage": default_storage,
        "cloudflare_config": cloudflare_config,
        "cloudflared_service": cloudflared_service,
        "ats_home": ats_home,
    }

    _ats_save_config_file(resolved)
    print(f"\n{_W_GREEN}  Saved to {CONFIG_FILE} -- future runs on this server will use these automatically.{_W_RESET}\n")

    if instance_name:
        script_path = os.path.abspath(__file__) if '__file__' in globals() else os.path.abspath(sys.argv[0] if sys.argv else 'ats.py')
        print(f"  {_W_CYAN}To launch this exact instance again, run:{_W_RESET}")
        print(f"    {_W_BOLD}sudo ATS_INSTANCE={instance_name} python3 {script_path}{_W_RESET}\n")

        if make_wrapper:
            wrapper_path = f"/usr/local/bin/ats-{instance_name}"
            try:
                with open(wrapper_path, 'w') as f:
                    f.write(f"#!/bin/bash\nexec env ATS_INSTANCE={instance_name} python3 {script_path} \"$@\"\n")
                os.chmod(wrapper_path, 0o755)
                print(f"  {_W_GREEN}Created {wrapper_path} -- from now on just run: sudo ats-{instance_name}{_W_RESET}\n")
            except Exception as e:
                print(f"  {_W_YELLOW}Could not create shortcut ({e}) -- use the command above instead.{_W_RESET}\n")

    time.sleep(1.5)
    return resolved


def load_ats_config() -> Dict:
    cfg = _ats_load_config_file()
    resolved = {}
    needs_wizard = False

    for key in ("service_user", "main_domain", "default_storage", "cloudflare_config",
                "ats_home", "cloudflared_service"):
        val = _ats_resolve_value(key, cfg)
        if val:
            resolved[key] = val
            continue

        if key == "service_user":
            resolved[key] = _ats_detect_service_user()
        elif key == "cloudflare_config":
            resolved[key] = _ats_detect_cloudflare_config() or "/etc/cloudflared/config.yml"
        elif key == "default_storage":
            resolved[key] = _ats_detect_default_storage()
        elif key == "cloudflared_service":
            # Safe default matching the original single-tunnel behavior --
            # never triggers the wizard on its own.
            resolved[key] = "cloudflared"
        else:
            # main_domain / ats_home have no safe auto-detected default
            needs_wizard = True

    if needs_wizard:
        if "--api" in sys.argv:
            raise RuntimeError("not_configured: Run ATS interactively once to configure this instance")
        resolved = _ats_first_run_wizard(cfg)
    else:
        resolved.setdefault("service_group", resolved["service_user"])
        if not resolved.get("ats_home"):
            resolved["ats_home"] = f"/home/{resolved['service_user']}/ats"
        if not os.path.exists(CONFIG_FILE):
            _ats_save_config_file(resolved)

    return resolved


_ats_cfg = load_ats_config()

ATS_HOME = _ats_cfg["ats_home"]
DB_FILE = os.path.join(ATS_HOME, "ats.db")
LOG_FILE = os.path.join(ATS_HOME, "ats.log")
AUDIT_FILE = os.path.join(ATS_HOME, "audit.trace")
METRICS_FILE = os.path.join(ATS_HOME, "metrics.prom")

# Must exist before logging.FileHandler(LOG_FILE) and DatabaseManager(DB_FILE)
# below try to open files inside it -- both run at import time, well before
# __main__'s own os.makedirs(ATS_HOME) call further down in the file.
os.makedirs(ATS_HOME, exist_ok=True)
try:
    os.chmod(ATS_HOME, 0o700)
except Exception:
    pass

# --- Dynamic Locking ---
IS_DAEMON = "--daemon" in sys.argv
# Scoped under ATS_HOME (not a shared /tmp path) so independent instances --
# e.g. multiple clones on the same box, each with its own ATS_CONFIG_FILE --
# never contend for the same lock or delete it out from under each other.
LOCK_FILE = os.path.join(ATS_HOME, f"{'daemon' if IS_DAEMON else 'cli'}.lock")


SERVICE_USER = _ats_cfg["service_user"]
SERVICE_GROUP = _ats_cfg.get("service_group", SERVICE_USER)
MAIN_DOMAIN = _ats_cfg["main_domain"]
CLOUDFLARE_CONFIG = _ats_cfg["cloudflare_config"]
CLOUDFLARED_SERVICE = _ats_cfg.get("cloudflared_service", "cloudflared")
DEFAULT_STORAGE = _ats_cfg["default_storage"]
BACKUP_DIR = os.path.join(DEFAULT_STORAGE, "backups")

# --- Google Drive Backup (rclone) ---
# Generalized: no longer tied to one specific deployed app. Logs and the
# encryption key now live under ATS_HOME, which is unique per server,
# instead of a hardcoded path under one particular app's directory.
GDRIVE_REMOTE = os.environ.get("ATS_GDRIVE_REMOTE", "gdrive")
GDRIVE_FOLDER = f"{GDRIVE_REMOTE}:backups"
ATS_LOG_DIR = os.path.join(ATS_HOME, "logs")
# Where generated service units are written (a module constant so tests can redirect it).
SYSTEMD_DIR = "/etc/systemd/system"

# Per-service flock files (<name>.lock): shared by the CLI, the daemon and any
# other ATS process so only one update/restart/redeploy runs per service.
LOCKS_DIR = os.path.join(ATS_HOME, "locks")
BACKUP_LOG = os.path.join(ATS_LOG_DIR, "backup.log")
GDRIVE_RETENTION_DAYS = int(os.environ.get("ATS_GDRIVE_RETENTION_DAYS", "7"))
RCLONE_BWLIMIT = os.environ.get("ATS_RCLONE_BWLIMIT", "5M")
ENCRYPTION_KEY_FILE = os.path.join(ATS_HOME, ".backup_key")

# Storage roots must never be (or live under) these system locations. "/" only
# blocks the exact root (every path is technically "under" it). "/lib*" covers
# /lib, /lib32, /lib64, /libx32.
BLOCKED_PATHS = ["/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
                 "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var"]
# The only places under a blocked prefix that are acceptable storage roots.
ALLOWED_STORAGE_EXCEPTIONS = ["/var/www", "/var/lib/ats*"]

# All of these are used with fullmatch(): "$" would accept a trailing newline.
SERVICE_NAME_RE = re.compile(r"[a-zA-Z0-9_-]{1,64}")
BRANCH_RE = re.compile(r"(?!-)[A-Za-z0-9._/-]{1,100}")

# Allowed ranges for per-service resource settings.
WORKERS_RANGE = (1, 32)
MEMORY_RANGE_MB = (64, 65536)
CPU_QUOTA_RANGE = (5, 800)

# ==============================================================================
#   PROMETHEUS METRICS
# ==============================================================================

if PROMETHEUS_AVAILABLE:
    DEPLOY_COUNTER = Counter('ats_deployments_total', 'Total deployments', ['status'])
    DEPLOY_DURATION = Histogram('ats_deploy_duration_seconds', 'Deployment duration')
    SERVICE_STATUS = Gauge('ats_service_status', 'Service status (1=up, 0=down)', ['service'])
    BACKUP_COUNTER = Counter('ats_backups_total', 'Total backups created')
    HEALTH_CHECK_DURATION = Histogram('ats_health_check_seconds', 'Health check duration', ['service'])

# ==============================================================================
#   DATA MODELS
# ==============================================================================

@dataclass
class ServiceConfig:
    name: str
    port: int
    domain: str
    storage_path: str
    repo_url: str
    workers: int = 0
    max_memory_mb: int = 512
    cpu_quota: int = 50
    runtime: str = "python"   # ✅ "python" or "node"


    def __post_init__(self):
        if self.workers == 0:
            import multiprocessing
            self.workers = min(multiprocessing.cpu_count() * 2 + 1, 8)

# ==============================================================================
#   VISUAL STYLING
# ==============================================================================

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"
C_BLUE = "\033[94m"
C_MAGENTA = "\033[95m"

def print_header():
    os.system('clear')
    print(f"{C_CYAN}{C_BOLD}")
    print(r"""
                    █████╗ ████████╗███████╗
                   ██╔══██╗╚══██╔══╝██╔════╝
                   ███████║   ██║   ███████╗
                   ██╔══██║   ██║   ╚════██║
                   ██║  ██║   ██║   ███████║
                   ╚═╝  ╚═╝   ╚═╝   ╚══════╝

      ░▒▓ AUTOMATED TECH STACK (or) ABINAAV TIME SAVER ▓▒░
      ────────────────────────────────────────────────────
                        Version 1.0.2 | ATS
                    Hardened • Automated • Scalable
    """ + f"{C_RESET}")
    print(f"{C_CYAN}{'=' * 70}{C_RESET}")

def print_status(msg: str, status: str = "info"):
    colors = {"info": C_CYAN, "success": C_GREEN, "error": C_RED, "warning": C_YELLOW}
    symbols = {"info": "▶", "success": "✓", "error": "✗", "warning": "⚠"}
    color = colors.get(status, C_CYAN)
    symbol = symbols.get(status, "▶")
    print(f"{color}{symbol} {msg}{C_RESET}")

# ==============================================================================
#   LOGGING & AUDITING
# ==============================================================================

class SecurityLogger(logging.Handler):
    """Enhanced security-focused logger"""

    def emit(self, record):
        if record.levelno >= logging.ERROR:
            try:
                sec_log = os.path.join(ATS_HOME, "security.log")
                with open(sec_log, "a") as f:
                    f.write(f"{self.format(record)}\n")
            except Exception:
                pass

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)-8s | %(message)s', handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)])
logger = logging.getLogger()
logger.addHandler(SecurityLogger())

class _RedactCredentials(logging.Filter):
    def filter(self, record):
        record.msg = re.sub(r"(https?://)[^/\s@]+@", r"\1***@", record.getMessage())
        record.args = ()
        return True

logger.addFilter(_RedactCredentials())

def audit_log(action: str, target: str, metadata: Optional[Dict] = None):
    """Enhanced audit logging with structured data"""
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "action": action,
        "target": target,
        "user": os.environ.get('SUDO_USER', getpass.getuser()),
        "metadata": metadata or {}
    }
    try:
        with open(AUDIT_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.error(f"Audit log failed: {e}")

# ==============================================================================
#   DATABASE ENGINE
# ==============================================================================

class DatabaseManager:
    """Thread-safe database manager"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        """Initialize database with enhanced schema"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                port INTEGER UNIQUE NOT NULL,
                domain TEXT UNIQUE NOT NULL,
                storage_path TEXT NOT NULL,
                repo_url TEXT NOT NULL,
                workers INTEGER DEFAULT 4,
                max_memory_mb INTEGER DEFAULT 512,
                cpu_quota INTEGER DEFAULT 50,
                status TEXT DEFAULT 'active',
                health_check_failures INTEGER DEFAULT 0,
                last_health_check TIMESTAMP,
                deployment_hash TEXT,
                branch TEXT DEFAULT 'main',
                runtime TEXT DEFAULT 'python',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS backups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT,
                filename TEXT,
                size_bytes INTEGER,
                checksum TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(service_name) REFERENCES services(name) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS deployments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT,
                status TEXT,
                duration_seconds REAL,
                error_message TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(service_name) REFERENCES services(name) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT,
                cpu_percent REAL,
                memory_mb REAL,
                requests_per_min INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS remote_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT UNIQUE,
                type TEXT,
                target TEXT,
                auto_offload INTEGER DEFAULT 0,
                FOREIGN KEY(service_name) REFERENCES services(name) ON DELETE CASCADE
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS webhook_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_name TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event TEXT,
                ref TEXT,
                commit_sha TEXT,
                result TEXT,
                message TEXT
            )
        ''')
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_webhook_events_service ON webhook_events(service_name, id)")

        webhook_cols = {row[1] for row in cursor.execute("PRAGMA table_info(webhook_events)")}
        for col in ('delivery', 'signature'):
            if col not in webhook_cols:
                try: cursor.execute('ALTER TABLE webhook_events ADD COLUMN ' + col + ' TEXT')
                except sqlite3.OperationalError as e:
                    if 'duplicate column' not in str(e).lower(): raise
        conn.commit()

        # --- MIGRATIONS FOR EXISTING DATABASES (idempotent) ---
        # Column names/types below are literals, never user input.
        existing_cols = {row[1] for row in cursor.execute("PRAGMA table_info(services)")}
        for col, ddl in (
            ("branch", "TEXT DEFAULT 'main'"),
            ("container_port", "INTEGER"),
            ("auto_update", "INTEGER DEFAULT 1"),
            ("webhook_secret", "TEXT"),
        ):
            if col in existing_cols:
                continue
            try:
                cursor.execute(f"ALTER TABLE services ADD COLUMN {col} {ddl}")
                conn.commit()
            except sqlite3.OperationalError as e:
                # Another ATS process may have added it between the check and the ALTER.
                if "duplicate column" not in str(e).lower():
                    raise

        backup_cols = {row[1] for row in cursor.execute("PRAGMA table_info(backups)")}
        for col, ddl in (("location", "TEXT DEFAULT 'local'"), ("encrypted", "INTEGER DEFAULT 0"), ("local_path", "TEXT")):
            if col not in backup_cols:
                try:
                    cursor.execute(f"ALTER TABLE backups ADD COLUMN {col} {ddl}")
                except sqlite3.OperationalError as error:
                    if "duplicate column" not in str(error).lower(): raise
        conn.commit()

        for backup in cursor.execute("SELECT id, filename FROM backups WHERE location='local' AND local_path IS NULL").fetchall():
            if os.path.basename(backup[1]) == backup[1]:
                cursor.execute("UPDATE backups SET local_path=? WHERE id=?", (os.path.join(BACKUP_DIR, backup[1]), backup[0]))
        conn.commit()

        # Backfill: every service must have its own webhook secret.
        for row in cursor.execute(
                "SELECT id FROM services WHERE webhook_secret IS NULL OR webhook_secret = ''").fetchall():
            cursor.execute(
                "UPDATE services SET webhook_secret=? WHERE id=? AND (webhook_secret IS NULL OR webhook_secret = '')",
                (secrets.token_hex(32), row[0]))
        conn.commit()

        conn.close()

        try:
            os.chmod(self.db_path, 0o600)
        except Exception:
            pass

    def query(self, sql: str, args=(), fetch_all=False, fetch_one=False):
        """Execute database query with error handling"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(sql, args)

            res = None
            if fetch_one:
                res = cursor.fetchone()
            elif fetch_all:
                res = cursor.fetchall()
            else:
                conn.commit()

            return res
        except sqlite3.Error as e:
            logger.error(f"DB Error: {e}")
            logger.error(f"SQL: {sql}")
            logger.error(f"Args: {args}")
            # Return a safe empty list (not None) for fetch_all so the many
            # call sites that do `for x in db.query(..., fetch_all=True)`
            # degrade to "no rows" on a transient DB error instead of
            # crashing with "TypeError: NoneType is not iterable".
            return [] if fetch_all else None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    def insert(self, sql: str, args=()) -> Optional[int]:
        """Execute an INSERT and return the new row id (None on a database error)."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.execute("PRAGMA busy_timeout=5000")
            cursor = conn.cursor()
            cursor.execute(sql, args)
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"DB Error: {e}")
            return None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

db = DatabaseManager(DB_FILE)

# Identifiers cannot be bound as SQL parameters, so table names that end up in
# a query are only ever taken from this allow-list.
DB_COUNT_TABLES = ("services", "backups", "deployments", "metrics_history")


def table_row_count(table: str) -> int:
    """COUNT(*) for an allow-listed table (raises ValueError for anything else)."""
    if table not in DB_COUNT_TABLES:
        raise ValueError(f"Unknown table: {table!r}")
    result = db.query(f"SELECT COUNT(*) as count FROM {table}", fetch_one=True)  # nosec: allow-listed identifier
    return result['count'] if result else 0

# ==============================================================================
#   PORT AND SERVICE CHECKING
# ==============================================================================

def check_port_listening(port: int, timeout: float = 1.0) -> bool:
    """Check if a port is listening using direct socket connection"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex(('127.0.0.1', port))
        return result == 0
    except socket.error:
        return False
    finally:
        try:
            sock.close()
        except Exception:
            pass

def check_systemd_active(service_name: str) -> bool:
    """Check if systemd service is active"""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return result.stdout.strip() == b"active"
    except Exception as e:
        logger.debug(f"Systemd check failed for {service_name}: {e}")
        return False

def get_service_pid(service_name: str) -> Optional[int]:
    """Get service PID using systemctl"""
    try:
        result = subprocess.run(
            ["systemctl", "show", "--property", "MainPID", "--value", service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        pid_str = result.stdout.strip().decode()
        pid = int(pid_str)
        return pid if pid > 0 else None
    except Exception as e:
        logger.debug(f"Failed to get PID for {service_name}: {e}")
        return None

def check_service_health(service_name: str, port: int) -> bool:
    """Check service health - both systemd status and port listening"""
    if not check_systemd_active(service_name):
        return False
    return check_port_listening(port, timeout=2.0)

# ==============================================================================
#   ASYNC UTILITIES
# ==============================================================================

async def run_async_command(cmd: List[str], cwd: Optional[str] = None, timeout: int = 300) -> Tuple[int, str, str]:
    """Run command asynchronously with timeout"""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            return process.returncode, stdout.decode(), stderr.decode()
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise TimeoutError(f"Command timed out after {timeout}s")

    except Exception as e:
        logger.error(f"Async command failed: {e}")
        raise

async def check_single_service_health_async(svc: Dict) -> Tuple[str, bool]:
    """Async wrapper for health check"""
    try:
        loop = asyncio.get_running_loop()
        is_healthy = await loop.run_in_executor(
            None,
            check_service_health,
            svc['name'],
            svc['port']
        )
        return svc['name'], is_healthy
    except Exception as e:
        logger.debug(f"Health check error for {svc['name']}: {e}")
        return svc['name'], False

async def parallel_health_checks(services: List[Dict]) -> Dict[str, bool]:
    """Run health checks in parallel for all services"""
    if not services:
        return {}

    results = await asyncio.gather(
        *[check_single_service_health_async(s) for s in services],
        return_exceptions=True
    )

    health_dict = {}
    for result in results:
        if isinstance(result, tuple):
            name, status = result
            health_dict[name] = status
        else:
            logger.debug(f"Health check exception: {result}")

    return health_dict

# ==============================================================================
#   CORE UTILITIES
# ==============================================================================

def acquire_lock():
    """Acquire exclusive lock to prevent concurrent ATS runs"""
    try:
        lock_fd = open(LOCK_FILE, 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lock_fd.write(str(os.getpid()))
        lock_fd.flush()

        def cleanup_lock():
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                lock_fd.close()
                if os.path.exists(LOCK_FILE):
                    os.remove(LOCK_FILE)
            except Exception:
                pass

        atexit.register(cleanup_lock)
        return lock_fd
    except IOError:
        print(f"{C_RED}CRITICAL: ATS is locked (Another instance running).{C_RESET}")
        sys.exit(1)

def run_as_gaia(cmd: List[str], cwd: Optional[str] = None, timeout: int = 300, capture: bool = False):
    """
    Execute command as the configured SERVICE_USER.

    Output is always captured internally (previously discarded to DEVNULL
    when capture=False), so that on failure the real stderr/stdout is
    attached to the raised error instead of a bare "Command failed" with no
    diagnostic info. This does not change what's printed to the terminal on
    success — non-capture callers never streamed live output either way.
    """
    env = os.environ.copy()
    env["HOME"] = f"/home/{SERVICE_USER}"
    full_cmd = ["sudo", "-u", SERVICE_USER] + cmd
    logger.info(f"EXEC(GAIA): {' '.join(cmd)}")

    try:
        result = subprocess.run(
            full_cmd, cwd=cwd, env=env, timeout=timeout,
            capture_output=True, text=True
        )

        if result.returncode != 0:
            stderr_tail = (result.stderr or "").strip()[-1000:]
            stdout_tail = (result.stdout or "").strip()[-500:]
            detail = stderr_tail or stdout_tail or "(command produced no output)"
            logger.error(f"Command failed: {' '.join(cmd)}\n{detail}")
            if capture:
                return result.returncode, result.stdout, result.stderr
            raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{detail}")

        return result.returncode, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Command timeout: {' '.join(cmd)}")

def run_root(cmd: List[str], timeout: int = 60):
    """
    Execute command as root.

    Like run_as_gaia, output is always captured so a failure raises with the
    real stderr attached instead of a bare CalledProcessError with no
    message — the class of bug that made the earlier venv-creation and
    cloudflared-restart failures hard to diagnose from ATS's own output.
    """
    logger.info(f"EXEC(ROOT): {' '.join(cmd)}")
    result = subprocess.run(cmd, timeout=timeout, capture_output=True, text=True)
    if result.returncode != 0:
        stderr_tail = (result.stderr or "").strip()[-1000:]
        stdout_tail = (result.stdout or "").strip()[-500:]
        detail = stderr_tail or stdout_tail or "(command produced no output)"
        logger.error(f"Command failed: {' '.join(cmd)}\n{detail}")
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{detail}")

def restart_cloudflared_resilient(poll_timeout: int = 20, poll_interval: float = 1.0,
                                   max_attempts: int = 3, backoff_seconds: Tuple[int, ...] = (10, 20, 30),
                                   service_name: str = None):
    """
    Restart the cloudflared systemd service, tolerating both:

      (a) systemd's own Restart=on-failure self-healing after a single slow
          start (poll 'systemctl is-active' briefly before treating a
          non-zero restart exit as fatal), and

      (b) longer transient blips (observed on resource-constrained hardware,
          e.g. a Raspberry Pi doing heavy git/pip work right before this
          runs) where cloudflared's connectivity precheck keeps failing for
          up to a couple of minutes and a single restart+poll isn't enough.
          For this, the restart itself is retried up to `max_attempts` times
          with increasing backoff between attempts.

    `service_name` defaults to CLOUDFLARED_SERVICE (itself defaulting to the
    original hardcoded "cloudflared") so a per-instance setup with its own
    genuinely separate Cloudflare Tunnel -- its own systemd unit, not just
    its own ingress config file -- can be targeted correctly instead of
    always restarting whatever the single global "cloudflared" service is.

    Only raises (with real diagnostics attached) if the service still isn't
    active after all attempts are exhausted.
    """
    svc = service_name or CLOUDFLARED_SERVICE
    last_result = None
    for attempt in range(1, max_attempts + 1):
        logger.info(f"EXEC(ROOT): systemctl restart {svc} (attempt {attempt}/{max_attempts})")
        result = subprocess.run(
            ["systemctl", "restart", svc],
            timeout=60, capture_output=True, text=True
        )
        last_result = result

        if result.returncode == 0:
            return

        logger.warning(
            f"systemctl restart {svc} returned {result.returncode} "
            f"(stderr: {result.stderr.strip()[:300]}) — polling for self-recovery via "
            f"systemd Restart=on-failure..."
        )

        deadline = time.time() + poll_timeout
        while time.time() < deadline:
            if check_systemd_active(svc):
                logger.info(f"{svc} recovered on its own after restart attempt {attempt}")
                return
            time.sleep(poll_interval)

        if attempt < max_attempts:
            wait = backoff_seconds[min(attempt - 1, len(backoff_seconds) - 1)]
            logger.warning(
                f"{svc} still not active after attempt {attempt}/{max_attempts} "
                f"(poll_timeout={poll_timeout}s) — waiting {wait}s before retrying restart..."
            )
            time.sleep(wait)

    try:
        journal = subprocess.run(
            ["journalctl", "-u", svc, "-n", "20", "--no-pager"],
            capture_output=True, text=True, timeout=10
        ).stdout
    except Exception:
        journal = "(could not read journalctl)"

    raise RuntimeError(
        f"{svc} did not become active after {max_attempts} restart attempts "
        f"(~{sum(backoff_seconds[:max_attempts-1]) + poll_timeout * max_attempts}s total).\n"
        f"stderr: {last_result.stderr.strip()[:300] if last_result else 'n/a'}\n"
        f"Recent journal:\n{journal[-1500:]}"
    )

def get_service_path(storage: str, name: str) -> str:
    """
    Intelligently determines service path.
    Handles legacy (/websites), standard (/api), and nested input errors.
    """
    base = os.path.abspath(storage)

    if base.endswith("/websites") or base.endswith("/api"):
        return os.path.join(base, name)

    legacy_path = os.path.join(base, "websites", name)
    if os.path.exists(legacy_path):
        return legacy_path

    return os.path.join(base, "api", name)

def calculate_file_hash(filepath: str) -> str:
    """Calculate SHA256 hash of file"""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for block in iter(lambda: f.read(4096), b''):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Failed to calculate hash: {e}")
        return "error"

# ==============================================================================
#   VALIDATION
# ==============================================================================

def _storage_path_blocked(real: str) -> bool:
    """True if `real` (an already-realpath'ed absolute path) is blocked."""
    if real == "/":
        return True
    parts = [p for p in real.split("/") if p]
    for blocked in BLOCKED_PATHS:
        if blocked == "/":
            continue
        if real == blocked or real.startswith(blocked + "/"):
            # Explicit carve-outs under /var only.
            if parts[:2] == ["var", "www"]:
                return False
            if len(parts) >= 3 and parts[:2] == ["var", "lib"] and parts[2].startswith("ats"):
                return False
            return True
    return False


def validate_storage(path: str) -> str:
    """Validate storage path exists and is not restricted (symlinks resolved, sub-paths blocked)"""
    if not path:
        path = DEFAULT_STORAGE
    if not os.path.exists(path):
        raise ValueError(f"Path does not exist: {path}")
    clean = os.path.realpath(path)
    if _storage_path_blocked(clean):
        raise ValueError(f"Restricted path: {clean}")
    if not os.path.isdir(clean):
        raise ValueError(f"Not a directory: {clean}")
    if not os.access(clean, os.W_OK):
        raise ValueError(f"Path not writable: {clean}")
    return clean


def domain_in_use(domain: str, exclude_name: Optional[str] = None) -> Optional[str]:
    """Return the name of the service already using `domain` (case-insensitive), else None."""
    row = db.query("SELECT name FROM services WHERE lower(domain)=?", (domain.lower(),), fetch_one=True)
    if row and row['name'] != exclude_name:
        return row['name']
    return None


def validate_domain(domain: str, exclude_name: Optional[str] = None) -> str:
    """Validate domain format and availability. Returns the lowercased domain."""
    clean = _check_domain_format(domain)          # lowercases first
    if domain_in_use(clean, exclude_name):
        raise ValueError(f"Domain {clean} already exists.")
    return clean

def validate_port(port: str) -> int:
    """Validate port is numeric, in range, and available"""
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise ValueError("Port must be numeric.")

    if not (1024 <= p <= 65535):
        raise ValueError("Port must be between 1024-65535.")

    if db.query("SELECT 1 FROM services WHERE port=?", (p,), fetch_one=True):
        raise ValueError(f"Port {p} already registered.")

    if check_port_listening(p, timeout=0.5):
        raise ValueError(f"Port {p} already in use on system.")

    return p

def _validate_int_range(value, label: str, lo: int, hi: int) -> int:
    """Parse `value` (int or numeric string) and range-check it; raises ValueError."""
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a whole number.")
    if isinstance(value, int):
        n = value
    else:
        text = str(value).strip() if value is not None else ""
        if not re.fullmatch(r"[+-]?[0-9]+", text):
            raise ValueError(f"{label} must be a whole number.")
        n = int(text)
    if not (lo <= n <= hi):
        raise ValueError(f"{label} must be between {lo} and {hi}.")
    return n

def validate_workers(value) -> int:
    """Validate gunicorn worker count (1-32)."""
    return _validate_int_range(value, "Workers", *WORKERS_RANGE)

def validate_memory(value) -> int:
    """Validate memory limit in MB (64-65536)."""
    return _validate_int_range(value, "Max memory (MB)", *MEMORY_RANGE_MB)

def validate_cpu(value) -> int:
    """Validate CPU quota in percent (5-800)."""
    return _validate_int_range(value, "CPU quota (%)", *CPU_QUOTA_RANGE)

def validate_service_name(name: str) -> str:
    """Validate a service name (^[a-zA-Z0-9_-]{1,64}$)."""
    if not isinstance(name, str) or not SERVICE_NAME_RE.fullmatch(name) or name.startswith("-"):
        raise ValueError("Invalid service name format (use letters, digits, '_' or '-', max 64 chars)")
    return name

def validate_branch(branch: str) -> str:
    """Validate a git branch name (no leading '-', no whitespace/odd characters)."""
    if not isinstance(branch, str) or not BRANCH_RE.fullmatch(branch) or ".." in branch:
        raise ValueError("Invalid branch name.")
    return branch

def validate_git_url(url: str) -> str:
    """Validate git repository URL (https:// or git@ only; no whitespace/control characters)"""
    if not url:
        raise ValueError("Git URL cannot be empty")
    if re.search(r"[\s\x00-\x1f\x7f]", url):
        raise ValueError("Git URL must not contain whitespace or control characters.")
    if len(url) > 2048:
        raise ValueError("Git URL too long.")
    if url.startswith("https://"):
        if len(url) <= len("https://"):
            raise ValueError("Invalid Git URL format.")
    elif url.startswith("git@"):
        if ":" not in url[4:]:
            raise ValueError("Invalid Git URL format.")
    else:
        raise ValueError("Invalid Git URL format (only https:// and git@ URLs are accepted; plain http:// is rejected).")
    return url

# ==============================================================================
#   CLOUDFLARE MANAGEMENT
# ==============================================================================

class CloudflareManager:
    """Manage Cloudflare Tunnel configuration with atomic updates"""

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.backup_path = config_path + ".bak"

    def _backup_config(self):
        """Create backup of current configuration"""
        if os.path.exists(self.config_path):
            shutil.copy(self.config_path, self.backup_path)

    def _restore_config(self):
        """Restore configuration from backup"""
        if os.path.exists(self.backup_path):
            shutil.copy(self.backup_path, self.config_path)
            try:
                # Single fast attempt only: the caller (add_route/remove_route)
                # already exhausted its own full retry budget before reaching
                # here, so doubling that wait would just delay surfacing the
                # real error. This call is best-effort (failure is swallowed
                # below) -- if cloudflared genuinely can't come up right now,
                # it'll pick the restored config back up on its own once
                # connectivity returns, via Restart=on-failure.
                restart_cloudflared_resilient(max_attempts=1, poll_timeout=15)
            except Exception:
                pass

    def add_route(self, domain: str, port: int):
        """Add new route to Cloudflare Tunnel"""
        try:
            self._backup_config()

            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)

            if not config or 'ingress' not in config:
                raise ValueError("Invalid Cloudflare config YAML")

            ingress = config['ingress']

            existing_route = next((r for r in ingress if r.get('hostname') == domain), None)
            if existing_route:
                if existing_route.get('service') == f'http://localhost:{port}':
                    logger.info(f"Route {domain} already exists and is correct")
                    return
                else:
                    logger.info(f"Updating existing route {domain} to port {port}")
                    existing_route['service'] = f'http://localhost:{port}'
            else:
                new_rule = {'hostname': domain, 'service': f'http://localhost:{port}'}
                catch_all_idx = next((i for i, r in enumerate(ingress) if r.get('service') == 'http_status:404'), -1)

                if catch_all_idx != -1:
                    ingress.insert(catch_all_idx, new_rule)
                else:
                    ingress.append(new_rule)

            with open(self.config_path, 'w') as f:
                yaml.dump(config, f, sort_keys=False, default_flow_style=False)

            restart_cloudflared_resilient()
            logger.info(f"Cloudflare route added: {domain} -> {port}")

        except Exception as e:
            logger.error(f"Cloudflare add route failed: {e}")
            self._restore_config()
            raise

    def remove_route(self, domain: str):
        """Remove route from Cloudflare Tunnel"""
        try:
            self._backup_config()

            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)

            if not config or 'ingress' not in config:
                raise ValueError("Invalid Cloudflare config YAML")

            original_count = len(config['ingress'])
            config['ingress'] = [r for r in config['ingress'] if r.get('hostname') != domain]

            if len(config['ingress']) == original_count:
                logger.warning(f"Route {domain} not found")
                return

            with open(self.config_path, 'w') as f:
                yaml.dump(config, f, sort_keys=False, default_flow_style=False)

            restart_cloudflared_resilient()
            logger.info(f"Cloudflare route removed: {domain}")

        except Exception as e:
            logger.error(f"Cloudflare remove route failed: {e}")
            self._restore_config()
            raise

cloudflare = CloudflareManager(CLOUDFLARE_CONFIG)

# ==============================================================================
#   SYSTEMD SERVICE GENERATION
# ==============================================================================

def generate_systemd_service(config: ServiceConfig, api_dir: str, log_dir: str, db_dir: str) -> str:
    """Generate systemd service file — supports Python (gunicorn) and Node.js (npm start)"""

    if config.runtime == "node":
        exec_start = f"/usr/bin/npm start"
        env_block  = (
            f'Environment="PATH=/usr/local/bin:/usr/bin:/bin"\n'
            f'Environment="NODE_ENV=production"\n'
            f'Environment="PORT={config.port}"'
        )
    else:
        exec_start = (
            f"{api_dir}/venv/bin/gunicorn \\\n"
            f"    --bind 127.0.0.1:{config.port} \\\n"
            f"    --workers {config.workers} \\\n"
            f"    --worker-class sync \\\n"
            f"    --timeout 120 \\\n"
            f"    --max-requests 1000 \\\n"
            f"    --max-requests-jitter 100 \\\n"
            f"    --worker-connections 1000 \\\n"
            f"    --access-logfile {log_dir}/access.log \\\n"
            f"    --error-logfile {log_dir}/error.log \\\n"
            f"    --log-level info \\\n"
            f"    app:app"
        )
        env_block = (
            f'Environment="PATH={api_dir}/venv/bin:/usr/local/bin:/usr/bin"\n'
            f'Environment="PYTHONUNBUFFERED=1"'
        )

    content = f"""[Unit]
Description={config.name} API [ATS v7.0 MANAGED]
After=network-online.target
Wants=network-online.target
Documentation=https://{MAIN_DOMAIN}/docs/{config.name}

[Service]
Type=simple
User={SERVICE_USER}
Group={SERVICE_GROUP}
WorkingDirectory={api_dir}

# Environment
{env_block}

# Execution
ExecStart={exec_start}

# Logging
StandardOutput=append:{log_dir}/stdout.log
StandardError=append:{log_dir}/stderr.log
SyslogIdentifier={config.name}

# Restart behavior
Restart=on-failure
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3
KillSignal=SIGINT
TimeoutStartSec=90
TimeoutStopSec=30

# Security Hardening
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# Filesystem Access
ReadWritePaths={api_dir}
ReadWritePaths={log_dir}
ReadWritePaths={db_dir}

# Resource Limits
MemoryMax={config.max_memory_mb}M
MemoryHigh={int(config.max_memory_mb * 0.9)}M
CPUQuota={config.cpu_quota}%
TasksMax=256
LimitNOFILE=65536
LimitNPROC=512

# File permissions
UMask=0027

[Install]
WantedBy=multi-user.target
"""
    return content

# ==============================================================================
#   HEALTH CHECKING
# ==============================================================================

def health_check_deployment(name: str, port: int, max_retries: int = 5) -> bool:
    """Synchronous health check for deployment"""
    for attempt in range(max_retries):
        print_status(f"Health check attempt {attempt + 1}/{max_retries}...", "info")

        if not check_systemd_active(name):
            print(f"  {C_YELLOW}└─ Service not active in systemd{C_RESET}")
            time.sleep(2)
            continue

        if check_port_listening(port, timeout=2.0):
            print_status("Health check PASSED", "success")
            return True

        print(f"  {C_YELLOW}└─ Port {port} not responding{C_RESET}")

        if attempt < max_retries - 1:
            time.sleep(2)

    print_status("Health check FAILED", "error")
    return False

# ==============================================================================
#   DEPLOYMENT ENGINE
# ==============================================================================

async def deploy_service_async():
    """Enhanced asynchronous service deployment - AUTO STANDARD STRUCTURE"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ DEPLOY NEW SERVICE ═══{C_RESET}\n")

    start_time = time.time()
    config = None
    api_dir = None
    db_dir = None
    log_dir = None
    svc_file = None
    domain = None
    name = None
    storage = None
    lock_handle = None

    try:
        # ========== INPUT VALIDATION ==========
        name = input(f"{C_BOLD}Service Name (alphanumeric):{C_RESET} ").strip()
        validate_service_name(name)
        if db.query("SELECT 1 FROM services WHERE name=?", (name,), fetch_one=True):
            raise ValueError(f"Service '{name}' already exists")

        # Exclude any other deploy/update/restart of this name (CLI, daemon, API).
        try:
            lock_handle = acquire_service_lock(name)
        except ServiceBusyError as busy_err:
            name = None   # nothing of ours exists yet: the rollback below must not touch it
            print_status(str(busy_err), "warning")
            await asyncio.get_running_loop().run_in_executor(
                None, lambda: input(f"\n{C_CYAN}Press Enter to return to main menu...{C_RESET}"))
            return

        # Storage path - defaults to /opt
        storage_input = input(f"{C_BOLD}Storage Path [{DEFAULT_STORAGE}]:{C_RESET} ").strip()

        if not storage_input:
            # User pressed Enter - use standard structure
            storage = DEFAULT_STORAGE
            print(f"  {C_CYAN}→ Using standard structure: {DEFAULT_STORAGE}/api/{name}{C_RESET}")
        else:
            # User provided custom path
            storage = validate_storage(storage_input)
            print(f"  {C_CYAN}→ Using custom path: {storage}/api/{name}{C_RESET}")

        print(f"\n{C_CYAN}Domain Configuration:{C_RESET}")
        print(f"  1. Subdomain of {MAIN_DOMAIN}")
        print(f"  2. Custom full domain")
        dom_choice = input(f"{C_BOLD}Choice (1/2):{C_RESET} ").strip()

        if dom_choice == "1":
            subdomain = input(f"  Subdomain prefix: ").strip()
            domain = validate_domain(f"{subdomain}.{MAIN_DOMAIN}")
        else:
            domain = validate_domain(input(f"  Full domain: ").strip())

        port = validate_port(input(f"{C_BOLD}Port (1024-65535):{C_RESET} ").strip())
        repo_url = validate_git_url(input(f"{C_BOLD}Git Repository URL:{C_RESET} ").strip())
        branch = validate_branch(input(f"{C_BOLD}Git Branch [main]:{C_RESET} ").strip() or "main")

        print(f"\n{C_CYAN}Runtime:{C_RESET}")
        print(f"  1. Python (Flask/Gunicorn) [default]")
        print(f"  2. Node.js (npm start)")
        runtime_choice = input(f"{C_BOLD}Choice (1/2):{C_RESET} ").strip()
        runtime = "node" if runtime_choice == "2" else "python"
        print(f"  {C_CYAN}→ Runtime: {runtime}{C_RESET}")

        print(f"\n{C_YELLOW}Advanced Settings (press Enter for defaults):{C_RESET}")

        workers_input = input(f"  Workers [auto]: ").strip()
        workers = validate_workers(workers_input) if workers_input else 0

        memory_input = input(f"  Max Memory MB [512]: ").strip()
        max_memory = validate_memory(memory_input) if memory_input else 512

        cpu_input = input(f"  CPU Quota % [50]: ").strip()
        cpu_quota = validate_cpu(cpu_input) if cpu_input else 50

        config = ServiceConfig(
            name=name,
            port=port,
            domain=domain,
            storage_path=storage,
            repo_url=repo_url,
            workers=workers,
            max_memory_mb=max_memory,
            cpu_quota=cpu_quota,
            runtime=runtime
        )

        # ========== INFRASTRUCTURE PROVISIONING ==========
        print(f"\n{C_GREEN}{'=' * 70}{C_RESET}")
        print_status("PROVISIONING INFRASTRUCTURE", "info")

        # Always use standard /api structure
        api_parent = os.path.join(storage, "api")
        api_dir = os.path.join(api_parent, name)
        db_dir = os.path.join(storage, "database", name)
        log_dir = os.path.join(api_dir, "logs")
        svc_file = f"{SYSTEMD_DIR}/{name}.service"

        print(f"\n{C_CYAN}Deployment structure:{C_RESET}")
        print(f"  Storage:   {storage}")
        print(f"  Code:      {api_dir}")
        print(f"  Database:  {db_dir}")
        print(f"  Logs:      {log_dir}\n")

        # STEP 1: Create parent /api directory
        try:
            if not os.path.exists(api_parent):
                os.makedirs(api_parent, exist_ok=True)
                print_status(f"Created: {api_parent}", "success")

            # Ensure proper ownership
            shutil.chown(api_parent, user=SERVICE_USER, group=SERVICE_GROUP)
            os.chmod(api_parent, 0o755)

        except Exception as e:
            raise RuntimeError(f"Failed to create API parent directory: {e}")

        # STEP 2: Create database directory
        try:
            os.makedirs(db_dir, exist_ok=True)
            shutil.chown(db_dir, user=SERVICE_USER, group=SERVICE_GROUP)
            os.chmod(db_dir, 0o750)
            print_status(f"Created: {db_dir}", "success")
        except Exception as e:
            raise RuntimeError(f"Failed to create database directory: {e}")

        # ========== CLONE REPOSITORY ==========
        print_status("CLONING REPOSITORY", "info")
        print(f"  From: {redact_repo_url(repo_url)}")
        print(f"  To:   {api_dir}\n")

        try:
            # Verify parent exists and is accessible
            if not os.path.exists(api_parent):
                raise RuntimeError(f"Parent directory disappeared: {api_parent}")

            if not os.access(api_parent, os.W_OK):
                raise RuntimeError(f"Parent directory not writable: {api_parent}")

            # Clone repository
            returncode, stdout, stderr = await run_async_command(
                ["sudo", "-u", SERVICE_USER, "git", "clone", "-b", branch, repo_url, name],
                cwd=api_parent,
                timeout=300
            )

            if returncode != 0:
                error_msg = stderr.strip() if stderr else "Unknown git error"
                raise RuntimeError(f"Git clone failed: {error_msg}")

            # Verify clone was successful
            if not os.path.exists(api_dir):
                raise RuntimeError(f"Git clone completed but directory not found: {api_dir}")

            print_status(f"Repository cloned successfully", "success")
            print(f"  Location: {api_dir}\n")

            # Check for app.py
            app_file = os.path.join(api_dir, "app.py")
            if not os.path.exists(app_file):
                print_status("Warning: app.py not found in repository root", "warning")
                print(f"  {C_YELLOW}Make sure your Flask app is named 'app.py'{C_RESET}\n")

        except Exception as git_error:
            raise RuntimeError(f"Repository clone failed: {git_error}")

        # STEP 3: Create logs directory
        try:
            if not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            shutil.chown(log_dir, user=SERVICE_USER, group=SERVICE_GROUP)
            os.chmod(log_dir, 0o750)
            print_status(f"Created: {log_dir}", "success")
        except Exception as e:
            raise RuntimeError(f"Failed to create logs directory: {e}")

        # ========== ENVIRONMENT SETUP ==========
        print(f"\n{C_CYAN}{'=' * 70}{C_RESET}")

        if runtime == "node":
            print_status("SETTING UP NODE.JS ENVIRONMENT", "info")

            # Check node/npm installed
            try:
                returncode, stdout, _ = await run_async_command(["node", "--version"])
                if returncode != 0:
                    raise RuntimeError("Node.js not found. Install with: sudo apt install nodejs npm")
                print_status(f"Node.js detected: {stdout.strip()}", "success")
            except FileNotFoundError:
                raise RuntimeError("Node.js not found. Install with: sudo apt install nodejs npm")

            # Check for package.json
            pkg_json = os.path.join(api_dir, "package.json")
            if not os.path.exists(pkg_json):
                print_status("Warning: package.json not found in repository root", "warning")
            else:
                print_status("Running npm install...", "info")
                try:
                    run_as_gaia(["npm", "install", "--production"], cwd=api_dir, timeout=300)
                    print_status("npm packages installed", "success")
                except Exception as e:
                    raise RuntimeError(f"npm install failed: {e}")

            print_status("Node.js environment ready", "success")

        else:
            print_status("CREATING PYTHON VIRTUAL ENVIRONMENT", "info")

            try:
                if not os.path.exists(api_dir):
                    raise RuntimeError(f"API directory missing before venv creation: {api_dir}")
                run_as_gaia([sys.executable, "-m", "venv", "venv"], cwd=api_dir, timeout=120)
                print_status("Virtual environment created", "success")
            except Exception as e:
                raise RuntimeError(f"Failed to create virtual environment: {e}")

            pip3_path = os.path.join(api_dir, "venv", "bin", "pip3")
            pip_path  = os.path.join(api_dir, "venv", "bin", "pip")
            if os.path.exists(pip3_path):
                pip_executable = pip3_path
            elif os.path.exists(pip_path):
                pip_executable = pip_path
            else:
                raise RuntimeError(f"Failed to create virtual environment - no pip found in {api_dir}/venv/bin/")

            print(f"  Using: {os.path.basename(pip_executable)}\n")

            print_status("Upgrading pip...", "info")
            try:
                run_as_gaia(
                    [pip_executable, "install", "--upgrade", "pip", "setuptools", "wheel"],
                    cwd=api_dir, timeout=120
                )
                print_status("Pip upgraded", "success")
            except Exception as e:
                print_status(f"Pip upgrade warning: {e}", "warning")

            requirements_file = os.path.join(api_dir, "requirements.txt")
            if os.path.exists(requirements_file):
                print_status("Installing requirements.txt...", "info")
                print(f"  This may take several minutes\n")
                try:
                    run_as_gaia(
                        [pip_executable, "install", "-r", "requirements.txt"],
                        cwd=api_dir, timeout=600
                    )
                    print_status("Dependencies installed", "success")
                except Exception as pip_error:
                    raise RuntimeError(f"Failed to install requirements: {pip_error}")
            else:
                print_status("No requirements.txt found, installing Flask defaults", "warning")
                try:
                    run_as_gaia(
                        [pip_executable, "install", "flask", "flask-cors"],
                        cwd=api_dir, timeout=120
                    )
                except Exception as e:
                    raise RuntimeError(f"Failed to install Flask: {e}")

            print_status("Installing Gunicorn...", "info")
            try:
                run_as_gaia([pip_executable, "install", "gunicorn"], cwd=api_dir, timeout=60)
                print_status("Gunicorn installed", "success")
            except Exception as e:
                raise RuntimeError(f"Failed to install Gunicorn: {e}")

            if PROMETHEUS_AVAILABLE:
                try:
                    run_as_gaia([pip_executable, "install", "prometheus-flask-exporter"], cwd=api_dir, timeout=60)
                except Exception:
                    pass

            print_status("Python environment ready", "success")

        # ========== SYSTEMD SERVICE ==========
        print(f"\n{C_CYAN}{'=' * 70}{C_RESET}")
        print_status("GENERATING SYSTEMD SERVICE", "info")

        try:
            service_content = generate_systemd_service(config, api_dir, log_dir, db_dir)

            with open(svc_file, 'w') as f:
                f.write(service_content)
            os.chmod(svc_file, 0o644)

            print_status(f"Service file created: {svc_file}", "success")

        except Exception as e:
            raise RuntimeError(f"Failed to create service file: {e}")

        # Enable and start service
        try:
            run_root(["systemctl", "daemon-reload"])
            run_root(["systemctl", "enable", name])
            run_root(["systemctl", "start", name])

            print_status(f"Service {name}.service started", "success")

        except Exception as e:
            raise RuntimeError(f"Failed to start service: {e}")

        # ========== HEALTH CHECKS ==========
        print(f"\n{C_YELLOW}{'=' * 70}{C_RESET}")
        print_status("RUNNING HEALTH CHECKS", "info")
        time.sleep(3)

        health_ok = health_check_deployment(name, port)

        if not health_ok:
            print(f"\n{C_YELLOW}Service failed health checks. Recent logs:{C_RESET}\n")
            try:
                result = subprocess.run(
                    ["journalctl", "-u", name, "-n", "30", "--no-pager"],
                    capture_output=True,
                    timeout=5
                )
                log_output = result.stdout.decode()
                print(f"{C_YELLOW}{log_output}{C_RESET}\n")
            except Exception:
                pass

            raise RuntimeError("Service failed to pass health checks")

        # ========== CLOUDFLARE TUNNEL ==========
        # Brief settle pause: the git clone + dependency installs just above are a
        # burst of CPU/network activity. On resource-constrained hosts (e.g. a
        # Raspberry Pi) that burst can transiently interfere with cloudflared's
        # connectivity precheck if we hit it immediately afterward. This is cheap
        # insurance, not a fix for a real outage — restart_cloudflared_resilient()
        # still retries with backoff and will fail loudly if the tunnel is
        # actually down.
        print_status("Settling before Cloudflare configuration...", "info")
        time.sleep(10)

        print_status("CONFIGURING CLOUDFLARE TUNNEL", "info")
        cloudflare_route_ok = True
        cloudflare_error = None
        try:
            cloudflare.add_route(domain, port)
            print_status(f"Route added: {domain} -> localhost:{port}", "success")
        except Exception as e:
            # A tunnel/network outage here does NOT mean the deployment itself
            # failed -- the app already passed its health check and is running.
            # Rolling back (and deleting venv/code/systemd unit/db dir) over a
            # transient Cloudflare problem destroys a working service to "fix"
            # a networking issue that retrying won't solve anyway. Register the
            # service and let the operator retry just the route once
            # connectivity is back, without redoing the whole deploy.
            cloudflare_route_ok = False
            cloudflare_error = str(e)
            logger.error(f"Cloudflare route configuration failed (deployment continuing): {cloudflare_error}")
            print_status(f"Cloudflare route configuration FAILED: {cloudflare_error}", "error")
            print(f"\n{C_YELLOW}Service is running locally on port {port} but not yet reachable via {domain}.{C_RESET}")
            print(f"{C_YELLOW}Retry once connectivity is confirmed: Service Operations -> Update Configuration "
                  f"-> Domain Swap (same domain re-adds the route without touching the app).{C_RESET}\n")

        # ========== DATABASE RECORD ==========
        print(f"\n{C_CYAN}{'=' * 70}{C_RESET}")
        print_status("REGISTERING SERVICE IN DATABASE", "info")

        try:
                # --- FIX: SMART DEPENDENCY HASHING ---
            if runtime == "node":
                target_file = os.path.join(api_dir, "package.json")
            else:
                target_file = os.path.join(api_dir, "requirements.txt")

            deployment_hash = calculate_file_hash(target_file) if os.path.exists(target_file) else "none"

            print_status("Inserting service record...", "info")
            webhook_secret = generate_webhook_secret()
            db.query(
                """INSERT INTO services (name, port, domain, storage_path, repo_url, workers, max_memory_mb, cpu_quota, deployment_hash, runtime, branch, webhook_secret) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (name, port, domain, storage, repo_url, config.workers, max_memory, cpu_quota, deployment_hash, runtime,
                 branch, webhook_secret)
            )

            # Verify insertion
            time.sleep(0.5)
            verify = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)

            if not verify:
                # Fallback to direct insert
                logger.error("Database query method failed, trying direct insert")
                import sqlite3
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                cursor.execute(
                    """INSERT INTO services (name, port, domain, storage_path, repo_url, workers, max_memory_mb, cpu_quota, deployment_hash, runtime, branch, webhook_secret) 
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (name, port, domain, storage, repo_url, config.workers, max_memory, cpu_quota, deployment_hash,
                     runtime, branch, webhook_secret)
                )
                conn.commit()
                conn.close()

                verify = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
                if not verify:
                    raise RuntimeError("Service deployed but failed to register in database")

            print_status(f"Service registered: ID={verify['id']}", "success")

            # Record deployment
            duration = time.time() - start_time
            db.query(
                "INSERT INTO deployments (service_name, status, duration_seconds) VALUES (?, ?, ?)",
                (name, "success", duration)
            )

            print_status("Deployment logged successfully", "success")

        except Exception as db_error:
            logger.error(f"Database registration error: {db_error}")
            print_status(f"DATABASE ERROR: {db_error}", "error")

            print(f"\n{C_YELLOW}{'=' * 70}{C_RESET}")
            print(f"{C_YELLOW}WARNING: Service running but not in ATS database!{C_RESET}")
            print(f"{C_YELLOW}{'=' * 70}{C_RESET}\n")

            print(f"{C_CYAN}Manual fix:{C_RESET}")
            print(f"sudo python3 register_service.py\n")

            raise RuntimeError(f"Service deployed but database registration failed: {db_error}")

        if PROMETHEUS_AVAILABLE:
            DEPLOY_COUNTER.labels(status='success' if cloudflare_route_ok else 'partial').inc()
            DEPLOY_DURATION.observe(duration)

        audit_log("DEPLOY_SUCCESS" if cloudflare_route_ok else "DEPLOY_PARTIAL_CLOUDFLARE_FAILED", name, {
            "domain": domain,
            "port": port,
            "duration": duration,
            "workers": config.workers,
            "cloudflare_route_ok": cloudflare_route_ok,
            **({"cloudflare_error": cloudflare_error} if not cloudflare_route_ok else {})
        })

        # ========== SUCCESS MESSAGE ==========
        if cloudflare_route_ok:
            print(f"\n{C_GREEN}{'=' * 70}{C_RESET}")
            print(f"{C_GREEN}{C_BOLD}✓ DEPLOYMENT SUCCESSFUL{C_RESET}")
            print(f"{C_GREEN}{'=' * 70}{C_RESET}")
        else:
            print(f"\n{C_YELLOW}{'=' * 70}{C_RESET}")
            print(f"{C_YELLOW}{C_BOLD}⚠ DEPLOYMENT PARTIALLY SUCCESSFUL — Cloudflare route pending{C_RESET}")
            print(f"{C_YELLOW}{'=' * 70}{C_RESET}")
            print(f"{C_YELLOW}The application is running and registered, but is not yet reachable{C_RESET}")
            print(f"{C_YELLOW}via https://{domain} until the tunnel route is retried successfully.{C_RESET}")
        print(f"\n{C_CYAN}Service Details:{C_RESET}")
        print(f"  {C_BOLD}Name:{C_RESET}       {name}")
        print(f"  {C_BOLD}Domain:{C_RESET}     https://{domain}" + ("" if cloudflare_route_ok else f"  {C_YELLOW}(route not active yet){C_RESET}"))
        print(f"  {C_BOLD}Port:{C_RESET}       {port}")
        print(f"  {C_BOLD}Workers:{C_RESET}    {config.workers}")
        print(f"  {C_BOLD}Memory:{C_RESET}     {max_memory}MB")
        print(f"  {C_BOLD}CPU:{C_RESET}        {cpu_quota}%")
        print(f"  {C_BOLD}Duration:{C_RESET}   {duration:.2f}s")
        print(f"\n{C_CYAN}Locations:{C_RESET}")
        print(f"  {C_BOLD}Code:{C_RESET}       {api_dir}")
        print(f"  {C_BOLD}Database:{C_RESET}   {db_dir}")
        print(f"  {C_BOLD}Logs:{C_RESET}       {log_dir}")
        print_webhook_setup(name)
        if cloudflare_route_ok:
            print(f"\n{C_GREEN}{'=' * 70}{C_RESET}\n")
        else:
            print(f"\n{C_YELLOW}Retry the route: Service Operations -> Update Configuration -> Domain Swap "
                  f"(enter the same domain: {domain}){C_RESET}")
            print(f"{C_YELLOW}{'=' * 70}{C_RESET}\n")

    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        print(f"\n{C_RED}{'=' * 70}{C_RESET}")
        print_status(f"DEPLOYMENT FAILED: {e}", "error")
        print(f"{C_RED}{'=' * 70}{C_RESET}\n")

        print_status("INITIATING ROLLBACK", "warning")

        # ========== ROLLBACK ==========
        try:
            if name and svc_file:
                try:
                    print_status("Stopping service...", "info")
                    run_root(["systemctl", "stop", name])
                    run_root(["systemctl", "disable", name])
                    print_status("Service stopped", "success")
                except Exception as svc_err:
                    print_status(f"Service stop warning: {svc_err}", "warning")

                if os.path.exists(svc_file):
                    try:
                        os.remove(svc_file)
                        run_root(["systemctl", "daemon-reload"])
                        print_status("Service file removed", "success")
                    except Exception as file_err:
                        print_status(f"Service file removal warning: {file_err}", "warning")

            if api_dir and os.path.exists(api_dir):
                try:
                    shutil.rmtree(api_dir)
                    print_status(f"Removed: {api_dir}", "success")
                except Exception as api_err:
                    print_status(f"API cleanup warning: {api_err}", "warning")

            if db_dir and os.path.exists(db_dir):
                try:
                    shutil.rmtree(db_dir)
                    print_status(f"Removed: {db_dir}", "success")
                except Exception as db_err:
                    print_status(f"Database cleanup warning: {db_err}", "warning")

            if domain:
                try:
                    cloudflare.remove_route(domain)
                    print_status("Cloudflare route removed", "success")
                except Exception as cf_err:
                    print_status(f"Cloudflare cleanup warning: {cf_err}", "warning")

            print(f"\n{C_GREEN}Rollback completed{C_RESET}\n")

        except Exception as rollback_error:
            logger.error(f"Rollback error: {rollback_error}")
            print_status(f"Rollback error: {rollback_error}", "error")

        duration = time.time() - start_time
        if name:
            db.query(
                "INSERT INTO deployments (service_name, status, duration_seconds, error_message) VALUES (?, ?, ?, ?)",
                (name, "failed", duration, str(e)[:500])
            )

        if PROMETHEUS_AVAILABLE:
            DEPLOY_COUNTER.labels(status='failed').inc()

        audit_log("DEPLOY_FAILED", name or "unknown", {"error": str(e)})

    finally:
        release_service_lock(lock_handle)

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to return to main menu...{C_RESET}"))

# ==============================================================================
#   SERVICE LISTING
# ==============================================================================

async def list_services_detailed():
    """Display detailed service information with smart pagination"""

    services = db.query("SELECT * FROM services ORDER BY created_at DESC", fetch_all=True)

    if not services:
        print_header()
        print(f"{C_CYAN}{C_BOLD}═══ SERVICE REGISTRY ═══{C_RESET}\n")
        print_status("No services deployed yet", "warning")
        print(f"\n{C_CYAN}Use option [1] to deploy your first service.{C_RESET}\n")
        input(f"{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    # ── Health check ONCE before loop ─────────────────────────────────────────
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ SERVICE REGISTRY ═══{C_RESET}\n")
    print_status("Checking service health...", "info")
    health_results = await parallel_health_checks(services)

    # ── Terminal size ──────────────────────────────────────────────────────────
    try:
        terminal_rows, terminal_cols = os.get_terminal_size()
    except OSError:
        terminal_rows, terminal_cols = 40, 100

    # ── Card mode ─────────────────────────────────────────────────────────────
    # Full card  = 14 lines (12 data lines + top border + bottom border + 1 blank)
    # Compact    =  8 lines ( 6 data lines + top border + bottom border + 1 blank)
    USE_COMPACT = terminal_rows < 50
    CARD_HEIGHT = 8  if USE_COMPACT else 14
    RESERVED    = 23 # exactly counted above

    usable      = terminal_rows - RESERVED
    per_page = max(1, min(3, usable // CARD_HEIGHT))
    total       = len(services)
    total_pages = max(1, (total + per_page - 1) // per_page)
    current     = 1

    while True:
        os.system('clear')
        print_header()

        print(f"{C_CYAN}{C_BOLD}═══ SERVICE REGISTRY ═══{C_RESET}")
        print(f"{C_CYAN}  Total: {C_BOLD}{total}{C_RESET}{C_CYAN} services"
              f"   │   Page {C_BOLD}{current}{C_RESET}{C_CYAN}/{C_BOLD}{total_pages}{C_RESET}"
              f"   │   {C_BOLD}{per_page}{C_RESET}{C_CYAN} per page"
              f"   │   {'Compact' if USE_COMPACT else 'Full'} view{C_RESET}\n")

        start         = (current - 1) * per_page
        end           = start + per_page
        page_services = services[start:end]

        for idx, svc in enumerate(page_services, start=start + 1):

            is_healthy  = health_results.get(svc['name'], False)
            status_icon = f"{C_GREEN}●{C_RESET}" if is_healthy else f"{C_RED}●{C_RESET}"
            status_text = f"{C_GREEN}ONLINE{C_RESET}"  if is_healthy else f"{C_RED}OFFLINE{C_RESET}"

            # ── Deployment stats ───────────────────────────────────────────────
            deploy_stats = db.query(
                """SELECT COUNT(*) as total,
                          SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) as successful
                   FROM deployments WHERE service_name=?""",
                (svc['name'],), fetch_one=True
            )
            if deploy_stats and deploy_stats['total'] and deploy_stats['total'] > 0:
                rate        = (deploy_stats['successful'] / deploy_stats['total']) * 100
                rate_color  = C_GREEN if rate >= 80 else (C_YELLOW if rate >= 50 else C_RED)
                deploy_line = (f"{deploy_stats['total']} total  "
                               f"{rate_color}{rate:.0f}% success{C_RESET}")
            else:
                deploy_line = f"{C_YELLOW}No deployments yet{C_RESET}"

            # ── Backup count ───────────────────────────────────────────────────
            backup_row   = db.query(
                "SELECT COUNT(*) as count FROM backups WHERE service_name=?",
                (svc['name'],), fetch_one=True
            )
            backup_count = backup_row['count'] if backup_row else 0
            backup_line  = (f"{C_GREEN}{backup_count} backups{C_RESET}"
                            if backup_count > 0
                            else f"{C_YELLOW}No backups yet{C_RESET}")

            # ── Timestamp ──────────────────────────────────────────────────────
            try:
                from datetime import datetime
                dt      = datetime.fromisoformat(str(svc['created_at']))
                created = dt.strftime("%d %b %Y  %H:%M")
            except Exception:
                created = str(svc['created_at'])

            # ── Truncate long strings ──────────────────────────────────────────
            max_val  = max(20, terminal_cols - 22)
            repo_url = (svc['repo_url'][:max_val]      + "..") if len(svc['repo_url'])      > max_val else svc['repo_url']
            domain   = (svc['domain'][:max_val]        + "..") if len(svc['domain'])        > max_val else svc['domain']
            storage  = (svc['storage_path'][:max_val]  + "..") if len(svc['storage_path'])  > max_val else svc['storage_path']

            top_label = f"#{idx}  {svc['name']}"
            top_line  = f"─ {top_label} {'─' * max(0, 58 - len(top_label))}"

            # ── FULL card ──────────────────────────────────────────────────────
            if not USE_COMPACT:
                print(f"{C_CYAN}┌{top_line}{C_RESET}")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Status     {C_RESET}  {status_icon} {status_text}")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Domain     {C_RESET}  https://{domain}")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Port       {C_RESET}  {svc['port']}")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Workers    {C_RESET}  {svc['workers']}")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Memory     {C_RESET}  {svc['max_memory_mb']} MB")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}CPU Quota  {C_RESET}  {svc['cpu_quota']}%")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Storage    {C_RESET}  {storage}")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Repository {C_RESET}  {repo_url}")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Created    {C_RESET}  {created}")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Deployments{C_RESET}  {deploy_line}")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Backups    {C_RESET}  {backup_line}")
                print(f"{C_CYAN}└{'─' * 62}{C_RESET}\n")

            # ── COMPACT card ───────────────────────────────────────────────────
            else:
                print(f"{C_CYAN}┌{top_line}{C_RESET}")
                print(f"{C_CYAN}│{C_RESET}  {status_icon} {status_text}"
                      f"   {C_BOLD}Port:{C_RESET} {svc['port']}"
                      f"   {C_BOLD}Workers:{C_RESET} {svc['workers']}"
                      f"   {C_BOLD}Mem:{C_RESET} {svc['max_memory_mb']}MB"
                      f"   {C_BOLD}CPU:{C_RESET} {svc['cpu_quota']}%")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Domain  {C_RESET}  https://{domain}")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Repo    {C_RESET}  {repo_url}")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Deploy  {C_RESET}  {deploy_line}")
                print(f"{C_CYAN}│{C_RESET}  {C_BOLD}Backups {C_RESET}  {backup_line}   {C_BOLD}Created:{C_RESET} {created}")
                print(f"{C_CYAN}└{'─' * 62}{C_RESET}\n")

        # ── Nav bar ────────────────────────────────────────────────────────────
        nav_parts = []
        if current > 1:
            nav_parts.append(f"{C_BOLD}[P]{C_RESET} Prev")
        if current < total_pages:
            nav_parts.append(f"{C_BOLD}[N]{C_RESET} Next")
        nav_parts.append(f"{C_BOLD}[1-{total}]{C_RESET} Jump")
        nav_parts.append(f"{C_BOLD}[Q]{C_RESET} Back")

        print(f"{C_CYAN}{'─' * 62}{C_RESET}")
        print(f"  {'   '.join(nav_parts)}")
        print(f"{C_CYAN}{'─' * 62}{C_RESET}")
        nav = input(f"\n  Navigation: ").strip().lower()

        if nav == 'n':
            if current < total_pages:
                current += 1
            else:
                print_status("Already on last page.", "warning")
                time.sleep(1)
        elif nav == 'p':
            if current > 1:
                current -= 1
            else:
                print_status("Already on first page.", "warning")
                time.sleep(1)
        elif nav == 'q':
            break
        else:
            try:
                chosen = int(nav)
                if 1 <= chosen <= total:
                    current = ((chosen - 1) // per_page) + 1
                else:
                    print_status(f"Enter a number between 1 and {total}.", "warning")
                    time.sleep(1)
            except ValueError:
                print_status("Invalid input. Use N / P / Q or a service number.", "warning")
                time.sleep(1)

# ==============================================================================
#   SERVICE OPERATIONS
# ==============================================================================

async def destroy_service():
    """Enhanced service destruction with ID selection"""
    print_header()
    print(f"{C_RED}{C_BOLD}═══ DESTROY SERVICE ═══{C_RESET}\n")
    print(f"{C_YELLOW}WARNING: This will permanently delete the service and all its data.{C_RESET}\n")

    services = db.query("SELECT id, name FROM services ORDER BY name", fetch_all=True)
    if not services:
        print_status("No services deployed.", "warning")
        await asyncio.sleep(1)
        return

    print(f"  {C_BOLD}{'ID':<6} {'SERVICE NAME'}{C_RESET}")
    print(f"  {C_CYAN}{'─' * 30}{C_RESET}")
    for s in services:
        print(f"  {s['id']:<6} {s['name']}")

    loop = asyncio.get_running_loop()
    svc_id = (await loop.run_in_executor(None, lambda: input(f"\n  {C_BOLD}Enter Service ID to Destroy (0 to cancel):{C_RESET} "))).strip()
    
    if svc_id == "0" or not svc_id: return

    svc = db.query("SELECT * FROM services WHERE id=?", (svc_id,), fetch_one=True)
    if not svc:
        print_status("Invalid Service ID.", "error")
        await asyncio.sleep(1)
        return

    name = svc['name']

    print(f"\n{C_CYAN}Service Information:{C_RESET}")
    print(f"  Name:    {svc['name']}")
    print(f"  Domain:  {svc['domain']}")
    print(f"  Port:    {svc['port']}")
    print(f"  Created: {svc['created_at']}")

    print(f"\n{C_RED}Type 'DELETE {name}' to confirm:{C_RESET} ", end='')
    confirmation = (await loop.run_in_executor(None, lambda: input())).strip()

    if confirmation != f"DELETE {name}":
        print_status("Destruction cancelled", "warning")
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
        return

    print(f"\n{C_YELLOW}{'=' * 70}{C_RESET}")
    print_status("STOPPING SERVICE", "info")

    # Every step below is independently fault-tolerant. Destroy's job is to
    # guarantee the service ends up fully gone (systemd unit, files, route,
    # DB record) regardless of what partial/inconsistent state it started
    # in -- e.g. a unit that's already not loaded, a route that's already
    # missing, or files that were already cleaned up manually. None of
    # those should block the remaining cleanup steps or leave the DB record
    # orphaned and permanently un-deletable through this menu.
    try:
        run_root(["systemctl", "stop", name])
    except Exception as e:
        logger.warning(f"[{name}] systemctl stop warning (continuing): {e}")
        print_status(f"Service already stopped or not loaded (continuing): {e}", "warning")

    try:
        run_root(["systemctl", "disable", name])
    except Exception as e:
        logger.warning(f"[{name}] systemctl disable warning (continuing): {e}")

    try:
        svc_file = f"{SYSTEMD_DIR}/{name}.service"
        if os.path.exists(svc_file):
            os.remove(svc_file)
        run_root(["systemctl", "daemon-reload"])
        print_status("Service stopped and disabled", "success")
    except Exception as e:
        logger.warning(f"[{name}] Service file cleanup warning (continuing): {e}")
        print_status(f"Service file cleanup warning (continuing): {e}", "warning")

    print_status("REMOVING CLOUDFLARE ROUTE", "info")
    try:
        cloudflare.remove_route(svc['domain'])
        print_status("Route removed", "success")
    except Exception as e:
        logger.warning(f"[{name}] Cloudflare route removal warning (continuing): {e}")
        print_status(f"Cloudflare route removal warning (continuing): {e}", "warning")

    print_status("DELETING SERVICE DATA", "info")
    try:
        service_root = get_service_path(svc['storage_path'], name)
        if os.path.exists(service_root):
            shutil.rmtree(service_root)

        db_root = os.path.join(svc['storage_path'], "database", name)
        if os.path.exists(db_root):
            shutil.rmtree(db_root)
        print_status("Data deleted", "success")
    except Exception as e:
        logger.warning(f"[{name}] Data deletion warning (continuing): {e}")
        print_status(f"Data deletion warning (continuing): {e}", "warning")

    try:
        print_status("UPDATING DATABASE", "info")
        db.query("DELETE FROM services WHERE id=?", (svc['id'],))
        db.query("DELETE FROM webhook_events WHERE service_name=?", (name,))
        print_status("Database updated", "success")

        audit_log("DESTROY", name, {"domain": svc['domain'], "port": svc['port']})

        print(f"\n{C_GREEN}{'=' * 70}{C_RESET}")
        print_status(f"SERVICE '{name}' DESTROYED", "success")
        print(f"{C_GREEN}{'=' * 70}{C_RESET}\n")
    except Exception as e:
        # This is the one step where failure genuinely matters -- if the DB
        # record itself couldn't be removed, the service will still show up
        # in listings even though everything else was cleaned up.
        logger.error(f"[{name}] Failed to remove database record: {e}")
        print_status(f"Cleanup done, but failed to remove database record: {e}", "error")

    input(f"\n{C_CYAN}Press Enter to return to main menu...{C_RESET}")

async def view_service_logs():
    """View service logs with ID selection"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ SERVICE LOGS ═══{C_RESET}\n")

    services = db.query("SELECT id, name FROM services ORDER BY name", fetch_all=True)
    if not services:
        print_status("No services deployed.", "warning")
        await asyncio.sleep(1)
        return

    print(f"  {C_BOLD}{'ID':<6} {'SERVICE NAME'}{C_RESET}")
    print(f"  {C_CYAN}{'─' * 30}{C_RESET}")
    for s in services:
        print(f"  {s['id']:<6} {s['name']}")

    loop = asyncio.get_running_loop()
    svc_id = (await loop.run_in_executor(None, lambda: input(f"\n  {C_BOLD}Enter Service ID (0 to cancel):{C_RESET} "))).strip()
    
    if svc_id == "0" or not svc_id: return

    svc = db.query("SELECT * FROM services WHERE id=?", (svc_id,), fetch_one=True)
    if not svc:
        print_status("Invalid Service ID.", "error")
        await asyncio.sleep(1)
        return

    name = svc['name']

    service_path = get_service_path(svc['storage_path'], name)
    log_dir = os.path.join(service_path, "logs")

    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
            shutil.chown(log_dir, user=SERVICE_USER, group=SERVICE_GROUP)
        except Exception:
            pass

    print(f"\n{C_CYAN}Available Logs:{C_RESET}")
    print("  1. Access Log (Gunicorn requests)")
    print("  2. Error Log (Application errors)")
    print("  3. Stdout Log (Standard output)")
    print("  4. Stderr Log (Standard error)")
    print("  5. Live tail (real-time)")
    print("  6. Log Intelligence & Analytics")
    print("  0. Cancel")

    choice = input(f"\n{C_CYAN}Select log:{C_RESET} ").strip()

    log_files = {
        "1": "access.log",
        "2": "error.log",
        "3": "stdout.log",
        "4": "stderr.log",
        "5": "access.log",
        "6": "access.log"
    }

    if choice == "0":
        return

    if choice not in log_files:
        print_status("Invalid choice", "error")
        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    log_file = os.path.join(log_dir, log_files[choice])

    if not os.path.exists(log_file):
        print_status(f"Log file not found: {log_files[choice]}", "error")
        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    if choice == "5":
        print(f"{C_CYAN}{'=' * 70}{C_RESET}")
        print(f"{C_CYAN}Streaming live logs (Ctrl+C to stop)...{C_RESET}")
        print(f"{C_CYAN}{'=' * 70}{C_RESET}\n")
        try:
            subprocess.run(["tail", "-f", log_file])
        except KeyboardInterrupt:
            print(f"\n{C_CYAN}{'=' * 70}{C_RESET}")
            print_status("Log streaming stopped", "info")
    elif choice == "6":
        await analyze_service_logs(name, log_dir)
    else:
        print(f"{C_CYAN}{'=' * 70}{C_RESET}")
        print(f"{C_CYAN}Last 50 lines of {log_files[choice]}:{C_RESET}")
        print(f"{C_CYAN}{'=' * 70}{C_RESET}\n")
        try:
            result = subprocess.run(
                ["tail", "-n", "50", log_file],
                capture_output=True,
                text=True
            )
            print(result.stdout)
        except Exception as e:
            print_status(f"Error reading log: {e}", "error")

        print(f"{C_CYAN}{'=' * 70}{C_RESET}")

    input(f"\n{C_CYAN}Press Enter to return to main menu...{C_RESET}")

async def analyze_service_logs(name: str, log_dir: str):
    """Scan logs for errors, 404s, and potential attacks"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ LOG INTELLIGENCE: {name} ═══{C_RESET}\n")
    
    access_log = os.path.join(log_dir, "access.log")
    error_log = os.path.join(log_dir, "error.log")
    
    stats = {"404": 0, "500": 0, "attacks": 0, "total_reqs": 0}
    attack_patterns = [r"wp-admin", r"\\.env", r"phpmyadmin", r"shell", r"config"]
    
    if os.path.exists(access_log):
        with open(access_log, 'r') as f:
            for line in f:
                stats["total_reqs"] += 1
                if " 404 " in line: stats["404"] += 1
                if " 500 " in line: stats["500"] += 1
                for pattern in attack_patterns:
                    if re.search(pattern, line, re.I):
                        stats["attacks"] += 1
                        break
                        
    print(f"  {C_BOLD}Total Requests:{C_RESET}  {stats['total_reqs']}")
    print(f"  {C_BOLD}404 Errors:{C_RESET}      {C_YELLOW if stats['404'] > 0 else C_GREEN}{stats['404']}{C_RESET}")
    print(f"  {C_BOLD}500 Crashes:{C_RESET}     {C_RED if stats['500'] > 0 else C_GREEN}{stats['500']}{C_RESET}")
    print(f"  {C_BOLD}Probe Attacks:{C_RESET}   {C_RED if stats['attacks'] > 0 else C_GREEN}{stats['attacks']}{C_RESET}")
    
    if os.path.exists(error_log):
        print(f"\n  {C_BOLD}Recent Application Errors:{C_RESET}")
        result = subprocess.run(["tail", "-n", "5", error_log], capture_output=True, text=True)
        if result.stdout.strip():
            print(f"    {C_RED}{result.stdout.strip()}{C_RESET}")
        else:
            print(f"    {C_GREEN}No recent errors recorded.{C_RESET}")

    input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

# ==============================================================================
#   SHARED SERVICE OPERATIONS
# ==============================================================================
#
# Plain module-level functions that implement the service operations once.
# They take (name, svc), do the work under the per-service lock, REPORT
# PROGRESS through an optional `log(message, level="info")` callback and
# RETURN a result dict -- or raise:
#
#   ValueError          input failed validation (nothing was changed)
#   ServiceBusyError    another process/thread holds the service lock
#   ServiceOpError      the operation failed; `.code` is one of
#                       "failed", "notfound", "unsupported", "venv_missing"
#
# They never call input() and never print on their own (the default `log`
# callback prints, pass your own to capture output). The interactive menus
# below are thin wrappers around them, and the headless API reuses them.
# `log` levels: "info" (default), "success", "warn", "error".

class ServiceBusyError(RuntimeError):
    """Raised when another operation already holds the service's lock."""


class ServiceOpError(RuntimeError):
    """A service operation failed. `code`: failed | notfound | unsupported | venv_missing."""

    def __init__(self, message: str, code: str = "failed"):
        super().__init__(message)
        self.code = code


class VenvMissingError(ServiceOpError):
    """The python venv has no pip; retry with rebuild_venv=True to recreate it."""

    def __init__(self, message: str):
        super().__init__(message, code="venv_missing")


def _print_log(msg: str, level: str = "info") -> None:
    """Default `log` callback: print to the terminal with the usual colours."""
    if level == "success":
        print(f"{C_GREEN}✓ {msg}{C_RESET}")
    elif level == "warn":
        print(f"{C_YELLOW}⚠ {msg}{C_RESET}")
    elif level == "error":
        print(f"{C_RED}✗ {msg}{C_RESET}")
    else:
        print(msg)


def _logger_log(msg: str, level: str = "info") -> None:
    """`log` callback that writes to the ATS logger (used by the daemon/webhook path)."""
    {"warn": logger.warning, "error": logger.error}.get(level, logger.info)(msg)


def _svc_field(svc, key: str, default=None):
    """Read a column from a sqlite3.Row or dict, tolerating columns missing from old rows."""
    try:
        if svc is not None and key in svc.keys():
            val = svc[key]
            return default if val is None else val
    except Exception:
        pass
    return default


def redact_repo_url(url: Optional[str]) -> str:
    """Hide credentials embedded in a repo URL: https://token@host/x -> https://***@host/x."""
    return re.sub(r"^(https?://)[^/@\s]+@", r"\1***@", url or "")


# ── per-service lock ─────────────────────────────────────────────────────────

_INPROC_LOCKS: set = set()
_INPROC_GUARD = threading.Lock()


class ServiceLockHandle:
    __slots__ = ("name", "fd")

    def __init__(self, name: str, fd: int):
        self.name = name
        self.fd = fd


def acquire_service_lock(name: str) -> ServiceLockHandle:
    """
    Take the non-blocking exclusive lock <ATS_HOME>/locks/<name>.lock.

    Combines an in-process guard (safe across asyncio tasks and executor
    threads) with an flock(2) so the CLI, the daemon and any other process
    exclude each other. Raises ServiceBusyError immediately if it is held.
    Pair every call with release_service_lock(), or use service_lock().
    """
    if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_-]+", name):
        raise ValueError("Invalid service name for lock")
    with _INPROC_GUARD:
        if name in _INPROC_LOCKS:
            raise ServiceBusyError(f"Service '{name}' is busy: another update/restart/redeploy is already running")
        _INPROC_LOCKS.add(name)
    fd = None
    try:
        os.makedirs(LOCKS_DIR, mode=0o700, exist_ok=True)
        fd = os.open(os.path.join(LOCKS_DIR, f"{name}.lock"), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            if e.errno in (errno.EAGAIN, errno.EACCES, errno.EWOULDBLOCK):
                raise ServiceBusyError(
                    f"Service '{name}' is busy: another update/restart/redeploy is already running")
            raise
        try:
            os.ftruncate(fd, 0)
            os.write(fd, str(os.getpid()).encode())
        except OSError:
            pass
        return ServiceLockHandle(name, fd)
    except BaseException:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        with _INPROC_GUARD:
            _INPROC_LOCKS.discard(name)
        raise


def release_service_lock(handle: Optional[ServiceLockHandle]) -> None:
    """Release a lock taken with acquire_service_lock() (None is ignored). The lock file stays."""
    if handle is None:
        return
    try:
        fcntl.flock(handle.fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(handle.fd)
    except OSError:
        pass
    with _INPROC_GUARD:
        _INPROC_LOCKS.discard(handle.name)


@contextlib.contextmanager
def service_lock(name: str):
    """Context manager around acquire/release_service_lock; raises ServiceBusyError if busy."""
    handle = acquire_service_lock(name)
    try:
        yield handle
    finally:
        release_service_lock(handle)


# ── low-level helpers ────────────────────────────────────────────────────────

SYSTEMCTL_TIMEOUT = 60
RESTART_SETTLE_SECONDS = 2


def _systemctl(action: str, name: str) -> None:
    """Run `systemctl <action> <name>`; raise ServiceOpError on failure."""
    try:
        result = subprocess.run(["systemctl", action, name], capture_output=True, text=True,
                                timeout=SYSTEMCTL_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise ServiceOpError(f"systemctl {action} {name} timed out")
    except OSError as e:
        raise ServiceOpError(f"systemctl {action} {name} failed: {e}")
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[-300:]
        raise ServiceOpError(f"systemctl {action} {name} failed" + (f": {detail}" if detail else ""))


def _systemctl_and_verify(action: str, name: str) -> None:
    """systemctl <action>, settle, then require the unit to be active."""
    _systemctl(action, name)
    time.sleep(RESTART_SETTLE_SECONDS)
    if not check_systemd_active(name):
        raise ServiceOpError(
            f"Service {action} failed: '{name}' is not active afterwards (check: journalctl -u {name} -n 50)")


def _find_pip(venv_path: str) -> Optional[str]:
    for exe in ("pip3", "pip"):
        candidate = os.path.join(venv_path, "bin", exe)
        if os.path.exists(candidate):
            return candidate
    return None


def _unit_path(name: str) -> str:
    return f"{SYSTEMD_DIR}/{name}.service"


def _rewrite_unit(name: str, transform: Callable[[str], str]) -> None:
    """Read the unit file, apply `transform` to its text and write it back."""
    path = _unit_path(name)
    with open(path, 'r') as f:
        content = f.read()
    with open(path, 'w') as f:
        f.write(transform(content))


# ── restart / stop / start ───────────────────────────────────────────────────

def service_restart(name: str, svc=None, log: Callable = _print_log) -> Dict:
    """
    Restart the service's systemd unit and confirm it is active.
    Returns {"ok": True, "status": "active", "message": ...}.
    Raises ServiceBusyError / ServiceOpError.
    """
    with service_lock(name):
        log("Restarting service...")
        _systemctl_and_verify("restart", name)
    audit_log("RESTART", name)
    log("Service restarted successfully", "success")
    return {"ok": True, "status": "active", "message": "Service restarted successfully"}


def service_stop(name: str, svc=None, log: Callable = _print_log) -> Dict:
    """Stop the service's systemd unit. Returns {"ok": True, "status": "inactive", "message": ...}."""
    with service_lock(name):
        log("Stopping service...")
        _systemctl("stop", name)
        time.sleep(1)
    audit_log("STOP", name)
    log("Service stopped", "success")
    return {"ok": True, "status": "inactive", "message": "Service stopped"}


def service_start(name: str, svc=None, log: Callable = _print_log) -> Dict:
    """Start the service's systemd unit and confirm it is active."""
    with service_lock(name):
        log("Starting service...")
        _systemctl_and_verify("start", name)
    audit_log("START", name)
    log("Service started successfully", "success")
    return {"ok": True, "status": "active", "message": "Service started successfully"}


# ── git pull + restart ───────────────────────────────────────────────────────

def service_git_update(name: str, svc, log: Callable = _print_log) -> Dict:
    """Use the same branch-aware update path for CLI, web and signed webhooks."""
    import ats_manage_runtime
    return ats_manage_runtime.update(sys.modules[__name__], name, dict(svc), log=log)


# ── reinstall dependencies ───────────────────────────────────────────────────

def service_reinstall_deps(name: str, svc, log: Callable = _print_log, rebuild_venv: bool = False) -> Dict:
    """
    Reinstall dependencies (npm install / pip install -r requirements.txt + gunicorn).
    Does NOT restart the service; call service_restart() afterwards if wanted.

    If a python service's venv has no pip, raises VenvMissingError unless
    rebuild_venv=True (then the venv is deleted and recreated first).
    Returns {"ok", "runtime", "rebuilt_venv", "packages_installed", "duration", "message"}.
    """
    service_path = get_service_path(svc['storage_path'], name)
    runtime = _svc_field(svc, 'runtime', 'python')

    with service_lock(name):
        # ── Node.js ──────────────────────────────────────────────────────
        if runtime == "node":
            if not os.path.exists(os.path.join(service_path, "package.json")):
                raise ServiceOpError(f"package.json not found at {service_path}", "notfound")
            log("Running npm install...")
            started = time.time()
            try:
                run_as_gaia(["npm", "install", "--production"], cwd=service_path, timeout=300)
            except Exception as e:
                raise ServiceOpError(f"npm install failed: {e}")
            audit_log("REINSTALL_DEPS", name, {"runtime": "node", "rebuilt_venv": False})
            log("npm packages reinstalled", "success")
            return {"ok": True, "runtime": "node", "rebuilt_venv": False, "packages_installed": None,
                    "duration": round(time.time() - started, 1), "message": "npm packages reinstalled"}

        # ── Python ───────────────────────────────────────────────────────
        requirements_file = os.path.join(service_path, "requirements.txt")
        venv_path = os.path.join(service_path, "venv")
        log(f"Service path: {service_path}")
        log(f"Virtual env:  {venv_path}")

        if not os.path.exists(service_path):
            raise ServiceOpError("Service directory not found", "notfound")
        if not os.path.exists(requirements_file):
            raise ServiceOpError("requirements.txt not found", "notfound")

        rebuilt = False
        pip_executable = _find_pip(venv_path)
        if not pip_executable:
            if not rebuild_venv:
                raise VenvMissingError(
                    "Virtual environment is missing or corrupted (neither pip3 nor pip found in venv/bin/)")
            log("Rebuilding virtual environment...", "warn")
            if os.path.exists(venv_path):
                try:
                    shutil.rmtree(venv_path)
                    log("Old venv removed", "success")
                except Exception as e:
                    raise ServiceOpError(f"Failed to remove old venv: {e}")
            log("Creating new virtual environment...")
            try:
                run_as_gaia([sys.executable, "-m", "venv", "venv"], cwd=service_path, timeout=120)
            except Exception as e:
                raise ServiceOpError(f"Failed to create venv: {e}")
            pip_executable = _find_pip(venv_path)
            if not pip_executable:
                raise ServiceOpError("Failed to create pip executable")
            rebuilt = True
            log("Virtual environment created", "success")
        log(f"Pip path:     {pip_executable}")

        log("Upgrading pip and setuptools...")
        try:
            returncode, _out, _err = run_as_gaia(
                [pip_executable, "install", "--upgrade", "pip", "setuptools", "wheel"],
                cwd=service_path, capture=True, timeout=120
            )
            if returncode == 0:
                log("Pip upgraded", "success")
            else:
                log("Pip upgrade had warnings (continuing anyway)", "warn")
        except Exception as e:
            log(f"Pip upgrade warning: {e}", "warn")

        log("Installing requirements.txt... (this may take several minutes)")
        started = time.time()
        try:
            returncode, stdout, stderr = run_as_gaia(
                [pip_executable, "install", "-r", "requirements.txt"],
                cwd=service_path, capture=True, timeout=600
            )
        except TimeoutError:
            raise ServiceOpError("Installation timed out after 10 minutes")
        except Exception as e:
            raise ServiceOpError(f"Installation error: {e}")
        duration = time.time() - started

        if returncode != 0:
            tail = "\n".join([l for l in (stderr or "").split("\n") if l.strip()][-20:])
            raise ServiceOpError("Installation failed" + (f":\n{tail}" if tail else ""))

        pkg_count = 0
        for line in (stdout or "").split("\n"):
            if "Successfully installed" in line:
                pkg_count = len(line.replace("Successfully installed", "").split())
                break
        log(f"Dependencies installed successfully ({duration:.1f}s)"
            + (f", {pkg_count} packages" if pkg_count else ""), "success")

        log("Installing gunicorn...")
        try:
            returncode, _out, _err = run_as_gaia(
                [pip_executable, "install", "gunicorn"], cwd=service_path, capture=True, timeout=60)
            if returncode == 0:
                log("Gunicorn installed", "success")
            else:
                log("Gunicorn installation warning", "warn")
        except Exception as e:
            log(f"Gunicorn warning: {e}", "warn")

        audit_log("REINSTALL_DEPS", name, {"runtime": "python", "rebuilt_venv": rebuilt})
        return {"ok": True, "runtime": "python", "rebuilt_venv": rebuilt, "packages_installed": pkg_count,
                "duration": round(duration, 1), "message": "Dependencies installed"}


# ── read-only helpers ────────────────────────────────────────────────────────

def service_systemd_status(name: str, svc=None) -> str:
    """Return the text of `systemctl status <name> --no-pager`."""
    try:
        result = subprocess.run(["systemctl", "status", name, "--no-pager"],
                                capture_output=True, text=True, timeout=15)
    except Exception as e:
        raise ServiceOpError(f"Could not read systemd status: {e}")
    return (result.stdout or "") + (result.stderr or "")


def service_resource_usage(name: str, svc=None) -> Dict:
    """
    CPU/memory/thread usage of the service's main process.
    Returns {"running": False, "pid": None, "message"} if it is not running, else
    {"running": True, "pid", "cpu_percent", "memory_mb", "threads", "children"}.
    Raises ServiceOpError(code="unsupported") when psutil is not installed.
    """
    if not psutil:
        raise ServiceOpError("psutil not available - install with: pip install psutil", "unsupported")
    pid = get_service_pid(name)
    if not pid:
        return {"running": False, "pid": None, "message": "Service is not running or PID not found"}
    try:
        process = psutil.Process(pid)
        cpu = process.cpu_percent(interval=1)
        mem_mb = process.memory_info().rss / 1024 / 1024
        return {"running": True, "pid": pid, "cpu_percent": cpu, "memory_mb": mem_mb,
                "threads": process.num_threads(), "children": len(process.children(recursive=True))}
    except Exception as e:
        raise ServiceOpError(f"Could not retrieve resource usage: {e}")


# ── update configuration ─────────────────────────────────────────────────────

def service_update_config(name: str, svc=None, *, port=None, domain=None, cpu_quota=None,
                          max_memory_mb=None, workers=None, log: Callable = _print_log) -> Dict:
    """
    Change a service's port, domain and/or resources.

    Every provided value is validated first (ValueError, nothing changed), then
    applied: port migration (stop, move the Cloudflare route, rewrite the unit,
    start), domain swap (passing the service's current domain re-adds its
    route), resource scaling (unit limits + gunicorn workers, restart).
    `svc` is ignored; the row is re-read from the database.
    Returns {"ok", "changed": [...], "restarted": bool, "service": {row}}.
    """
    row = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    if not row:
        raise ServiceOpError("Service not found", "notfound")
    cur = dict(row)

    # ---- validate everything up front ----
    new_port = None
    if port is not None and str(port).strip() != "":
        try:
            port_int = int(str(port).strip())
        except ValueError:
            raise ValueError("Port must be numeric.")
        if port_int != cur['port']:
            new_port = validate_port(port_int)
    new_domain = validate_domain(domain, exclude_name=name) if domain is not None else None
    new_cpu = validate_cpu(cpu_quota) if cpu_quota is not None else None
    new_mem = validate_memory(max_memory_mb) if max_memory_mb is not None else None
    new_workers = validate_workers(workers) if workers is not None else None

    changed: List[str] = []
    restarted = False
    with service_lock(name):
        # ---- port migration ----
        if new_port is not None:
            log(f"Migrating {name} from {cur['port']} to {new_port}...")
            _systemctl("stop", name)
            try:
                cloudflare.remove_route(cur['domain'])
                cloudflare.add_route(cur['domain'], new_port)

                _rewrite_unit(name, lambda c: c
                              .replace(f"--bind 127.0.0.1:{cur['port']}", f"--bind 127.0.0.1:{new_port}")
                              .replace(f'Environment="PORT={cur["port"]}"', f'Environment="PORT={new_port}"'))
                db.query("UPDATE services SET port=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (new_port, cur['id']))
            except Exception:
                try:
                    _systemctl("start", name)   # don't leave the service down on a failed migration
                except Exception:
                    pass
                raise
            run_root(["systemctl", "daemon-reload"])
            _systemctl("start", name)
            audit_log("CONFIG_PORT", name, {"old_port": cur['port'], "new_port": new_port})
            log("Port migration successful", "success")
            cur['port'] = new_port
            changed.append("port")

        # ---- domain swap ----
        if new_domain is not None:
            log(f"Swapping domain for {name} from {cur['domain']} to {new_domain}...")
            cloudflare.remove_route(cur['domain'])
            cloudflare.add_route(new_domain, cur['port'])

            # Documentation line in the generated unit file only.
            _rewrite_unit(name, lambda c: c.replace(
                f"https://{MAIN_DOMAIN}/docs/{name}", f"https://{MAIN_DOMAIN}/docs/{new_domain}"))
            db.query("UPDATE services SET domain=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (new_domain, cur['id']))
            run_root(["systemctl", "daemon-reload"])
            audit_log("CONFIG_DOMAIN", name, {"old_domain": cur['domain'], "new_domain": new_domain})
            log("Domain swap successful", "success")
            cur['domain'] = new_domain
            changed.append("domain")

        # ---- resource scaling ----
        if new_cpu is not None or new_mem is not None or new_workers is not None:
            cpu_val = new_cpu if new_cpu is not None else cur['cpu_quota']
            mem_val = new_mem if new_mem is not None else cur['max_memory_mb']
            workers_val = new_workers if new_workers is not None else cur['workers']
            log(f"Scaling resources for {name}...")

            def _scale(content: str) -> str:
                content = re.sub(r"CPUQuota=\d+%", f"CPUQuota={cpu_val}%", content)
                content = re.sub(r"MemoryMax=\d+M", f"MemoryMax={mem_val}M", content)
                content = re.sub(r"MemoryHigh=\d+M", f"MemoryHigh={int(mem_val * 0.9)}M", content)
                if new_workers is not None:
                    content = re.sub(r"--workers \d+", f"--workers {workers_val}", content)
                return content

            _rewrite_unit(name, _scale)
            db.query("UPDATE services SET cpu_quota=?, max_memory_mb=?, workers=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                     (cpu_val, mem_val, workers_val, cur['id']))
            run_root(["systemctl", "daemon-reload"])
            _systemctl("restart", name)
            restarted = True
            meta = {"cpu": cpu_val, "mem": mem_val}
            if new_workers is not None:
                meta["workers"] = workers_val
            audit_log("CONFIG_RESOURCES", name, meta)
            log("Resource scaling applied", "success")
            changed.append("resources")

    fresh = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    return {"ok": True, "changed": changed, "restarted": restarted, "service": dict(fresh) if fresh else cur}


# ── redeploy (new git source) ────────────────────────────────────────────────

def service_redeploy(name: str, svc, repo_url: str, branch: str = "main", log: Callable = _print_log) -> Dict:
    """
    Redeploy from a new repository: stop, delete the code directory, clone,
    reinstall dependencies, start, then record the new repo/branch.

    Validates repo_url/branch first (ValueError). Returns
    {"ok", "started": bool, "repo_url", "branch", "runtime", "warnings": [...]}.
    A service that fails to come back up is reported via started=False (the
    new code IS deployed); everything earlier raises ServiceOpError.
    """
    repo_url = validate_git_url((repo_url or "").strip())
    branch = validate_branch((branch or "main").strip() or "main")
    service_path = get_service_path(svc['storage_path'], name)
    runtime = _svc_field(svc, 'runtime', 'python')
    old_repo = _svc_field(svc, 'repo_url', '')
    warnings: List[str] = []

    with service_lock(name):
        logger.info(f"[{name}] Redeploy started — repo: {redact_repo_url(repo_url)}, branch: {branch}")
        audit_log("REDEPLOY_START", name, {
            "old_repo": redact_repo_url(old_repo),
            "new_repo": redact_repo_url(repo_url),
            "branch": branch
        })

        try:
            # Stop service
            log("[1/6] Stopping service...")
            try:
                _systemctl("stop", name)
                time.sleep(1)
                log("Service stopped", "success")
            except Exception as stop_err:
                log("Service was not running", "warn")
                logger.warning(f"[{name}] Redeploy stop: {stop_err}")

            # Remove old code directory
            log("[2/6] Removing old code directory...")
            if os.path.exists(service_path):
                try:
                    shutil.rmtree(service_path)
                    log("Old code removed", "success")
                except Exception as rm_err:
                    logger.error(f"[{name}] Failed to remove old code: {rm_err}")
                    raise RuntimeError(f"Failed to remove old code: {rm_err}")
            else:
                log("Old code directory not found — continuing", "warn")

            # Clone new repo
            log("[3/6] Cloning new repository...")
            api_parent = os.path.dirname(service_path)
            os.makedirs(api_parent, exist_ok=True)
            returncode, _stdout, stderr = run_as_gaia(
                ["git", "clone", "-b", branch, repo_url, name],
                cwd=api_parent, capture=True, timeout=300
            )
            if returncode != 0:
                error_msg = stderr.strip() if stderr else "Unknown git error"
                logger.error(f"[{name}] Git clone failed: {error_msg}")
                raise RuntimeError(f"Git clone failed: {error_msg}")
            if not os.path.exists(service_path):
                raise RuntimeError(f"Git clone completed but directory not found: {service_path}")
            log(f"Repository cloned to {service_path}", "success")

            # Create logs directory
            log_dir = os.path.join(service_path, "logs")
            os.makedirs(log_dir, exist_ok=True)
            shutil.chown(log_dir, user=SERVICE_USER, group=SERVICE_GROUP)
            os.chmod(log_dir, 0o750)

            # Reinstall dependencies
            if runtime == "node":
                log("[4/6] Installing Node.js dependencies...")
                if os.path.exists(os.path.join(service_path, "package.json")):
                    try:
                        run_as_gaia(["npm", "install", "--production"], cwd=service_path, timeout=300)
                        log("npm packages installed", "success")
                    except Exception as npm_err:
                        warnings.append(f"npm install failed: {npm_err}")
                        log(f"npm install failed: {npm_err}", "error")
                else:
                    warnings.append("package.json not found — skipped npm install")
                    log("package.json not found — skipping", "warn")
            else:
                log("[4/6] Creating virtual environment...")
                try:
                    run_as_gaia([sys.executable, "-m", "venv", "venv"], cwd=service_path, timeout=120)
                    log("Virtual environment created", "success")
                except Exception as venv_err:
                    logger.error(f"[{name}] Venv creation failed: {venv_err}")
                    raise RuntimeError(f"Virtual environment creation failed: {venv_err}")

                requirements_file = os.path.join(service_path, "requirements.txt")
                pip_path = os.path.join(service_path, "venv", "bin", "pip")

                log("[5/6] Installing Python dependencies...")
                if os.path.exists(requirements_file):
                    started = time.time()
                    try:
                        returncode, _stdout, stderr = run_as_gaia(
                            [pip_path, "install", "-r", "requirements.txt"],
                            cwd=service_path, capture=True, timeout=600
                        )
                        if returncode == 0:
                            log(f"Dependencies installed ({time.time() - started:.1f}s)", "success")
                        else:
                            err_preview = stderr[:200] if stderr else "unknown"
                            warnings.append(f"pip install failed: {err_preview}")
                            log(f"pip install failed: {err_preview}", "error")
                    except Exception as pip_err:
                        warnings.append(f"pip install error: {pip_err}")
                        log(f"pip install error: {pip_err}", "error")
                else:
                    warnings.append("requirements.txt not found — skipped")
                    log("requirements.txt not found — skipping", "warn")

                try:
                    run_as_gaia([pip_path, "install", "gunicorn"], cwd=service_path, timeout=60)
                    log("Gunicorn installed", "success")
                except Exception as g_err:
                    warnings.append(f"gunicorn install warning: {g_err}")
                    log(f"Gunicorn install warning: {g_err}", "warn")

            # Start service
            log("[6/6] Starting service...")
            started_ok = False
            try:
                _systemctl("start", name)
                time.sleep(RESTART_SETTLE_SECONDS)
                if check_systemd_active(name):
                    started_ok = True
                    log("Service started successfully", "success")
                else:
                    log(f"Service failed to start. Check logs: journalctl -u {name} -n 50", "error")
            except Exception as start_err:
                log(f"Service start failed: {start_err}", "error")
                logger.error(f"[{name}] Service start exception after redeploy: {start_err}")

            # Update database with new repo
            db.query(
                "UPDATE services SET repo_url=?, branch=?, updated_at=CURRENT_TIMESTAMP WHERE name=?",
                (repo_url, branch, name)
            )
            audit_log("REDEPLOY_SUCCESS", name, {
                "old_repo": redact_repo_url(old_repo),
                "new_repo": redact_repo_url(repo_url),
                "branch": branch,
                "runtime": runtime
            })
        except Exception as e:
            logger.error(f"[{name}] Redeployment failed: {e}")
            audit_log("REDEPLOY_FAILED", name, {
                "new_repo": redact_repo_url(repo_url),
                "branch": branch,
                "error": str(e)
            })
            raise ServiceOpError(str(e))

    return {"ok": True, "started": started_ok, "repo_url": redact_repo_url(repo_url), "branch": branch,
            "runtime": runtime, "warnings": warnings}


# ==============================================================================
#   SERVICE OPERATIONS MENU (interactive wrappers around the functions above)
# ==============================================================================

def _print_service_summary(name: str, svc) -> None:
    """Name / domain / port / live status header shared by the service menus."""
    print(f"\n{C_CYAN}Service: {C_BOLD}{name}{C_RESET}")
    print(f"Domain:  https://{svc['domain']}")
    print(f"Port:    {svc['port']}")

    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True,
            timeout=5
        )
        is_active = result.stdout.strip() == b"active"
        status_icon = f"{C_GREEN}●{C_RESET}" if is_active else f"{C_RED}●{C_RESET}"
        status_text = "ACTIVE" if is_active else "INACTIVE"
        print(f"Status:  {status_icon} {status_text}")
    except Exception:
        print(f"Status:  {C_YELLOW}UNKNOWN{C_RESET}")


async def _service_menu_action(choice: str, name: str, svc) -> None:
    """Run one menu choice (1-9) for a service: prompts and printing only, logic lives in service_*()."""
    loop = asyncio.get_running_loop()

    async def pause():
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))

    async def ask(prompt: str) -> str:
        print(prompt, end='', flush=True)
        return (await loop.run_in_executor(None, input)).strip().lower()

    async def call(fn, *args, **kwargs):
        return await loop.run_in_executor(None, functools.partial(fn, *args, **kwargs))

    def report_error(e: Exception):
        if isinstance(e, ServiceBusyError):
            print(f"{C_YELLOW}⚠ {e}{C_RESET}")
        else:
            print(f"{C_RED}✗ Error: {e}{C_RESET}")

    if choice == "1":
        print()
        try:
            await call(service_restart, name, svc)
        except Exception as e:
            report_error(e)
        await pause()

    elif choice == "2":
        if await ask(f"\n{C_RED}Stop service '{name}'? (yes/no):{C_RESET} ") == "yes":
            print()
            try:
                await call(service_stop, name, svc)
            except Exception as e:
                report_error(e)
        else:
            print(f"{C_YELLOW}Cancelled{C_RESET}")
        await pause()

    elif choice == "3":
        print()
        try:
            await call(service_start, name, svc)
        except Exception as e:
            report_error(e)
        await pause()

    elif choice == "4":
        await direct_update(name, svc)

    elif choice == "5":
        print(f"\n{C_YELLOW}Reinstalling dependencies...{C_RESET}")
        try:
            try:
                result = await call(service_reinstall_deps, name, svc)
            except VenvMissingError as e:
                print(f"{C_RED}✗ {e}{C_RESET}\n")
                if await ask(f"{C_CYAN}Would you like to rebuild the virtual environment? (yes/no):{C_RESET} ") != "yes":
                    print(f"{C_YELLOW}Cancelled{C_RESET}")
                    await pause()
                    return
                print(f"\n{C_YELLOW}{'=' * 70}{C_RESET}")
                print(f"{C_YELLOW}REBUILDING VIRTUAL ENVIRONMENT{C_RESET}")
                print(f"{C_YELLOW}{'=' * 70}{C_RESET}\n")
                result = await call(service_reinstall_deps, name, svc, rebuild_venv=True)

            print(f"\n{C_GREEN}{'=' * 70}{C_RESET}")
            print(f"{C_GREEN}All dependencies installed successfully!{C_RESET}")
            print(f"{C_GREEN}{'=' * 70}{C_RESET}\n")

            if await ask(f"{C_CYAN}Restart service to apply changes? (yes/no):{C_RESET} ") == "yes":
                try:
                    await call(service_restart, name, svc)
                    if result.get("runtime") != "node":
                        await asyncio.sleep(1)
                        if check_port_listening(svc['port'], timeout=2.0):
                            print(f"{C_GREEN}✓ Service is responding on port {svc['port']}{C_RESET}")
                        else:
                            print(f"{C_YELLOW}⚠ Service active but port not responding yet{C_RESET}")
                except Exception as e:
                    print(f"{C_RED}✗ Restart failed: {e}{C_RESET}")
            else:
                print(f"{C_YELLOW}Restart cancelled{C_RESET}")
        except ServiceBusyError as e:
            print(f"{C_YELLOW}⚠ {e}{C_RESET}")
        except Exception as e:
            print(f"{C_RED}✗ {e}{C_RESET}" if isinstance(e, ServiceOpError) else f"{C_RED}✗ Unexpected error: {e}{C_RESET}")
        await pause()

    elif choice == "6":
        print(f"\n{C_CYAN}{'=' * 70}{C_RESET}")
        try:
            print(await call(service_systemd_status, name, svc))
        except Exception:
            pass
        print(f"{C_CYAN}{'=' * 70}{C_RESET}")
        await pause()

    elif choice == "7":
        print(f"\n{C_CYAN}Resource Usage for '{name}':{C_RESET}\n")
        try:
            usage = await call(service_resource_usage, name, svc)
            if usage["running"]:
                print(f"  {C_BOLD}PID:{C_RESET}        {usage['pid']}")
                print(f"  {C_BOLD}CPU:{C_RESET}        {usage['cpu_percent']:.1f}%")
                print(f"  {C_BOLD}Memory:{C_RESET}     {usage['memory_mb']:.1f} MB")
                print(f"  {C_BOLD}Threads:{C_RESET}    {usage['threads']}")
                if usage["children"]:
                    print(f"  {C_BOLD}Workers:{C_RESET}    {usage['children']} child processes")
            else:
                print(f"{C_YELLOW}{usage['message']}{C_RESET}")
        except ServiceOpError as e:
            print(f"{C_YELLOW}{e}{C_RESET}")
            if e.code == "unsupported":
                print(f"Install with: {C_CYAN}pip install psutil{C_RESET}")
        await pause()

    elif choice == "8":
        await call(update_service_config, name)

    elif choice == "10":
        await call(manage_webhook_menu, name)

    elif choice == "9":
        # REDEPLOY — stop service, delete code dir, clone new repo, reinstall deps, start
        new_repo_url = (await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}New Git Repository URL:{C_RESET} "))).strip()
        if not new_repo_url:
            print(f"{C_YELLOW}No URL entered. Cancelled{C_RESET}")
            await asyncio.sleep(1)
            await pause()
            return

        new_branch = (await loop.run_in_executor(None, lambda: input(f"{C_CYAN}Branch (default: main):{C_RESET} "))).strip()
        if not new_branch:
            new_branch = "main"

        try:
            validate_git_url(new_repo_url)
            validate_branch(new_branch)
        except ValueError as e:
            print(f"{C_RED}✗ {e}{C_RESET}")
            await pause()
            return

        print(f"\n{C_RED}{C_BOLD}{'=' * 60}{C_RESET}")
        print(f"{C_RED}{C_BOLD}  REDEPLOY SERVICE: {name}{C_RESET}")
        print(f"{C_RED}  Old Repo: {redact_repo_url(svc['repo_url'])}{C_RESET}")
        print(f"{C_RED}  New Repo: {redact_repo_url(new_repo_url)}{C_RESET}")
        print(f"{C_RED}  Branch:   {new_branch}{C_RESET}")
        print(f"{C_RED}{C_BOLD}{'=' * 60}{C_RESET}")

        confirm = (await loop.run_in_executor(None, lambda: input(f"\n{C_RED}Type 'REDEPLOY' to confirm:{C_RESET} "))).strip()
        if confirm != "REDEPLOY":
            print(f"{C_YELLOW}Redeploy cancelled{C_RESET}")
            logger.info(f"[{name}] Redeploy cancelled by user")
            await asyncio.sleep(1)
            await pause()
            return

        print()
        try:
            await call(service_redeploy, name, svc, new_repo_url, new_branch)
            print(f"\n{C_GREEN}{'=' * 60}{C_RESET}")
            print(f"{C_GREEN}{C_BOLD}  ✓ REDEPLOYMENT COMPLETE: {name}{C_RESET}")
            print(f"{C_GREEN}{'=' * 60}{C_RESET}")
        except Exception as e:
            print(f"\n{C_RED}{'=' * 60}{C_RESET}")
            print(f"{C_RED}  ✗ REDEPLOYMENT FAILED: {name}{C_RESET}")
            print(f"{C_RED}  Error: {e}{C_RESET}")
            print(f"{C_RED}{'=' * 60}{C_RESET}")
        await pause()

    elif choice == "0":
        return

    else:
        print_status("Invalid choice", "warning")
        await asyncio.sleep(1)


async def service_operations():
    """Service management operations menu - ID selection"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ SERVICE OPERATIONS ═══{C_RESET}\n")

    services = db.query("SELECT id, name FROM services ORDER BY name", fetch_all=True)
    if not services:
        print_status("No services deployed.", "warning")
        await asyncio.sleep(1)
        return

    print(f"  {C_BOLD}{'ID':<6} {'SERVICE NAME'}{C_RESET}")
    print(f"  {C_CYAN}{'─' * 30}{C_RESET}")
    for s in services:
        print(f"  {s['id']:<6} {s['name']}")

    loop = asyncio.get_running_loop()
    svc_id = (await loop.run_in_executor(None, lambda: input(f"\n  {C_BOLD}Enter Service ID (0 to cancel):{C_RESET} "))).strip()

    if svc_id == "0" or not svc_id: return

    svc = db.query("SELECT * FROM services WHERE id=?", (svc_id,), fetch_one=True)
    if not svc:
        print_status("Invalid Service ID.", "error")
        await asyncio.sleep(1)
        return

    name = svc['name']
    _print_service_summary(name, svc)

    print(f"\n{C_CYAN}{'=' * 70}{C_RESET}")
    print(f"{C_CYAN}Available Operations:{C_RESET}")
    print("  1. Restart service")
    print("  2. Stop service")
    print("  3. Start service")
    print("  4. Git Pull and Restart")
    print("  5. Reinstall dependencies")
    print("  6. View systemd status")
    print("  7. View resource usage")
    print("  8. Update configuration")
    print("  9. Redeploy service (new git)")
    print("  10. Webhook URL / secret (view, rotate)")
    print("  0. Cancel")

    choice = (await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Select operation:{C_RESET} "))).strip()
    await _service_menu_action(choice, name, svc)

# ==============================================================================
#   WEBHOOK LISTENER
# ==============================================================================

# ──────────────────────────────────────────────────────────────────────────────
#   INTERNAL HELPER — shared git-pull + restart logic (no blocking I/O)
# ──────────────────────────────────────────────────────────────────────────────

async def _do_git_update(name: str, svc: dict, log: Callable = _logger_log) -> bool:
    """
    Async wrapper around service_git_update() for the daemon and menus.
    Runs it in the default executor (so the event loop is never blocked) and
    returns True on success, False on failure or when the service is busy.
    """
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, functools.partial(service_git_update, name, svc, log))
        return True
    except ServiceBusyError as e:
        log(str(e), "warn")
        return False
    except Exception as e:
        log(str(e), "error")
        return False

# ──────────────────────────────────────────────────────────────────────────────
#   direct_update  — interactive menu action (git pull + restart)
# ──────────────────────────────────────────────────────────────────────────────

async def direct_update(name: str, svc: dict):           # FIX: added svc param
    # GIT PULL AND RESTART
    print(f"\n{C_YELLOW}Updating code...{C_RESET}")

    await _do_git_update(name, svc, _print_log)           # shared helper, prints progress

    loop = asyncio.get_running_loop()                     # FIX: not get_event_loop()
    await loop.run_in_executor(                           # FIX: was blocking input()
        None,
        lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
    )

# ──────────────────────────────────────────────────────────────────────────────
#   Webhook secrets, events and request helpers
# ──────────────────────────────────────────────────────────────────────────────

WEBHOOK_PORT = 9999
WEBHOOK_DEFAULT_BIND = "127.0.0.1"
WEBHOOK_MAX_BODY = 1024 * 1024        # 1 MiB
WEBHOOK_READ_TIMEOUT = 10             # seconds, for the whole request (line + headers + body)
WEBHOOK_MAX_HEADERS = 100
WEBHOOK_EVENT_RETENTION = 200         # webhook_events rows kept per service
_WEBHOOK_REPO_RE = re.compile(r"[A-Za-z0-9._-]{1,100}")
_WEBHOOK_TASKS: set = set()           # keeps background update tasks referenced until done


def webhook_bind_address() -> str:
    """Address the listener binds to: 127.0.0.1 unless ATS_WEBHOOK_BIND overrides it."""
    return os.environ.get("ATS_WEBHOOK_BIND", "").strip() or WEBHOOK_DEFAULT_BIND


def webhook_url(name: str) -> str:
    """Public payload URL to configure on GitHub for this service."""
    import ats_cluster
    node = ats_cluster.Store().node()
    if node and node["role"] == "global":
        return ""
    host = node["webhook"] if node else f"webhook.{MAIN_DOMAIN}"
    return f"https://{host}/webhook/{name}"


def generate_webhook_secret() -> str:
    """32 random bytes, hex encoded."""
    return secrets.token_hex(32)


def sanitize_for_log(value, max_len: int = 200) -> str:
    """Make attacker-controlled text safe to log/audit: control characters become spaces, truncated."""
    text = "" if value is None else str(value)
    text = re.sub(r"[\x00-\x1f\x7f-\x9f  ]", " ", text)
    return text if len(text) <= max_len else text[:max_len] + "..."


def verify_webhook_signature(secret: str, body: bytes, header: Optional[str]) -> bool:
    """Check an `X-Hub-Signature-256: sha256=<hex>` header (constant-time compare)."""
    if not secret or not header:
        return False
    header = header.strip()
    if not header.startswith("sha256="):
        return False
    try:
        provided = header[len("sha256="):].encode("ascii")
    except UnicodeEncodeError:
        return False
    expected = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest().encode("ascii")
    return hmac.compare_digest(expected, provided)


def get_webhook_info(name: str) -> Optional[Dict]:
    """{"name", "url", "secret", "auto_update", "branch"} for a service, or None."""
    row = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    if not row:
        return None
    auto = _svc_field(row, 'auto_update', 1)
    return {
        "name": row['name'],
        "url": webhook_url(row['name']),
        "secret": _svc_field(row, 'webhook_secret', "") or "",
        "auto_update": bool(auto),
        "branch": _svc_field(row, 'branch', 'main') or 'main',
    }


def rotate_webhook_secret(name: str) -> str:
    """Replace the service's webhook secret with a fresh random one and return it."""
    if not db.query("SELECT 1 FROM services WHERE name=?", (name,), fetch_one=True):
        raise ValueError(f"Service '{name}' not found")
    new_secret = generate_webhook_secret()
    db.query("UPDATE services SET webhook_secret=?, updated_at=CURRENT_TIMESTAMP WHERE name=?", (new_secret, name))
    audit_log("WEBHOOK_SECRET_ROTATED", name)
    return new_secret


def set_auto_update(name: str, enabled: bool) -> None:
    """Turn webhook-triggered updates on/off for a service."""
    if not db.query("SELECT 1 FROM services WHERE name=?", (name,), fetch_one=True):
        raise ValueError(f"Service '{name}' not found")
    db.query("UPDATE services SET auto_update=? WHERE name=?", (1 if enabled else 0, name))
    audit_log("WEBHOOK_AUTO_UPDATE", name, {"enabled": bool(enabled)})


def record_webhook_event(service_name: str, event: Optional[str], ref: Optional[str],
                         commit_sha: Optional[str], result: str, message: str = "", delivery: str = "", signature: str = "manual") -> Optional[int]:
    """Insert a webhook_events row (fields sanitised) and keep only the newest 200 per service."""
    event_id = db.insert(
        "INSERT INTO webhook_events (service_name, event, ref, commit_sha, result, message, delivery, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (service_name, sanitize_for_log(event, 40), sanitize_for_log(ref, 200),
         sanitize_for_log(commit_sha, 64), result, sanitize_for_log(message, 300), sanitize_for_log(delivery, 100), signature)
    )
    db.query(
        "DELETE FROM webhook_events WHERE service_name=? AND id NOT IN "
        "(SELECT id FROM webhook_events WHERE service_name=? ORDER BY id DESC LIMIT ?)",
        (service_name, service_name, WEBHOOK_EVENT_RETENTION)
    )
    return event_id


def update_webhook_event(event_id: Optional[int], result: str, message: str = "") -> None:
    """Set the final result/message of a previously recorded delivery."""
    if event_id is None:
        return
    db.query("UPDATE webhook_events SET result=?, message=? WHERE id=?",
             (result, sanitize_for_log(message, 300), event_id))


def list_webhook_events(name: str, limit: int = 20) -> List[Dict]:
    """Newest-first deliveries for a service: [{timestamp, event, ref, commit, result, message}]."""
    rows = db.query(
        "SELECT timestamp, event, ref, commit_sha, result, message, delivery, signature FROM webhook_events "
        "WHERE service_name=? ORDER BY id DESC LIMIT ?", (name, int(limit)), fetch_all=True)
    return [{"timestamp": r['timestamp'], "event": r['event'], "ref": r['ref'], "commit": r['commit_sha'],
             "result": r['result'], "message": r['message'], "delivery": r['delivery'], "signature": r['signature'] or "unknown"} for r in rows]


def get_service_by_name(name: str) -> Optional[dict]:
    """Look up service by name first, then fall back to repo URL match"""
    row = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    if row:
        return dict(row)

    # Fallback: match against the repo URL (GitHub repo name may differ from service name)
    # e.g. repo 'abinaavk_portfolio' should match service with repo_url ending in 'abinaavk_portfolio'
    safe_name = name.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    row = db.query(
        "SELECT * FROM services WHERE repo_url LIKE ? ESCAPE '\\'",
        (f"%/{safe_name}",),
        fetch_one=True
    )
    if row:
        return dict(row)

    row = db.query(
        "SELECT * FROM services WHERE repo_url LIKE ? ESCAPE '\\'",
        (f"%/{safe_name}.git",),
        fetch_one=True
    )
    if row:
        return dict(row)

    return None

# ──────────────────────────────────────────────────────────────────────────────
#   handle_webhook  — GitHub push-event handler (authenticated)
# ──────────────────────────────────────────────────────────────────────────────

_HTTP_REASONS = {
    200: "OK", 202: "Accepted", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout", 411: "Length Required",
    413: "Payload Too Large", 431: "Request Header Fields Too Large", 500: "Internal Server Error",
}


class _BadWebhookRequest(Exception):
    """Malformed/oversized request: carries the HTTP status to answer with."""

    def __init__(self, status: int, detail: str = ""):
        super().__init__(detail or _HTTP_REASONS.get(status, ""))
        self.status = status


async def _http_reply(writer, status: int, body: str = "") -> None:
    """Write a minimal HTTP/1.1 response and close-delimit it. Bodies never carry detail on 4xx."""
    reason = _HTTP_REASONS.get(status, "")
    payload = (body or reason).encode()
    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Content-Type: text/plain\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    writer.write(head + payload)
    await writer.drain()


async def _read_webhook_request(reader) -> Tuple[str, str, Dict[str, str], bytes]:
    """Read request line, headers and (size-limited) body. Raises _BadWebhookRequest."""
    try:
        request_line = (await reader.readline()).decode("latin-1").strip()
    except (ValueError, asyncio.LimitOverrunError):
        raise _BadWebhookRequest(431)
    parts = request_line.split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        raise _BadWebhookRequest(400)
    method, target = parts[0].upper(), parts[1]

    headers: Dict[str, str] = {}
    while True:
        try:
            line = (await reader.readline()).decode("latin-1").strip()
        except (ValueError, asyncio.LimitOverrunError):
            raise _BadWebhookRequest(431)
        if not line:
            break                                        # blank line = end of headers
        if len(headers) >= WEBHOOK_MAX_HEADERS:
            raise _BadWebhookRequest(431)
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower()
            if key in headers:
                raise _BadWebhookRequest(400, "duplicate content-length")
            headers[key] = val.strip()

    if "transfer-encoding" in headers:
        raise _BadWebhookRequest(411)
    raw_len = headers.get("content-length", "0")
    if not re.fullmatch(r"[0-9]{1,12}", raw_len):        # integer, >= 0 (no sign, no spaces)
        raise _BadWebhookRequest(400, "bad content-length")
    content_length = int(raw_len)
    if content_length > WEBHOOK_MAX_BODY:
        raise _BadWebhookRequest(413)

    body = b""
    if content_length:
        try:
            body = await reader.readexactly(content_length)
        except asyncio.IncompleteReadError:
            raise _BadWebhookRequest(400, "truncated body")
    return method, target, headers, body


async def _run_webhook_update(name: str, svc: dict, event_id: Optional[int]) -> None:
    """Background: run the update under the per-service lock and record the outcome."""
    loop = asyncio.get_running_loop()
    started = time.time()
    try:
        res = await loop.run_in_executor(None, functools.partial(service_git_update, name, svc, _logger_log))
        result, message = "updated", res.get("message", "")
    except ServiceBusyError as e:
        result, message = "busy", str(e)
        logger.warning(f"[{name}] Webhook update skipped: {e}")
    except Exception as e:
        result, message = "failed", str(e)[:300]
        logger.error(f"[{name}] Webhook update failed: {e}")
    update_webhook_event(event_id, result, message)
    audit_log("WEBHOOK_UPDATE", name, {"result": result})


async def handle_webhook(reader, writer):
    """
    Handle one webhook delivery (see MANAGE_SPEC 2.6):

      * POST /webhook/<service> (or /<service>); the name must match
        ^[a-zA-Z0-9_-]{1,64}$. The repo-name fallback (payload repository.name)
        may still locate the service, but the signature is always verified
        against THAT service's secret.
      * X-Hub-Signature-256 = sha256 HMAC of the raw body, constant-time compared.
        Bad/missing -> 401, service without a secret -> 403 (no detail in the body).
      * body <= 1 MiB (413), Content-Length validated, whole read bounded by a timeout.
      * ping -> 200; only push events for the tracked branch update; reply 202
        immediately and update in the background under the per-service lock.
      * every delivery for a known service is recorded in webhook_events.
    """
    try:
        try:
            method, target, headers, body = await asyncio.wait_for(
                _read_webhook_request(reader), timeout=WEBHOOK_READ_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning("Webhook: timed out reading request")
            await _http_reply(writer, 408)
            return
        except _BadWebhookRequest as e:
            logger.warning(f"Webhook: rejected malformed request ({e.status})")
            await _http_reply(writer, e.status)
            return

        if method != "POST":
            await _http_reply(writer, 405)
            return

        import ats_routing
        status, message = await ats_routing.receive(sys.modules[__name__], target, headers, body)
        await _http_reply(writer, status, message)

    except ConnectionError:
        pass                                  # client went away mid-reply
    except Exception as e:
        logger.error(f"Webhook error: {sanitize_for_log(e, 300)}")
        try:
            await _http_reply(writer, 500)
        except Exception:
            pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

# ──────────────────────────────────────────────────────────────────────────────
#   start_webhook_server / run_webhook_listener
# ──────────────────────────────────────────────────────────────────────────────

async def start_webhook_server(bind: Optional[str] = None, port: int = WEBHOOK_PORT):
    """Start background webhook listener (127.0.0.1:9999 unless ATS_WEBHOOK_BIND says otherwise)"""
    import ats_cluster
    node = ats_cluster.Store().node()
    if not node or node["role"] != "local":
        raise ValueError("Only a configured primary Local can start a webhook receiver")
    bind = bind or webhook_bind_address()
    try:
        server = await asyncio.start_server(handle_webhook, bind, port)
        print_status(f"Webhook Listener active on {bind}:{port}", "success")
        logger.info(f"Webhook Listener active on {bind}:{port}")
        if bind not in ("127.0.0.1", "::1", "localhost"):
            logger.warning(f"Webhook listener is bound to {bind}, not loopback; "
                           f"requests are still HMAC-authenticated per service")
        async with server:
            await server.serve_forever()
    except Exception as e:
        logger.error(f"Could not start webhook server: {e}")
        print_status(f"Webhook server failed: {e}", "error")

def print_webhook_setup(name: str) -> None:
    """Print what the owner must enter on GitHub for this service (URL + secret)."""
    import ats_cluster
    node = ats_cluster.Store().node()
    if node and node["role"] == "global":
        print("Configure the repository mapping and GitHub webhook on the primary Local; Global has no webhook endpoint.")
        return
    info = get_webhook_info(name)
    if not info:
        return
    print(f"\n{C_CYAN}GitHub webhook (Settings -> Webhooks -> Add webhook):{C_RESET}")
    print(f"  {C_BOLD}Payload URL:{C_RESET}   {info['url']}")
    print(f"  {C_BOLD}Content type:{C_RESET}  application/json")
    print(f"  {C_BOLD}Secret:{C_RESET}        {info['secret']}")
    print(f"  {C_BOLD}Events:{C_RESET}        Just the push event (updates run for branch '{info['branch']}')")
    print(f"  {C_YELLOW}Keep the secret private; rotate it from Service Operations -> Webhook.{C_RESET}")

def manage_webhook_menu(name: str):
    """Interactive: show this service's webhook URL + secret, rotate the secret, toggle auto-update."""
    while True:
        info = get_webhook_info(name)
        if not info:
            print_status("Service not found", "error")
            return
        print_header()
        print(f"{C_CYAN}{C_BOLD}═══ WEBHOOK: {name} ═══{C_RESET}\n")
        print(f"  {C_BOLD}Payload URL:{C_RESET}   {info['url']}")
        print(f"  {C_BOLD}Content type:{C_RESET}  application/json")
        print(f"  {C_BOLD}Secret:{C_RESET}        {info['secret'] or '(none - rotate to generate one)'}")
        print(f"  {C_BOLD}Events:{C_RESET}        Just the push event (branch '{info['branch']}')")
        print(f"  {C_BOLD}Auto-update:{C_RESET}   {'ON' if info['auto_update'] else 'OFF'}")
        print(f"  {C_BOLD}Listener:{C_RESET}      {webhook_bind_address()}:{WEBHOOK_PORT}")
        events = list_webhook_events(name, 5)
        if events:
            print(f"\n  {C_BOLD}Recent deliveries:{C_RESET}")
            for ev in events:
                print(f"    {str(ev['timestamp'])[:19]}  {(ev['event'] or '-'):<8} {ev['result']:<18} {ev['message'] or ''}")
        print(f"\n  {C_BOLD}[1]{C_RESET} Rotate secret")
        print(f"  {C_BOLD}[2]{C_RESET} Turn auto-update {'OFF' if info['auto_update'] else 'ON'}")
        print(f"  {C_BOLD}[0]{C_RESET} Back\n")

        choice = input(f"  {C_BOLD}Select:{C_RESET} ").strip()
        if choice == "0" or not choice:
            return
        try:
            if choice == "1":
                if input(f"  {C_RED}Rotate secret? GitHub must be updated afterwards (yes/no):{C_RESET} ").strip().lower() == "yes":
                    rotate_webhook_secret(name)
                    print_status("Secret rotated - update it in the GitHub webhook settings.", "success")
                    time.sleep(1)
            elif choice == "2":
                set_auto_update(name, not info['auto_update'])
        except Exception as e:
            print_status(f"Failed: {e}", "error")
            input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

async def run_webhook_listener():
    """Menu wrapper to start listener with Cloudflare tunnel auto-config"""
    print_header()
    import ats_cluster
    node = ats_cluster.Store().node()
    if node and node['role'] == 'global':
        raise ValueError('Global servers do not host a webhook receiver')
    webhook_domain = node['webhook'] if node else f"webhook.{MAIN_DOMAIN}"
    print_status('Configure and validate the Cloudflare route manually; ATS will not overwrite it.', 'info')
    print(f"  → Public URL: {C_CYAN}https://{webhook_domain}{C_RESET}")
    print(f"  → Listening:  {C_CYAN}{webhook_bind_address()}:{WEBHOOK_PORT}{C_RESET} (local; reached through the tunnel)")
    print(f"  → Payload:    {C_CYAN}application/json{C_RESET}")
    print(f"  → Auth:       {C_CYAN}X-Hub-Signature-256 with the per-service secret below{C_RESET}")

    services = db.query("SELECT name FROM services ORDER BY name", fetch_all=True)
    if services:
        print(f"\n  {C_BOLD}Per-service GitHub settings (Payload URL / Secret):{C_RESET}")
        for s in services:
            info = get_webhook_info(s['name'])
            if info:
                print(f"  {C_CYAN}{info['name']}{C_RESET}")
                print(f"    URL:    {info['url']}")
                print(f"    Secret: {info['secret'] or '(none)'}")
    print(f"\n{C_YELLOW}Listener is now running in the background.{C_RESET}")

    if not hasattr(run_webhook_listener, "started"):
        asyncio.create_task(start_webhook_server())
        run_webhook_listener.started = True
    else:
        print_status("Listener already running.", "info")

    loop = asyncio.get_running_loop()                    # FIX: was get_event_loop()
    await loop.run_in_executor(
        None,
        lambda: input(f"\n{C_CYAN}Press Enter to return to main menu...{C_RESET}")
    )

# ==============================================================================
#   SERVICE LISTING / MANAGEMENT
# ==============================================================================

async def manage_service(name: str, svc: dict):          # FIX: was floating orphan code
    _print_service_summary(name, svc)

    print(f"\n{C_CYAN}{'=' * 70}{C_RESET}")
    print(f"{C_CYAN}Available Operations:{C_RESET}")
    print("  1. Restart service")
    print("  2. Stop service")
    print("  3. Start service")
    print("  4. Git pull and restart")
    print("  5. Reinstall dependencies (pip install -r requirements.txt)")
    print("  6. View systemd status")
    print("  7. View resource usage")
    print("  10. Webhook URL / secret (view, rotate)")
    print("  0. Cancel")

    loop = asyncio.get_running_loop()                    # FIX: needed for all input() calls

    choice = await loop.run_in_executor(                 # FIX: was blocking input()
        None,
        lambda: input(f"\n{C_CYAN}Select operation:{C_RESET} ").strip()
    )
    await _service_menu_action(choice, name, svc)

def update_service_config(name: str):
    """Interactively update service configuration (port, domain, resources)"""
    svc = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    if not svc:
        print_status("Service not found", "error")
        return

    while True:
        print_header()
        print(f"{C_CYAN}{C_BOLD}═══ UPDATE CONFIGURATION: {name} ═══{C_RESET}\n")
        print(f"  {C_BOLD}[1]{C_RESET} Port Migration    (Current: {svc['port']})")
        print(f"  {C_BOLD}[2]{C_RESET} Domain Swap       (Current: {svc['domain']})")
        print(f"  {C_BOLD}[3]{C_RESET} Resource Scaling  (CPU: {svc['cpu_quota']}%, Mem: {svc['max_memory_mb']}MB)")
        print(f"  {C_BOLD}[0]{C_RESET} Back\n")

        choice = input(f"  {C_BOLD}Select update type:{C_RESET} ").strip()

        if choice == "0":
            break

        try:
            if choice == "1":
                new_port = input(f"\n  New Port (1024-65535): ").strip()
                service_update_config(name, svc, port=new_port)

            elif choice == "2":
                new_domain = input(f"\n  New Domain: ").strip()
                service_update_config(name, svc, domain=new_domain)

            elif choice == "3":
                cpu_input = input(f"\n  New CPU Quota % [{svc['cpu_quota']}]: ").strip()
                mem_input = input(f"  New Max Memory MB [{svc['max_memory_mb']}]: ").strip()
                service_update_config(name, svc,
                                      cpu_quota=cpu_input or None,
                                      max_memory_mb=mem_input or None)

            svc = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True) or svc
            input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

        except Exception as e:
            print_status(f"Update failed: {e}", "error")
            input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

# ==============================================================================
#   BACKUP MANAGEMENT
# ==============================================================================

async def backup_service():
    """Create backup of service database with optional remote offloading"""
    while True:
        print_header()
        print(f"{C_CYAN}{C_BOLD}═══ BACKUP MANAGEMENT ═══{C_RESET}\n")
        print(f"  {C_BOLD}[1]{C_RESET} Create Local Database Backup")
        print(f"  {C_BOLD}[2]{C_RESET} Configure Remote Offloading (S3/Drive/SCP)")
        print(f"  {C_BOLD}[3]{C_RESET} Manual Sync Backups to Remote")
        print(f"  {C_BOLD}[4]{C_RESET} Google Drive Backup Now (rclone)")
        print(f"  {C_BOLD}[5]{C_RESET} Restore Backup (Local / Google Drive)")
        print(f"  {C_BOLD}[0]{C_RESET} Back\n")

        loop = asyncio.get_running_loop()
        choice = (await loop.run_in_executor(None, lambda: input(f"  {C_BOLD}Select action:{C_RESET} "))).strip()

        if choice == "0":
            break

        if choice == "1":
            services = db.query("SELECT id, name FROM services ORDER BY name", fetch_all=True)
            if not services:
                print_status("No services deployed.", "warning")
                await asyncio.sleep(1)
                continue

            print(f"  {C_BOLD}{'ID':<6} {'SERVICE NAME'}{C_RESET}")
            print(f"  {C_CYAN}{'─' * 30}{C_RESET}")
            for s in services:
                print(f"  {s['id']:<6} {s['name']}")

            svc_id = (await loop.run_in_executor(None, lambda: input(f"\n  {C_BOLD}Enter Service ID to Backup (0 to cancel):{C_RESET} "))).strip()
            
            if svc_id == "0" or not svc_id: continue

            svc = db.query("SELECT * FROM services WHERE id=?", (svc_id,), fetch_one=True)
            if not svc:
                print_status("Invalid Service ID.", "error")
                await asyncio.sleep(1)
                continue

            backup_file = backup_file = await loop.run_in_executor(None, create_local_backup, svc)
            if backup_file:
                # Check if auto-offload is enabled for this service
                config = db.query("SELECT * FROM remote_configs WHERE service_name=?", (svc['name'],), fetch_one=True)
                if config and config['auto_offload']:
                    await offload_backup(backup_file, config)

            await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))

        elif choice == "2":
            await configure_remote_offloading()

        elif choice == "3":
            await sync_all_backups_remote()

        elif choice == "4":
            print(f"\n  {C_CYAN}Running Google Drive backup...{C_RESET}")
            success, result = await gdrive_backup_now_async()
            if success:
                print_status(f"Backup successful: {result}", "success")
            else:
                print_status(f"Backup failed: {result}", "error")
            await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))

        elif choice == "5":
            await restore_backup_menu()

def create_local_backup(svc, retain_legacy=True):
    """Internal logic to create a zip of the database"""
    name = svc['name']
    try:
        # FIX: storage_path may include trailing /api from deployment
        storage_base = svc['storage_path'].rstrip('/')
        if storage_base.endswith('/api'):
            storage_base = storage_base[:-4]

        db_path = os.path.join(storage_base, "database", name)

        if not os.path.exists(db_path):
            logger.error(f"[{name}] Backup failed: database path missing: {db_path}")
            print_status(f"Database path missing: {db_path}", "error")
            audit_log("BACKUP_FAILED", name, {"stage": "path_check", "path": db_path})
            return None

        db_files = [f for f in os.listdir(db_path) if os.path.isfile(os.path.join(db_path, f))]
        if not db_files:
            logger.warning(f"[{name}] Backup skipped: no files in {db_path}")
            print_status(f"No files to backup in {db_path}", "warning")
            audit_log("BACKUP_SKIPPED", name, {"reason": "no_files", "path": db_path})
            return None

        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR, exist_ok=True)

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filename = f"{name}_db_{timestamp}.zip"
        backup_path = os.path.join(BACKUP_DIR, filename)

        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for f in db_files:
                zf.write(os.path.join(db_path, f), f)

        file_size = os.path.getsize(backup_path)
        checksum = calculate_file_hash(backup_path)

        db.query(
            "INSERT INTO backups (service_name, filename, size_bytes, checksum, local_path) VALUES (?, ?, ?, ?, ?)",
            (name, filename, file_size, checksum, backup_path)
        )

        logger.info(f"[{name}] Backup created: {filename} ({file_size/1024/1024:.2f} MB)")
        print_status(f"Local backup created: {filename} ({file_size/1024/1024:.2f} MB)", "success")
        audit_log("BACKUP_CREATE", name, {
            "filename": filename,
            "size_mb": round(file_size/1024/1024, 2),
            "files_backed_up": len(db_files),
            "path": db_path
        })

        # Legacy/manual retention must never remove a scheduled backup.
        import ats_operations
        ats_operations.init(sys.modules[__name__])
        backups = db.query(
            "SELECT id, filename FROM backups WHERE service_name=? AND location='local' AND id NOT IN (SELECT backup_id FROM ops_backups) ORDER BY id DESC",
            (name,), fetch_all=True
        )
        if retain_legacy and len(backups) > 7:
            for oldest in backups[7:]:
                old_path = os.path.join(BACKUP_DIR, oldest['filename'])
                if os.path.exists(old_path):
                    try:
                        os.remove(old_path)
                    except Exception as e:
                        logger.warning(f"[{name}] Could not delete old backup file: {e}")
                db.query("DELETE FROM backups WHERE id=?", (oldest['id'],))
                logger.info(f"[{name}] Retention: deleted {oldest['filename']}")
                audit_log("BACKUP_RETENTION_DELETE", name, {"filename": oldest['filename']})

        return backup_path

    except Exception as e:
        logger.error(f"[{name}] Backup failed: {e}")
        print_status(f"Local backup failed: {e}", "error")
        audit_log("BACKUP_FAILED", name, {"stage": "unexpected", "error": str(e)})
        return None


# ==============================================================================
#   GOOGLE DRIVE BACKUP (rclone)
# ==============================================================================

def _write_backup_log(msg):
    """Append a timestamped line to the backup log file"""
    try:
        os.makedirs(ATS_LOG_DIR, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(BACKUP_LOG, "a") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception as e:
        logger.error(f"Failed to write backup log: {e}")


def _read_key_file() -> Optional[str]:
    """Return the stored key (stripped) or None if missing/empty."""
    try:
        with open(ENCRYPTION_KEY_FILE, 'r') as f:
            key = f.read().strip()
    except FileNotFoundError:
        return None
    return key or None


def _get_or_create_key() -> Optional[str]:
    """
    Get the backup encryption key from its file, or generate and save one.

    Returns a non-empty key, or None if no usable key could be obtained --
    never an empty string, so callers can never encrypt with an empty
    password. The key file is created atomically with mode 0600
    (O_CREAT|O_EXCL), never written world-readable and chmod'ed afterwards.
    """
    try:
        key = _read_key_file()
        if key:
            try:
                if os.stat(ENCRYPTION_KEY_FILE).st_mode & 0o077:
                    os.chmod(ENCRYPTION_KEY_FILE, 0o600)
            except OSError:
                pass
            return key

        # An existing but empty key file is unusable; replace it.
        if os.path.exists(ENCRYPTION_KEY_FILE):
            os.remove(ENCRYPTION_KEY_FILE)

        # Generate a new 256-bit key
        result = subprocess.run(
            ["openssl", "rand", "-hex", "32"],
            capture_output=True, text=True, timeout=10
        )
        key = result.stdout.strip()
        if result.returncode != 0 or not re.fullmatch(r"[0-9a-f]{64}", key):
            logger.error("Could not generate a backup encryption key (openssl rand failed); refusing to continue without a key")
            return None

        fd = os.open(ENCRYPTION_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(key)
        except Exception:
            try:
                os.remove(ENCRYPTION_KEY_FILE)
            except OSError:
                pass
            raise
        logger.info(f"Generated new backup encryption key at {ENCRYPTION_KEY_FILE}")
        return key
    except FileExistsError:
        # Another process created the key between our check and our create.
        return _read_key_file()
    except Exception as e:
        logger.error(f"Failed to get/create encryption key: {e}")
        return None


def _encrypt_file(input_path, output_path):
    """
    Encrypt a file using AES-256-CBC via OpenSSL. Returns True only if openssl
    succeeded AND produced a non-empty output file. The key is passed to
    openssl as `-pass file:<keyfile>`, never on the command line.
    """
    key = _get_or_create_key()
    if not key:
        return False
    ok = False
    try:
        result = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2",
             "-in", input_path, "-out", output_path, "-pass", f"file:{ENCRYPTION_KEY_FILE}"],
            capture_output=True, text=True, timeout=120
        )
        ok = (result.returncode == 0
              and os.path.isfile(output_path)
              and os.path.getsize(output_path) > 0)
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
    if not ok and os.path.exists(output_path):
        try:
            os.remove(output_path)
        except OSError:
            pass
    return ok


def _decrypt_file(input_path, output_path):
    """Decrypt a file using AES-256-CBC via OpenSSL. Returns True on success."""
    # Decryption must never mint a fresh key: that could only ever fail (or,
    # worse, mask a lost key), so require the existing one.
    if not _read_key_file():
        logger.error("Decryption failed: backup encryption key is missing")
        return False
    try:
        result = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
             "-in", input_path, "-out", output_path, "-pass", f"file:{ENCRYPTION_KEY_FILE}"],
            capture_output=True, text=True, timeout=120
        )
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        return False


def _rclone_delete_old(remote_path):
    """Delete backups older than GDRIVE_RETENTION_DAYS from a remote path"""
    try:
        result = subprocess.run(
            ["rclone", "delete", remote_path,
             "--min-age", f"{GDRIVE_RETENTION_DAYS}d",
             "--bwlimit", RCLONE_BWLIMIT],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            if result.stdout.strip():
                _write_backup_log(f"Retention: deleted old backups from {remote_path}")
            return True
        else:
            _write_backup_log(f"WARNING: Retention cleanup failed for {remote_path}: {result.stderr.strip()}")
            return False
    except Exception as e:
        _write_backup_log(f"WARNING: Retention cleanup error: {e}")
        return False


def _rclone_show_size():
    """Show total Drive storage used under gdrive:backups"""
    try:
        result = subprocess.run(
            ["rclone", "size", GDRIVE_FOLDER, "--json"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            import json
            data = json.loads(result.stdout)
            total_bytes = data.get("bytes", 0)
            total_files = data.get("count", 0)
            size_mb = total_bytes / 1024 / 1024
            if size_mb >= 1024:
                size_str = f"{size_mb / 1024:.2f} GB"
            else:
                size_str = f"{size_mb:.2f} MB"
            print(f"  {C_CYAN}Drive usage: {size_str} ({total_files} files){C_RESET}")
            _write_backup_log(f"Drive storage: {size_str} across {total_files} files")
        else:
            print(f"  {C_YELLOW}Could not fetch Drive size: {result.stderr.strip()}{C_RESET}")
    except Exception as e:
        print(f"  {C_YELLOW}Could not fetch Drive size: {e}{C_RESET}")


def backup_gdrive_now():
    """
    Backup all services' databases to Google Drive via rclone.
    Each service gets its own folder under gdrive:backups/<service_name>/.

    Flow per service:
      1. Stop service
      2. Zip DB into a private (0700) temp dir created with mkdtemp
      3. Encrypt it; start service again
      4. Upload the ENCRYPTED file to gdrive:backups/<service_name>/ (retry once
         on failure). If encryption fails the backup for that service FAILS --
         a plaintext archive is never uploaded.
      5. Remove the temp dir

    Returns: (success: bool, filename_or_reason: str)
    """
    services = db.query("SELECT * FROM services", fetch_all=True)
    if not services:
        reason = "No services found to backup"
        _write_backup_log(reason)
        logger.warning("GDrive backup: no services found")
        audit_log("GDRIVE_BACKUP_SKIP", "SYSTEM", {"reason": "no_services"})
        return (False, reason)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    results = []
    all_ok = True

    logger.info(f"GDrive backup started for {len(services)} services")
    audit_log("GDRIVE_BACKUP_START", "SYSTEM", {"services": len(services)})

    for svc in services:
        name = svc['name']
        storage_base = svc['storage_path'].rstrip('/')
        if storage_base.endswith('/api'):
            storage_base = storage_base[:-4]

        db_dir = os.path.join(storage_base, "database", name)
        backup_filename = f"{name}-{timestamp}.zip"
        remote_target = f"{GDRIVE_FOLDER}/{name}"
        service_restarted = False
        tmp_dir = None
        lock_handle = None

        try:
            # Private scratch dir (mode 0700): no predictable /tmp path as root.
            tmp_dir = tempfile.mkdtemp(prefix="ats-backup-")
            tmp_path = os.path.join(tmp_dir, backup_filename)

            # Hold the per-service lock for the stop..start window so a webhook
            # update/restart cannot interleave with the backup.
            lock_handle = acquire_service_lock(name)

            # Step 1: Stop service
            _write_backup_log(f"[{name}] Stopping service...")
            result = subprocess.run(
                ["systemctl", "stop", name],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                reason = f"systemctl stop {name} failed: {result.stderr.strip()}"
                _write_backup_log(f"[{name}] ERROR: {reason}")
                all_ok = False
                results.append(f"{name}: FAILED - {reason}")
                continue

            # Step 2: Zip database files into the scratch dir
            db_files = []
            if os.path.exists(db_dir):
                db_files = [f for f in os.listdir(db_dir) if os.path.isfile(os.path.join(db_dir, f))]

            if not db_files:
                reason = f"No database files found at {db_dir}"
                _write_backup_log(f"[{name}] ERROR: {reason}")
                subprocess.run(["systemctl", "start", name], timeout=30)
                all_ok = False
                results.append(f"{name}: FAILED - {reason}")
                continue

            # Zip all DB files into a single backup
            with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for f in db_files:
                    zf.write(os.path.join(db_dir, f), f)
            _write_backup_log(f"[{name}] Database zipped to {tmp_path}")

            # Encrypt the backup before upload
            enc_path = tmp_path + ".enc"
            encrypted = _encrypt_file(tmp_path, enc_path)

            # Step 3: Restart service immediately after the copy (whatever the
            # encryption outcome -- downtime must not depend on openssl).
            subprocess.run(["systemctl", "start", name], timeout=30)
            service_restarted = True
            release_service_lock(lock_handle)
            lock_handle = None
            _write_backup_log(f"[{name}] Service restarted")

            if not encrypted:
                # Never fall back to uploading the plaintext archive.
                reason = "Encryption failed; refusing to upload an unencrypted backup"
                _write_backup_log(f"[{name}] ERROR: {reason}")
                logger.error(f"[{name}] GDrive backup aborted: {reason}")
                audit_log("GDRIVE_BACKUP_FAIL", name, {"error": "encryption_failed"})
                all_ok = False
                results.append(f"{name}: FAILED - {reason}")
                continue

            _write_backup_log(f"[{name}] Backup encrypted: {enc_path}")
            upload_path = enc_path
            backup_filename_enc = backup_filename + ".enc"

            # Step 4: Upload to Google Drive (with one retry on failure, bandwidth throttle)
            uploaded = False
            for attempt in range(2):
                _write_backup_log(f"[{name}] Uploading to {remote_target} (attempt {attempt + 1}/2)...")
                result = subprocess.run(
                    ["rclone", "copy", upload_path, remote_target, "--bwlimit", RCLONE_BWLIMIT],
                    capture_output=True, text=True, timeout=300
                )
                if result.returncode == 0:
                    _write_backup_log(f"[{name}] Backup successful: {backup_filename_enc}")
                    logger.info(f"[{name}] GDrive backup uploaded: {backup_filename_enc} -> {remote_target}")
                    audit_log("GDRIVE_BACKUP_OK", name, {"filename": backup_filename_enc, "target": remote_target})
                    results.append(f"{name}: {backup_filename_enc}")
                    uploaded = True
                    break
                else:
                    reason = f"rclone failed (exit {result.returncode}): {result.stderr.strip()}"
                    _write_backup_log(f"[{name}] WARNING: {reason}")
                    if attempt == 0:
                        _write_backup_log(f"[{name}] Retrying upload...")
                        time.sleep(2)
                    else:
                        _write_backup_log(f"[{name}] Backup failed: {reason}")
                        logger.error(f"[{name}] GDrive backup failed: {reason}")
                        audit_log("GDRIVE_BACKUP_FAIL", name, {"error": reason})
                        all_ok = False
                        results.append(f"{name}: FAILED - {reason}")

            # Step 5 (temp dir removal) happens in the finally block below.

            # Step 6: Retention — delete old backups on Drive
            if uploaded:
                _rclone_delete_old(remote_target)

        except ServiceBusyError as e:
            # Nothing was stopped, so there is nothing to restart.
            reason = str(e)
            _write_backup_log(f"[{name}] Backup skipped: {reason}")
            audit_log("GDRIVE_BACKUP_FAIL", name, {"error": "busy"})
            all_ok = False
            results.append(f"{name}: FAILED - {reason}")

        except subprocess.TimeoutExpired:
            reason = f"Command timed out for {name}"
            _write_backup_log(f"[{name}] Backup failed: {reason}")
            logger.error(f"[{name}] GDrive backup timeout: {reason}")
            audit_log("GDRIVE_BACKUP_FAIL", name, {"error": reason})
            if not service_restarted:
                try:
                    subprocess.run(["systemctl", "start", name], timeout=30)
                except Exception:
                    pass
            all_ok = False
            results.append(f"{name}: FAILED - {reason}")

        except Exception as e:
            reason = str(e)
            _write_backup_log(f"[{name}] Backup failed: {reason}")
            logger.error(f"[{name}] GDrive backup error: {reason}")
            audit_log("GDRIVE_BACKUP_FAIL", name, {"error": reason})
            if not service_restarted:
                try:
                    subprocess.run(["systemctl", "start", name], timeout=30)
                except Exception:
                    pass
            all_ok = False
            results.append(f"{name}: FAILED - {reason}")

        finally:
            release_service_lock(lock_handle)
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

    # Print summary
    for r in results:
        if r.endswith("FAILED") or "FAILED" in r:
            print(f"  {r}")
        else:
            print(f"  {r}")

    if all_ok:
        summary = f"Backup successful: {len(services)} services"
        logger.info(f"GDrive backup completed: {len(services)} services")
        audit_log("GDRIVE_BACKUP_END", "SYSTEM", {"services_count": len(services), "status": "success"})
    else:
        failed = sum(1 for r in results if "FAILED" in r)
        summary = f"Backup failed: {failed}/{len(services)} services failed"
        logger.error(f"GDrive backup completed with failures: {failed}/{len(services)}")
        audit_log("GDRIVE_BACKUP_END", "SYSTEM", {"services_count": len(services), "failed": failed, "status": "partial_fail"})

    _write_backup_log(summary)

    # Show total Drive storage used
    _rclone_show_size()

    return (all_ok, summary)


async def gdrive_backup_now_async():
    """Async wrapper for backup_gdrive_now()"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, backup_gdrive_now)


# ==============================================================================
#   RESTORE BACKUP MENU
# ==============================================================================

def _is_safe_backup_filename(name: str) -> bool:
    """A bare file name only: no path separators, no '.'/'..', no control characters."""
    return (bool(name) and name == os.path.basename(name) and name not in (".", "..")
            and not re.search(r"[\x00-\x1f\x7f/\\]", name))


def _plan_zip_extraction(zf: "zipfile.ZipFile", dest: str) -> List[Tuple["zipfile.ZipInfo", str, bool]]:
    """
    Validate every member of a backup archive against extraction into `dest`
    and return [(ZipInfo, absolute_target, is_dir)]. Raises ValueError on:
    absolute paths, '..' components, NUL bytes, symlinks / special files, and
    any member whose resolved path would land outside `dest`.
    Nothing is written; call this before touching the live database.
    """
    dest_real = os.path.realpath(dest)
    plan = []
    for info in zf.infolist():
        name = info.filename
        if not name or "\x00" in name:
            raise ValueError("Unsafe entry in backup archive (empty or NUL name)")
        norm = name.replace("\\", "/")
        if norm.startswith("/") or re.match(r"^[A-Za-z]:", norm):
            raise ValueError(f"Unsafe absolute path in backup archive: {name!r}")
        parts = [p for p in norm.split("/") if p not in ("", ".")]
        if ".." in parts:
            raise ValueError(f"Unsafe '..' path in backup archive: {name!r}")
        file_type = (info.external_attr >> 16) & 0o170000
        if file_type == 0o120000:
            raise ValueError(f"Symlink in backup archive is not allowed: {name!r}")
        if file_type not in (0, 0o100000, 0o040000):
            raise ValueError(f"Special file in backup archive is not allowed: {name!r}")
        if not parts:
            continue
        target = os.path.join(dest_real, *parts)
        resolved = os.path.realpath(target)
        if os.path.commonpath([dest_real, resolved]) != dest_real:
            raise ValueError(f"Backup entry escapes the target directory: {name!r}")
        is_dir = name.endswith("/") or file_type == 0o040000
        plan.append((info, target, is_dir))
    return plan


def _safe_extract_zip(zip_path: str, dest: str) -> int:
    """Extract a backup zip into `dest` after validating all members. Returns the file count."""
    count = 0
    with zipfile.ZipFile(zip_path, 'r') as zf:
        plan = _plan_zip_extraction(zf, dest)
        os.makedirs(dest, exist_ok=True)
        for info, target, is_dir in plan:
            if is_dir:
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if os.path.islink(target):
                raise ValueError(f"Refusing to write through symlink: {target}")
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o660)
            with os.fdopen(fd, 'wb') as out, zf.open(info) as src:
                shutil.copyfileobj(src, out)
            count += 1
    return count


def _rollback_restore(db_path: str, archived: Optional[str]):
    """Put the pre-restore database back after a failed extraction."""
    if not archived or not os.path.exists(archived):
        return
    try:
        if os.path.exists(db_path):
            shutil.rmtree(db_path)
        shutil.move(archived, db_path)
        logger.info(f"Restore rolled back: {archived} -> {db_path}")
    except Exception as e:
        logger.error(f"Restore rollback failed ({archived} -> {db_path}): {e}")


async def restore_backup_menu():
    """Restore backup from local or Google Drive"""
    loop = asyncio.get_running_loop()

    while True:
        print_header()
        print(f"{C_CYAN}{C_BOLD}═══ RESTORE BACKUP ═══{C_RESET}\n")
        print(f"  {C_BOLD}[1]{C_RESET} Restore from Local Backup")
        print(f"  {C_BOLD}[2]{C_RESET} Restore from Google Drive")
        print(f"  {C_BOLD}[0]{C_RESET} Back\n")

        choice = (await loop.run_in_executor(None, lambda: input(f"  {C_BOLD}Select action:{C_RESET} "))).strip()

        if choice == "0":
            break
        elif choice == "1":
            await restore_from_local()
        elif choice == "2":
            await restore_from_drive()


async def restore_from_local():
    """Restore a backup from the local /opt/backups directory"""
    loop = asyncio.get_running_loop()

    logger.info("Local restore initiated")
    audit_log("RESTORE_LOCAL_START", "SYSTEM")

    # List services
    services = db.query("SELECT id, name FROM services ORDER BY name", fetch_all=True)
    if not services:
        print_status("No services deployed.", "warning")
        await asyncio.sleep(1)
        return

    print(f"\n  {C_BOLD}{'ID':<6} {'SERVICE NAME'}{C_RESET}")
    print(f"  {C_CYAN}{'─' * 30}{C_RESET}")
    for s in services:
        print(f"  {s['id']:<6} {s['name']}")

    svc_id = (await loop.run_in_executor(None, lambda: input(f"\n  {C_BOLD}Enter Service ID to restore (0 to cancel):{C_RESET} "))).strip()
    if svc_id == "0" or not svc_id:
        return

    svc = db.query("SELECT * FROM services WHERE id=?", (svc_id,), fetch_one=True)
    if not svc:
        print_status("Invalid Service ID.", "error")
        return

    name = svc['name']

    # List local backups for this service
    backups = db.query(
        "SELECT id, filename, size_bytes, timestamp FROM backups WHERE service_name=? ORDER BY timestamp DESC",
        (name,), fetch_all=True
    )
    if not backups:
        print_status(f"No local backups found for '{name}'.", "warning")
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
        return

    print(f"\n  {C_BOLD}Local backups for {name}:{C_RESET}")
    print(f"  {C_BOLD}{'ID':<6} {'FILENAME':<45} {'SIZE':<12} {'DATE'}{C_RESET}")
    print(f"  {C_CYAN}{'─' * 80}{C_RESET}")
    for b in backups:
        size_mb = b['size_bytes'] / 1024 / 1024 if b['size_bytes'] else 0
        print(f"  {b['id']:<6} {b['filename']:<45} {size_mb:<12.2f} MB {b['timestamp']}")

    bk_id = (await loop.run_in_executor(None, lambda: input(f"\n  {C_BOLD}Enter Backup ID to restore (0 to cancel):{C_RESET} "))).strip()
    if bk_id == "0" or not bk_id:
        return

    backup = db.query("SELECT * FROM backups WHERE id=?", (bk_id,), fetch_one=True)
    if not backup:
        print_status("Invalid Backup ID.", "error")
        return

    backup_path = os.path.join(BACKUP_DIR, backup['filename'])
    if not os.path.exists(backup_path):
        print_status(f"Backup file missing: {backup['filename']}", "error")
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
        return

    await _do_restore(svc, backup_path, backup['filename'])


async def restore_from_drive():
    """Download and restore a backup from Google Drive"""
    loop = asyncio.get_running_loop()

    logger.info("Google Drive restore initiated")
    audit_log("RESTORE_DRIVE_START", "SYSTEM")

    # List services
    services = db.query("SELECT id, name FROM services ORDER BY name", fetch_all=True)
    if not services:
        print_status("No services deployed.", "warning")
        await asyncio.sleep(1)
        return

    print(f"\n  {C_BOLD}{'ID':<6} {'SERVICE NAME'}{C_RESET}")
    print(f"  {C_CYAN}{'─' * 30}{C_RESET}")
    for s in services:
        print(f"  {s['id']:<6} {s['name']}")

    svc_id = (await loop.run_in_executor(None, lambda: input(f"\n  {C_BOLD}Enter Service ID to restore (0 to cancel):{C_RESET} "))).strip()
    if svc_id == "0" or not svc_id:
        return

    svc = db.query("SELECT * FROM services WHERE id=?", (svc_id,), fetch_one=True)
    if not svc:
        print_status("Invalid Service ID.", "error")
        return

    name = svc['name']
    remote_path = f"{GDRIVE_FOLDER}/{name}"

    # List backups on Google Drive
    print(f"\n  {C_CYAN}Fetching backups from {remote_path}...{C_RESET}")
    try:
        result = subprocess.run(
            ["rclone", "lsf", remote_path, "--bwlimit", RCLONE_BWLIMIT],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            print_status(f"Failed to list remote backups: {result.stderr.strip()}", "error")
            logger.error(f"GDrive restore list failed for {name}: {result.stderr.strip()}")
            await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
            return

        files = [f.strip() for f in result.stdout.strip().split('\n')
                 if f.strip() and _is_safe_backup_filename(f.strip())]
        if not files:
            print_status(f"No backups found on Google Drive for '{name}'.", "warning")
            await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
            return

    except subprocess.TimeoutExpired:
        print_status("rclone list timed out.", "error")
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
        return

    # Show available backups
    print(f"\n  {C_BOLD}Google Drive backups for {name}:{C_RESET}")
    print(f"  {C_BOLD}{'#':<6} {'FILENAME'}{C_RESET}")
    print(f"  {C_CYAN}{'─' * 60}{C_RESET}")
    for idx, f in enumerate(files, start=1):
        print(f"  {idx:<6} {f}")

    sel = (await loop.run_in_executor(None, lambda: input(f"\n  {C_BOLD}Enter backup # to restore (0 to cancel):{C_RESET} "))).strip()
    if sel == "0" or not sel:
        return

    try:
        sel_idx = int(sel) - 1
        if sel_idx < 0 or sel_idx >= len(files):
            print_status("Invalid selection.", "error")
            await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
            return
    except ValueError:
        print_status("Invalid selection.", "error")
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
        return

    selected_file = files[sel_idx]
    remote_file = f"{remote_path}/{selected_file}"

    # Private scratch dir (mkdtemp -> mode 0700) instead of predictable /tmp
    # paths as root; always removed in the finally block below.
    tmp_dir = tempfile.mkdtemp(prefix="ats-restore-")
    try:
        local_tmp = os.path.join(tmp_dir, selected_file)

        # Download from Google Drive
        print(f"\n  {C_CYAN}Downloading {selected_file}...{C_RESET}")
        try:
            result = subprocess.run(
                ["rclone", "copy", remote_file, tmp_dir, "--bwlimit", RCLONE_BWLIMIT],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode != 0:
                print_status(f"Download failed: {result.stderr.strip()}", "error")
                logger.error(f"GDrive restore download failed for {name}: {result.stderr.strip()}")
                audit_log("RESTORE_DRIVE_FAIL", name, {"error": result.stderr.strip()})
                await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
                return
        except subprocess.TimeoutExpired:
            print_status("Download timed out.", "error")
            logger.error(f"GDrive restore download timed out for {name}")
            audit_log("RESTORE_DRIVE_FAIL", name, {"error": "download_timeout"})
            await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
            return

        if not os.path.exists(local_tmp):
            print_status(f"Downloaded file not found at {local_tmp}", "error")
            await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
            return

        # Decrypt if encrypted (.enc file)
        restore_file = local_tmp
        if selected_file.endswith(".enc"):
            print(f"  {C_CYAN}Decrypting backup...{C_RESET}")
            dec_path = local_tmp[:-4]  # Remove .enc extension
            if _decrypt_file(local_tmp, dec_path):
                restore_file = dec_path
                _write_backup_log(f"[{name}] Backup decrypted")
                logger.info(f"[{name}] Backup decrypted for restore")
            else:
                print_status("Decryption failed — check encryption key", "error")
                logger.error(f"[{name}] Restore decryption failed")
                audit_log("RESTORE_DRIVE_FAIL", name, {"error": "decryption_failed"})
                await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
                return

        display_name = selected_file[:-4] if selected_file.endswith(".enc") else selected_file
        await _do_restore(svc, restore_file, display_name)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


async def _do_restore(svc, backup_path, filename):
    """Common restore logic for both local and Drive backups"""
    loop = asyncio.get_running_loop()
    name = svc['name']

    print(f"\n{C_RED}{C_BOLD}═══ RESTORE DATABASE: {name} ═══{C_RESET}")
    print(f"{C_YELLOW}WARNING: This will overwrite current database files with: {filename}{C_RESET}\n")

    confirm = (await loop.run_in_executor(None, lambda: input(f"  Type 'RESTORE' to confirm: "))).strip()
    if confirm != "RESTORE":
        print_status("Restore cancelled", "warning")
        logger.info(f"[{name}] Restore cancelled by user")
        audit_log("RESTORE_CANCELLED", name, {"filename": filename})
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
        return

    temp_old = None
    lock_handle = None
    try:
        db_path = os.path.join(svc['storage_path'], "database", name)

        logger.info(f"[{name}] Restore started: {filename}")
        audit_log("RESTORE_START", name, {"filename": filename})

        # Reject unsafe archives (absolute paths, '..', symlinks) BEFORE the
        # service is stopped or the live database is touched.
        with zipfile.ZipFile(backup_path, 'r') as zf:
            _plan_zip_extraction(zf, db_path)

        lock_handle = acquire_service_lock(name)   # busy -> ServiceBusyError, nothing touched
        print_status(f"Stopping service {name}...", "info")
        run_root(["systemctl", "stop", name])
        logger.info(f"[{name}] Service stopped for restore")

        # Archive current DB files
        if os.path.exists(db_path) and os.listdir(db_path):
            temp_old = db_path + "_pre_restore_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            shutil.move(db_path, temp_old)
            os.makedirs(db_path, exist_ok=True)
            print_status("Current database archived to temporary folder", "info")
            logger.info(f"[{name}] Current DB archived to {temp_old}")
        else:
            os.makedirs(db_path, exist_ok=True)

        print_status("Extracting backup files...", "info")
        _safe_extract_zip(backup_path, db_path)
        logger.info(f"[{name}] Backup extracted to {db_path}")

        # Set permissions
        for root, dirs, files in os.walk(db_path):
            for d in dirs:
                shutil.chown(os.path.join(root, d), user=SERVICE_USER, group=SERVICE_GROUP)
            for f in files:
                filepath = os.path.join(root, f)
                shutil.chown(filepath, user=SERVICE_USER, group=SERVICE_GROUP)
                os.chmod(filepath, 0o660)

        print_status("Restarting service...", "info")
        run_root(["systemctl", "start", name])

        print_status(f"Restore successful: {filename}", "success")
        logger.info(f"[{name}] Restore completed: {filename}")
        audit_log("RESTORE_SUCCESS", name, {"filename": filename})

    except ServiceBusyError as e:
        print_status(str(e), "warning")
        audit_log("RESTORE_FAILED", name, {"filename": filename, "error": "busy"})
    except Exception as e:
        logger.error(f"[{name}] Restore failed: {e}")
        print_status(f"Restore failed: {e}", "error")
        audit_log("RESTORE_FAILED", name, {"filename": filename, "error": str(e)})
        _rollback_restore(os.path.join(svc['storage_path'], "database", name), temp_old)
        # Try to restart service anyway
        try:
            run_root(["systemctl", "start", name])
        except Exception:
            pass
    finally:
        release_service_lock(lock_handle)

    await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))


async def configure_remote_offloading():
    """Setup remote storage targets using rclone or scp"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ REMOTE OFFLOAD CONFIG ═══{C_RESET}\n")
    
    loop = asyncio.get_running_loop()
    name = (await loop.run_in_executor(None, lambda: input("  Service Name to configure: "))).strip()
    if not name:
        print_status("Service name cannot be empty.", "error")
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to exit...{C_RESET}"))
        return

    svc = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    if not svc:
        print_status(f"Service '{name}' not found.", "error")
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to exit...{C_RESET}"))
        return

    print(f"\n  Current configuration for {C_BOLD}{name}{C_RESET}:")
    config = db.query("SELECT * FROM remote_configs WHERE service_name=?", (name,), fetch_one=True)
    
    if config:
        print(f"    Type: {config['type']} | Target: {config['target']} | Auto: {config['auto_offload']}")
    else:
        print("    No remote config found.")

    print(f"\n  {C_BOLD}[1]{C_RESET} Setup SCP/SFTP (Second Server)")
    print(f"  {C_BOLD}[2]{C_RESET} Setup Rclone (S3/Drive/Dropbox)")
    print(f"  {C_BOLD}[3]{C_RESET} Delete Remote Config")
    print(f"  {C_BOLD}[0]{C_RESET} Cancel")

    rtype = (await loop.run_in_executor(None, lambda: input(f"\n  Choice: "))).strip()
    if rtype == "0": return

    if rtype == "3":
        if config:
            db.query("DELETE FROM remote_configs WHERE service_name=?", (name,))
            print_status(f"Remote config for '{name}' deleted.", "success")
            audit_log("REMOTE_CONFIG_DELETE", name)
        else:
            print_status(f"No remote config found for '{name}'.", "warning")
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
        return

    if rtype not in ["1", "2"]:
        print_status("Invalid choice.", "error")
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to exit...{C_RESET}"))
        return

    method = "scp" if rtype == "1" else "rclone"
    
    if rtype == "1":
        print(f"\n  Example target: {C_CYAN}user@backup-server:/path/to/backups{C_RESET}")
        target = (await loop.run_in_executor(None, lambda: input("  Remote Target: "))).strip()
    else:
        print(f"\n  Example target: {C_CYAN}my-s3-bucket:ats-backups{C_RESET}")
        target = (await loop.run_in_executor(None, lambda: input("  Rclone Remote:Target: "))).strip()

    if not target:
        print_status("Remote target cannot be empty.", "error")
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to exit...{C_RESET}"))
        return

    auto_input = (await loop.run_in_executor(None, lambda: input("  Enable auto-offload after every backup? (y/n): "))).lower()
    auto = auto_input == 'y'

    db.query("DELETE FROM remote_configs WHERE service_name=?", (name,))
    db.query("INSERT INTO remote_configs (service_name, type, target, auto_offload) VALUES (?, ?, ?, ?)",
             (name, method, target, 1 if auto else 0))
    
    print_status("Remote configuration saved.", "success")
    await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))

async def offload_backup(file_path: str, config: Dict):
    """Send a file to the remote target"""
    filename = os.path.basename(file_path)
    print_status(f"Offloading {filename} to {config['target']}...", "info")
    
    try:
        if config['type'] == "scp":
            # BatchMode=yes prevents hanging on password prompts
            cmd = ["scp", "-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", file_path, config['target']]
        else:
            cmd = ["rclone", "copy", file_path, config['target'], "--bwlimit", RCLONE_BWLIMIT]
            
        process = await asyncio.create_subprocess_exec(*cmd)
        await process.wait()
        
        if process.returncode == 0:
            print_status(f"Successfully offloaded {filename}", "success")
            audit_log("BACKUP_OFFLOAD", config['service_name'], {"filename": filename, "target": config['target']})
            return True
        else:
            print_status(f"Offload failed for {filename} with exit code {process.returncode}", "error")
            return False
    except Exception as e:
        print_status(f"Offload failed for {filename}: {e}", "error")
        return False

async def sync_all_backups_remote():
    """Manually push all local backups to configured remotes"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ MANUAL REMOTE SYNC ═══{C_RESET}\n")

    configs = db.query("SELECT * FROM remote_configs", fetch_all=True)
    loop = asyncio.get_running_loop()
    if not configs:
        print_status("No remote configurations found. Please configure Option 2 first.", "warning")
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
        return

    print_status(f"Found {len(configs)} remote configurations. Starting sync...\n", "info")

    total_synced = 0
    total_failed = 0

    for cfg in configs:
        name = cfg['service_name']
        backups = db.query("SELECT filename FROM backups WHERE service_name=?", (name,), fetch_all=True)
        
        if not backups:
            print(f"  {C_YELLOW}! No local backups found for {name}{C_RESET}")
            continue

        print(f"  {C_CYAN}Syncing {len(backups)} backups for {C_BOLD}{name}{C_RESET} to {cfg['target']}...")
        for b in backups:
            path = os.path.join(BACKUP_DIR, b['filename'])
            if os.path.exists(path):
                if await offload_backup(path, cfg):
                    total_synced += 1
                else:
                    total_failed += 1
            else:
                print(f"    {C_RED}✗ Local file missing: {b['filename']}{C_RESET}")
                total_failed += 1
    
    print(f"\n{C_CYAN}{'─' * 55}{C_RESET}")
    print(f"  {C_BOLD}Sync Results:{C_RESET}")
    print(f"  {C_GREEN}✓ Successfully synced: {total_synced}{C_RESET}")
    if total_failed > 0:
        print(f"  {C_RED}✗ Failed/Missing:     {total_failed}{C_RESET}")
    print(f"{C_CYAN}{'─' * 55}{C_RESET}")

    await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Manual sync complete. Press Enter to return to menu...{C_RESET}"))

async def list_backups():
    """Service-specific backup management with deletion"""
    while True:
        print_header()
        print(f"{C_CYAN}{C_BOLD}═══ BACKUP EXPLORER ═══{C_RESET}\n")
        
        services = db.query("SELECT id, name FROM services ORDER BY name", fetch_all=True)
        if not services:
            print_status("No services deployed.", "warning")
            await asyncio.sleep(1)
            return

        print(f"  {C_BOLD}{'ID':<6} {'SERVICE NAME'}{C_RESET}")
        print(f"  {C_CYAN}{'─' * 30}{C_RESET}")
        for s in services:
            print(f"  {s['id']:<6} {s['name']}")
        
        loop = asyncio.get_running_loop()
        svc_id = (await loop.run_in_executor(None, lambda: input(f"\n  {C_BOLD}Enter Service ID to view backups (0 to back):{C_RESET} "))).strip()
        
        if svc_id == "0" or not svc_id: break
        
        svc = db.query("SELECT name FROM services WHERE id=?", (svc_id,), fetch_one=True)
        if not svc:
            print_status("Invalid Service ID.", "error")
            await asyncio.sleep(1)
            continue

        await show_service_backups(svc['name'])

async def show_service_backups(name: str):
    """View and manage backups for a specific service"""
    while True:
        print_header()
        print(f"{C_CYAN}{C_BOLD}═══ BACKUPS: {name} ═══{C_RESET}\n")
        
        backups = db.query("SELECT * FROM backups WHERE service_name=? ORDER BY timestamp DESC", (name,), fetch_all=True)
        
        if not backups:
            print_status(f"No backups found for {name}", "warning")
            await asyncio.get_running_loop().run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
            return

        print(f"  {C_BOLD}{'ID':<4} {'SIZE (MB)':<12} {'DATE':<20} {'STATUS'}{C_RESET}")
        print(f"  {C_CYAN}{'─' * 60}{C_RESET}")
        for idx, b in enumerate(backups, 1):
            size_mb = b['size_bytes'] / 1024 / 1024
            ts = b['timestamp'][:19]
            backup_file = os.path.join(BACKUP_DIR, b['filename'])
            status = f"{C_GREEN}✓{C_RESET}" if os.path.exists(backup_file) else f"{C_RED}✗{C_RESET}"
            print(f"  {idx:<4} {size_mb:<12.2f} {ts:<20} {status}")

        print(f"\n  {C_BOLD}[ID]{C_RESET} Restore  |  {C_BOLD}[D + ID]{C_RESET} Delete (ex: d1)  |  {C_BOLD}[0]{C_RESET} Back")
        
        loop = asyncio.get_running_loop()
        choice = (await loop.run_in_executor(None, lambda: input(f"\n  Selection: "))).strip().lower()
        
        if choice == "0": break
        
        if choice.startswith('d'):
            try:
                idx = int(choice[1:])
                if 1 <= idx <= len(backups):
                    await delete_backup(backups[idx-1])
                else: raise ValueError
            except Exception:
                print_status("Invalid selection", "error")
                await asyncio.sleep(1)
        else:
            try:
                idx = int(choice)
                if 1 <= idx <= len(backups):
                    await restore_backup(backups[idx-1])
                else: raise ValueError
            except Exception:
                print_status("Invalid selection", "error")
                await asyncio.sleep(1)

async def delete_backup(backup: Dict):
    """Permanently delete a backup file and database record"""
    filename = backup['filename']
    path = os.path.join(BACKUP_DIR, filename)
    
    print(f"\n{C_RED}Delete backup {filename}? (yes/no):{C_RESET} ", end="")
    loop = asyncio.get_running_loop()
    confirm = (await loop.run_in_executor(None, lambda: input())).strip().lower()
    
    if confirm == "yes":
        if os.path.exists(path):
            os.remove(path)
        db.query("DELETE FROM backups WHERE id=?", (backup['id'],))
        print_status("Backup deleted successfully", "success")
        audit_log("BACKUP_DELETE", backup['service_name'], {"filename": filename})
        await asyncio.sleep(1)

async def restore_backup(backup: Dict):
    """Automatically restore database files from a backup zip"""
    name = backup['service_name']
    filename = backup['filename']
    backup_path = os.path.join(BACKUP_DIR, filename)

    loop = asyncio.get_running_loop()
    if not os.path.exists(backup_path):
        print_status(f"Backup file missing: {filename}", "error")
        return

    svc = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    if not svc:
        print_status(f"Service '{name}' no longer exists in database.", "error")
        return

    print(f"\n{C_RED}{C_BOLD}═══ RESTORE DATABASE: {name} ═══{C_RESET}")
    print(f"{C_YELLOW}WARNING: This will overwrite current database files with backup from {backup['timestamp']}{C_RESET}\n")
    
    confirm = (await loop.run_in_executor(None, lambda: input(f"  Type 'RESTORE' to confirm: "))).strip()
    if confirm != "RESTORE":
        print_status("Restore cancelled", "warning")
        return

    temp_old = None
    lock_handle = None
    try:
        db_path = os.path.join(svc['storage_path'], "database", name)

        # Reject unsafe archives before the service is stopped.
        with zipfile.ZipFile(backup_path, 'r') as zf:
            _plan_zip_extraction(zf, db_path)

        lock_handle = acquire_service_lock(name)   # busy -> ServiceBusyError, nothing touched
        print_status(f"Stopping service {name}...", "info")
        run_root(["systemctl", "stop", name])

        # Backup current files just in case
        if os.path.exists(db_path) and os.listdir(db_path):
            temp_old = db_path + "_pre_restore_" + datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            shutil.move(db_path, temp_old)
            os.makedirs(db_path, exist_ok=True)
            print_status("Current database archived to temporary folder", "info")
        else:
            os.makedirs(db_path, exist_ok=True)

        print_status("Extracting backup files...", "info")
        _safe_extract_zip(backup_path, db_path)

        # Set permissions
        for root, dirs, files in os.walk(db_path):
            for d in dirs:
                shutil.chown(os.path.join(root, d), user=SERVICE_USER, group=SERVICE_GROUP)
            for f in files:
                filepath = os.path.join(root, f)
                shutil.chown(filepath, user=SERVICE_USER, group=SERVICE_GROUP)
                os.chmod(filepath, 0o660)

        print_status("Restarting service...", "info")
        run_root(["systemctl", "start", name])
        release_service_lock(lock_handle)   # never hold the lock across the prompt below
        lock_handle = None

        print_status("Restore successful", "success")
        audit_log("BACKUP_RESTORE", name, {"filename": filename})
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))

    except ServiceBusyError as e:
        print_status(str(e), "warning")
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
    except Exception as e:
        logger.error(f"Restore failed: {e}")
        print_status(f"Restore failed: {e}", "error")
        _rollback_restore(os.path.join(svc['storage_path'], "database", name), temp_old)
        try:
            run_root(["systemctl", "start", name])
        except Exception:
            pass
        await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
    finally:
        release_service_lock(lock_handle)

async def global_operations():
    """Perform actions on all deployed services at once"""
    while True:
        print_header()
        print(f"{C_CYAN}{C_BOLD}═══ GLOBAL OPERATIONS ═══{C_RESET}\n")
        
        services = db.query("SELECT name FROM services", fetch_all=True)
        loop = asyncio.get_running_loop()
        if not services:
            print_status("No services deployed.", "warning")
            await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))
            return

        print(f"  Targeting {len(services)} services.\n")
        print(f"  {C_BOLD}[1]{C_RESET} Mass Restart")
        print(f"  {C_BOLD}[2]{C_RESET} Mass Stop")
        print(f"  {C_BOLD}[3]{C_RESET} Mass Start")
        print(f"  {C_BOLD}[4]{C_RESET} Bulk Dependency Audit")
        print(f"  {C_BOLD}[0]{C_RESET} Back\n")

        choice = (await loop.run_in_executor(None, lambda: input(f"  {C_BOLD}Select action:{C_RESET} "))).strip()

        if choice == "0":
            break

        if choice in ["1", "2", "3"]:
            action = {"1": "restart", "2": "stop", "3": "start"}[choice]
            print(f"\n{C_RED}{C_BOLD}!!! CONFIRM MASS {action.upper()} !!!{C_RESET}")
            confirm = (await loop.run_in_executor(None, lambda: input(f"  Type 'GLOBAL {action.upper()}' to confirm: "))).strip()
            if confirm != f"GLOBAL {action.upper()}":
                print_status("Action cancelled", "warning")
                await asyncio.sleep(1)
                continue

            print()
            for svc in services:
                name = svc['name']
                print_status(f"{action.capitalize()}ing {name}...", "info")
                try:
                    with service_lock(name):
                        run_root(["systemctl", action, name])
                except ServiceBusyError:
                    print_status(f"{name} is busy (another operation holds its lock) - skipped", "warning")
                except Exception:
                    print_status(f"Failed to {action} {name}", "error")
            
            print_status(f"Mass {action} completed", "success")
            audit_log(f"MASS_{action.upper()}", "GLOBAL")
            await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}"))

        elif choice == "4":
            await dependency_audit()

async def dependency_audit():
    """Scan all services for outdated/insecure dependencies"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ DEPENDENCY AUDIT ═══{C_RESET}\n")
    
    services = db.query("SELECT name, storage_path, runtime FROM services", fetch_all=True)
    if not services:
        print_status("No services to audit.", "warning")
        return

    print_status(f"Scanning {len(services)} services for issues...\n", "info")

    for svc in services:
        name = svc['name']
        path = get_service_path(svc['storage_path'], name)
        runtime = svc['runtime']
        
        print(f"  {C_BOLD}[ {name} ]{C_RESET}")
        
        if runtime == "python":
            venv_pip = os.path.join(path, "venv", "bin", "pip")
            if not os.path.exists(venv_pip):
                print(f"    {C_RED}✗ Virtual environment missing{C_RESET}")
                continue
            
            # Use 'pip list --outdated'
            ret, out, err = run_as_gaia([venv_pip, "list", "--outdated", "--format=columns"], capture=True)
            if ret == 0:
                lines = [l for l in out.split("\n") if l.strip()][2:] # Skip header
                if not lines:
                    print(f"    {C_GREEN}✓ All packages up to date{C_RESET}")
                else:
                    print(f"    {C_YELLOW}⚠ {len(lines)} outdated packages found:{C_RESET}")
                    for l in lines[:5]:
                        print(f"      - {l}")
                    if len(lines) > 5:
                        print(f"      ... and {len(lines)-5} more")
            else:
                print(f"    {C_RED}✗ Failed to run pip audit{C_RESET}")

        elif runtime == "node":
            # Use 'npm outdated'
            ret, out, err = run_as_gaia(["npm", "outdated"], cwd=path, capture=True)
            if ret == 0:
                print(f"    {C_GREEN}✓ All packages up to date{C_RESET}")
            elif ret == 1: # npm outdated returns 1 if issues found
                lines = [l for l in out.split("\n") if l.strip()][1:]
                print(f"    {C_YELLOW}⚠ {len(lines)} outdated packages found{C_RESET}")
            else:
                print(f"    {C_RED}✗ Failed to run npm audit{C_RESET}")
        print()

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, lambda: input(f"{C_CYAN}Press Enter to continue...{C_RESET}"))

# ==============================================================================
#   METRICS & MONITORING
# ==============================================================================

async def export_metrics():
    """Export Prometheus metrics"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ EXPORT METRICS ═══{C_RESET}\n")

    # ── Prometheus availability check ──────────────────────────────────────────
    if not PROMETHEUS_AVAILABLE:
        print_status("Prometheus client not installed.", "warning")
        print(f"\n  Install with: {C_CYAN}pip install prometheus-client{C_RESET}")
        input(f"\n  {C_CYAN}Press Enter to continue...{C_RESET}")
        return

    try:
        services = db.query("SELECT * FROM services", fetch_all=True)

        if not services:
            print_status("No services to export metrics for.", "warning")
            input(f"\n  {C_CYAN}Press Enter to continue...{C_RESET}")
            return

        # ── Health checks ──────────────────────────────────────────────────────
        print_status("Checking service health...", "info")
        health_results = await parallel_health_checks(services)

        online_count  = 0
        offline_count = 0

        for svc in services:
            is_healthy = health_results.get(svc['name'], False)
            SERVICE_STATUS.labels(service=svc['name']).set(1 if is_healthy else 0)
            if is_healthy:
                online_count += 1
            else:
                offline_count += 1

        # ── System metrics via psutil ──────────────────────────────────────────
        cpu_pct  = None
        mem_pct  = None
        disk_pct = None

        if psutil:
            print_status("Collecting system metrics...", "info")
            try:
                cpu_pct   = psutil.cpu_percent(interval=0.5)
                mem       = psutil.virtual_memory()
                disk      = psutil.disk_usage('/')
                mem_pct   = mem.percent
                disk_pct  = disk.percent

                cpu_color  = C_RED    if cpu_pct  > 80 else (C_YELLOW if cpu_pct  > 60 else C_GREEN)
                mem_color  = C_RED    if mem_pct  > 90 else (C_YELLOW if mem_pct  > 75 else C_GREEN)
                disk_color = C_RED    if disk_pct > 90 else (C_YELLOW if disk_pct > 75 else C_GREEN)

                print(f"  {C_BOLD}CPU:  {C_RESET}{cpu_color}{cpu_pct:.1f}%{C_RESET}"
                      f"   {C_BOLD}RAM:  {C_RESET}{mem_color}{mem_pct:.1f}%{C_RESET}"
                      f"   {C_BOLD}Disk: {C_RESET}{disk_color}{disk_pct:.1f}%{C_RESET}")
            except Exception as e:
                logger.debug(f"Could not collect system metrics: {e}")
        else:
            print(f"  {C_YELLOW}psutil not available — system metrics skipped{C_RESET}")

        # ── Write metrics file ─────────────────────────────────────────────────
        print_status("Writing metrics to file...", "info")
        os.makedirs(ATS_HOME, exist_ok=True)

        metrics_data = generate_latest(REGISTRY)
        with open(METRICS_FILE, 'wb') as f:
            f.write(metrics_data)

        try:
            os.chmod(METRICS_FILE, 0o644)
        except Exception:
            pass

        file_size = os.path.getsize(METRICS_FILE)

        # ── Also save snapshot to metrics history DB ───────────────────────────
        if psutil and cpu_pct is not None:
            from datetime import datetime
            for svc in services:
                try:
                    proc_name = svc['name']
                    svc_cpu   = None
                    svc_mem   = None

                    # Try to find the gunicorn process for this service by port
                    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_info']):
                        try:
                            cmdline = " ".join(proc.info['cmdline'] or [])
                            if str(svc['port']) in cmdline and 'gunicorn' in cmdline:
                                svc_cpu = proc.info['cpu_percent']
                                svc_mem = proc.info['memory_info'].rss / 1024 / 1024
                                break
                        except Exception:
                            continue

                    if svc_cpu is not None:
                        db.query(
                            """INSERT INTO metrics_history
                               (service_name, cpu_percent, memory_mb, requests_per_min)
                               VALUES (?, ?, ?, ?)""",
                            (svc['name'], svc_cpu, svc_mem, 0)
                        )
                except Exception:
                    continue

        # ── Success output ─────────────────────────────────────────────────────
        print()
        print(f"  {C_CYAN}{'─' * 55}{C_RESET}")
        print(f"  {C_GREEN}{C_BOLD}✓ Metrics exported successfully{C_RESET}")
        print(f"  {C_CYAN}{'─' * 55}{C_RESET}\n")

        print(f"  {C_BOLD}File        {C_RESET}  {METRICS_FILE}")
        print(f"  {C_BOLD}File Size   {C_RESET}  {file_size} bytes  ({file_size/1024:.2f} KB)")
        print()
        print(f"  {C_BOLD}Services    {C_RESET}  {len(services)} total")
        print(f"  {C_BOLD}Online      {C_RESET}  {C_GREEN}{online_count}{C_RESET}")
        print(f"  {C_BOLD}Offline     {C_RESET}  {C_RED}{offline_count}{C_RESET}")
        print()

        # ── Per-service status table ───────────────────────────────────────────
        print(f"  {C_BOLD}{'SERVICE':<25} {'STATUS':<12} {'PORT':<8}{C_RESET}")
        print(f"  {C_CYAN}{'─' * 48}{C_RESET}")
        for svc in services:
            is_healthy = health_results.get(svc['name'], False)
            status_col = f"{C_GREEN}● ONLINE{C_RESET}" if is_healthy else f"{C_RED}● OFFLINE{C_RESET}"
            name       = (svc['name'][:23] + "..") if len(svc['name']) > 23 else svc['name']
            print(f"  {name:<25} {status_col:<20} {svc['port']:<8}")

        # ── System metrics summary if available ────────────────────────────────
        if cpu_pct is not None:
            print()
            print(f"  {C_BOLD}{'RESOURCE':<15} {'USAGE':<10} {'STATUS':<10}{C_RESET}")
            print(f"  {C_CYAN}{'─' * 38}{C_RESET}")

            for label, val, warn, crit in [
                ("CPU",  cpu_pct,  60, 80),
                ("RAM",  mem_pct,  75, 90),
                ("Disk", disk_pct, 75, 90),
            ]:
                color  = C_RED if val > crit else (C_YELLOW if val > warn else C_GREEN)
                status = "CRITICAL" if val > crit else ("WARNING" if val > warn else "OK")
                print(f"  {label:<15} {color}{val:.1f}%{C_RESET:<10} {color}{status}{C_RESET}")

        print(f"\n  {C_CYAN}{'─' * 55}{C_RESET}")
        from datetime import datetime
        print(f"  {C_CYAN}Exported at: {datetime.now().strftime('%d %b %Y  %H:%M:%S')}{C_RESET}")
        print(f"  {C_CYAN}{'─' * 55}{C_RESET}")

    except Exception as e:
        logger.error(f"Metrics export failed: {e}")
        print_status(f"Export failed: {e}", "error")

    input(f"\n  {C_CYAN}Press Enter to continue...{C_RESET}")

# ==============================================================================
#   SYSTEM DIAGNOSTICS
# ==============================================================================

async def run_diagnostics():
    """Comprehensive system diagnostics"""
    from datetime import datetime

    print_header()
    print(f"{C_YELLOW}{C_BOLD}═══ ATS SYSTEM DIAGNOSTICS ═══{C_RESET}\n")
    print_status("Running diagnostic checks...", "info")
    print()

    checks  = []   # (label, passed, detail)
    PASS    = f"{C_GREEN}✓ PASS{C_RESET}"
    FAIL    = f"{C_RED}✗ FAIL{C_RESET}"
    WARN    = f"{C_YELLOW}⚠ WARN{C_RESET}"

    def check_line(label, status, detail=""):
        col = {"pass": PASS, "fail": FAIL, "warn": WARN}.get(status, WARN)
        detail_str = f"  {C_CYAN}{detail}{C_RESET}" if detail else ""
        print(f"  {label:<35} {col}{detail_str}")

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 1 — SYSTEM CHECKS
    # ══════════════════════════════════════════════════════════════════════════
    print(f"{C_CYAN}{C_BOLD}── System ─────────────────────────────────────────{C_RESET}")

    # Root access
    root_ok = os.geteuid() == 0
    checks.append(("Root Access", root_ok))
    check_line("Root Access", "pass" if root_ok else "fail",
               "Running as root" if root_ok else "Not root — some features may fail")

    # OS info
    try:
        with open("/etc/os-release") as f:
            os_info = {}
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    os_info[k] = v.strip('"')
        os_name = os_info.get("PRETTY_NAME", "Unknown")
        check_line("Operating System", "pass", os_name)
    except Exception:
        check_line("Operating System", "warn", "Could not read /etc/os-release")

    # Python version
    import sys
    py_ver = sys.version.split()[0]
    py_ok  = int(py_ver.split(".")[1]) >= 8
    checks.append(("Python Version", py_ok))
    check_line("Python Version", "pass" if py_ok else "warn",
               f"Python {py_ver}")

    # Systemd available
    systemd_ok = subprocess.call(
        ["which", "systemctl"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) == 0
    checks.append(("Systemd", systemd_ok))
    check_line("Systemd Available", "pass" if systemd_ok else "fail",
               "systemctl found" if systemd_ok else "systemctl not found")

    # Git available
    git_ok = subprocess.call(
        ["which", "git"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) == 0
    checks.append(("Git", git_ok))
    check_line("Git Available", "pass" if git_ok else "fail",
               "git found" if git_ok else "git not installed")

    # Nginx available
    nginx_ok = subprocess.call(
        ["which", "nginx"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) == 0
    check_line("Nginx Available", "pass" if nginx_ok else "warn",
               "nginx found" if nginx_ok else "nginx not installed")

    # Gunicorn available
    gunicorn_ok = subprocess.call(
        ["which", "gunicorn"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) == 0
    checks.append(("Gunicorn", gunicorn_ok))
    check_line("Gunicorn Available", "pass" if gunicorn_ok else "fail",
               "gunicorn found" if gunicorn_ok else "gunicorn not installed")

    print()

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 2 — ATS FILES & PATHS
    # ══════════════════════════════════════════════════════════════════════════
    print(f"{C_CYAN}{C_BOLD}── ATS Paths ──────────────────────────────────────{C_RESET}")

    # ATS home
    ats_home_ok = os.path.exists(ATS_HOME) and os.access(ATS_HOME, os.W_OK)
    checks.append(("ATS Home", ats_home_ok))
    check_line("ATS Home Dir", "pass" if ats_home_ok else "fail", ATS_HOME)

    # Database
    db_ok = os.path.exists(DB_FILE) and os.access(DB_FILE, os.W_OK)
    checks.append(("Database", db_ok))
    if db_ok:
        db_size = os.path.getsize(DB_FILE) / 1024
        check_line("Database File", "pass", f"{DB_FILE}  ({db_size:.1f} KB)")
    else:
        check_line("Database File", "fail", f"{DB_FILE} — missing or not writable")

    # Log file
    log_ok = os.path.exists(LOG_FILE) or os.access(os.path.dirname(LOG_FILE), os.W_OK)
    check_line("Log File", "pass" if log_ok else "warn", LOG_FILE)

    # Backup dir
    backup_ok = os.path.exists(BACKUP_DIR) and os.access(BACKUP_DIR, os.W_OK)
    checks.append(("Backup Dir", backup_ok))
    check_line("Backup Directory", "pass" if backup_ok else "warn",
               BACKUP_DIR if backup_ok else f"{BACKUP_DIR} — missing or not writable")

    # Default storage
    storage_ok = os.path.exists(DEFAULT_STORAGE) and os.access(DEFAULT_STORAGE, os.W_OK)
    checks.append(("Default Storage", storage_ok))
    check_line("Default Storage", "pass" if storage_ok else "fail", DEFAULT_STORAGE)

    # Cloudflare config
    cf_ok = os.path.exists(CLOUDFLARE_CONFIG)
    checks.append(("Cloudflare Config", cf_ok))
    check_line("Cloudflare Config", "pass" if cf_ok else "warn",
               CLOUDFLARE_CONFIG if cf_ok else f"{CLOUDFLARE_CONFIG} — not found")

    # Audit file
    audit_ok = os.path.exists(AUDIT_FILE) or os.access(ATS_HOME, os.W_OK)
    check_line("Audit Trace File", "pass" if audit_ok else "warn", AUDIT_FILE)

    print()

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 3 — DISK SPACE
    # ══════════════════════════════════════════════════════════════════════════
    print(f"{C_CYAN}{C_BOLD}── Disk Space ─────────────────────────────────────{C_RESET}")

    def check_disk(path, label):
        try:
            usage   = os.statvfs(path)
            total   = usage.f_frsize * usage.f_blocks  / (1024**3)
            free    = usage.f_frsize * usage.f_bfree   / (1024**3)
            used    = total - free
            percent = (used / total * 100) if total > 0 else 0
            status  = "fail" if percent > 90 else ("warn" if percent > 75 else "pass")
            check_line(f"Disk ({label})", status,
                       f"{used:.1f} GB / {total:.1f} GB  ({percent:.1f}% used)  {free:.1f} GB free")
            return status != "fail"
        except Exception as e:
            check_line(f"Disk ({label})", "warn", f"Could not check: {e}")
            return True

    checks.append(("Root Disk",    check_disk("/",              "/")))
    checks.append(("Storage Disk", check_disk(DEFAULT_STORAGE, DEFAULT_STORAGE)))

    print()

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 4 — NETWORK & CONNECTIVITY
    # ══════════════════════════════════════════════════════════════════════════
    print(f"{C_CYAN}{C_BOLD}── Network ────────────────────────────────────────{C_RESET}")

    # Internet
    inet_ok = subprocess.call(
        ["ping", "-c", "1", "-W", "2", "1.1.1.1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) == 0
    checks.append(("Internet", inet_ok))
    check_line("Internet Connectivity", "pass" if inet_ok else "fail",
               "1.1.1.1 reachable" if inet_ok else "No internet connection")

    # DNS resolution
    dns_ok = subprocess.call(
        ["ping", "-c", "1", "-W", "2", "github.com"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) == 0
    checks.append(("DNS", dns_ok))
    check_line("DNS Resolution", "pass" if dns_ok else "fail",
               "github.com reachable" if dns_ok else "DNS not resolving")

    # Cloudflared tunnel
    cf_tunnel = subprocess.call(
        ["systemctl", "is-active", "--quiet", CLOUDFLARED_SERVICE],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    ) == 0
    checks.append(("Cloudflare Tunnel", cf_tunnel))
    check_line("Cloudflare Tunnel", "pass" if cf_tunnel else "warn",
               f"{CLOUDFLARED_SERVICE} active" if cf_tunnel else f"{CLOUDFLARED_SERVICE} not running")

    # Port conflicts — check if any non-ATS process is using a registered port
    services_for_ports = db.query("SELECT name, port FROM services", fetch_all=True)
    port_conflicts = []
    if services_for_ports:
        for svc in services_for_ports:
            result = subprocess.run(
                ["sudo", "lsof", "-i", f":{svc['port']}", "-t"],
                capture_output=True, text=True
            )
            pids = result.stdout.strip().split("\n")
            pids = [p for p in pids if p]
            if len(pids) > 1:
                port_conflicts.append(f":{svc['port']} ({svc['name']}) — {len(pids)} processes")

    if port_conflicts:
        check_line("Port Conflicts", "warn", f"{len(port_conflicts)} conflict(s) found")
        for conflict in port_conflicts:
            print(f"    {C_YELLOW}│  {conflict}{C_RESET}")
    else:
        check_line("Port Conflicts", "pass", "No conflicts detected")

    print()

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 5 — SERVICE HEALTH
    # ══════════════════════════════════════════════════════════════════════════
    print(f"{C_CYAN}{C_BOLD}── Service Health ─────────────────────────────────{C_RESET}")

    services = db.query("SELECT * FROM services", fetch_all=True)
    if not services:
        print(f"  {C_YELLOW}No services deployed yet.{C_RESET}")
    else:
        health_results  = await parallel_health_checks(services)
        healthy_count   = 0
        unhealthy_count = 0

        for svc in services:
            is_healthy = health_results.get(svc['name'], False)
            label      = f"{svc['name']} (:{svc['port']})"
            check_line(label, "pass" if is_healthy else "fail",
                       "Online" if is_healthy else "Offline / not responding")
            if is_healthy:
                healthy_count += 1
            else:
                unhealthy_count += 1

        print(f"\n  {C_BOLD}Summary:{C_RESET}  "
              f"{C_GREEN}{healthy_count} healthy{C_RESET}   "
              f"{C_RED}{unhealthy_count} unhealthy{C_RESET}")

    print()

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 6 — SYSTEM RESOURCES
    # ══════════════════════════════════════════════════════════════════════════
    print(f"{C_CYAN}{C_BOLD}── System Resources ───────────────────────────────{C_RESET}")

    if psutil:
        cpu_pct = psutil.cpu_percent(interval=1)
        mem     = psutil.virtual_memory()
        swap    = psutil.swap_memory()

        cpu_status = "fail" if cpu_pct > 80 else ("warn" if cpu_pct > 60 else "pass")
        mem_status = "fail" if mem.percent > 90 else ("warn" if mem.percent > 75 else "pass")
        swp_status = "warn" if swap.percent > 50 else "pass"

        check_line("CPU Usage",  cpu_status,
                   f"{cpu_pct:.1f}%  ({psutil.cpu_count(logical=False)} cores / "
                   f"{psutil.cpu_count(logical=True)} logical)")
        check_line("RAM Usage",  mem_status,
                   f"{mem.used/1024**3:.1f} GB / {mem.total/1024**3:.1f} GB  ({mem.percent:.1f}%)")
        check_line("Swap Usage", swp_status,
                   f"{swap.used/1024**2:.0f} MB / {swap.total/1024**2:.0f} MB  ({swap.percent:.1f}%)")

        # Uptime
        try:
            boot_time  = datetime.fromtimestamp(psutil.boot_time())
            uptime     = datetime.now() - boot_time
            uptime_str = f"{uptime.days}d {uptime.seconds//3600}h {(uptime.seconds%3600)//60}m"
            check_line("System Uptime", "pass", uptime_str)
        except Exception:
            pass

        # Load average
        try:
            load1, load5, load15 = os.getloadavg()
            load_status = "warn" if load1 > psutil.cpu_count() else "pass"
            check_line("Load Average", load_status,
                       f"1m: {load1:.2f}  5m: {load5:.2f}  15m: {load15:.2f}")
        except Exception:
            pass

    else:
        check_line("psutil", "warn", "Not installed — run: pip install psutil")

    print()

    # ══════════════════════════════════════════════════════════════════════════
    # SECTION 7 — DATABASE INTEGRITY
    # ══════════════════════════════════════════════════════════════════════════
    print(f"{C_CYAN}{C_BOLD}── Database Integrity ─────────────────────────────{C_RESET}")

    try:
        integrity = db.query("PRAGMA integrity_check", fetch_one=True)
        integrity_ok = integrity and list(integrity)[0] == "ok"
        checks.append(("DB Integrity", integrity_ok))
        check_line("Integrity Check", "pass" if integrity_ok else "fail",
                   "ok" if integrity_ok else "Errors found — run cleanup")
    except Exception as e:
        check_line("Integrity Check", "warn", f"Could not run: {e}")

    try:
        wal_file = DB_FILE + "-wal"
        if os.path.exists(wal_file):
            wal_size = os.path.getsize(wal_file) / 1024
            wal_status = "warn" if wal_size > 1024 else "pass"
            check_line("WAL File", wal_status, f"{wal_size:.1f} KB")
        else:
            check_line("WAL File", "pass", "Not present (clean)")
    except Exception:
        pass

    # Table record counts
    for table in DB_COUNT_TABLES:
        count  = table_row_count(table)
        flag   = "warn" if count > 500 else "pass"
        check_line(f"Table: {table}", flag, f"{count} records")

    print()

    # ══════════════════════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ══════════════════════════════════════════════════════════════════════════
    passed = sum(1 for _, ok in checks if ok)
    failed = sum(1 for _, ok in checks if not ok)
    total  = len(checks)

    print(f"{C_CYAN}{'═' * 55}{C_RESET}")
    if failed == 0:
        print(f"  {C_GREEN}{C_BOLD}✓ ALL CHECKS PASSED  ({passed}/{total}){C_RESET}")
    elif failed <= 2:
        print(f"  {C_YELLOW}{C_BOLD}⚠ {passed}/{total} PASSED — Minor issues detected{C_RESET}")
    else:
        print(f"  {C_RED}{C_BOLD}✗ {passed}/{total} PASSED — Attention required{C_RESET}")

    if failed > 0:
        print(f"\n  {C_RED}Failed checks:{C_RESET}")
        for name, ok in checks:
            if not ok:
                print(f"    {C_RED}✗{C_RESET}  {name}")

    print(f"{C_CYAN}{'═' * 55}{C_RESET}")
    print(f"  {C_CYAN}Completed at: {datetime.now().strftime('%d %b %Y  %H:%M:%S')}{C_RESET}")
    print(f"{C_CYAN}{'═' * 55}{C_RESET}\n")

    input(f"  {C_CYAN}Press Enter to continue...{C_RESET}")

# ==============================================================================
#   OPTION 10: VIEW DATABASE
# ==============================================================================

async def view_database():
    """View and browse ATS database tables"""

    while True:
        print_header()
        print(f"{C_CYAN}{C_BOLD}═══ DATABASE VIEWER ═══{C_RESET}\n")
        print(f"  {C_BOLD}[1]{C_RESET} Services")
        print(f"  {C_BOLD}[2]{C_RESET} Backups")
        print(f"  {C_BOLD}[3]{C_RESET} Deployments")
        print(f"  {C_BOLD}[4]{C_RESET} Metrics History")
        print(f"  {C_BOLD}[5]{C_RESET} All Tables Summary")
        print(f"  {C_BOLD}[0]{C_RESET} Back\n")

        loop = asyncio.get_running_loop()
        choice = (await loop.run_in_executor(None, lambda: input(f"  {C_BOLD}Select table:{C_RESET} "))).strip()

        if choice == "0":
            return

        os.system('clear')
        print_header()

        try:
            # ── SERVICES ───────────────────────────────────────────────────────
            if choice == "1":
                rows = db.query("SELECT * FROM services ORDER BY created_at DESC", fetch_all=True)
                if not rows:
                    print_status("No services in database", "warning")
                else:
                    print(f"{C_CYAN}{C_BOLD}═══ SERVICES ({len(rows)} total) ═══{C_RESET}\n")
                    print(f"  {C_BOLD}{'ID':<4} {'NAME':<18} {'PORT':<6} {'DOMAIN':<32} {'WORKERS':<8} {'STATUS':<10} {'CREATED':<20}{C_RESET}")
                    print(f"  {C_CYAN}{'─' * 100}{C_RESET}")
                    for svc in rows:
                        created   = svc['created_at'][:19] if svc['created_at'] else "Unknown"
                        name      = (svc['name'][:16]   + "..") if len(svc['name'])   > 16 else svc['name']
                        domain    = (svc['domain'][:30] + "..") if len(svc['domain']) > 30 else svc['domain']
                        status_col = (f"{C_GREEN}{svc['status']}{C_RESET}"
                                      if svc['status'] == 'active'
                                      else f"{C_RED}{svc['status']}{C_RESET}")
                        print(f"  {svc['id']:<4} {name:<18} {svc['port']:<6} {domain:<32} "
                              f"{svc['workers']:<8} {status_col:<18} {created:<20}")

                    print(f"\n  {C_CYAN}Enter service ID for full details (or Enter to skip):{C_RESET} ", end='')
                    detail_id = (await loop.run_in_executor(None, lambda: input())).strip()
                    if detail_id.isascii() and detail_id.isdigit():
                        svc = db.query("SELECT * FROM services WHERE id=?", (int(detail_id),), fetch_one=True)
                        if svc:
                            print(f"\n  {C_CYAN}{'─' * 60}{C_RESET}")
                            print(f"  {C_BOLD}Full Details — Service ID {svc['id']}{C_RESET}")
                            print(f"  {C_CYAN}{'─' * 60}{C_RESET}")
                            for key in svc.keys():
                                print(f"    {C_BOLD}{key:<25}{C_RESET} {svc[key]}")
                        else:
                            print_status("Service ID not found", "error")

            # ── BACKUPS ────────────────────────────────────────────────────────
            elif choice == "2":
                rows = db.query("SELECT * FROM backups ORDER BY timestamp DESC LIMIT 50", fetch_all=True)
                if not rows:
                    print_status("No backups in database", "warning")
                else:
                    print(f"{C_CYAN}{C_BOLD}═══ BACKUPS ({len(rows)} shown) ═══{C_RESET}\n")
                    print(f"  {C_BOLD}{'ID':<4} {'SERVICE':<18} {'SIZE':<12} {'CHECKSUM':<16} {'TIMESTAMP':<20}{C_RESET}")
                    print(f"  {C_CYAN}{'─' * 80}{C_RESET}")
                    for b in rows:
                        size_mb   = f"{(b['size_bytes']/1024/1024):.2f} MB" if b['size_bytes'] else "0 MB"
                        timestamp = b['timestamp'][:19] if b['timestamp'] else "Unknown"
                        checksum  = (b['checksum'][:13] + "..") if b['checksum'] and len(b['checksum']) > 13 else (b['checksum'] or "None")
                        svc_name  = (b['service_name'][:16] + "..") if b['service_name'] and len(b['service_name']) > 16 else (b['service_name'] or "—")
                        print(f"  {b['id']:<4} {svc_name:<18} {size_mb:<12} {checksum:<16} {timestamp:<20}")

            # ── DEPLOYMENTS ────────────────────────────────────────────────────
            elif choice == "3":
                rows = db.query("SELECT * FROM deployments ORDER BY timestamp DESC LIMIT 50", fetch_all=True)
                if not rows:
                    print_status("No deployment history", "warning")
                else:
                    success = sum(1 for d in rows if d['status'] == 'success')
                    failed  = len(rows) - success
                    print(f"{C_CYAN}{C_BOLD}═══ DEPLOYMENTS ({len(rows)} shown) ═══{C_RESET}")
                    print(f"  {C_GREEN}✓ Successful: {success}{C_RESET}   {C_RED}✗ Failed: {failed}{C_RESET}\n")
                    print(f"  {C_BOLD}{'ID':<4} {'SERVICE':<18} {'STATUS':<10} {'DURATION':<10} {'TIMESTAMP':<20} {'ERROR':<30}{C_RESET}")
                    print(f"  {C_CYAN}{'─' * 100}{C_RESET}")
                    for d in rows:
                        status_col = (f"{C_GREEN}SUCCESS{C_RESET}"
                                      if d['status'] == 'success'
                                      else f"{C_RED}FAILED{C_RESET}")
                        duration  = f"{d['duration_seconds']:.1f}s" if d['duration_seconds'] else "N/A"
                        timestamp = d['timestamp'][:19] if d['timestamp'] else "Unknown"
                        error     = (d['error_message'][:28] + "..") if d['error_message'] and len(d['error_message']) > 28 else (d['error_message'] or "—")
                        svc_name  = (d['service_name'][:16] + "..") if d['service_name'] and len(d['service_name']) > 16 else (d['service_name'] or "—")
                        print(f"  {d['id']:<4} {svc_name:<18} {status_col:<18} {duration:<10} {timestamp:<20} {C_YELLOW}{error}{C_RESET}")

            # ── METRICS HISTORY ────────────────────────────────────────────────
            elif choice == "4":
                rows = db.query("SELECT * FROM metrics_history ORDER BY timestamp DESC LIMIT 50", fetch_all=True)
                if not rows:
                    print_status("No metrics history", "warning")
                else:
                    print(f"{C_CYAN}{C_BOLD}═══ METRICS HISTORY ({len(rows)} shown) ═══{C_RESET}\n")
                    print(f"  {C_BOLD}{'ID':<4} {'SERVICE':<18} {'CPU %':<8} {'MEM MB':<10} {'REQ/MIN':<10} {'TIMESTAMP':<20}{C_RESET}")
                    print(f"  {C_CYAN}{'─' * 80}{C_RESET}")
                    for m in rows:
                        timestamp = m['timestamp'][:19] if m['timestamp'] else "Unknown"
                        cpu       = f"{m['cpu_percent']:.1f}%" if m['cpu_percent'] else "N/A"
                        mem       = f"{m['memory_mb']:.0f}"    if m['memory_mb']    else "N/A"
                        req       = str(m['requests_per_min']) if m['requests_per_min'] else "N/A"
                        svc_name  = (m['service_name'][:16] + "..") if m['service_name'] and len(m['service_name']) > 16 else (m['service_name'] or "—")
                        cpu_col   = (f"{C_RED}{cpu}{C_RESET}"
                                     if m['cpu_percent'] and m['cpu_percent'] > 80
                                     else f"{C_GREEN}{cpu}{C_RESET}")
                        mem_col   = (f"{C_RED}{mem}{C_RESET}"
                                     if m['memory_mb'] and m['memory_mb'] > 400
                                     else f"{C_GREEN}{mem}{C_RESET}")
                        print(f"  {m['id']:<4} {svc_name:<18} {cpu_col:<16} {mem_col:<18} {req:<10} {timestamp:<20}")

            # ── ALL TABLES SUMMARY ─────────────────────────────────────────────
            elif choice == "5":
                all_tables = list(DB_COUNT_TABLES)
                print(f"{C_CYAN}{C_BOLD}═══ DATABASE SUMMARY ═══{C_RESET}\n")
                print(f"  {C_BOLD}{'TABLE':<28} {'RECORDS':<12} {'EST. SIZE':<12}{C_RESET}")
                print(f"  {C_CYAN}{'─' * 55}{C_RESET}")
                total_records = 0
                for table in all_tables:
                    count  = table_row_count(table)
                    total_records += count
                    size_kb = f"{count * 0.5:.1f} KB"
                    print(f"  {table:<28} {count:<12} {size_kb:<12}")
                print(f"  {C_CYAN}{'─' * 55}{C_RESET}")
                print(f"  {'TOTAL':<28} {C_BOLD}{total_records}{C_RESET}")
                if os.path.exists(DB_FILE):
                    db_size = os.path.getsize(DB_FILE) / 1024
                    print(f"\n  {C_BOLD}File:{C_RESET}  {DB_FILE}")
                    print(f"  {C_BOLD}Size:{C_RESET}  {db_size:.2f} KB")
                    print(f"  {C_BOLD}Mode:{C_RESET}  WAL (concurrent access enabled)")

            else:
                print_status("Invalid choice. Enter 1-5 or 0 to go back.", "warning")

        except Exception as e:
            logger.error(f"Database view error: {e}")
            print_status(f"Error: {e}", "error")

        print(f"\n  {C_CYAN}{'─' * 70}{C_RESET}")
        await loop.run_in_executor(None, lambda: input(f"  {C_CYAN}Press Enter to go back...{C_RESET}"))


# ==============================================================================
#   OPTION 11: DATABASE CLEANUP
# ==============================================================================

async def database_cleanup():
    """Clean up old/orphaned database records"""

    while True:
        print_header()
        print(f"{C_RED}{C_BOLD}═══ DATABASE CLEANUP ═══{C_RESET}\n")
        print(f"{C_YELLOW}  WARNING: Deleted records cannot be recovered.{C_RESET}\n")
        print(f"  {C_BOLD}[1]{C_RESET} Delete old deployment history      (keep last 100)")
        print(f"  {C_BOLD}[2]{C_RESET} Delete old metrics history         (keep last 1000)")
        print(f"  {C_BOLD}[3]{C_RESET} Delete orphaned backup records     (service no longer exists)")
        print(f"  {C_BOLD}[4]{C_RESET} Delete specific service            (all records)")
        print(f"  {C_BOLD}[5]{C_RESET} Vacuum database                    (optimize file size)")
        print(f"  {C_BOLD}[6]{C_RESET} Full cleanup                       (1 + 2 + 3 + 5)")
        print(f"  {C_BOLD}[7]{C_RESET} Delete failed deployments only     (keep successful ones)")
        print(f"  {C_BOLD}[8]{C_RESET} Reset metrics for one service      (clear its history)")
        print(f"  {C_BOLD}[9]{C_RESET} Delete backups older than N days   (custom retention)")
        print(f"  {C_BOLD}[D]{C_RESET} Database health report             (stats + warnings)")
        print(f"  {C_BOLD}[0]{C_RESET} Back\n")

        loop = asyncio.get_running_loop()
        choice = (await loop.run_in_executor(None, lambda: input(f"  {C_BOLD}Select action:{C_RESET} "))).strip().lower()

        if choice == "0":
            return

        if choice not in ("1","2","3","4","5","6","7","8","9","d"):
            print_status("Invalid choice.", "warning")
            await asyncio.sleep(1)
            continue

        # ── Database Health Report (no confirmation needed) ────────────────────
        if choice == "d":
            os.system('clear')
            print_header()
            print(f"{C_CYAN}{C_BOLD}═══ DATABASE HEALTH REPORT ═══{C_RESET}\n")

            tables = list(DB_COUNT_TABLES)

            print(f"  {C_BOLD}{'TABLE':<25} {'RECORDS':<12} {'EST. SIZE':<12}{C_RESET}")
            print(f"  {C_CYAN}{'─' * 52}{C_RESET}")

            total_records = 0
            for table in tables:
                count  = table_row_count(table)
                total_records += count
                size_kb = count * 0.5
                flag = f"  {C_YELLOW}⚠ Large{C_RESET}" if count > 500 else ""
                print(f"  {table:<25} {count:<12} {size_kb:<8.1f} KB{flag}")

            print(f"  {C_CYAN}{'─' * 52}{C_RESET}")
            print(f"  {'TOTAL':<25} {C_BOLD}{total_records}{C_RESET}\n")

            # DB file size
            if os.path.exists(DB_FILE):
                db_size = os.path.getsize(DB_FILE) / 1024
                print(f"  {C_BOLD}File size:{C_RESET}     {db_size:.2f} KB")
                if db_size > 10240:
                    print(f"  {C_YELLOW}⚠ DB file is over 10 MB — consider vacuum{C_RESET}")

            # Failed deployments
            failed = db.query(
                "SELECT COUNT(*) as count FROM deployments WHERE status != 'success'",
                fetch_one=True
            )
            failed_count = failed['count'] if failed else 0
            if failed_count > 0:
                print(f"  {C_YELLOW}⚠ {failed_count} failed deployment records found{C_RESET}")
            else:
                print(f"  {C_GREEN}✓ No failed deployment records{C_RESET}")

            # Orphaned backups
            orphaned = db.query("""
                SELECT COUNT(*) as count FROM backups
                WHERE service_name NOT IN (SELECT name FROM services)
            """, fetch_one=True)
            orphaned_count = orphaned['count'] if orphaned else 0
            if orphaned_count > 0:
                print(f"  {C_YELLOW}⚠ {orphaned_count} orphaned backup records found{C_RESET}")
            else:
                print(f"  {C_GREEN}✓ No orphaned backup records{C_RESET}")

            # Old deployments
            old_deploys = db.query(
                "SELECT COUNT(*) as count FROM deployments",
                fetch_one=True
            )
            old_count = old_deploys['count'] if old_deploys else 0
            if old_count > 100:
                print(f"  {C_YELLOW}⚠ {old_count} deployment records — recommend keeping last 100{C_RESET}")
            else:
                print(f"  {C_GREEN}✓ Deployment history is clean ({old_count} records){C_RESET}")

            # WAL file check
            wal_file = DB_FILE + "-wal"
            if os.path.exists(wal_file):
                wal_size = os.path.getsize(wal_file) / 1024
                if wal_size > 1024:
                    print(f"  {C_YELLOW}⚠ WAL file is {wal_size:.1f} KB — run vacuum to merge{C_RESET}")
                else:
                    print(f"  {C_GREEN}✓ WAL file size normal ({wal_size:.1f} KB){C_RESET}")

            print(f"\n  {C_CYAN}{'─' * 52}{C_RESET}")
            await loop.run_in_executor(None, lambda: input(f"  {C_CYAN}Press Enter to continue...{C_RESET}"))
            continue

        # ── Confirmation for destructive actions ───────────────────────────────
        os.system('clear')
        print_header()
        print(f"{C_RED}{C_BOLD}═══ CONFIRM CLEANUP ═══{C_RESET}\n")
        print(f"  {C_YELLOW}This action cannot be undone.{C_RESET}\n")
        confirm = (await loop.run_in_executor(None, lambda: input(f"  Type {C_BOLD}CLEANUP{C_RESET} to confirm: "))).strip()

        if confirm != "CLEANUP":
            print_status("Cleanup cancelled.", "warning")
            await asyncio.sleep(1)
            continue

        os.system('clear')
        print_header()
        print(f"{C_RED}{C_BOLD}═══ RUNNING CLEANUP ═══{C_RESET}\n")

        deleted_count = 0

        try:
            # ── Option 1: Old deployments ──────────────────────────────────────
            if choice in ("1", "6"):
                print_status("Cleaning old deployment history...", "info")
                db.query("""
                    DELETE FROM deployments
                    WHERE id NOT IN (
                        SELECT id FROM deployments
                        ORDER BY timestamp DESC
                        LIMIT 100
                    )
                """)
                result = db.query("SELECT COUNT(*) as count FROM deployments", fetch_one=True)
                print_status(f"Deployments kept: {result['count'] if result else 0}", "success")

            # ── Option 2: Old metrics ──────────────────────────────────────────
            if choice in ("2", "6"):
                print_status("Cleaning old metrics history...", "info")
                db.query("""
                    DELETE FROM metrics_history
                    WHERE id NOT IN (
                        SELECT id FROM metrics_history
                        ORDER BY timestamp DESC
                        LIMIT 1000
                    )
                """)
                result = db.query("SELECT COUNT(*) as count FROM metrics_history", fetch_one=True)
                print_status(f"Metrics kept: {result['count'] if result else 0}", "success")

            # ── Option 3: Orphaned backups ─────────────────────────────────────
            if choice in ("3", "6"):
                print_status("Checking for orphaned backup records...", "info")
                orphaned = db.query("""
                    SELECT b.id, b.service_name, b.filename
                    FROM backups b
                    WHERE b.service_name NOT IN (SELECT name FROM services)
                """, fetch_all=True)

                if not orphaned:
                    print_status("No orphaned backups found.", "info")
                else:
                    print(f"\n  {C_YELLOW}Found {len(orphaned)} orphaned record(s):{C_RESET}")
                    for backup in orphaned:
                        svc_name = backup['service_name'] or "unknown"
                        fname    = backup['filename']     or "unknown"
                        print(f"  {C_CYAN}│{C_RESET}  {svc_name}  →  {fname}")
                        if backup['filename']:
                            backup_file = os.path.join(BACKUP_DIR, backup['filename'])
                            if os.path.exists(backup_file):
                                try:
                                    os.remove(backup_file)
                                    print(f"  {C_CYAN}│{C_RESET}  {C_GREEN}✓ File deleted{C_RESET}")
                                except Exception as fe:
                                    print(f"  {C_CYAN}│{C_RESET}  {C_YELLOW}⚠ Could not delete file: {fe}{C_RESET}")
                        db.query("DELETE FROM backups WHERE id=?", (backup['id'],))
                        deleted_count += 1
                    print_status(f"Removed {len(orphaned)} orphaned record(s).", "success")

            # ── Option 4: Delete specific service ─────────────────────────────
            if choice == "4":
                print()
                services = db.query("SELECT name FROM services ORDER BY name", fetch_all=True)
                if not services:
                    print_status("No services in database.", "warning")
                    await asyncio.sleep(1)
                    continue

                print(f"  {C_CYAN}Available services:{C_RESET}")
                for s in services:
                    print(f"  {C_CYAN}│{C_RESET}  {s['name']}")
                print()

                service_name = (await loop.run_in_executor(None, lambda: input(f"  {C_BOLD}Service name to delete:{C_RESET} "))).strip()
                if not service_name:
                    print_status("No name entered. Cancelled.", "warning")
                    await asyncio.sleep(1)
                    continue

                svc = db.query("SELECT * FROM services WHERE name=?", (service_name,), fetch_one=True)
                if not svc:
                    print_status(f"'{service_name}' not found.", "error")
                else:
                    print(f"\n  {C_YELLOW}Deleting ALL records for {C_BOLD}'{service_name}'{C_RESET}{C_YELLOW}:{C_RESET}")
                    print(f"  {C_CYAN}│{C_RESET}  Service record")
                    print(f"  {C_CYAN}│{C_RESET}  Backup records")
                    print(f"  {C_CYAN}│{C_RESET}  Deployment history")
                    print(f"  {C_CYAN}│{C_RESET}  Metrics history")
                    print()
                    confirm2 = (await loop.run_in_executor(None, lambda: input(f"  Type {C_BOLD}'{service_name}'{C_RESET} to confirm: "))).strip()
                    if confirm2 == service_name:
                        db.query("DELETE FROM metrics_history WHERE service_name=?", (service_name,))
                        db.query("DELETE FROM deployments    WHERE service_name=?", (service_name,))
                        db.query("DELETE FROM backups        WHERE service_name=?", (service_name,))
                        db.query("DELETE FROM services       WHERE name=?",         (service_name,))
                        db.query("DELETE FROM webhook_events WHERE service_name=?", (service_name,))
                        deleted_count += 1
                        print_status(f"'{service_name}' fully removed.", "success")
                    else:
                        print_status("Name didn't match. Cancelled.", "warning")

            # ── Option 5: Vacuum ───────────────────────────────────────────────
            if choice in ("5", "6"):
                print_status("Optimizing database file...", "info")
                size_before = os.path.getsize(DB_FILE) / 1024 if os.path.exists(DB_FILE) else 0
                try:
                    conn = sqlite3.connect(DB_FILE)
                    conn.execute("VACUUM")
                    conn.close()
                    size_after = os.path.getsize(DB_FILE) / 1024 if os.path.exists(DB_FILE) else 0
                    saved      = max(0.0, size_before - size_after)
                    print_status(
                        f"Optimized  {size_before:.1f} KB → {size_after:.1f} KB  "
                        f"(saved {saved:.1f} KB)", "success"
                    )
                except Exception as ve:
                    print_status(f"Vacuum failed: {ve}", "error")

            # ── Option 7: Delete failed deployments only ───────────────────────
            if choice == "7":
                print_status("Removing failed deployment records...", "info")
                before = db.query("SELECT COUNT(*) as count FROM deployments WHERE status != 'success'", fetch_one=True)
                db.query("DELETE FROM deployments WHERE status != 'success'")
                after  = db.query("SELECT COUNT(*) as count FROM deployments", fetch_one=True)
                removed = before['count'] if before else 0
                deleted_count += removed
                print_status(f"Removed {removed} failed record(s). {after['count'] if after else 0} successful kept.", "success")

            # ── Option 8: Reset metrics for one service ────────────────────────
            if choice == "8":
                print()
                services = db.query("SELECT name FROM services ORDER BY name", fetch_all=True)
                if not services:
                    print_status("No services in database.", "warning")
                    await asyncio.sleep(1)
                    continue

                print(f"  {C_CYAN}Available services:{C_RESET}")
                for s in services:
                    count = db.query(
                        "SELECT COUNT(*) as count FROM metrics_history WHERE service_name=?",
                        (s['name'],), fetch_one=True
                    )
                    print(f"  {C_CYAN}│{C_RESET}  {s['name']:<25} {count['count'] if count else 0} records")
                print()

                service_name = (await loop.run_in_executor(None, lambda: input(f"  {C_BOLD}Service name to clear metrics:{C_RESET} "))).strip()
                if not service_name:
                    print_status("No name entered. Cancelled.", "warning")
                    await asyncio.sleep(1)
                    continue

                result = db.query(
                    "SELECT COUNT(*) as count FROM metrics_history WHERE service_name=?",
                    (service_name,), fetch_one=True
                )
                count = result['count'] if result else 0
                if count == 0:
                    print_status(f"No metrics found for '{service_name}'.", "warning")
                else:
                    db.query("DELETE FROM metrics_history WHERE service_name=?", (service_name,))
                    deleted_count += count
                    print_status(f"Cleared {count} metrics records for '{service_name}'.", "success")

            # ── Option 9: Delete backups older than N days ─────────────────────
            if choice == "9":
                print()
                days_str = (await loop.run_in_executor(None, lambda: input(f"  {C_BOLD}Delete backups older than how many days?{C_RESET} "))).strip()
                if not (days_str.isascii() and days_str.isdigit()) or not (1 <= int(days_str) <= 36500):
                    print_status("Invalid number. Enter a positive integer.", "warning")
                    await asyncio.sleep(1)
                    continue

                days = int(days_str)
                old_backups = db.query("""
                    SELECT id, service_name, filename, timestamp
                    FROM backups
                    WHERE timestamp < datetime('now', ?)
                    ORDER BY timestamp ASC
                """, (f"-{days} days",), fetch_all=True)

                if not old_backups:
                    print_status(f"No backups older than {days} days found.", "info")
                else:
                    print(f"\n  {C_YELLOW}Found {len(old_backups)} backup(s) older than {days} days:{C_RESET}")
                    for b in old_backups:
                        ts       = b['timestamp'][:19] if b['timestamp'] else "Unknown"
                        svc_name = b['service_name'] or "unknown"
                        fname    = b['filename']     or "unknown"
                        print(f"  {C_CYAN}│{C_RESET}  {svc_name:<20} {fname:<35} {ts}")

                        if b['filename']:
                            backup_file = os.path.join(BACKUP_DIR, b['filename'])
                            if os.path.exists(backup_file):
                                try:
                                    os.remove(backup_file)
                                    print(f"  {C_CYAN}│{C_RESET}  {C_GREEN}✓ File deleted{C_RESET}")
                                except Exception as fe:
                                    print(f"  {C_CYAN}│{C_RESET}  {C_YELLOW}⚠ {fe}{C_RESET}")

                        db.query("DELETE FROM backups WHERE id=?", (b['id'],))
                        deleted_count += 1

                    print_status(f"Removed {len(old_backups)} old backup(s).", "success")

            # ── Audit + done ───────────────────────────────────────────────────
            audit_log("DATABASE_CLEANUP", "ATS", {
                "action": choice,
                "records_deleted": deleted_count
            })

            print(f"\n  {C_CYAN}{'─' * 55}{C_RESET}")
            print(f"  {C_GREEN}{C_BOLD}✓ Cleanup completed{C_RESET}")
            print(f"  {C_GREEN}Records affected: {deleted_count}{C_RESET}")
            print(f"  {C_CYAN}{'─' * 55}{C_RESET}")

        except Exception as e:
            logger.error(f"Database cleanup error: {e}")
            print_status(f"Cleanup failed: {e}", "error")

        await loop.run_in_executor(None, lambda: input(f"\n  {C_CYAN}Press Enter to continue...{C_RESET}"))

async def update_database_async():
    """Update service statuses or edit metadata in the database"""
    while True:
        print_header()
        print(f"{C_CYAN}{C_BOLD}═══ DATABASE MANAGEMENT ═══{C_RESET}\n")
        print(f"  {C_BOLD}[1]{C_RESET} Refresh All Service Statuses (Health Check)")
        print(f"  {C_BOLD}[2]{C_RESET} Edit Service Metadata (Name, Repo Link)")
        print(f"  {C_BOLD}[3]{C_RESET} Update Service Location (Storage Path)")
        print(f"  {C_BOLD}[0]{C_RESET} Return to Main Menu\n")

        choice = input(f"  {C_BOLD}Select action:{C_RESET} ").strip()

        if choice == "0":
            break

        if choice == "1":
            services = db.query("SELECT * FROM services", fetch_all=True)
            if not services:
                print_status("No services in database to update.", "warning")
                time.sleep(1)
                continue

            print_status(f"Updating status for {len(services)} services...", "info")
            health_dict = await parallel_health_checks(services)

            updated_count = 0
            for svc in services:
                is_healthy = health_dict.get(svc['name'], False)
                status = 'active' if is_healthy else 'inactive'

                db.query(
                    "UPDATE services SET status=?, last_health_check=? WHERE id=?",
                    (status, datetime.datetime.now().isoformat(), svc['id'])
                )
                updated_count += 1
                status_icon = f"{C_GREEN}●{C_RESET}" if is_healthy else f"{C_RED}●{C_RESET}"
                print(f"  {status_icon} {svc['name']:<30} → {status}")

            print_status(f"Updated {updated_count} records.", "success")
            audit_log("DATABASE_REFRESH", "ATS", {"updated_count": updated_count})
            input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

        elif choice == "2":
            services = db.query("SELECT id, name, repo_url FROM services ORDER BY name", fetch_all=True)
            if not services:
                print_status("No services available to edit.", "warning")
                time.sleep(1)
                continue

            print(f"\n  {C_BOLD}{'ID':<4} {'NAME':<20} {'REPO LINK'}{C_RESET}")
            print(f"  {C_CYAN}{'─' * 60}{C_RESET}")
            for s in services:
                repo = (s['repo_url'][:35] + "..") if len(s['repo_url']) > 35 else s['repo_url']
                print(f"  {s['id']:<4} {s['name']:<20} {repo}")

            svc_id = input(f"\n  {C_BOLD}Enter Service ID to edit (or 0 to cancel):{C_RESET} ").strip()
            if svc_id == "0" or not svc_id: continue

            svc = db.query("SELECT * FROM services WHERE id=?", (svc_id,), fetch_one=True)
            if not svc:
                print_status("Invalid ID.", "error")
                time.sleep(1)
                continue

            print(f"\n  {C_CYAN}Editing: {C_BOLD}{svc['name']}{C_RESET}")
            new_name = input(f"  New Name [{svc['name']}]: ").strip() or svc['name']
            new_repo = input(f"  New Repo [{svc['repo_url']}]: ").strip() or svc['repo_url']

            if new_name != svc['name'] or new_repo != svc['repo_url']:
                db.query(
                    "UPDATE services SET name=?, repo_url=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (new_name, new_repo, svc_id)
                )
                # If name changed, update related records
                if new_name != svc['name']:
                    db.query("UPDATE backups SET service_name=? WHERE service_name=?", (new_name, svc['name']))
                    db.query("UPDATE deployments SET service_name=? WHERE service_name=?", (new_name, svc['name']))
                    db.query("UPDATE metrics_history SET service_name=? WHERE service_name=?", (new_name, svc['name']))

                print_status("Database record updated successfully.", "success")
                audit_log("DATABASE_EDIT", svc['name'], {"old_name": svc['name'], "new_name": new_name, "new_repo": new_repo})
            else:
                print_status("No changes made.", "info")

            input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

        elif choice == "3":
            services = db.query("SELECT id, name, storage_path FROM services ORDER BY name", fetch_all=True)
            if not services:
                print_status("No services available to update.", "warning")
                logger.warning("Location update: no services found in database")
                time.sleep(1)
                continue

            print(f"\n  {C_BOLD}{'ID':<4} {'NAME':<20} {'STORAGE PATH'}{C_RESET}")
            print(f"  {C_CYAN}{'─' * 60}{C_RESET}")
            for s in services:
                spath = (s['storage_path'][:40] + "..") if len(s['storage_path']) > 40 else s['storage_path']
                print(f"  {s['id']:<4} {s['name']:<20} {spath}")

            svc_id = input(f"\n  {C_BOLD}Enter Service ID to update location (0 to cancel):{C_RESET} ").strip()
            if svc_id == "0" or not svc_id:
                logger.info("Location update: user cancelled at service selection")
                continue

            svc = db.query("SELECT * FROM services WHERE id=?", (svc_id,), fetch_one=True)
            if not svc:
                print_status("Invalid ID.", "error")
                logger.error(f"Location update: invalid service ID '{svc_id}'")
                time.sleep(1)
                continue

            name = svc['name']
            old_storage = svc['storage_path']
            old_api_dir = os.path.join(old_storage, "api", name)
            old_db_dir = os.path.join(old_storage, "database", name)

            logger.info(f"[{name}] Location update initiated — current storage: {old_storage}")
            audit_log("LOCATION_UPDATE_INIT", name, {
                "old_storage": old_storage,
                "service_id": svc_id
            })

            print(f"\n  {C_CYAN}Service: {C_BOLD}{name}{C_RESET}")
            print(f"  {C_CYAN}Current Storage: {C_BOLD}{old_storage}{C_RESET}")

            new_storage = input(f"  {C_BOLD}New Storage Path: {C_RESET}").strip()
            if not new_storage:
                print_status("No path entered. Cancelled.", "warning")
                logger.info(f"[{name}] Location update: cancelled — no path entered")
                time.sleep(1)
                continue

            try:
                new_storage = validate_storage(new_storage)
            except ValueError as ve:
                print_status(f"Invalid path: {ve}", "error")
                logger.error(f"[{name}] Location update: invalid new path — {ve}")
                audit_log("LOCATION_UPDATE_FAILED", name, {"stage": "validate_path", "error": str(ve)})
                input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
                continue

            new_api_dir = os.path.join(new_storage, "api", name)
            new_db_dir = os.path.join(new_storage, "database", name)

            print(f"\n  {C_YELLOW}{'=' * 60}{C_RESET}")
            print(f"  {C_YELLOW}Moving service from:{C_RESET}")
            print(f"    {old_storage}")
            print(f"  {C_YELLOW}To:{C_RESET}")
            print(f"    {new_storage}")
            print(f"  {C_YELLOW}{'=' * 60}{C_RESET}")

            confirm = input(f"\n  {C_BOLD}Type 'MOVE' to confirm: {C_RESET}").strip()
            if confirm != "MOVE":
                print_status("Location update cancelled.", "warning")
                logger.info(f"[{name}] Location update: cancelled by user at confirmation")
                audit_log("LOCATION_UPDATE_CANCELLED", name, {"new_storage": new_storage})
                time.sleep(1)
                continue

            logger.info(f"[{name}] Location update confirmed — moving from {old_storage} to {new_storage}")
            audit_log("LOCATION_UPDATE_START", name, {
                "old_storage": old_storage,
                "new_storage": new_storage,
                "old_api_dir": old_api_dir,
                "new_api_dir": new_api_dir,
                "old_db_dir": old_db_dir,
                "new_db_dir": new_db_dir
            })

            try:
                # Stop service
                print_status("Stopping service...", "info")
                try:
                    run_root(["systemctl", "stop", name])
                    logger.info(f"[{name}] Service stopped for location migration")
                except Exception as stop_err:
                    print_status("Service was not running", "warning")
                    logger.warning(f"[{name}] Service stop during migration: {stop_err}")
                    audit_log("LOCATION_UPDATE_WARN", name, {"stage": "stop_service", "warning": str(stop_err)})

                # Create new directories
                print_status("Creating new directory structure...", "info")
                new_api_parent = os.path.join(new_storage, "api")
                os.makedirs(new_api_parent, exist_ok=True)
                shutil.chown(new_api_parent, user=SERVICE_USER, group=SERVICE_GROUP)
                os.chmod(new_api_parent, 0o755)
                logger.info(f"[{name}] Created API parent directory: {new_api_parent}")

                new_db_parent = os.path.join(new_storage, "database")
                os.makedirs(new_db_parent, exist_ok=True)
                shutil.chown(new_db_parent, user=SERVICE_USER, group=SERVICE_GROUP)
                logger.info(f"[{name}] Created database parent directory: {new_db_parent}")

                # Move api directory
                if os.path.exists(old_api_dir):
                    print_status(f"Moving code from {old_api_dir} to {new_api_dir}...", "info")
                    logger.info(f"[{name}] Moving code: {old_api_dir} → {new_api_dir}")
                    shutil.move(old_api_dir, new_api_dir)
                    print_status("Code directory moved", "success")
                    logger.info(f"[{name}] Code directory moved successfully")
                else:
                    print_status(f"Old code directory not found ({old_api_dir}) — cloning fresh", "warning")
                    logger.warning(f"[{name}] Old code directory missing at {old_api_dir} — attempting git clone")
                    audit_log("LOCATION_UPDATE_WARN", name, {
                        "stage": "move_code",
                        "warning": "old_dir_missing",
                        "old_api_dir": old_api_dir
                    })
                    os.makedirs(new_api_dir, exist_ok=True)
                    try:
                        returncode, stdout, stderr = run_as_gaia(
                            ["git", "clone", "-b", svc.get('branch', 'main'), svc['repo_url'], name],
                            cwd=new_api_parent, capture=True, timeout=300
                        )
                        if returncode == 0:
                            print_status("Repository cloned to new location", "success")
                            logger.info(f"[{name}] Fresh clone succeeded: {svc['repo_url']} → {new_api_dir}")
                        else:
                            error_msg = stderr[:200] if stderr else "unknown"
                            print_status(f"Git clone warning: {error_msg}", "warning")
                            logger.warning(f"[{name}] Git clone returned non-zero (rc={returncode}): {error_msg}")
                    except Exception as git_err:
                        print_status(f"Git clone failed: {git_err}", "warning")
                        logger.error(f"[{name}] Git clone exception: {git_err}")
                        audit_log("LOCATION_UPDATE_WARN", name, {
                            "stage": "git_clone",
                            "error": str(git_err)
                        })

                # Move database directory
                if os.path.exists(old_db_dir):
                    os.makedirs(new_db_parent, exist_ok=True)
                    print_status(f"Moving database from {old_db_dir} to {new_db_dir}...", "info")
                    logger.info(f"[{name}] Moving database: {old_db_dir} → {new_db_dir}")
                    shutil.move(old_db_dir, new_db_dir)
                    print_status("Database directory moved", "success")
                    logger.info(f"[{name}] Database directory moved successfully")
                else:
                    print_status(f"Old database directory not found ({old_db_dir}) — creating empty", "warning")
                    logger.warning(f"[{name}] Old DB directory missing at {old_db_dir} — creating empty")
                    os.makedirs(new_db_dir, exist_ok=True)
                    audit_log("LOCATION_UPDATE_WARN", name, {
                        "stage": "move_database",
                        "warning": "old_dir_missing",
                        "old_db_dir": old_db_dir
                    })

                # Ensure log directory exists in new location
                new_log_dir = os.path.join(new_api_dir, "logs")
                os.makedirs(new_log_dir, exist_ok=True)
                logger.info(f"[{name}] Log directory ensured at {new_log_dir}")

                # Set permissions on new directories
                for d in [new_api_dir, new_db_dir, new_log_dir]:
                    try:
                        shutil.chown(d, user=SERVICE_USER, group=SERVICE_GROUP)
                        os.chmod(d, 0o750)
                    except Exception as perm_err:
                        logger.warning(f"[{name}] Permission set failed for {d}: {perm_err}")
                        audit_log("LOCATION_UPDATE_WARN", name, {
                            "stage": "permissions",
                            "directory": d,
                            "warning": str(perm_err)
                        })
                logger.info(f"[{name}] Permissions set on new directories")

                # Update systemd service file
                svc_file = f"{SYSTEMD_DIR}/{name}.service"
                if os.path.exists(svc_file):
                    print_status("Updating systemd service file...", "info")
                    logger.info(f"[{name}] Updating systemd file: {svc_file}")

                    with open(svc_file, 'r') as f:
                        content = f.read()

                    old_log_dir = os.path.join(old_api_dir, "logs")

                    content = content.replace(old_api_dir, new_api_dir)
                    content = content.replace(old_log_dir, new_log_dir)
                    content = content.replace(old_db_dir, new_db_dir)

                    with open(svc_file, 'w') as f:
                        f.write(content)

                    print_status("Service file updated", "success")
                    logger.info(f"[{name}] Systemd service file paths updated")
                    audit_log("LOCATION_UPDATE_SYSTEMD", name, {
                        "svc_file": svc_file,
                        "replaced": {
                            "api_dir": f"{old_api_dir} → {new_api_dir}",
                            "log_dir": f"{old_log_dir} → {new_log_dir}",
                            "db_dir": f"{old_db_dir} → {new_db_dir}"
                        }
                    })
                else:
                    print_status("Service file not found — skipping systemd update", "warning")
                    logger.warning(f"[{name}] Systemd file missing at {svc_file} — skipped")
                    audit_log("LOCATION_UPDATE_WARN", name, {
                        "stage": "systemd_update",
                        "warning": "service_file_not_found",
                        "svc_file": svc_file
                    })

                # Update database
                print_status("Updating database record...", "info")
                db.query(
                    "UPDATE services SET storage_path=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (new_storage, svc['id'])
                )
                logger.info(f"[{name}] DB record updated: storage_path={new_storage}")
                print_status("Database updated", "success")

                # Reload and start service
                try:
                    run_root(["systemctl", "daemon-reload"])
                    logger.info(f"[{name}] systemd daemon-reload completed")
                    run_root(["systemctl", "start", name])
                    print_status(f"Service {name} restarted", "success")
                    logger.info(f"[{name}] Service started after location migration")
                except Exception as start_err:
                    print_status(f"Service start warning: {start_err}", "warning")
                    logger.error(f"[{name}] Service restart failed after migration: {start_err}")
                    audit_log("LOCATION_UPDATE_WARN", name, {
                        "stage": "service_start",
                        "error": str(start_err)
                    })

                audit_log("LOCATION_UPDATE_SUCCESS", name, {
                    "old_storage": old_storage,
                    "new_storage": new_storage,
                    "api_dir": new_api_dir,
                    "db_dir": new_db_dir,
                    "log_dir": new_log_dir,
                    "svc_file": svc_file
                })

                print(f"\n  {C_GREEN}{'=' * 60}{C_RESET}")
                print(f"  {C_GREEN}{C_BOLD}✓ LOCATION UPDATED SUCCESSFULLY{C_RESET}")
                print(f"  {C_GREEN}{'=' * 60}{C_RESET}")
                print(f"\n  {C_BOLD}Old:{C_RESET}  {old_storage}")
                print(f"  {C_BOLD}New:{C_RESET}  {new_storage}")
                print(f"  {C_BOLD}Code:{C_RESET} {new_api_dir}")
                print(f"  {C_BOLD}DB:{C_RESET}   {new_db_dir}")
                print(f"  {C_GREEN}{'=' * 60}{C_RESET}")

                logger.info(f"[{name}] Location migration completed successfully")

            except Exception as e:
                logger.error(f"[{name}] Location update failed: {e}")
                print_status(f"Location update failed: {e}", "error")
                audit_log("LOCATION_UPDATE_FAILED", name, {
                    "error": str(e),
                    "old_storage": old_storage,
                    "new_storage": new_storage
                })

            input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

# ==============================================================================
#   TELEMETRY
# ==============================================================================

async def get_telemetry_async() -> Tuple[float, str, str, int]:
    """Get system telemetry asynchronously"""
    # Services count comes from the database and has nothing to do with
    # psutil -- compute it unconditionally so it's never wrong just because
    # psutil isn't installed/importable in this process.
    services = db.query("SELECT * FROM services WHERE status='active'", fetch_all=True)
    active_count = len(services) if services else 0

    if not psutil:
        return 0.0, "N/A", "N/A", active_count

    # Non-blocking CPU check
    cpu = psutil.cpu_percent(interval=None) 
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    ram_str = f"{mem.used / 1024 ** 3:.1f}/{mem.total / 1024 ** 3:.1f}GB"
    disk_str = f"{disk.used / 1024 ** 3:.0f}/{disk.total / 1024 ** 3:.0f}GB"

    return cpu, ram_str, disk_str, active_count

# ==============================================================================
#   MAIN MENU
# ==============================================================================

async def auto_backup_scheduler():
    """Background task to backup all services every day at 12:00 AM"""
    if getattr(auto_backup_scheduler, "started", False):
        logger.warning("auto_backup_scheduler: already running — skipping duplicate start")
        return
    auto_backup_scheduler.started = True

    logger.info("Auto-backup scheduler started.")

    while True:
        try:
            now = datetime.datetime.now()
            # Calculate time until next midnight
            tomorrow = now + datetime.timedelta(days=1)
            next_midnight = datetime.datetime.combine(tomorrow, datetime.time.min)
            sleep_seconds = (next_midnight - now).total_seconds()
            
            logger.info(f"Next auto-backup scheduled for 12:00 AM (in {sleep_seconds/3600:.1f} hours)")
            await asyncio.sleep(sleep_seconds)
            
            # --- START MIDNIGHT BACKUP ---
            logger.info("Triggering scheduled midnight backup for all services...")
            audit_log("SCHEDULED_BACKUP_START", "SYSTEM")
            services = db.query("SELECT * FROM services", fetch_all=True)

            if services:
                loop = asyncio.get_running_loop()
                backed_up = 0
                for svc in services:
                    try:
                        # An explicit per-service schedule overrides the legacy midnight job,
                        # including when that schedule has been disabled by the administrator.
                        import ats_operations
                        ats_operations.init(sys.modules[__name__])
                        with ats_operations.connection(sys.modules[__name__]) as conn:
                            if conn.execute('SELECT name FROM ops_config WHERE name=?', (svc['name'],)).fetchone():
                                continue
                        backup_file = await loop.run_in_executor(None, create_local_backup, svc)
                        if backup_file:
                            backed_up += 1
                            # Check for remote offloading
                            config = db.query(
                                "SELECT * FROM remote_configs WHERE service_name=?",
                                (svc['name'],), fetch_one=True
                            )
                            if config and config['auto_offload']:
                                await offload_backup(backup_file, config)
                    except Exception as svc_err:
                        # One bad service shouldn't abort the rest of the run
                        logger.error(f"[{svc['name']}] Scheduled backup failed: {svc_err}")
                        audit_log("SCHEDULED_BACKUP_SERVICE_FAILED", svc['name'], {"error": str(svc_err)})

                logger.info(f"Midnight backup completed: {backed_up}/{len(services)} services backed up.")
                audit_log("SCHEDULED_BACKUP_END", "SYSTEM", {"services_count": len(services), "backed_up": backed_up})
            else:
                logger.info("No services found for scheduled backup.")
                audit_log("SCHEDULED_BACKUP_SKIP", "SYSTEM", {"reason": "no_services"})

            # --- Google Drive backup at midnight ---
            logger.info("Triggering scheduled Google Drive backup...")
            loop = asyncio.get_running_loop()
            success, result = await loop.run_in_executor(None, backup_gdrive_now)
            if success:
                logger.info(f"Google Drive backup successful: {result}")
            else:
                logger.error(f"Google Drive backup failed: {result}")
                
        except Exception as e:
            logger.error(f"Scheduler error: {e}")
            await asyncio.sleep(60) # Sleep 1 minute before retrying

async def mainmenu():
    # Start the scheduler as a background task within the same event loop
    import ats_operations
    asyncio.create_task(ats_operations.worker(sys.modules[__name__]))
    asyncio.create_task(auto_backup_scheduler())
    
    while True:
        try:
            print_header()

            cpu, ram, disk, svccount = await get_telemetry_async()

            print(f"{C_CYAN}{'═' * 68}{C_RESET}")
            print(f"{C_CYAN}│{C_RESET} {C_BOLD}System{C_RESET}: CPU {cpu:.1f}% | RAM: {ram} | Disk: {disk} | Services: {svccount} {C_CYAN}│{C_RESET}")
            print(f"{C_CYAN}{'═' * 68}{C_RESET}")
            print(f"{C_CYAN}{'=' * 175}{C_RESET}")

            services = db.query("SELECT * FROM services ORDER BY name", fetch_all=True)

            if services:
                health_results = await parallel_health_checks(services)

                # Table Header
                header = f"  {'S.No.':<6} {'NAME':<40} {'PORT':<7} {'STATUS':<12} {'DOMAIN':<42} {'LOCATION':<60}"
                separator = f"  {C_CYAN}{'─' * 6} {'─' * 40} {'─' * 7} {'─' * 12} {'─' * 42} {'─' * 60}{C_RESET}"

                print(f"{C_CYAN}│{C_RESET}{C_BOLD}{header}{C_RESET}")
                print(f"{C_CYAN}│{C_RESET}{C_CYAN}{separator}{C_RESET}")

                for idx, svc in enumerate(services, start=1):
                    is_healthy = health_results.get(svc['name'], False)
                    status_str = f"{C_GREEN}● ONLINE{C_RESET}" if is_healthy else f"{C_RED}● OFFLINE{C_RESET}"

                    name = svc['name'][:38] + ".." if len(svc['name']) > 38 else svc['name']
                    domain = svc['domain'][:40] + ".." if len(svc['domain']) > 40 else svc['domain']
                    full_loc = os.path.join(svc['storage_path'], "api", svc['name'])
                    location = full_loc[:60] + ".." if len(full_loc) > 60 else full_loc

                    row = (
                        f"  {C_BOLD}{idx:<6}{C_RESET}"
                        f" {name:<40} "
                        f"{svc['port']:<7} "
                        f"{status_str:<21}"
                        f" {domain:<42}"
                        f"{C_CYAN}{location}{C_RESET}")
                    print(f"{C_CYAN}│{C_RESET}{row}")

            else:
                print(f"{C_CYAN}│{C_RESET}  {C_YELLOW}No services deployed yet — use Option 1 to get started{C_RESET}")

            print(f"{C_CYAN}{'─' * 175}{C_RESET}")

            # ════ MENU ════
            W = 55
            T = 113

            def menu_row(left_num, left_text, right_num, right_text, col_width=53):
                left = f"{C_BOLD}{left_num}{C_RESET}  {left_text}"
                right = f"{C_BOLD}{right_num}{C_RESET}  {right_text}"
                left_visible = len(left_num) + 2 + len(left_text)
                right_visible = len(right_num) + 2 + len(right_text)
                left_pad = col_width - left_visible
                right_pad = col_width - right_visible
                return (
                    f"{C_CYAN}║{C_RESET}  {left}{' ' * left_pad}"
                    f"{C_CYAN}║{C_RESET}  {right}{' ' * right_pad}"
                    f"{C_CYAN}║{C_RESET}"
                )

            def menu_single_row(num, text, total_width=113):
                content = f"{C_RED}{C_BOLD}{num}{C_RESET}  {text}"
                visible = len(num) + 2 + len(text)
                pad = total_width - visible - 4
                return f"{C_CYAN}║{C_RESET}  {content}{' ' * pad}{C_CYAN}║{C_RESET}"

            print(f"\n{C_CYAN}╔{'═' * W}╦{'═' * W}╗{C_RESET}")
            print(f"{C_CYAN}║{C_RESET}  {C_BOLD}{'DEPLOYMENT & SERVICES':<{W - 2}}{C_CYAN}║{C_RESET}  {C_BOLD}{'SYSTEM & DATABASE':<{W - 2}}{C_CYAN}║{C_RESET}")
            print(f"{C_CYAN}╠{'═' * W}╬{'═' * W}╣{C_RESET}")
            print(menu_row("1", "Deploy Service", "5", "Service Operations"))
            print(menu_row("2", "List Services", "6", "Backup Service"))
            print(menu_row("3", "Destroy Service", "7", "List Backups"))
            print(menu_row("4", "View Logs", "8", "Export Metrics"))
            print(f"{C_CYAN}╠{'═' * W}╬{'═' * W}╣{C_RESET}")
            print(menu_row("9", "View Database", "10", "Database Cleanup"))
            print(menu_row("11", "Update Database", "D", "System Diagnostics"))
            print(menu_row("G", "Global Operations", "W", "Webhook Listener"))
            print(f"{C_CYAN}╠{'═' * W}╩{'═' * W}╣{C_RESET}")
            print(menu_single_row("[ 0 ]", "Exit ATS"))
            print(f"{C_CYAN}╚{'═' * (T-2)}╝{C_RESET}")

            # Run input in executor to avoid blocking the event loop
            loop = asyncio.get_running_loop()
            choice = (await loop.run_in_executor(None, lambda: input(f"\n{C_CYAN}{C_BOLD}ATS ▶{C_RESET} "))).strip().lower()

            if choice == "1":
                await deploy_service_async()
            elif choice == "2":
                await list_services_detailed()
            elif choice == "3":
                await destroy_service()
            elif choice == "4":
                await view_service_logs()
            elif choice == "5":
                await service_operations()
            elif choice == "6":
                await backup_service()
            elif choice == "7":
                await list_backups()
            elif choice == "8":
                await export_metrics()
            elif choice == "9":
                await view_database()
            elif choice == "10":
                await database_cleanup()
            elif choice == "11":
                await update_database_async()
            elif choice == "d":
                await run_diagnostics()
            elif choice == "g":
                await global_operations()
            elif choice == "w":
                await run_webhook_listener()
            elif choice == "0":
                print(f"\n{C_CYAN}{'═' * 70}{C_RESET}")
                print(f"{C_CYAN}Thank you for using ATS v7.0!{C_RESET}")
                print(f"{C_CYAN}{'═' * 70}{C_RESET}")
                sys.exit(0)
            else:
                print_status("Invalid choice", "warning")
                await asyncio.sleep(1)

        except EOFError:
            logger.error("Terminal disconnected or running as service without --daemon. Exiting menu.")
            return
        except KeyboardInterrupt:
            print(f"\n{C_YELLOW}Use option [0] to exit properly.{C_RESET}")
            await asyncio.sleep(1)
        except Exception as e:
            logger.error(f"Menu error: {e}")
            print_status(f"Error: {e}", "error")
            await asyncio.sleep(2)

# ==============================================================================
#   ENTRY POINT
# ==============================================================================

async def run_daemon():
    """Run ATS in background mode (Scheduler + Webhook Listener)"""
    print_header()
    print(f"{C_GREEN}Starting ATS Daemon v7.0...{C_RESET}")
    
    import ats_cluster
    node = ats_cluster.Store().node()
    if node and node['role'] == 'global':
        import ats_operations
        import ats_remote
        asyncio.create_task(ats_operations.worker(sys.modules[__name__]))
        asyncio.create_task(auto_backup_scheduler())
        await asyncio.to_thread(ats_remote.serve, ats_cluster.Store(), int(os.environ.get('ATS_REMOTE_PORT', '9997')))
        return
    # Tunnel configuration is an explicit operator task, never a daemon side effect.
    print(f"{C_CYAN}→ Auto-Backup Scheduler: ACTIVE{C_RESET}")
    print(f"{C_CYAN}→ Webhook Listener:     ACTIVE ({webhook_bind_address()}:{WEBHOOK_PORT}){C_RESET}")
    
    import ats_routing
    await ats_routing.recover(sys.modules[__name__])
    # Start tasks
    import ats_operations
    asyncio.create_task(ats_operations.worker(sys.modules[__name__]))
    asyncio.create_task(auto_backup_scheduler())
    await start_webhook_server() # This runs forever

async def run_backup_all():
    """Perform a one-off backup of all services and exit"""
    print_status("Starting manual system-wide backup...", "info")
    audit_log("MANUAL_SYSTEM_BACKUP_START", "SYSTEM")
    services = db.query("SELECT * FROM services", fetch_all=True)
    if services:
        loop = asyncio.get_running_loop()
        for svc in services:
            backup_file = await loop.run_in_executor(None, create_local_backup, svc)
            if backup_file:
                config = db.query("SELECT * FROM remote_configs WHERE service_name=?", (svc['name'],), fetch_one=True)
                if config and config['auto_offload']:
                    await offload_backup(backup_file, config)
        print_status(f"System-wide backup complete for {len(services)} services.", "success")
        audit_log("MANUAL_SYSTEM_BACKUP_END", "SYSTEM", {"count": len(services)})
    else:
        print_status("No services found to backup.", "warning")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{C_RED}ERROR: ATS requires root privileges.{C_RESET}")
        print(f"Run: sudo python3 {sys.argv[0]}")
        sys.exit(1)

    if not os.path.exists(ATS_HOME):
        os.makedirs(ATS_HOME, exist_ok=True)
        os.chmod(ATS_HOME, 0o700)

    # Check for non-blocking flags before locking
    if len(sys.argv) > 1 and sys.argv[1] == "--backup-all":
        try:
            asyncio.run(run_backup_all())
        except KeyboardInterrupt:
            pass
        sys.exit(0)

    # CLI: ats backup now — trigger Google Drive backup immediately
    if len(sys.argv) > 2 and sys.argv[1] == "backup" and sys.argv[2] == "now":
        success, result = backup_gdrive_now()
        if success:
            print(f"Backup successful: {result}")
            sys.exit(0)
        else:
            print(f"Backup failed: {result}")
            sys.exit(1)

    lock = acquire_lock()

    # Check for daemon flag
    if len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        try:
            asyncio.run(run_daemon())
        except KeyboardInterrupt:
            pass
        sys.exit(0)

    print_header()
    print(f"{C_GREEN}Initializing ATS v7.0...{C_RESET}")
    
    try:
        asyncio.run(mainmenu())
    except KeyboardInterrupt:
        print(f"\n{C_CYAN}Shutting down ATS...{C_RESET}")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Critical error: {e}")
        print(f"{C_RED}CRITICAL ERROR: {e}{C_RESET}")
        sys.exit(1)
