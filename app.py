#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATS | AUTOMATED TECH STACK | v7.0
Architect: Abinaav K
Status: PRODUCTION - ALL BUGS FIXED
"""

import os
import sys
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
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass

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

# ==============================================================================
#   CONFIGURATION KERNEL
# ==============================================================================

ATS_HOME = "/home/gaia/ats"
DB_FILE = os.path.join(ATS_HOME, "ats.db")
LOG_FILE = os.path.join(ATS_HOME, "ats.log")
AUDIT_FILE = os.path.join(ATS_HOME, "audit.trace")
LOCK_FILE = "/tmp/ats.lock"
METRICS_FILE = os.path.join(ATS_HOME, "metrics.prom")

SERVICE_USER = "gaia"
SERVICE_GROUP = "gaia"
MAIN_DOMAIN = "gaiasentinel.online"
CLOUDFLARE_CONFIG = "/etc/cloudflared/config.yml"
DEFAULT_STORAGE = "/opt/extra1_1tb"
BACKUP_DIR = os.path.join(DEFAULT_STORAGE, "backups")

BLOCKED_PATHS = ["/", "/bin", "/boot", "/dev", "/etc", "/lib", "/root", "/run", "/sys", "/usr", "/var"]

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

      ░▒▓ AUTOMATED TECH STACK ▓▒░
      ─────────────────────────────
            Version 7.0 | ATS
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
            except:
                pass


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()
logger.addHandler(SecurityLogger())


def audit_log(action: str, target: str, metadata: Optional[Dict] = None):
    """Enhanced audit logging with structured data - FIXED"""
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "action": action,
        "target": target,
        "user": os.environ.get('SUDO_USER', getpass.getuser()),  # FIXED: Using getpass instead of os.getlogin()
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

        conn.commit()
        conn.close()
        try:
            os.chmod(self.db_path, 0o600)
        except:
            pass

    def query(self, sql: str, args=(), fetch_all=False, fetch_one=False):
        """Execute database query with error handling"""
        try:
            conn = sqlite3.connect(self.db_path)
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
            conn.close()
            return res
        except sqlite3.Error as e:
            logger.error(f"DB Error: {e}")
            return None


db = DatabaseManager(DB_FILE)


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
        except:
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
        loop = asyncio.get_event_loop()
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
            except:
                pass

        atexit.register(cleanup_lock)
        return lock_fd
    except IOError:
        print(f"{C_RED}CRITICAL: ATS is locked (Another instance running).{C_RESET}")
        sys.exit(1)


def run_as_gaia(cmd: List[str], cwd: Optional[str] = None, timeout: int = 300, capture: bool = False):
    """Execute command as gaia user"""
    env = os.environ.copy()
    env["HOME"] = f"/home/{SERVICE_USER}"
    full_cmd = ["sudo", "-u", SERVICE_USER] + cmd
    logger.info(f"EXEC(GAIA): {' '.join(cmd)}")

    try:
        if capture:
            result = subprocess.run(
                full_cmd, cwd=cwd, env=env, timeout=timeout,
                capture_output=True, text=True
            )
            return result.returncode, result.stdout, result.stderr
        else:
            subprocess.check_call(
                full_cmd, cwd=cwd, env=env, timeout=timeout,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            return 0, "", ""
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"Command timeout: {' '.join(cmd)}")


def run_root(cmd: List[str], timeout: int = 60):
    """Execute command as root"""
    logger.info(f"EXEC(ROOT): {' '.join(cmd)}")
    subprocess.check_call(cmd, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def get_service_path(storage: str, name: str) -> str:
    """
    Intelligently determines service path.
    Handles legacy (/websites), standard (/api), and nested input errors.
    """
    # 1. Clean the input
    base = os.path.abspath(storage)

    # 2. Check if storage input ALREADY points to a parent container
    #    (e.g., if storage was saved as "/opt/websites")
    if base.endswith("/websites") or base.endswith("/api"):
        return os.path.join(base, name)

    # 3. Check Priority 1: Legacy 'websites' folder (Gaia Sentinel)
    legacy_path = os.path.join(base, "websites", name)
    if os.path.exists(legacy_path):
        return legacy_path

    # 4. Default: Standard 'api' folder (Pinnacle & New Apps)
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

def validate_storage(path: str) -> str:
    """Validate storage path exists and is not restricted"""
    if not path:
        path = DEFAULT_STORAGE
    if not os.path.exists(path):
        raise ValueError(f"Path does not exist: {path}")
    clean = os.path.abspath(path)
    if clean in BLOCKED_PATHS:
        raise ValueError(f"Restricted path: {clean}")
    if not os.access(clean, os.W_OK):
        raise ValueError(f"Path not writable: {clean}")
    return clean


def validate_domain(domain: str) -> str:
    """Validate domain format and availability"""
    if not domain:
        raise ValueError("Domain cannot be empty")
    if not re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
        raise ValueError("Invalid domain format.")
    if db.query("SELECT 1 FROM services WHERE domain=?", (domain,), fetch_one=True):
        raise ValueError(f"Domain {domain} already exists.")
    return domain.lower()


def validate_port(port: str) -> int:
    """Validate port is numeric, in range, and available"""
    try:
        p = int(port)
    except:
        raise ValueError("Port must be numeric.")

    if not (1024 <= p <= 65535):
        raise ValueError("Port must be between 1024-65535.")

    if db.query("SELECT 1 FROM services WHERE port=?", (p,), fetch_one=True):
        raise ValueError(f"Port {p} already registered.")

    if check_port_listening(p, timeout=0.5):
        raise ValueError(f"Port {p} already in use on system.")

    return p


def validate_git_url(url: str) -> str:
    """Validate git repository URL"""
    if not url:
        raise ValueError("Git URL cannot be empty")
    if not (url.startswith("http://") or url.startswith("https://") or url.startswith("git@")):
        raise ValueError("Invalid Git URL format.")
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
                run_root(["systemctl", "restart", "cloudflared"])
            except:
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

            if any(r.get('hostname') == domain for r in ingress):
                logger.warning(f"Route {domain} already exists")
                return

            new_rule = {'hostname': domain, 'service': f'http://localhost:{port}'}
            catch_all_idx = next((i for i, r in enumerate(ingress) if r.get('service') == 'http_status:404'), -1)

            if catch_all_idx != -1:
                ingress.insert(catch_all_idx, new_rule)
            else:
                ingress.append(new_rule)

            with open(self.config_path, 'w') as f:
                yaml.dump(config, f, sort_keys=False, default_flow_style=False)

            run_root(["systemctl", "restart", "cloudflared"])
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

            run_root(["systemctl", "restart", "cloudflared"])
            logger.info(f"Cloudflare route removed: {domain}")

        except Exception as e:
            logger.error(f"Cloudflare remove route failed: {e}")
            self._restore_config()
            raise


cloudflare = CloudflareManager(CLOUDFLARE_CONFIG)


# ==============================================================================
#   SYSTEMD SERVICE GENERATION - FIXED
# ==============================================================================

def generate_systemd_service(config: ServiceConfig, api_dir: str, log_dir: str, db_dir: str) -> str:
    """Generate enhanced systemd service file - FIXED Type and Watchdog"""

    content = f"""[Unit]
Description={config.name} API [ATS v7.0 MANAGED]
After=network-online.target
Wants=network-online.target
Documentation=https://gaiasentinel.online/docs/{config.name}

[Service]
Type=simple
User={SERVICE_USER}
Group={SERVICE_GROUP}
WorkingDirectory={api_dir}

# Environment
Environment="PATH={api_dir}/venv/bin:/usr/local/bin:/usr/bin"
Environment="PYTHONUNBUFFERED=1"

# Execution
ExecStart={api_dir}/venv/bin/gunicorn \\
    --bind 127.0.0.1:{config.port} \\
    --workers {config.workers} \\
    --worker-class sync \\
    --timeout 120 \\
    --max-requests 1000 \\
    --max-requests-jitter 100 \\
    --worker-connections 1000 \\
    --access-logfile {log_dir}/access.log \\
    --error-logfile {log_dir}/error.log \\
    --log-level info \\
    app:app

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
ProtectSystem=strict
ProtectHome=true
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
    """Enhanced asynchronous service deployment"""
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

    try:
        name = input(f"{C_BOLD}Service Name (alphanumeric):{C_RESET} ").strip()
        if not re.match(r"^[a-zA-Z0-9_-]+$", name):
            raise ValueError("Invalid service name format")
        if db.query("SELECT 1 FROM services WHERE name=?", (name,), fetch_one=True):
            raise ValueError(f"Service '{name}' already exists")

        storage = validate_storage(input(f"{C_BOLD}Storage Path [{DEFAULT_STORAGE}]:{C_RESET} ").strip() or DEFAULT_STORAGE)

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

        print(f"\n{C_YELLOW}Advanced Settings (press Enter for defaults):{C_RESET}")
        workers_input = input(f"  Workers [auto]: ").strip()
        workers = int(workers_input) if workers_input else 0

        memory_input = input(f"  Max Memory MB [512]: ").strip()
        max_memory = int(memory_input) if memory_input else 512

        cpu_input = input(f"  CPU Quota % [50]: ").strip()
        cpu_quota = int(cpu_input) if cpu_input else 50

        config = ServiceConfig(name=name, port=port, domain=domain, storage_path=storage, repo_url=repo_url, workers=workers, max_memory_mb=max_memory, cpu_quota=cpu_quota)

        print(f"\n{C_GREEN}{'=' * 70}{C_RESET}")
        print_status("PROVISIONING INFRASTRUCTURE", "info")

        api_dir = os.path.join(storage, "api", name)
        db_dir = os.path.join(storage, "database", name)
        log_dir = os.path.join(api_dir, "logs")
        svc_file = f"/etc/systemd/system/{name}.service"

        for directory in [api_dir, db_dir, log_dir]:
            os.makedirs(directory, exist_ok=True)
            shutil.chown(directory, user=SERVICE_USER, group=SERVICE_GROUP)
            os.chmod(directory, 0o750)

        print_status(f"Created: {api_dir}", "success")
        print_status(f"Created: {db_dir}", "success")
        print_status(f"Created: {log_dir}", "success")

        print_status("CLONING REPOSITORY", "info")
        returncode, stdout, stderr = await run_async_command(["sudo", "-u", SERVICE_USER, "git", "clone", repo_url, "."], cwd=api_dir, timeout=300)
        if returncode != 0:
            raise RuntimeError(f"Git clone failed: {stderr}")
        print_status("Repository cloned successfully", "success")

        print_status("CREATING PYTHON VIRTUAL ENVIRONMENT", "info")
        run_as_gaia([sys.executable, "-m", "venv", "venv"], cwd=api_dir, timeout=120)

        pip_path = os.path.join(api_dir, "venv", "bin", "pip")

        run_as_gaia([pip_path, "install", "--upgrade", "pip"], cwd=api_dir)

        requirements_file = os.path.join(api_dir, "requirements.txt")
        if os.path.exists(requirements_file):
            print_status("Installing requirements.txt", "info")
            run_as_gaia([pip_path, "install", "-r", "requirements.txt"], cwd=api_dir, timeout=600)
        else:
            print_status("Installing default Flask stack", "warning")
            run_as_gaia([pip_path, "install", "flask", "flask-cors"], cwd=api_dir)

        run_as_gaia([pip_path, "install", "gunicorn"], cwd=api_dir)

        if PROMETHEUS_AVAILABLE:
            run_as_gaia([pip_path, "install", "prometheus-flask-exporter"], cwd=api_dir)

        print_status("Python environment ready", "success")

        print_status("GENERATING SYSTEMD SERVICE", "info")
        service_content = generate_systemd_service(config, api_dir, log_dir, db_dir)

        with open(svc_file, 'w') as f:
            f.write(service_content)
        os.chmod(svc_file, 0o644)

        run_root(["systemctl", "daemon-reload"])
        run_root(["systemctl", "enable", name])
        run_root(["systemctl", "start", name])

        print_status(f"Service {name}.service created and started", "success")

        print(f"\n{C_YELLOW}{'=' * 70}{C_RESET}")
        print_status("RUNNING HEALTH CHECKS", "info")
        time.sleep(3)

        health_ok = health_check_deployment(name, port)

        if not health_ok:
            raise RuntimeError("Service failed health checks")

        print_status("CONFIGURING CLOUDFLARE TUNNEL", "info")
        cloudflare.add_route(domain, port)
        print_status(f"Route added: {domain} -> localhost:{port}", "success")

        deployment_hash = calculate_file_hash(requirements_file) if os.path.exists(requirements_file) else "none"

        db.query("""INSERT INTO services (name, port, domain, storage_path, repo_url, workers, max_memory_mb, cpu_quota, deployment_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, port, domain, storage, repo_url, config.workers, max_memory, cpu_quota, deployment_hash))

        duration = time.time() - start_time
        db.query("INSERT INTO deployments (service_name, status, duration_seconds) VALUES (?, ?, ?)",(name, "success", duration))

        if PROMETHEUS_AVAILABLE:
            DEPLOY_COUNTER.labels(status='success').inc()
            DEPLOY_DURATION.observe(duration)

        audit_log("DEPLOY_SUCCESS", name, {"domain": domain, "port": port, "duration": duration, "workers": config.workers})

        print(f"\n{C_GREEN}{'=' * 70}{C_RESET}")
        print(f"{C_GREEN}{C_BOLD}✓ DEPLOYMENT SUCCESSFUL{C_RESET}")
        print(f"\n{C_CYAN}Service Details:{C_RESET}")
        print(f"  Name:       {C_BOLD}{name}{C_RESET}")
        print(f"  Domain:     {C_BOLD}https://{domain}{C_RESET}")
        print(f"  Port:       {C_BOLD}{port}{C_RESET}")
        print(f"  Workers:    {C_BOLD}{config.workers}{C_RESET}")
        print(f"  Memory:     {C_BOLD}{max_memory}MB{C_RESET}")
        print(f"  CPU Quota:  {C_BOLD}{cpu_quota}%{C_RESET}")
        print(f"  Duration:   {C_BOLD}{duration:.2f}s{C_RESET}")
        print(f"{C_GREEN}{'=' * 70}{C_RESET}\n")

    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        print(f"\n{C_RED}{'=' * 70}{C_RESET}")
        print_status(f"DEPLOYMENT FAILED: {e}", "error")
        print(f"{C_RED}{'=' * 70}{C_RESET}\n")

        print_status("INITIATING ROLLBACK", "warning")

        try:
            if name and svc_file:
                try:
                    run_root(["systemctl", "stop", name])
                    run_root(["systemctl", "disable", name])
                except:
                    pass

                if os.path.exists(svc_file):
                    os.remove(svc_file)
                    run_root(["systemctl", "daemon-reload"])

            if api_dir and os.path.exists(api_dir):
                shutil.rmtree(api_dir)

            if db_dir and os.path.exists(db_dir):
                shutil.rmtree(db_dir)

            if domain:
                try:
                    cloudflare.remove_route(domain)
                except:
                    pass

            print_status("Rollback completed", "success")

        except Exception as rollback_error:
            logger.error(f"Rollback error: {rollback_error}")
            print_status(f"Rollback error: {rollback_error}", "error")

        duration = time.time() - start_time
        if name:
            db.query("INSERT INTO deployments (service_name, status, duration_seconds, error_message) VALUES (?, ?, ?, ?)",(name, "failed", duration, str(e)))

        if PROMETHEUS_AVAILABLE:
            DEPLOY_COUNTER.labels(status='failed').inc()

        audit_log("DEPLOY_FAILED", name or "unknown", {"error": str(e)})

    input(f"\n{C_CYAN}Press Enter to return to main menu...{C_RESET}")


def deploy_service():
    """Wrapper to run async deployment"""
    asyncio.run(deploy_service_async())


# ==============================================================================
#   SERVICE LISTING
# ==============================================================================

def list_services_detailed():
    """Display detailed service information"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ SERVICE REGISTRY ═══{C_RESET}\n")

    services = db.query("SELECT * FROM services ORDER BY created_at DESC", fetch_all=True)

    if not services:
        print_status("No services deployed yet", "warning")
        print(f"\n{C_CYAN}Use option [1] to deploy your first service.{C_RESET}\n")
        input(f"{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    print(f"{C_CYAN}Total Services: {C_BOLD}{len(services)}{C_RESET}\n")

    print_status("Checking service health...", "info")
    health_results = asyncio.run(parallel_health_checks(services))
    print()

    for idx, svc in enumerate(services, 1):
        is_healthy = health_results.get(svc['name'], False)
        status_icon = f"{C_GREEN}●{C_RESET}" if is_healthy else f"{C_RED}●{C_RESET}"
        status_text = "ONLINE" if is_healthy else "OFFLINE"

        print(f"{C_CYAN}┌─ SERVICE #{idx} {'─' * 55}{C_RESET}")
        print(f"{C_CYAN}│{C_RESET} {C_BOLD}Name:{C_RESET}          {svc['name']}")
        print(f"{C_CYAN}│{C_RESET} {C_BOLD}Status:{C_RESET}        {status_icon} {status_text}")
        print(f"{C_CYAN}│{C_RESET} {C_BOLD}Domain:{C_RESET}        https://{svc['domain']}")
        print(f"{C_CYAN}│{C_RESET} {C_BOLD}Port:{C_RESET}          {svc['port']}")
        print(f"{C_CYAN}│{C_RESET} {C_BOLD}Workers:{C_RESET}       {svc['workers']}")
        print(f"{C_CYAN}│{C_RESET} {C_BOLD}Memory Limit:{C_RESET}  {svc['max_memory_mb']} MB")
        print(f"{C_CYAN}│{C_RESET} {C_BOLD}CPU Quota:{C_RESET}     {svc['cpu_quota']}%")
        print(f"{C_CYAN}│{C_RESET} {C_BOLD}Storage:{C_RESET}       {svc['storage_path']}")
        print(f"{C_CYAN}│{C_RESET} {C_BOLD}Repository:{C_RESET}    {svc['repo_url']}")
        print(f"{C_CYAN}│{C_RESET} {C_BOLD}Created:{C_RESET}       {svc['created_at']}")

        deploy_stats = db.query(
            "SELECT COUNT(*) as total, SUM(CASE WHEN status='success' THEN 1 ELSE 0 END) as successful FROM deployments WHERE service_name=?",
            (svc['name'],),
            fetch_one=True
        )
        if deploy_stats and deploy_stats['total'] > 0:
            success_rate = (deploy_stats['successful'] / deploy_stats['total']) * 100
            print(
                f"{C_CYAN}│{C_RESET} {C_BOLD}Deployments:{C_RESET}   {deploy_stats['total']} ({success_rate:.0f}% success)")

        backup_count = db.query(
            "SELECT COUNT(*) as count FROM backups WHERE service_name=?",
            (svc['name'],),
            fetch_one=True
        )
        if backup_count:
            print(f"{C_CYAN}│{C_RESET} {C_BOLD}Backups:{C_RESET}       {backup_count['count']}")

        print(f"{C_CYAN}└{'─' * 68}{C_RESET}\n")

    input(f"{C_CYAN}Press Enter to return to main menu...{C_RESET}")


# ==============================================================================
#   SERVICE OPERATIONS
# ==============================================================================

def destroy_service():
    """Enhanced service destruction with confirmation"""
    print_header()
    print(f"{C_RED}{C_BOLD}═══ DESTROY SERVICE ═══{C_RESET}\n")
    print(f"{C_YELLOW}WARNING: This will permanently delete the service and all its data.{C_RESET}\n")

    name = input("Service Name: ").strip()
    svc = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)

    if not svc:
        print_status("Service not found", "error")
        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    print(f"\n{C_CYAN}Service Information:{C_RESET}")
    print(f"  Name:    {svc['name']}")
    print(f"  Domain:  {svc['domain']}")
    print(f"  Port:    {svc['port']}")
    print(f"  Created: {svc['created_at']}")

    print(f"\n{C_RED}Type 'DELETE {name}' to confirm:{C_RESET} ", end='')
    confirmation = input()

    if confirmation != f"DELETE {name}":
        print_status("Destruction cancelled", "warning")
        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    try:
        print(f"\n{C_YELLOW}{'=' * 70}{C_RESET}")
        print_status("STOPPING SERVICE", "info")
        run_root(["systemctl", "stop", name])
        run_root(["systemctl", "disable", name])

        svc_file = f"/etc/systemd/system/{name}.service"
        if os.path.exists(svc_file):
            os.remove(svc_file)
        run_root(["systemctl", "daemon-reload"])
        print_status("Service stopped and disabled", "success")

        print_status("REMOVING CLOUDFLARE ROUTE", "info")
        cloudflare.remove_route(svc['domain'])
        print_status("Route removed", "success")

        print_status("DELETING SERVICE DATA", "info")
        service_root = get_service_path(svc['storage_path'], name)
        if os.path.exists(service_root):
            shutil.rmtree(service_root)

        db_root = os.path.join(svc['storage_path'], "database", name)
        if os.path.exists(db_root):
            shutil.rmtree(db_root)
        print_status("Data deleted", "success")

        print_status("UPDATING DATABASE", "info")
        db.query("DELETE FROM services WHERE id=?", (svc['id'],))
        print_status("Database updated", "success")

        audit_log("DESTROY", name, {"domain": svc['domain'], "port": svc['port']})

        print(f"\n{C_GREEN}{'=' * 70}{C_RESET}")
        print_status(f"SERVICE '{name}' DESTROYED", "success")
        print(f"{C_GREEN}{'=' * 70}{C_RESET}\n")

    except Exception as e:
        logger.error(f"Destroy failed: {e}")
        print_status(f"Destruction failed: {e}", "error")

    input(f"\n{C_CYAN}Press Enter to return to main menu...{C_RESET}")


def view_service_logs():
    """View service logs with options"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ SERVICE LOGS ═══{C_RESET}\n")

    name = input("Service Name: ").strip()
    svc = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)

    if not svc:
        print_status("Service not found", "error")
        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    # Remove debug prints for production
    service_path = get_service_path(svc['storage_path'], name)
    log_dir = os.path.join(service_path, "logs")

    # Auto-create log dir if missing (prevents crashes on fresh repos)
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir, exist_ok=True)
            shutil.chown(log_dir, user=SERVICE_USER, group=SERVICE_GROUP)
        except:
            pass

    print(f"\n{C_CYAN}Available Logs:{C_RESET}")
    print("  1. Access Log (Gunicorn requests)")
    print("  2. Error Log (Application errors)")
    print("  3. Stdout Log (Standard output)")
    print("  4. Stderr Log (Standard error)")
    print("  5. Live tail (real-time)")
    print("  0. Cancel")

    choice = input(f"\n{C_CYAN}Select log:{C_RESET} ").strip()

    log_files = {
        "1": "access.log",
        "2": "error.log",
        "3": "stdout.log",
        "4": "stderr.log",
        "5": "access.log"
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
        print(f"\n{C_CYAN}{'═' * 70}{C_RESET}")
        print(f"{C_CYAN}Streaming live logs (Ctrl+C to stop)...{C_RESET}")
        print(f"{C_CYAN}{'═' * 70}{C_RESET}\n")
        try:
            subprocess.run(["tail", "-f", log_file])
        except KeyboardInterrupt:
            print(f"\n\n{C_CYAN}{'═' * 70}{C_RESET}")
            print_status("Log streaming stopped", "info")
    else:
        print(f"\n{C_CYAN}{'═' * 70}{C_RESET}")
        print(f"{C_CYAN}Last 50 lines of {log_files[choice]}:{C_RESET}")
        print(f"{C_CYAN}{'═' * 70}{C_RESET}\n")

        try:
            result = subprocess.run(
                ["tail", "-n", "50", log_file],
                capture_output=True,
                text=True
            )
            print(result.stdout)
        except Exception as e:
            print_status(f"Error reading log: {e}", "error")

    print(f"\n{C_CYAN}{'═' * 70}{C_RESET}")
    input(f"\n{C_CYAN}Press Enter to return to main menu...{C_RESET}")


def service_operations():
    """Service management operations menu - ENHANCED"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ SERVICE OPERATIONS ═══{C_RESET}\n")

    name = input("Service Name: ").strip()

    if not name:
        print_status("Service name cannot be empty", "error")
        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    svc = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)

    if not svc:
        print_status("Service not found", "error")

        all_services = db.query("SELECT name FROM services ORDER BY name", fetch_all=True)
        if all_services:
            print(f"\n{C_CYAN}Available services:{C_RESET}")
            for s in all_services:
                print(f"  - {s['name']}")

        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    # Show service info
    print(f"\n{C_CYAN}Service: {C_BOLD}{name}{C_RESET}")
    print(f"Domain:  https://{svc['domain']}")
    print(f"Port:    {svc['port']}\n")

    # Check status
    try:
        result = subprocess.run(
            ["systemctl", "is-active", name],
            capture_output=True,
            timeout=5
        )
        is_active = result.stdout.strip() == b"active"
        status_icon = f"{C_GREEN}●{C_RESET}" if is_active else f"{C_RED}●{C_RESET}"
        status_text = "ACTIVE" if is_active else "INACTIVE"
        print(f"Status:  {status_icon} {status_text}\n")
    except:
        print(f"Status:  {C_YELLOW}UNKNOWN{C_RESET}\n")
        is_active = False

    print(f"{C_CYAN}{'─' * 70}{C_RESET}\n")
    print(f"{C_CYAN}Available Operations:{C_RESET}\n")
    print("  1. Restart service")
    print("  2. Stop service")
    print("  3. Start service")
    print("  4. Git pull and restart")
    print("  5. Reinstall dependencies (pip install -r requirements.txt)")
    print("  6. View systemd status")
    print("  7. View resource usage")
    print("  0. Cancel")

    choice = input(f"\n{C_CYAN}Select operation:{C_RESET} ").strip()

    if choice == "1":
        # RESTART
        print(f"\n{C_YELLOW}Restarting service...{C_RESET}")
        try:
            subprocess.run(["systemctl", "restart", name], timeout=10, check=True)
            time.sleep(2)

            result = subprocess.run(["systemctl", "is-active", name], capture_output=True, timeout=5)
            if result.stdout.strip() == b"active":
                print(f"{C_GREEN}✓ Service restarted successfully{C_RESET}")
                audit_log("RESTART", name)
            else:
                print(f"{C_RED}✗ Service restart failed{C_RESET}")
        except Exception as e:
            print(f"{C_RED}✗ Error: {e}{C_RESET}")

        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

    elif choice == "2":
        # STOP
        print(f"\n{C_RED}Stop service '{name}'? (yes/no):{C_RESET} ", end='')
        if input().strip().lower() == "yes":
            print(f"\n{C_YELLOW}Stopping service...{C_RESET}")
            try:
                subprocess.run(["systemctl", "stop", name], timeout=10, check=True)
                time.sleep(1)
                print(f"{C_GREEN}✓ Service stopped{C_RESET}")
                audit_log("STOP", name)
            except Exception as e:
                print(f"{C_RED}✗ Error: {e}{C_RESET}")
        else:
            print(f"{C_YELLOW}Cancelled{C_RESET}")

        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

    elif choice == "3":
        # START
        print(f"\n{C_YELLOW}Starting service...{C_RESET}")
        try:
            subprocess.run(["systemctl", "start", name], timeout=10, check=True)
            time.sleep(2)

            result = subprocess.run(["systemctl", "is-active", name], capture_output=True, timeout=5)
            if result.stdout.strip() == b"active":
                print(f"{C_GREEN}✓ Service started successfully{C_RESET}")
                audit_log("START", name)
            else:
                print(f"{C_RED}✗ Service start failed{C_RESET}")
        except Exception as e:
            print(f"{C_RED}✗ Error: {e}{C_RESET}")

        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

    elif choice == "4":
        # GIT PULL
        print(f"\n{C_YELLOW}Updating code...{C_RESET}")
        try:
            service_path = get_service_path(svc['storage_path'], name)

            print("Pulling from git...")
            returncode, stdout, stderr = run_as_gaia(["git", "pull"], cwd=service_path, capture=True)

            if returncode == 0:
                print(f"{C_GREEN}✓ Code updated{C_RESET}")
                if "Already up to date" in stdout or "Already up-to-date" in stdout:
                    print("  (no new changes)")

                print("\nRestarting service...")
                subprocess.run(["systemctl", "restart", name], timeout=10, check=True)
                time.sleep(2)

                result = subprocess.run(["systemctl", "is-active", name], capture_output=True, timeout=5)
                if result.stdout.strip() == b"active":
                    print(f"{C_GREEN}✓ Service restarted with new code{C_RESET}")
                    audit_log("UPDATE", name, {"method": "git_pull"})
                else:
                    print(f"{C_RED}✗ Service restart failed{C_RESET}")
            else:
                print(f"{C_RED}✗ Git pull failed{C_RESET}")
                if stderr:
                    print(f"Error: {stderr[:200]}")
        except Exception as e:
            print(f"{C_RED}✗ Error: {e}{C_RESET}")

        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")


    elif choice == "5":

        # REINSTALL DEPENDENCIES WITH AUTO-REBUILD

        print(f"\n{C_YELLOW}Reinstalling dependencies...{C_RESET}")

        try:

            service_path = get_service_path(svc['storage_path'], name)

            requirements_file = os.path.join(service_path, "requirements.txt")

            venv_path = os.path.join(service_path, "venv")

            print(f"Service path: {service_path}")

            print(f"Virtual env:  {venv_path}")

            # Step 1: Check service directory exists

            if not os.path.exists(service_path):
                print(f"{C_RED}✗ Service directory not found{C_RESET}")

                input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

                return

            # Step 2: Check requirements.txt exists

            if not os.path.exists(requirements_file):
                print(f"{C_RED}✗ requirements.txt not found{C_RESET}")

                input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

                return

            # Step 3: Determine which pip to use

            pip3_path = os.path.join(venv_path, "bin", "pip3")

            pip_path = os.path.join(venv_path, "bin", "pip")

            # Check which one exists

            if os.path.exists(pip3_path):

                pip_executable = pip3_path

                print(f"Pip path:     {pip_executable}\n")

            elif os.path.exists(pip_path):

                pip_executable = pip_path

                print(f"Pip path:     {pip_executable}\n")

            else:

                # Neither pip nor pip3 found - venv is missing or corrupted

                print(f"Pip path:     {pip3_path} (not found)\n")

                print(f"{C_RED}✗ Virtual environment is missing or corrupted{C_RESET}")

                print(f"{C_YELLOW}Neither pip3 nor pip found in venv/bin/{C_RESET}\n")

                print(f"{C_CYAN}Would you like to rebuild the virtual environment? (yes/no):{C_RESET} ", end='')

                if input().strip().lower() != "yes":
                    print(f"{C_YELLOW}Cancelled{C_RESET}")

                    input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

                    return

                # REBUILD VENV

                print(f"\n{C_YELLOW}{'=' * 70}{C_RESET}")

                print(f"{C_YELLOW}REBUILDING VIRTUAL ENVIRONMENT{C_RESET}")

                print(f"{C_YELLOW}{'=' * 70}{C_RESET}\n")

                # Step 1: Remove old venv if it exists

                if os.path.exists(venv_path):

                    print(f"{C_CYAN}Removing corrupted venv...{C_RESET}")

                    try:

                        shutil.rmtree(venv_path)

                        print(f"{C_GREEN}✓ Old venv removed{C_RESET}")

                    except Exception as e:

                        print(f"{C_RED}✗ Failed to remove old venv: {e}{C_RESET}")

                        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

                        return

                # Step 2: Create fresh venv

                print(f"\n{C_CYAN}Creating new virtual environment...{C_RESET}")

                try:

                    run_as_gaia([sys.executable, "-m", "venv", "venv"], cwd=service_path, timeout=120)

                    print(f"{C_GREEN}✓ Virtual environment created{C_RESET}")

                except Exception as e:

                    print(f"{C_RED}✗ Failed to create venv: {e}{C_RESET}")

                    input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

                    return

                # Step 3: Determine which pip was created

                if os.path.exists(pip3_path):

                    pip_executable = pip3_path

                elif os.path.exists(pip_path):

                    pip_executable = pip_path

                else:

                    print(f"{C_RED}✗ Failed to create pip executable{C_RESET}")

                    input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

                    return

                print(f"{C_GREEN}✓ Using: {pip_executable}{C_RESET}")

            # Step 4: Upgrade pip and setuptools

            print(f"\n{C_CYAN}Upgrading pip and setuptools...{C_RESET}")

            try:

                returncode, stdout, stderr = run_as_gaia(

                    [pip_executable, "install", "--upgrade", "pip", "setuptools", "wheel"],

                    cwd=service_path,

                    capture=True,

                    timeout=120

                )

                if returncode == 0:

                    print(f"{C_GREEN}✓ Pip upgraded{C_RESET}")

                else:

                    print(f"{C_YELLOW}⚠ Pip upgrade had warnings (continuing anyway){C_RESET}")

            except Exception as e:

                print(f"{C_YELLOW}⚠ Pip upgrade warning: {e}{C_RESET}")

            # Step 5: Install requirements.txt

            print(f"\n{C_CYAN}Installing requirements.txt...{C_RESET}")

            print(f"  This may take several minutes...\n")

            start_time = time.time()

            try:

                returncode, stdout, stderr = run_as_gaia(

                    [pip_executable, "install", "-r", "requirements.txt"],

                    cwd=service_path,

                    capture=True,

                    timeout=600

                )

                duration = time.time() - start_time

                if returncode == 0:

                    print(f"{C_GREEN}✓ Dependencies installed successfully ({duration:.1f}s){C_RESET}")

                    # Show what was installed

                    if "Successfully installed" in stdout:

                        packages = [line for line in stdout.split("\n") if "Successfully installed" in line]

                        if packages:
                            pkg_line = packages[0].replace("Successfully installed", "").strip()

                            pkg_count = len(pkg_line.split())

                            print(f"  {C_CYAN}Installed {pkg_count} packages{C_RESET}")

                    # Step 6: Install gunicorn (essential for service)

                    print(f"\n{C_CYAN}Installing gunicorn...{C_RESET}")

                    try:

                        returncode, stdout, stderr = run_as_gaia(

                            [pip_executable, "install", "gunicorn"],

                            cwd=service_path,

                            capture=True,

                            timeout=60

                        )

                        if returncode == 0:

                            print(f"{C_GREEN}✓ Gunicorn installed{C_RESET}")

                        else:

                            print(f"{C_YELLOW}⚠ Gunicorn installation warning{C_RESET}")

                    except Exception as e:

                        print(f"{C_YELLOW}⚠ Gunicorn warning: {e}{C_RESET}")

                    # Step 7: Offer to restart service

                    print(f"\n{C_GREEN}{'=' * 70}{C_RESET}")

                    print(f"{C_GREEN}All dependencies installed successfully!{C_RESET}")

                    print(f"{C_GREEN}{'=' * 70}{C_RESET}\n")

                    print(f"{C_CYAN}Restart service to apply changes? (yes/no):{C_RESET} ", end='')

                    if input().strip().lower() == "yes":

                        print(f"\n{C_YELLOW}Restarting {name}...{C_RESET}")

                        try:

                            subprocess.run(["systemctl", "restart", name], timeout=10, check=True)

                            time.sleep(2)

                            result = subprocess.run(

                                ["systemctl", "is-active", name],

                                capture_output=True,

                                timeout=5

                            )

                            if result.stdout.strip() == b"active":

                                print(f"{C_GREEN}✓ Service restarted successfully{C_RESET}")

                                # Health check

                                time.sleep(1)

                                if check_port_listening(svc['port'], timeout=2.0):

                                    print(f"{C_GREEN}✓ Service is responding on port {svc['port']}{C_RESET}")

                                else:

                                    print(
                                        f"{C_YELLOW}⚠ Service active but port not responding yet (may need more time){C_RESET}")

                                audit_log("REINSTALL_DEPS", name, {"rebuilt_venv": True})

                            else:

                                print(f"{C_RED}✗ Service failed to start{C_RESET}")

                                print(f"{C_YELLOW}Check logs: journalctl -u {name} -n 50{C_RESET}")

                        except Exception as e:

                            print(f"{C_RED}✗ Restart failed: {e}{C_RESET}")

                    else:

                        print(
                            f"{C_YELLOW}Restart cancelled - service will use new dependencies on next restart{C_RESET}")


                else:

                    print(f"{C_RED}✗ Installation failed{C_RESET}")

                    print(f"\n{C_YELLOW}Error output (last 20 lines):{C_RESET}")

                    if stderr:

                        error_lines = [l for l in stderr.split("\n") if l.strip()][-20:]

                        for line in error_lines:
                            print(f"  {line}")


            except TimeoutError:

                print(f"{C_RED}✗ Installation timed out after 10 minutes{C_RESET}")

                print(f"{C_YELLOW}Large packages may take longer. Try again or check network.{C_RESET}")

            except Exception as e:

                print(f"{C_RED}✗ Installation error: {e}{C_RESET}")


        except Exception as e:

            print(f"{C_RED}✗ Unexpected error: {e}{C_RESET}")

            import traceback

            traceback.print_exc()

        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")


    elif choice == "6":
        # SYSTEMD STATUS
        print(f"\n{C_CYAN}{'═' * 70}{C_RESET}")
        try:
            subprocess.run(["systemctl", "status", name, "--no-pager", "-l"], timeout=10)
        except Exception as e:
            print(f"{C_RED}Error: {e}{C_RESET}")
        print(f"{C_CYAN}{'═' * 70}{C_RESET}")

        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

    elif choice == "7":
        # RESOURCE USAGE
        print(f"\n{C_CYAN}{'═' * 70}{C_RESET}")
        print(f"{C_CYAN}Resource Usage:{C_RESET}\n")

        if psutil:
            found = False
            total_cpu = 0.0
            total_memory = 0.0
            process_count = 0

            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        cmdline = ' '.join(proc.info['cmdline'] or [])
                        if name in cmdline and 'gunicorn' in cmdline:
                            cpu = proc.cpu_percent(interval=0.5)
                            mem = proc.memory_info().rss / (1024 * 1024)

                            print(f"PID {proc.pid}:")
                            print(f"  CPU:         {cpu:.1f}%")
                            print(f"  Memory:      {mem:.1f} MB")
                            print(f"  Threads:     {proc.num_threads()}")
                            print()

                            total_cpu += cpu
                            total_memory += mem
                            process_count += 1
                            found = True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                if found:
                    print(f"{C_BOLD}Total ({process_count} processes):{C_RESET}")
                    print(f"  CPU:         {total_cpu:.1f}%")
                    print(f"  Memory:      {total_memory:.1f} MB")

                    # Show limits
                    print(f"\n{C_BOLD}Configured Limits:{C_RESET}")
                    print(f"  CPU Quota:   {svc['cpu_quota']}%")
                    print(f"  Memory Max:  {svc['max_memory_mb']} MB")

                    # Calculate usage percentages
                    cpu_usage = (total_cpu / svc['cpu_quota']) * 100 if svc['cpu_quota'] > 0 else 0
                    mem_usage = (total_memory / svc['max_memory_mb']) * 100 if svc['max_memory_mb'] > 0 else 0

                    print(f"\n{C_BOLD}Usage vs Limits:{C_RESET}")
                    cpu_color = C_RED if cpu_usage > 90 else C_YELLOW if cpu_usage > 70 else C_GREEN
                    mem_color = C_RED if mem_usage > 90 else C_YELLOW if mem_usage > 70 else C_GREEN
                    print(f"  CPU:         {cpu_color}{cpu_usage:.1f}%{C_RESET}")
                    print(f"  Memory:      {mem_color}{mem_usage:.1f}%{C_RESET}")
                else:
                    print(f"{C_YELLOW}No Gunicorn processes found{C_RESET}")
                    print(f"Service may not be running")
            except Exception as e:
                print(f"{C_RED}Error: {e}{C_RESET}")
        else:
            print(f"{C_YELLOW}psutil not installed{C_RESET}")
            print(f"\nInstall with: pip install psutil")

        print(f"\n{C_CYAN}{'═' * 70}{C_RESET}")
        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

    elif choice == "0":
        return

    else:
        print(f"\n{C_RED}Invalid choice{C_RESET}")
        time.sleep(1)

# ==============================================================================
#   BACKUP SYSTEM - FIXED
# ==============================================================================

def backup_service():
    """Enhanced backup with detailed information - FIXED"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ BACKUP CENTER ═══{C_RESET}\n")

    name = input("Service to Backup: ").strip()

    if not name:
        print_status("Service name cannot be empty", "error")
        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    svc = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)

    if not svc:
        print_status("Service not found", "error")

        all_services = db.query("SELECT name FROM services", fetch_all=True)
        if all_services:
            print(f"\n{C_CYAN}Available services:{C_RESET}")
            for s in all_services:
                print(f"  - {s['name']}")

        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    try:
        if not os.path.exists(BACKUP_DIR):
            print_status(f"Creating backup directory: {BACKUP_DIR}", "info")
            os.makedirs(BACKUP_DIR, exist_ok=True)
            try:
                shutil.chown(BACKUP_DIR, user=SERVICE_USER, group=SERVICE_GROUP)
                os.chmod(BACKUP_DIR, 0o755)
            except Exception as e:
                logger.warning(f"Could not set backup dir ownership: {e}")

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"{name}_{timestamp}"

        service_path = get_service_path(svc['storage_path'], name)

        if not os.path.exists(service_path):
            raise ValueError(f"Service path does not exist: {service_path}")

        backup_path = os.path.join(BACKUP_DIR, backup_filename)

        print(f"\n{C_YELLOW}{'=' * 70}{C_RESET}")
        print_status("Analyzing service data...", "info")

        total_size = 0
        file_count = 0

        try:
            for dirpath, dirnames, filenames in os.walk(service_path):
                dirnames[:] = [d for d in dirnames if d not in ['venv', '__pycache__', '.git']]

                for filename_iter in filenames:
                    filepath = os.path.join(dirpath, filename_iter)
                    try:
                        total_size += os.path.getsize(filepath)
                        file_count += 1
                    except Exception as e:
                        logger.debug(f"Could not stat file {filepath}: {e}")
        except Exception as e:
            logger.warning(f"Error calculating size: {e}")

        print(f"  {C_CYAN}└─ {file_count} files, {total_size / (1024 * 1024):.2f} MB{C_RESET}")

        print_status("Creating compressed archive...", "info")
        start_time = time.time()

        try:
            archive_base = shutil.make_archive(
                backup_path,
                'zip',
                service_path,
                logger=logger
            )
            compression_time = time.time() - start_time

            archive_file = archive_base

            if not os.path.exists(archive_file):
                raise FileNotFoundError(f"Archive was not created: {archive_file}")

        except Exception as e:
            raise RuntimeError(f"Archive creation failed: {e}")

        file_size = os.path.getsize(archive_file)
        compression_ratio = (1 - file_size / total_size) * 100 if total_size > 0 else 0

        print(f"  {C_CYAN}└─ Compressed in {compression_time:.2f}s ({compression_ratio:.1f}% reduction){C_RESET}")

        print_status("Calculating checksum...", "info")
        checksum = calculate_file_hash(archive_file)

        if checksum == "error":
            checksum = "checksum_failed"

        print(f"  {C_CYAN}└─ SHA256: {checksum[:32]}...{C_RESET}")

        db.query(
            "INSERT INTO backups (service_name, filename, size_bytes, checksum) VALUES (?, ?, ?, ?)",
            (name, os.path.basename(archive_file), file_size, checksum)
        )

        if PROMETHEUS_AVAILABLE:
            BACKUP_COUNTER.inc()

        audit_log("BACKUP", name, {
            "filename": os.path.basename(archive_file),
            "size_bytes": file_size,
            "file_count": file_count,
            "checksum": checksum[:16] if checksum != "checksum_failed" else "failed"
        })

        print(f"{C_YELLOW}{'=' * 70}{C_RESET}\n")

        print(f"{C_GREEN}{'=' * 70}{C_RESET}")
        print(f"{C_GREEN}{C_BOLD}✓ BACKUP CREATED SUCCESSFULLY{C_RESET}")
        print(f"{C_GREEN}{'=' * 70}{C_RESET}\n")

        print(f"{C_CYAN}Backup Details:{C_RESET}\n")
        print(f"  {C_BOLD}Service:{C_RESET}       {name}")
        print(f"  {C_BOLD}Filename:{C_RESET}      {os.path.basename(archive_file)}")
        print(f"  {C_BOLD}Location:{C_RESET}      {BACKUP_DIR}")
        print(f"  {C_BOLD}Full Path:{C_RESET}     {archive_file}")
        print(f"  {C_BOLD}Size:{C_RESET}          {file_size / (1024 * 1024):.2f} MB")
        print(f"  {C_BOLD}Files:{C_RESET}         {file_count}")
        print(f"  {C_BOLD}Compression:{C_RESET}   {compression_ratio:.1f}% reduction")
        print(f"  {C_BOLD}Time:{C_RESET}          {compression_time:.2f}s")
        print(f"  {C_BOLD}Checksum:{C_RESET}      {checksum[:32]}...")
        print(f"  {C_BOLD}Timestamp:{C_RESET}     {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        print(f"\n{C_GREEN}{'=' * 70}{C_RESET}\n")

        print_status(f"Backup saved to: {archive_file}", "success")

    except Exception as e:
        logger.error(f"Backup failed: {e}")
        print(f"\n{C_RED}{'=' * 70}{C_RESET}")
        print_status(f"Backup failed: {e}", "error")
        print(f"{C_RED}{'=' * 70}{C_RESET}\n")

        print(f"\n{C_YELLOW}Debug Information:{C_RESET}")
        print(f"  Service path: {service_path if 'service_path' in locals() else 'N/A'}")
        print(f"  Backup dir: {BACKUP_DIR}")
        print(f"  Backup dir exists: {os.path.exists(BACKUP_DIR)}")
        print(f"  Backup dir writable: {os.access(BACKUP_DIR, os.W_OK) if os.path.exists(BACKUP_DIR) else 'N/A'}")

    input(f"\n{C_CYAN}Press Enter to return to main menu...{C_RESET}")


def list_backups():
    """List all backups with detailed information - FIXED"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ BACKUP HISTORY ═══{C_RESET}\n")

    try:
        backups = db.query(
            "SELECT * FROM backups ORDER BY timestamp DESC LIMIT 50",
            fetch_all=True
        )
    except Exception as e:
        print_status(f"Database error: {e}", "error")
        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    if not backups:
        print_status("No backups found", "warning")
        print(f"\n{C_CYAN}Use option [6] to create your first backup.{C_RESET}")
        print(f"\n{C_YELLOW}Backup directory: {BACKUP_DIR}{C_RESET}")

        if os.path.exists(BACKUP_DIR):
            try:
                files = [f for f in os.listdir(BACKUP_DIR) if f.endswith('.zip')]
                if files:
                    print(f"\n{C_CYAN}Files found in backup directory (not in database):{C_RESET}")
                    for f in sorted(files)[:10]:
                        size = os.path.getsize(os.path.join(BACKUP_DIR, f)) / (1024 * 1024)
                        print(f"  - {f} ({size:.2f} MB)")
            except Exception as e:
                print(f"\n{C_RED}Error reading backup directory: {e}{C_RESET}")
        else:
            print(f"\n{C_YELLOW}Backup directory does not exist yet.{C_RESET}")

        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    print(f"{C_CYAN}Total Backups: {C_BOLD}{len(backups)}{C_RESET}\n")

    total_size = sum(b['size_bytes'] or 0 for b in backups)
    print(f"{C_CYAN}Total Storage Used: {C_BOLD}{total_size / (1024 ** 3):.2f} GB{C_RESET}\n")

    print(f"{C_BOLD}{'#':<4} {'SERVICE':<15} {'SIZE':<12} {'DATE':<20} {'STATUS'}{C_RESET}")
    print(f"{C_CYAN}{'─' * 80}{C_RESET}")

    for idx, backup in enumerate(backups, 1):
        size_mb = backup['size_bytes'] / (1024 * 1024) if backup['size_bytes'] else 0
        timestamp = backup['timestamp'][:19] if backup['timestamp'] else "Unknown"

        backup_file = os.path.join(BACKUP_DIR, backup['filename'])
        exists = os.path.exists(backup_file)
        status = f"{C_GREEN}✓ EXISTS{C_RESET}" if exists else f"{C_RED}✗ MISSING{C_RESET}"

        print(f"{idx:<4} {backup['service_name']:<15} {size_mb:>8.2f} MB  {timestamp:<20} {status}")

    print(f"{C_CYAN}{'─' * 80}{C_RESET}\n")

    print(f"{C_CYAN}Backup Location:{C_RESET} {BACKUP_DIR}\n")

    if os.path.exists(BACKUP_DIR):
        try:
            backup_files = [f for f in os.listdir(BACKUP_DIR) if f.endswith('.zip')]
            actual_size = sum(os.path.getsize(os.path.join(BACKUP_DIR, f)) for f in backup_files) / (1024 ** 3)
            print(f"{C_CYAN}Actual disk usage:{C_RESET} {actual_size:.2f} GB ({len(backup_files)} files)\n")
        except Exception as e:
            logger.debug(f"Could not calculate disk usage: {e}")

    input(f"{C_CYAN}Press Enter to return to main menu...{C_RESET}")


# ==============================================================================
#   DEPLOYMENT HISTORY - FIXED (was missing)
# ==============================================================================

def view_deployment_history():
    """View deployment history with detailed information - FIXED"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ DEPLOYMENT HISTORY ═══{C_RESET}\n")

    deployments = db.query(
        "SELECT * FROM deployments ORDER BY timestamp DESC LIMIT 30",
        fetch_all=True
    )

    if not deployments:
        print_status("No deployment history", "warning")
        print(f"\n{C_CYAN}Deployment history will appear here after your first deployment.{C_RESET}\n")
        input(f"{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    total = len(deployments)
    successful = sum(1 for d in deployments if d['status'] == 'success')
    failed = total - successful
    success_rate = (successful / total * 100) if total > 0 else 0
    avg_duration = sum(d['duration_seconds'] or 0 for d in deployments) / total if total > 0 else 0

    print(f"{C_CYAN}Statistics:{C_RESET}\n")
    print(f"  {C_BOLD}Total Deployments:{C_RESET}  {total}")
    print(f"  {C_BOLD}Successful:{C_RESET}         {C_GREEN}{successful}{C_RESET}")
    print(f"  {C_BOLD}Failed:{C_RESET}             {C_RED}{failed}{C_RESET}")
    print(f"  {C_BOLD}Success Rate:{C_RESET}       {success_rate:.1f}%")
    print(f"  {C_BOLD}Avg Duration:{C_RESET}       {avg_duration:.2f}s")
    print()

    print(f"{C_BOLD}{'#':<4} {'SERVICE':<15} {'STATUS':<12} {'DURATION':<12} {'TIMESTAMP'}{C_RESET}")
    print(f"{C_CYAN}{'─' * 80}{C_RESET}")

    for idx, dep in enumerate(deployments, 1):
        if dep['status'] == 'success':
            status_str = f"{C_GREEN}✓ SUCCESS{C_RESET}"
        else:
            status_str = f"{C_RED}✗ FAILED{C_RESET}"

        duration = f"{dep['duration_seconds']:.2f}s" if dep['duration_seconds'] else "N/A"
        timestamp = dep['timestamp'][:19]

        print(f"{idx:<4} {dep['service_name']:<15} {status_str:<20} {duration:<12} {timestamp}")

        if dep['error_message']:
            error_short = dep['error_message'][:60]
            print(f"     {C_YELLOW}└─ Error: {error_short}...{C_RESET}")

    print(f"{C_CYAN}{'─' * 80}{C_RESET}\n")

    input(f"{C_CYAN}Press Enter to return to main menu...{C_RESET}")


# ==============================================================================
#   METRICS EXPORT - FIXED
# ==============================================================================

def export_metrics():
    """Export Prometheus metrics with feedback - FIXED"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ METRICS EXPORT ═══{C_RESET}\n")

    if not PROMETHEUS_AVAILABLE:
        print_status("Prometheus client not installed", "error")
        print(f"\n{C_YELLOW}Install with: pip install prometheus-client{C_RESET}")
        print(f"\n{C_CYAN}Run:{C_RESET}")
        print(f"  sudo pip3 install prometheus-client")
        print(f"\nOr in a virtual environment:")
        print(f"  pip install prometheus-client")
        input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
        return

    try:
        print_status("Collecting service metrics...", "info")

        services = db.query("SELECT * FROM services", fetch_all=True)

        if not services:
            print_status("No services found", "warning")
            input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")
            return

        metrics_count = 0
        online_count = 0
        offline_count = 0

        for svc in services:
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", svc['name']],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=5
                )
                is_active = result.stdout.strip() == b"active"

                SERVICE_STATUS.labels(service=svc['name']).set(1 if is_active else 0)
                metrics_count += 1

                if is_active:
                    online_count += 1
                else:
                    offline_count += 1

            except Exception as e:
                logger.debug(f"Could not check service {svc['name']}: {e}")
                SERVICE_STATUS.labels(service=svc['name']).set(0)
                offline_count += 1

        print(f"  {C_CYAN}└─ {metrics_count} service metrics collected{C_RESET}")
        print(f"     {C_GREEN}▶ {online_count} online{C_RESET}")
        print(f"     {C_RED}▶ {offline_count} offline{C_RESET}")

        if psutil:
            print_status("Collecting system metrics...", "info")
            try:
                cpu_percent = psutil.cpu_percent(interval=0.5)
                mem = psutil.virtual_memory()
                disk = psutil.disk_usage('/')

                print(
                    f"  {C_CYAN}└─ CPU: {cpu_percent:.1f}%, Memory: {mem.percent:.1f}%, Disk: {disk.percent:.1f}%{C_RESET}")
            except Exception as e:
                logger.debug(f"Could not collect system metrics: {e}")

        print_status("Writing metrics to file...", "info")

        if not os.path.exists(ATS_HOME):
            os.makedirs(ATS_HOME, exist_ok=True)
            os.chmod(ATS_HOME, 0o755)

        try:
            metrics_data = generate_latest(REGISTRY)

            with open(METRICS_FILE, 'wb') as f:
                f.write(metrics_data)

            try:
                os.chmod(METRICS_FILE, 0o644)
            except:
                pass

            file_size = os.path.getsize(METRICS_FILE)

            print(f"  {C_CYAN}└─ {file_size} bytes written{C_RESET}")

        except Exception as e:
            raise RuntimeError(f"Failed to write metrics file: {e}")

        print(f"\n{C_GREEN}{'=' * 70}{C_RESET}")
        print(f"{C_GREEN}{C_BOLD}✓ METRICS EXPORTED SUCCESSFULLY{C_RESET}")
        print(f"{C_GREEN}{'=' * 70}{C_RESET}\n")

        print(f"{C_CYAN}Export Details:{C_RESET}\n")
        print(f"  {C_BOLD}File:{C_RESET}          {METRICS_FILE}")
        print(f"  {C_BOLD}Size:{C_RESET}          {file_size} bytes")
        print(f"  {C_BOLD}Services:{C_RESET}      {metrics_count} total")
        print(f"  {C_BOLD}Online:{C_RESET}        {online_count}")
        print(f"  {C_BOLD}Offline:{C_RESET}       {offline_count}")
        print(f"  {C_BOLD}Timestamp:{C_RESET}     {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        print(f"\n{C_CYAN}Usage:{C_RESET}")
        print(f"  Use Prometheus node_exporter textfile collector")
        print(f"  Or configure HTTP endpoint to serve this file")
        print(f"\n{C_CYAN}View metrics:{C_RESET}")
        print(f"  cat {METRICS_FILE}")

        print(f"\n{C_GREEN}{'=' * 70}{C_RESET}\n")

        print(f"{C_CYAN}Metrics Preview:{C_RESET}\n")
        try:
            with open(METRICS_FILE, 'r') as f:
                lines = f.readlines()
                for line in lines[:15]:
                    if line.strip() and not line.startswith('#'):
                        print(f"  {line.rstrip()}")
                if len(lines) > 15:
                    print(f"  ... ({len(lines) - 15} more lines)")
        except Exception as e:
            logger.debug(f"Could not preview metrics: {e}")

        logger.info("Prometheus metrics exported")

    except Exception as e:
        logger.error(f"Metrics export failed: {e}")
        print(f"\n{C_RED}{'=' * 70}{C_RESET}")
        print_status(f"Metrics export failed: {e}", "error")
        print(f"{C_RED}{'=' * 70}{C_RESET}\n")

        print(f"\n{C_YELLOW}Debug Information:{C_RESET}")
        print(f"  Prometheus available: {PROMETHEUS_AVAILABLE}")
        print(f"  ATS Home: {ATS_HOME}")
        print(f"  ATS Home exists: {os.path.exists(ATS_HOME)}")
        print(f"  Metrics file: {METRICS_FILE}")
        print(f"  Can write to ATS Home: {os.access(ATS_HOME, os.W_OK) if os.path.exists(ATS_HOME) else 'N/A'}")

    input(f"\n{C_CYAN}Press Enter to return to main menu...{C_RESET}")


# ==============================================================================
#   DIAGNOSTICS - FIXED
# ==============================================================================

async def run_diagnostics():
    """Comprehensive system diagnostics - FIXED"""
    print_header()
    print(f"{C_YELLOW}{C_BOLD}═══ ATS SYSTEM DIAGNOSTICS ═══{C_RESET}\n")

    checks = []

    print_status("Running diagnostic checks...", "info")
    print()

    # Root Access
    root_ok = os.geteuid() == 0
    checks.append(("Root Access", root_ok))
    print(f"{'Root Access':<30} {C_GREEN + '✓ PASS' + C_RESET if root_ok else C_RED + '✗ FAIL' + C_RESET}")

    # Database
    db_ok = os.path.exists(DB_FILE) and os.access(DB_FILE, os.W_OK)
    checks.append(("Database", db_ok))
    print(f"{'Database Access':<30} {C_GREEN + '✓ PASS' + C_RESET if db_ok else C_RED + '✗ FAIL' + C_RESET}")

    # Cloudflare Config
    cf_ok = os.path.exists(CLOUDFLARE_CONFIG)
    checks.append(("Cloudflare Config", cf_ok))
    print(f"{'Cloudflare Configuration':<30} {C_GREEN + '✓ PASS' + C_RESET if cf_ok else C_RED + '✗ FAIL' + C_RESET}")

    # Cloudflare Service
    result = subprocess.run(["systemctl", "is-active", "cloudflared"], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    cf_svc_ok = result.stdout.strip() == b"active"
    checks.append(("Cloudflare Service", cf_svc_ok))
    print(f"{'Cloudflare Service':<30} {C_GREEN + '✓ PASS' + C_RESET if cf_svc_ok else C_RED + '✗ FAIL' + C_RESET}")

    # Internet Connectivity
    inet_ok = subprocess.call(["ping", "-c", "1", "-W", "2", "1.1.1.1"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    checks.append(("Internet", inet_ok))
    print(f"{'Internet Connectivity':<30} {C_GREEN + '✓ PASS' + C_RESET if inet_ok else C_RED + '✗ FAIL' + C_RESET}")

    # Default Storage
    storage_ok = os.path.exists(DEFAULT_STORAGE) and os.access(DEFAULT_STORAGE, os.W_OK)
    checks.append(("Default Storage", storage_ok))
    print(f"{'Default Storage':<30} {C_GREEN + '✓ PASS' + C_RESET if storage_ok else C_RED + '✗ FAIL' + C_RESET}")

    # Python Dependencies - FIXED
    deps_ok = True
    missing_deps = []
    for module in ['yaml', 'psutil']:
        try:
            __import__(module)
        except:
            deps_ok = False
            missing_deps.append(module)
    checks.append(("Python Dependencies", deps_ok))
    status_str = C_GREEN + "✓ PASS" + C_RESET if deps_ok else C_RED + "✗ FAIL" + C_RESET
    print(f"{'Python Dependencies':<30} {status_str}", end='')
    if not deps_ok:
        print(f" {C_YELLOW}(missing: {', '.join(missing_deps)}){C_RESET}")
    else:
        print()

    # Storage Details
    print(f"\n{C_CYAN}Storage Analysis:{C_RESET}\n")

    if os.path.exists(DEFAULT_STORAGE):
        try:
            if psutil:
                disk_usage = psutil.disk_usage(DEFAULT_STORAGE)
                total_gb = disk_usage.total / (1024 ** 3)
                used_gb = disk_usage.used / (1024 ** 3)
                free_gb = disk_usage.free / (1024 ** 3)
                percent_used = disk_usage.percent

                print(f"  {C_BOLD}Path:{C_RESET}         {DEFAULT_STORAGE}")
                print(f"  {C_BOLD}Total:{C_RESET}        {total_gb:.2f} GB")
                print(f"  {C_BOLD}Used:{C_RESET}         {used_gb:.2f} GB ({percent_used:.1f}%)")
                print(f"  {C_BOLD}Available:{C_RESET}    {free_gb:.2f} GB")

                if percent_used > 90:
                    status_color = C_RED
                    status_msg = "CRITICAL"
                elif percent_used > 75:
                    status_color = C_YELLOW
                    status_msg = "WARNING"
                else:
                    status_color = C_GREEN
                    status_msg = "HEALTHY"

                print(f"  {C_BOLD}Status:{C_RESET}       {status_color}{status_msg}{C_RESET}")
            else:
                stat = os.statvfs(DEFAULT_STORAGE)
                total_gb = (stat.f_blocks * stat.f_frsize) / (1024 ** 3)
                free_gb = (stat.f_bavail * stat.f_frsize) / (1024 ** 3)
                used_gb = total_gb - free_gb
                percent_used = (used_gb / total_gb) * 100

                print(f"  {C_BOLD}Path:{C_RESET}         {DEFAULT_STORAGE}")
                print(f"  {C_BOLD}Total:{C_RESET}        {total_gb:.2f} GB")
                print(f"  {C_BOLD}Used:{C_RESET}         {used_gb:.2f} GB ({percent_used:.1f}%)")
                print(f"  {C_BOLD}Available:{C_RESET}    {free_gb:.2f} GB")

            print(f"\n  {C_CYAN}Directory Structure:{C_RESET}")
            try:
                subdirs = ['api', 'database', 'backups', 'websites']
                for subdir in subdirs:
                    subdir_path = os.path.join(DEFAULT_STORAGE, subdir)
                    if os.path.exists(subdir_path):
                        try:
                            item_count = len(os.listdir(subdir_path))
                            print(f"    /{subdir:<12} {C_GREEN}✓{C_RESET} ({item_count} items)")
                        except:
                            print(f"    /{subdir:<12} {C_GREEN}✓{C_RESET}")
                    else:
                        print(f"    /{subdir:<12} {C_YELLOW}✗ Not created{C_RESET}")
            except Exception as e:
                logger.debug(f"Could not list subdirectories: {e}")

            print(f"\n  {C_CYAN}Top Space Consumers:{C_RESET}")
            try:
                subdirs = ['api', 'database', 'backups']
                dir_sizes = []

                for subdir in subdirs:
                    subdir_path = os.path.join(DEFAULT_STORAGE, subdir)
                    if os.path.exists(subdir_path):
                        total_size = 0
                        for dirpath, dirnames, filenames in os.walk(subdir_path):
                            for filename in filenames:
                                filepath = os.path.join(dirpath, filename)
                                try:
                                    total_size += os.path.getsize(filepath)
                                except:
                                    pass
                        if total_size > 0:
                            dir_sizes.append((subdir, total_size))

                dir_sizes.sort(key=lambda x: x[1], reverse=True)

                for subdir, size in dir_sizes[:5]:
                    size_gb = size / (1024 ** 3)
                    if size_gb > 1:
                        print(f"    {subdir:<12} {size_gb:.2f} GB")
                    else:
                        size_mb = size / (1024 ** 2)
                        print(f"    {subdir:<12} {size_mb:.2f} MB")

                if not dir_sizes:
                    print(f"    {C_YELLOW}No data yet{C_RESET}")

            except Exception as e:
                logger.debug(f"Could not calculate directory sizes: {e}")
                print(f"    {C_YELLOW}Could not analyze space usage{C_RESET}")

        except Exception as e:
            print(f"  {C_RED}Error analyzing storage: {e}{C_RESET}")
    else:
        print(f"  {C_RED}Storage path does not exist: {DEFAULT_STORAGE}{C_RESET}")

    # Service Health Checks
    print(f"\n{C_CYAN}Service Health Checks:{C_RESET}\n")
    services = db.query("SELECT * FROM services", fetch_all=True)

    if services:
        health_results = await parallel_health_checks(services)

        healthy_count = 0
        unhealthy_count = 0

        for svc in services:
            is_healthy = health_results.get(svc['name'], False)
            status_str = C_GREEN + "HEALTHY" + C_RESET if is_healthy else C_RED + "UNHEALTHY" + C_RESET

            port_info = f"(port {svc['port']})"
            print(f"  {svc['name']:<20} {status_str:<20} {C_CYAN}{port_info}{C_RESET}")

            if is_healthy:
                healthy_count += 1
            else:
                unhealthy_count += 1

        print(
            f"\n  {C_BOLD}Summary:{C_RESET} {C_GREEN}{healthy_count} healthy{C_RESET}, {C_RED}{unhealthy_count} unhealthy{C_RESET}")
    else:
        print("  No services deployed")

    # System Resources
    print(f"\n{C_CYAN}System Resources:{C_RESET}\n")
    if psutil:
        cpu_percent = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        cpu_color = C_RED if cpu_percent > 80 else C_YELLOW if cpu_percent > 60 else C_GREEN
        print(f"  {C_BOLD}CPU Usage:{C_RESET}    {cpu_color}{cpu_percent:.1f}%{C_RESET}")

        mem_color = C_RED if mem.percent > 90 else C_YELLOW if mem.percent > 75 else C_GREEN
        print(
            f"  {C_BOLD}Memory:{C_RESET}       {mem.used / (1024 ** 3):.1f} GB / {mem.total / (1024 ** 3):.1f} GB ({mem_color}{mem.percent:.1f}%{C_RESET})")

        disk_color = C_RED if disk.percent > 90 else C_YELLOW if disk.percent > 75 else C_GREEN
        print(
            f"  {C_BOLD}Root Disk:{C_RESET}    {disk.used / (1024 ** 3):.1f} GB / {disk.total / (1024 ** 3):.1f} GB ({disk_color}{disk.percent:.1f}%{C_RESET})")

        print(f"\n  {C_BOLD}System Info:{C_RESET}")
        try:
            boot_time = datetime.datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.datetime.now() - boot_time
            uptime_str = f"{uptime.days}d {uptime.seconds // 3600}h {(uptime.seconds // 60) % 60}m"
            print(f"    Uptime:        {uptime_str}")
            print(f"    Boot Time:     {boot_time.strftime('%Y-%m-%d %H:%M:%S')}")
        except:
            pass

        try:
            cpu_count = psutil.cpu_count(logical=False)
            cpu_count_logical = psutil.cpu_count(logical=True)
            print(f"    CPU Cores:     {cpu_count} physical, {cpu_count_logical} logical")
        except:
            pass

    else:
        print(f"  {C_YELLOW}psutil not available - install for detailed metrics{C_RESET}")
        print(f"\n  Install with: {C_CYAN}pip install psutil{C_RESET}")

    # Summary
    passed = sum(1 for _, ok in checks if ok)
    total = len(checks)

    print(f"\n{C_CYAN}{'=' * 70}{C_RESET}")
    if passed == total:
        print(f"{C_GREEN}{C_BOLD}✓ ALL CHECKS PASSED ({passed}/{total}){C_RESET}")
    else:
        print(f"{C_YELLOW}{C_BOLD}⚠ {passed}/{total} CHECKS PASSED{C_RESET}")

        failed = [name for name, ok in checks if not ok]
        if failed:
            print(f"\n{C_RED}Failed checks:{C_RESET}")
            for check in failed:
                print(f"  - {check}")

    print(f"{C_CYAN}{'=' * 70}{C_RESET}\n")

    input(f"{C_CYAN}Press Enter to continue...{C_RESET}")


def ats_doctor():
    """Wrapper for async diagnostics"""
    asyncio.run(run_diagnostics())


# ==============================================================================
#   TELEMETRY
# ==============================================================================

async def get_telemetry_async() -> Tuple[float, str, str, int]:
    """Get system telemetry asynchronously"""
    if not psutil:
        return 0.0, "N/A", "N/A", 0

    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    services = db.query("SELECT * FROM services WHERE status='active'", fetch_all=True)
    active_count = len(services) if services else 0

    ram_str = f"{mem.used / (1024 ** 3):.1f}/{mem.total / (1024 ** 3):.1f}GB"
    disk_str = f"{disk.used / (1024 ** 3):.0f}/{disk.total / (1024 ** 3):.0f}GB"

    return cpu, ram_str, disk_str, active_count


# ==============================================================================
#   MAIN MENU
# ==============================================================================

def main_menu():
    """Main interactive menu"""
    while True:
        try:
            print_header()

            cpu, ram, disk, svc_count = asyncio.run(get_telemetry_async())
            print(f"{C_CYAN}┌{'─' * 68}┐{C_RESET}")
            print(f"{C_CYAN}│{C_RESET} {C_BOLD}System:{C_RESET} CPU {cpu:.1f}%  │  RAM {ram}  │  Disk {disk}  │  Services {svc_count} {C_CYAN}│{C_RESET}")
            print(f"{C_CYAN}└{'─' * 68}┘{C_RESET}\n")

            services = db.query("SELECT * FROM services ORDER BY name", fetch_all=True)

            print(f"{C_BOLD}{'NAME':<15} {'PORT':<8} {'STATUS':<12} {'DOMAIN'}{C_RESET}")
            print(f"{C_CYAN}{'─' * 70}{C_RESET}")

            if services:
                health_results = asyncio.run(parallel_health_checks(services))

                for svc in services:
                    is_healthy = health_results.get(svc['name'], False)

                    if is_healthy:
                        status_str = f"{C_GREEN}●{C_RESET} ONLINE"
                    else:
                        status_str = f"{C_RED}●{C_RESET} OFFLINE"

                    print(f"{svc['name']:<15} {svc['port']:<8} {status_str:<20} {svc['domain']}")
            else:
                print(f"{C_YELLOW}No services deployed{C_RESET}")

            print(f"{C_CYAN}{'─' * 70}{C_RESET}\n")

            print(f"{C_CYAN}┌─ DEPLOYMENT ────────────────┬─ MANAGEMENT ──────────────┐{C_RESET}")
            print(
                f"{C_CYAN}│{C_RESET} [1] Deploy Service          {C_CYAN}│{C_RESET} [5] Service Operations     {C_CYAN}│{C_RESET}")
            print(
                f"{C_CYAN}│{C_RESET} [2] List Services           {C_CYAN}│{C_RESET} [6] Backup Service         {C_CYAN}│{C_RESET}")
            print(
                f"{C_CYAN}│{C_RESET} [3] Destroy Service         {C_CYAN}│{C_RESET} [7] List Backups           {C_CYAN}│{C_RESET}")
            print(
                f"{C_CYAN}│{C_RESET} [4] View Logs               {C_CYAN}│{C_RESET} [8] Export Metrics         {C_CYAN}│{C_RESET}")
            print(f"{C_CYAN}└─────────────────────────────┴───────────────────────────┘{C_RESET}")
            print(
                f"{C_CYAN}│{C_RESET} [9] Deployment History      {C_CYAN}│{C_RESET} [D] System Diagnostics     {C_CYAN}│{C_RESET}")
            print(f"{C_CYAN}└─────────────────────────────┴───────────────────────────┘{C_RESET}")
            print(f"  {C_RED}[0] Exit{C_RESET}")

            choice = input(f"\n{C_CYAN}{C_BOLD}ATS>{C_RESET} ").strip().lower()

            if choice == "1":
                deploy_service()
            elif choice == "2":
                list_services_detailed()
            elif choice == "3":
                destroy_service()
            elif choice == "4":
                view_service_logs()
            elif choice == "5":
                service_operations()
            elif choice == "6":
                backup_service()
            elif choice == "7":
                list_backups()
            elif choice == "8":
                export_metrics()
            elif choice == "9":
                view_deployment_history()
            elif choice == "d":
                ats_doctor()
            elif choice == "0":
                print(f"\n{C_CYAN}{'═' * 70}{C_RESET}")
                print(f"{C_CYAN}Thank you for using ATS v7.0!{C_RESET}")
                print(f"{C_CYAN}{'═' * 70}{C_RESET}\n")
                sys.exit(0)
            else:
                print_status("Invalid choice", "warning")
                time.sleep(1)

        except KeyboardInterrupt:
            print(f"\n\n{C_YELLOW}Use option [0] to exit properly.{C_RESET}\n")
            time.sleep(1)
        except Exception as e:
            logger.error(f"Menu error: {e}")
            print_status(f"Error: {e}", "error")
            time.sleep(2)


# ==============================================================================
#   ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{C_RED}ERROR: ATS requires root privileges.{C_RESET}")
        print(f"Run: sudo python3 {sys.argv[0]}")
        sys.exit(1)

    if not os.path.exists(ATS_HOME):
        os.makedirs(ATS_HOME, exist_ok=True)
        os.chmod(ATS_HOME, 0o700)

    lock = acquire_lock()

    print_header()
    print(f"{C_GREEN}Initializing ATS v7.0...{C_RESET}\n")
    time.sleep(0.5)

    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n\n{C_CYAN}Shutting down ATS...{C_RESET}\n")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Critical error: {e}")
        print(f"\n{C_RED}CRITICAL ERROR: {e}{C_RESET}\n")
        sys.exit(1)
