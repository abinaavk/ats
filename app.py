#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATS | AUTOMATED TECH STACK | v7.0
Architect: Abinaav K
Status: PRODUCTION - DEBUGGED
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
       _/_/    _/_/_/_/_/    _/_/_/   
    _/    _/      _/      _/          
   _/_/_/_/      _/        _/_/       
  _/    _/      _/            _/      
 _/    _/      _/      _/_/_/         
                                      
    AUTOMATED TECH STACK v7.0
    """ + f"{C_RESET}")
    print(f"{C_CYAN}{'='*70}{C_RESET}")

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
    """Enhanced audit logging with structured data"""
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "action": action,
        "target": target,
        "user": os.getlogin(),
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
#   PORT AND SERVICE CHECKING - FIXED [web:31][web:36][web:39]
# ==============================================================================

def check_port_listening(port: int, timeout: float = 1.0) -> bool:
    """
    Check if a port is listening using direct socket connection [web:31][web:36][web:39]
    More reliable than curl for checking if service is up
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result == 0
    except socket.error:
        return False
    finally:
        try:
            sock.close()
        except:
            pass

def check_systemd_active(service_name: str) -> bool:
    """Check if systemd service is active [web:37][web:40]"""
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
    """Get service PID using systemctl [web:37][web:40]"""
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

# ==============================================================================
#   ASYNC UTILITIES - FIXED
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

def check_service_health(service_name: str, port: int) -> bool:
    """
    Synchronous health check - more reliable [web:31][web:36]
    Checks both systemd status and port listening
    """
    # First check if systemd thinks it's active
    if not check_systemd_active(service_name):
        return False
    
    # Then check if port is actually listening
    return check_port_listening(port, timeout=2.0)

async def check_single_service_health_async(svc: Dict) -> Tuple[str, bool]:
    """Async wrapper for health check"""
    try:
        # Run sync function in executor to avoid blocking
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
            # Handle exceptions
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
        atexit.register(lambda: fcntl.flock(lock_fd, fcntl.LOCK_UN))
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
    """Get service directory path"""
    legacy = os.path.join(storage, "websites", name)
    if os.path.exists(legacy): 
        return legacy
    return os.path.join(storage, "api", name)

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
#   SYSTEMD SERVICE GENERATION
# ==============================================================================

def generate_systemd_service(config: ServiceConfig, api_dir: str, log_dir: str, db_dir: str) -> str:
    """Generate enhanced systemd service file with security hardening"""
    
    content = f"""[Unit]
Description={config.name} API [ATS v7.0 MANAGED]
After=network-online.target
Wants=network-online.target
Documentation=https://gaiasentinel.online/docs/{config.name}

[Service]
Type=notify
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

# Watchdog
WatchdogSec=30

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
#   HEALTH CHECKING - SIMPLIFIED AND FIXED
# ==============================================================================

def health_check_deployment(name: str, port: int, max_retries: int = 5) -> bool:
    """
    Synchronous health check for deployment - more reliable [web:31][web:36]
    """
    for attempt in range(max_retries):
        print_status(f"Health check attempt {attempt + 1}/{max_retries}...", "info")
        
        # Check systemd status
        if not check_systemd_active(name):
            print(f"  {C_YELLOW}└─ Service not active in systemd{C_RESET}")
            time.sleep(2)
            continue
        
        # Check port listening
        if check_port_listening(port, timeout=2.0):
            print_status("Health check PASSED", "success")
            return True
        
        print(f"  {C_YELLOW}└─ Port {port} not responding{C_RESET}")
        
        if attempt < max_retries - 1:
            time.sleep(2)
    
    print_status("Health check FAILED", "error")
    return False

# ==============================================================================
#   DEPLOYMENT ENGINE - FIXED
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
        # ===== INTERACTIVE INPUT =====
        name = input(f"{C_BOLD}Service Name (alphanumeric):{C_RESET} ").strip()
        if not re.match(r"^[a-zA-Z0-9_-]+$", name): 
            raise ValueError("Invalid service name format")
        if db.query("SELECT 1 FROM services WHERE name=?", (name,), fetch_one=True):
            raise ValueError(f"Service '{name}' already exists")
        
        storage = validate_storage(
            input(f"{C_BOLD}Storage Path [{DEFAULT_STORAGE}]:{C_RESET} ").strip() or DEFAULT_STORAGE
        )
        
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
        
        config = ServiceConfig(
            name=name,
            port=port,
            domain=domain,
            storage_path=storage,
            repo_url=repo_url,
            workers=workers,
            max_memory_mb=max_memory,
            cpu_quota=cpu_quota
        )
        
        # ===== PROVISIONING =====
        print(f"\n{C_GREEN}{'='*70}{C_RESET}")
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
        
        # ===== GIT CLONE =====
        print_status("CLONING REPOSITORY", "info")
        returncode, stdout, stderr = await run_async_command(
            ["sudo", "-u", SERVICE_USER, "git", "clone", repo_url, "."],
            cwd=api_dir,
            timeout=300
        )
        if returncode != 0:
            raise RuntimeError(f"Git clone failed: {stderr}")
        print_status("Repository cloned successfully", "success")
        
        # ===== VIRTUAL ENVIRONMENT =====
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
        
        # ===== SYSTEMD SERVICE =====
        print_status("GENERATING SYSTEMD SERVICE", "info")
        service_content = generate_systemd_service(config, api_dir, log_dir, db_dir)
        
        with open(svc_file, 'w') as f:
            f.write(service_content)
        os.chmod(svc_file, 0o644)
        
        run_root(["systemctl", "daemon-reload"])
        run_root(["systemctl", "enable", name])
        run_root(["systemctl", "start", name])
        
        print_status(f"Service {name}.service created and started", "success")
        
        # ===== HEALTH CHECK =====
        print(f"\n{C_YELLOW}{'='*70}{C_RESET}")
        print_status("RUNNING HEALTH CHECKS", "info")
        time.sleep(3)
        
        health_ok = health_check_deployment(name, port)
        
        if not health_ok:
            raise RuntimeError("Service failed health checks")
        
        # ===== CLOUDFLARE TUNNEL =====
        print_status("CONFIGURING CLOUDFLARE TUNNEL", "info")
        cloudflare.add_route(domain, port)
        print_status(f"Route added: {domain} -> localhost:{port}", "success")
        
        # ===== DATABASE RECORD =====
        deployment_hash = calculate_file_hash(requirements_file) if os.path.exists(requirements_file) else "none"
        
        db.query(
            """INSERT INTO services 
            (name, port, domain, storage_path, repo_url, workers, max_memory_mb, cpu_quota, deployment_hash) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, port, domain, storage, repo_url, config.workers, max_memory, cpu_quota, deployment_hash)
        )
        
        duration = time.time() - start_time
        db.query(
            "INSERT INTO deployments (service_name, status, duration_seconds) VALUES (?, ?, ?)",
            (name, "success", duration)
        )
        
        # ===== METRICS =====
        if PROMETHEUS_AVAILABLE:
            DEPLOY_COUNTER.labels(status='success').inc()
            DEPLOY_DURATION.observe(duration)
        
        audit_log("DEPLOY_SUCCESS", name, {
            "domain": domain,
            "port": port,
            "duration": duration,
            "workers": config.workers
        })
        
        # ===== SUCCESS =====
        print(f"\n{C_GREEN}{'='*70}{C_RESET}")
        print(f"{C_GREEN}{C_BOLD}✓ DEPLOYMENT SUCCESSFUL{C_RESET}")
        print(f"\n{C_CYAN}Service Details:{C_RESET}")
        print(f"  Name:       {C_BOLD}{name}{C_RESET}")
        print(f"  Domain:     {C_BOLD}https://{domain}{C_RESET}")
        print(f"  Port:       {C_BOLD}{port}{C_RESET}")
        print(f"  Workers:    {C_BOLD}{config.workers}{C_RESET}")
        print(f"  Memory:     {C_BOLD}{max_memory}MB{C_RESET}")
        print(f"  CPU Quota:  {C_BOLD}{cpu_quota}%{C_RESET}")
        print(f"  Duration:   {C_BOLD}{duration:.2f}s{C_RESET}")
        print(f"{C_GREEN}{'='*70}{C_RESET}\n")
        
    except Exception as e:
        logger.error(f"Deployment failed: {e}")
        print(f"\n{C_RED}{'='*70}{C_RESET}")
        print_status(f"DEPLOYMENT FAILED: {e}", "error")
        print(f"{C_RED}{'='*70}{C_RESET}\n")
        
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
            db.query(
                "INSERT INTO deployments (service_name, status, duration_seconds, error_message) VALUES (?, ?, ?, ?)",
                (name, "failed", duration, str(e))
            )
        
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
        
        print(f"{C_CYAN}┌─ SERVICE #{idx} {'─'*55}{C_RESET}")
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
            print(f"{C_CYAN}│{C_RESET} {C_BOLD}Deployments:{C_RESET}   {deploy_stats['total']} ({success_rate:.0f}% success)")
        
        backup_count = db.query(
            "SELECT COUNT(*) as count FROM backups WHERE service_name=?",
            (svc['name'],),
            fetch_one=True
        )
        if backup_count:
            print(f"{C_CYAN}│{C_RESET} {C_BOLD}Backups:{C_RESET}       {backup_count['count']}")
        
        print(f"{C_CYAN}└{'─'*68}{C_RESET}\n")
    
    input(f"{C_CYAN}Press Enter to return to main menu...{C_RESET}")

# Continue with rest of the functions...
# [Due to length limits, I'll provide the remaining essential functions in the next part]
# The key fixes are:
# 1. Proper port checking using socket.connect_ex()
# 2. Systemd status checking
# 3. Fixed async/await handling
# 4. Better error handling
