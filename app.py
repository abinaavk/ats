#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATS | AUTOMATED TECH STACK | v7.0
Architect: Abinaav K
Status: PRODUCTION
Improvements: Async ops, Prometheus metrics, Watchdog, Enhanced security
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
import platform
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
    print("WARNING: prometheus_client not installed. Metrics disabled.")

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
            # Log critical events to separate security log
            try:
                with open(os.path.join(ATS_HOME, "security.log"), "a") as f:
                    f.write(f"{self.format(record)}\n")
            except: pass

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
#   DATABASE ENGINE WITH CONNECTION POOLING
# ==============================================================================

class DatabaseManager:
    """Thread-safe database manager with connection pooling"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Initialize database with enhanced schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Enhanced services table
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
        
        # Backups table
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
        
        # Deployment history
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
        
        # Metrics table for historical data
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
#   ASYNC UTILITIES
# ==============================================================================

async def run_async_command(cmd: List[str], cwd: Optional[str] = None, timeout: int = 300) -> Tuple[int, str, str]:
    """Run command asynchronously with timeout [web:11][web:15]"""
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

async def parallel_health_checks(services: List[Dict]) -> Dict[str, bool]:
    """Run health checks in parallel [web:11]"""
    async def check_service(svc):
        try:
            proc = await asyncio.create_subprocess_exec(
                "systemctl", "is-active", svc['name'],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            is_active = stdout.strip() == b"active"
            
            if is_active:
                # HTTP health check
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "--fail", "-m", "2", 
                    f"http://127.0.0.1:{svc['port']}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await proc.communicate()
                return svc['name'], proc.returncode == 0
            return svc['name'], False
        except:
            return svc['name'], False
    
    results = await asyncio.gather(*[check_service(s) for s in services])
    return dict(results)

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
    with open(filepath, 'rb') as f:
        for block in iter(lambda: f.read(4096), b''):
            sha256.update(block)
    return sha256.hexdigest()

# ==============================================================================
#   VALIDATION
# ==============================================================================

def validate_storage(path: str) -> str:
    """Validate storage path exists and is not restricted"""
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
    
    # Check if port is actually free on OS
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', p))
    sock.close()
    if result == 0: 
        raise ValueError(f"Port {p} already in use on system.")
    
    return p

def validate_git_url(url: str) -> str:
    """Validate git repository URL"""
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
        shutil.copy(self.config_path, self.backup_path)
    
    def _restore_config(self):
        """Restore configuration from backup"""
        if os.path.exists(self.backup_path):
            shutil.copy(self.backup_path, self.config_path)
            run_root(["systemctl", "restart", "cloudflared"])
    
    def add_route(self, domain: str, port: int):
        """Add new route to Cloudflare Tunnel"""
        try:
            self._backup_config()
            
            with open(self.config_path, 'r') as f: 
                config = yaml.safe_load(f)
            
            if not config or 'ingress' not in config:
                raise ValueError("Invalid Cloudflare config YAML")
            
            ingress = config['ingress']
            
            # Check if route already exists
            if any(r.get('hostname') == domain for r in ingress):
                logger.warning(f"Route {domain} already exists")
                return
            
            # Add new rule before catch-all
            new_rule = {'hostname': domain, 'service': f'http://localhost:{port}'}
            catch_all_idx = next((i for i, r in enumerate(ingress) if r.get('service') == 'http_status:404'), -1)
            
            if catch_all_idx != -1:
                ingress.insert(catch_all_idx, new_rule)
            else:
                ingress.append(new_rule)
            
            # Write atomically
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

def generate_systemd_service(config: ServiceConfig, api_dir: str, log_dir: str) -> str:
    """Generate enhanced systemd service file with security hardening [web:17][web:20]"""
    
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

# Watchdog - auto-restart if unresponsive
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
ReadWritePaths=/opt/extra1_1tb/database/{config.name}

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

async def health_check_async(name: str, port: int, max_retries: int = 5) -> bool:
    """Asynchronous health check with retries [web:11][web:15]"""
    
    # Check systemd status
    proc = await asyncio.create_subprocess_exec(
        "systemctl", "is-active", name,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, _ = await proc.communicate()
    
    if stdout.strip() != b"active":
        return False
    
    # HTTP health check with retries
    for attempt in range(max_retries):
        print_status(f"Health check attempt {attempt + 1}/{max_retries}...", "info")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sf", "--max-time", "3", f"http://127.0.0.1:{port}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=5
            )
            
            if proc.returncode == 0:
                print_status("Health check PASSED", "success")
                return True
                
        except asyncio.TimeoutError:
            logger.warning(f"Health check timeout for {name} (attempt {attempt + 1})")
        except Exception as e:
            logger.warning(f"Health check error: {e}")
        
        if attempt < max_retries - 1:
            await asyncio.sleep(2)
    
    print_status("Health check FAILED", "error")
    return False

# ==============================================================================
#   DEPLOYMENT ENGINE
# ==============================================================================

async def deploy_service_async():
    """Enhanced asynchronous service deployment [web:11]"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ DEPLOY NEW SERVICE ═══{C_RESET}\n")
    
    start_time = time.time()
    config = None
    api_dir = None
    db_dir = None
    log_dir = None
    svc_file = None
    domain = None
    
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
        
        # Optional advanced settings
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
        
        # Upgrade pip
        run_as_gaia([pip_path, "install", "--upgrade", "pip"], cwd=api_dir)
        
        # Install dependencies
        requirements_file = os.path.join(api_dir, "requirements.txt")
        if os.path.exists(requirements_file):
            print_status("Installing requirements.txt", "info")
            run_as_gaia([pip_path, "install", "-r", "requirements.txt"], cwd=api_dir, timeout=600)
        else:
            print_status("Installing default Flask stack", "warning")
            run_as_gaia([pip_path, "install", "flask", "flask-cors"], cwd=api_dir)
        
        # Install production server
        run_as_gaia([pip_path, "install", "gunicorn"], cwd=api_dir)
        
        if PROMETHEUS_AVAILABLE:
            run_as_gaia([pip_path, "install", "prometheus-flask-exporter"], cwd=api_dir)
        
        print_status("Python environment ready", "success")
        
        # ===== SYSTEMD SERVICE =====
        print_status("GENERATING SYSTEMD SERVICE", "info")
        service_content = generate_systemd_service(config, api_dir, log_dir)
        
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
        await asyncio.sleep(3)  # Give service time to start
        
        health_ok = await health_check_async(name, port)
        
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
        
        # ===== ROLLBACK =====
        print_status("INITIATING ROLLBACK", "warning")
        
        try:
            if name and svc_file:
                try:
                    run_root(["systemctl", "stop", name])
                    run_root(["systemctl", "disable", name])
                except: pass
                
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
                except: pass
            
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
    
    input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

def deploy_service():
    """Wrapper to run async deployment"""
    asyncio.run(deploy_service_async())

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
        time.sleep(2)
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
        time.sleep(1)
        return
    
    try:
        print(f"\n{C_YELLOW}{'='*70}{C_RESET}")
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
        
        print(f"\n{C_GREEN}{'='*70}{C_RESET}")
        print_status(f"SERVICE '{name}' DESTROYED", "success")
        print(f"{C_GREEN}{'='*70}{C_RESET}\n")
        
    except Exception as e:
        logger.error(f"Destroy failed: {e}")
        print_status(f"Destruction failed: {e}", "error")
    
    time.sleep(2)

def service_operations():
    """Service management operations menu"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ SERVICE OPERATIONS ═══{C_RESET}\n")
    
    name = input("Service Name: ").strip()
    svc = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    
    if not svc:
        print_status("Service not found", "error")
        time.sleep(1)
        return
    
    print(f"\n{C_CYAN}Operations:{C_RESET}")
    print("  1. Restart service")
    print("  2. Stop service")
    print("  3. Start service")
    print("  4. Git pull & restart")
    print("  5. View status")
    print("  6. View service logs (live)")
    print("  0. Cancel")
    
    choice = input(f"\n{C_CYAN}Select operation:{C_RESET} ").strip()
    
    try:
        if choice == "1":
            print_status("Restarting service...", "info")
            run_root(["systemctl", "restart", name])
            print_status("Service restarted", "success")
            
        elif choice == "2":
            print_status("Stopping service...", "info")
            run_root(["systemctl", "stop", name])
            print_status("Service stopped", "success")
            
        elif choice == "3":
            print_status("Starting service...", "info")
            run_root(["systemctl", "start", name])
            print_status("Service started", "success")
            
        elif choice == "4":
            service_path = get_service_path(svc['storage_path'], name)
            print_status("Pulling latest code...", "info")
            run_as_gaia(["git", "pull"], cwd=service_path)
            print_status("Restarting service...", "info")
            run_root(["systemctl", "restart", name])
            print_status("Update complete", "success")
            audit_log("UPDATE", name)
            
        elif choice == "5":
            subprocess.run(["systemctl", "status", name])
            
        elif choice == "6":
            service_path = get_service_path(svc['storage_path'], name)
            log_file = os.path.join(service_path, "logs", "access.log")
            if os.path.exists(log_file):
                print(f"\n{C_CYAN}Streaming logs (Ctrl+C to exit)...{C_RESET}\n")
                try:
                    subprocess.run(["tail", "-f", log_file])
                except KeyboardInterrupt:
                    print()
            else:
                print_status("Log file not found", "error")
        
        elif choice == "0":
            return
        
    except Exception as e:
        logger.error(f"Operation failed: {e}")
        print_status(f"Operation failed: {e}", "error")
    
    if choice != "6":
        time.sleep(2)

# ==============================================================================
#   BACKUP SYSTEM
# ==============================================================================

def backup_service():
    """Enhanced backup with compression and checksums"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ BACKUP CENTER ═══{C_RESET}\n")
    
    name = input("Service to Backup: ").strip()
    svc = db.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    
    if not svc:
        print_status("Service not found", "error")
        time.sleep(1)
        return
    
    try:
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR, exist_ok=True)
            shutil.chown(BACKUP_DIR, user=SERVICE_USER, group=SERVICE_GROUP)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{name}_{timestamp}"
        
        service_path = get_service_path(svc['storage_path'], name)
        backup_path = os.path.join(BACKUP_DIR, filename)
        
        print_status("Creating backup archive...", "info")
        shutil.make_archive(backup_path, 'zip', service_path)
        
        archive_file = backup_path + ".zip"
        file_size = os.path.getsize(archive_file)
        checksum = calculate_file_hash(archive_file)
        
        db.query(
            "INSERT INTO backups (service_name, filename, size_bytes, checksum) VALUES (?, ?, ?, ?)",
            (name, filename + ".zip", file_size, checksum)
        )
        
        if PROMETHEUS_AVAILABLE:
            BACKUP_COUNTER.inc()
        
        audit_log("BACKUP", name, {"filename": filename + ".zip", "size_bytes": file_size})
        
        print(f"\n{C_GREEN}{'='*70}{C_RESET}")
        print_status("BACKUP CREATED", "success")
        print(f"{C_CYAN}Details:{C_RESET}")
        print(f"  File:     {filename}.zip")
        print(f"  Size:     {file_size / (1024*1024):.2f} MB")
        print(f"  Location: {BACKUP_DIR}")
        print(f"  SHA256:   {checksum[:16]}...")
        print(f"{C_GREEN}{'='*70}{C_RESET}\n")
        
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        print_status(f"Backup failed: {e}", "error")
    
    time.sleep(2)

def list_backups():
    """List all backups"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ BACKUP HISTORY ═══{C_RESET}\n")
    
    backups = db.query("SELECT * FROM backups ORDER BY timestamp DESC LIMIT 20", fetch_all=True)
    
    if not backups:
        print_status("No backups found", "warning")
        time.sleep(1)
        return
    
    print(f"{C_BOLD}{'SERVICE':<15} {'FILENAME':<35} {'SIZE':<12} {'DATE'}{C_RESET}")
    print("="*80)
    
    for backup in backups:
        size_mb = backup['size_bytes'] / (1024*1024) if backup['size_bytes'] else 0
        timestamp = backup['timestamp'][:19]  # Remove microseconds
        print(f"{backup['service_name']:<15} {backup['filename']:<35} {size_mb:>8.2f} MB  {timestamp}")
    
    input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

# ==============================================================================
#   MONITORING & DIAGNOSTICS
# ==============================================================================

async def run_diagnostics():
    """Comprehensive system diagnostics"""
    print_header()
    print(f"{C_YELLOW}{C_BOLD}═══ ATS SYSTEM DIAGNOSTICS ═══{C_RESET}\n")
    
    checks = []
    
    # Basic checks
    print_status("Running diagnostic checks...", "info")
    print()
    
    # Root access
    root_ok = os.geteuid() == 0
    checks.append(("Root Access", root_ok))
    print(f"{'Root Access':<30} {C_GREEN + '✓ PASS' + C_RESET if root_ok else C_RED + '✗ FAIL' + C_RESET}")
    
    # Database
    db_ok = os.path.exists(DB_FILE) and os.access(DB_FILE, os.W_OK)
    checks.append(("Database", db_ok))
    print(f"{'Database Access':<30} {C_GREEN + '✓ PASS' + C_RESET if db_ok else C_RED + '✗ FAIL' + C_RESET}")
    
    # Cloudflare config
    cf_ok = os.path.exists(CLOUDFLARE_CONFIG)
    checks.append(("Cloudflare Config", cf_ok))
    print(f"{'Cloudflare Configuration':<30} {C_GREEN + '✓ PASS' + C_RESET if cf_ok else C_RED + '✗ FAIL' + C_RESET}")
    
    # Cloudflare service
    result = subprocess.run(["systemctl", "is-active", "cloudflared"], stdout=subprocess.PIPE)
    cf_svc_ok = result.stdout.strip() == b"active"
    checks.append(("Cloudflare Service", cf_svc_ok))
    print(f"{'Cloudflare Service':<30} {C_GREEN + '✓ PASS' + C_RESET if cf_svc_ok else C_RED + '✗ FAIL' + C_RESET}")
    
    # Internet connectivity
    inet_ok = subprocess.call(["ping", "-c", "1", "-W", "2", "1.1.1.1"], 
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    checks.append(("Internet", inet_ok))
    print(f"{'Internet Connectivity':<30} {C_GREEN + '✓ PASS' + C_RESET if inet_ok else C_RED + '✗ FAIL' + C_RESET}")
    
    # Storage
    storage_ok = os.path.exists(DEFAULT_STORAGE) and os.access(DEFAULT_STORAGE, os.W_OK)
    checks.append(("Default Storage", storage_ok))
    print(f"{'Default Storage':<30} {C_GREEN + '✓ PASS' + C_RESET if storage_ok else C_RED + '✗ FAIL' + C_RESET}")
    
    # Dependencies
    deps_ok = True
    for module in ['yaml', 'psutil']:
        try:
            __import__(module)
        except:
            deps_ok = False
            break
    checks.append(("Python Dependencies", deps_ok))
    print(f"{'Python Dependencies':<30} {C_GREEN + '✓ PASS' + C_RESET if deps_ok else C_RED + '✗ FAIL' + C_RESET}")
    
    # Service health checks
    print(f"\n{C_CYAN}Service Health Checks:{C_RESET}\n")
    services = db.query("SELECT * FROM services", fetch_all=True)
    
    if services:
        health_results = await parallel_health_checks(services)
        for svc in services:
            is_healthy = health_results.get(svc['name'], False)
            status_str = C_GREEN + "HEALTHY" + C_RESET if is_healthy else C_RED + "UNHEALTHY" + C_RESET
            print(f"  {svc['name']:<20} {status_str}")
    else:
        print("  No services deployed")
    
    # System resources
    print(f"\n{C_CYAN}System Resources:{C_RESET}\n")
    if psutil:
        cpu_percent = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        print(f"  CPU Usage:    {cpu_percent:.1f}%")
        print(f"  Memory:       {mem.used / (1024**3):.1f} GB / {mem.total / (1024**3):.1f} GB ({mem.percent:.1f}%)")
        print(f"  Disk:         {disk.used / (1024**3):.1f} GB / {disk.total / (1024**3):.1f} GB ({disk.percent:.1f}%)")
    else:
        print("  psutil not available - install for detailed metrics")
    
    # Summary
    passed = sum(1 for _, ok in checks if ok)
    total = len(checks)
    
    print(f"\n{C_CYAN}{'='*70}{C_RESET}")
    if passed == total:
        print(f"{C_GREEN}{C_BOLD}✓ ALL CHECKS PASSED ({passed}/{total}){C_RESET}")
    else:
        print(f"{C_YELLOW}{C_BOLD}⚠ {passed}/{total} CHECKS PASSED{C_RESET}")
    print(f"{C_CYAN}{'='*70}{C_RESET}\n")
    
    input(f"{C_CYAN}Press Enter to continue...{C_RESET}")

def ats_doctor():
    """Wrapper for async diagnostics"""
    asyncio.run(run_diagnostics())

# ==============================================================================
#   METRICS EXPORT
# ==============================================================================

def export_prometheus_metrics():
    """Export Prometheus metrics [web:16][web:19]"""
    if not PROMETHEUS_AVAILABLE:
        return
    
    try:
        # Update service status metrics
        services = db.query("SELECT * FROM services", fetch_all=True)
        for svc in services:
            result = subprocess.run(
                ["systemctl", "is-active", svc['name']], 
                stdout=subprocess.PIPE
            )
            is_active = 1 if result.stdout.strip() == b"active" else 0
            SERVICE_STATUS.labels(service=svc['name']).set(is_active)
        
        # Write metrics to file
        with open(METRICS_FILE, 'wb') as f:
            f.write(generate_latest(REGISTRY))
        
        logger.info("Prometheus metrics exported")
        
    except Exception as e:
        logger.error(f"Metrics export failed: {e}")

# ==============================================================================
#   MAIN MENU
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
    
    ram_str = f"{mem.used/(1024**3):.1f}/{mem.total/(1024**3):.1f}GB"
    disk_str = f"{disk.used/(1024**3):.0f}/{disk.total/(1024**3):.0f}GB"
    
    return cpu, ram_str, disk_str, active_count

def main_menu():
    """Main interactive menu"""
    while True:
        try:
            print_header()
            
            # System telemetry
            cpu, ram, disk, svc_count = asyncio.run(get_telemetry_async())
            print(f"{C_CYAN}┌{'─'*68}┐{C_RESET}")
            print(f"{C_CYAN}│{C_RESET} {C_BOLD}System:{C_RESET} CPU {cpu:.1f}%  │  RAM {ram}  │  Disk {disk}  │  Services {svc_count} {C_CYAN}│{C_RESET}")
            print(f"{C_CYAN}└{'─'*68}┘{C_RESET}\n")
            
            # Service status table
            services = db.query("SELECT * FROM services ORDER BY name", fetch_all=True)
            
            print(f"{C_BOLD}{'NAME':<15} {'PORT':<8} {'STATUS':<12} {'DOMAIN'}{C_RESET}")
            print(f"{C_CYAN}{'─'*70}{C_RESET}")
            
            if services:
                # Async health checks for all services
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
            
            print(f"{C_CYAN}{'─'*70}{C_RESET}\n")
            
            # Menu options
            print(f"{C_CYAN}┌─ DEPLOYMENT ──────────────┬─ MANAGEMENT ──────────────┐{C_RESET}")
            print(f"{C_CYAN}│{C_RESET} [1] Deploy Service         {C_CYAN}│{C_RESET} [5] Service Operations     {C_CYAN}│{C_RESET}")
            print(f"{C_CYAN}│{C_RESET} [2] List Services          {C_CYAN}│{C_RESET} [6] Backup Service         {C_CYAN}│{C_RESET}")
            print(f"{C_CYAN}│{C_RESET} [3] Destroy Service        {C_CYAN}│{C_RESET} [7] List Backups           {C_CYAN}│{C_RESET}")
            print(f"{C_CYAN}│{C_RESET} [4] View Deployment History{C_CYAN}│{C_RESET} [8] Export Metrics         {C_CYAN}│{C_RESET}")
            print(f"{C_CYAN}└───────────────────────────┴───────────────────────────┘{C_RESET}")
            print(f"{C_CYAN}│{C_RESET} [9] System Diagnostics     {C_RED}│{C_RESET} [0] Exit                   {C_CYAN}│{C_RESET}")
            print(f"{C_CYAN}└───────────────────────────┴───────────────────────────┘{C_RESET}")
            
            choice = input(f"\n{C_CYAN}{C_BOLD}ATS>${C_RESET} ").strip()
            
            if choice == "1":
                deploy_service()
            elif choice == "2":
                pass  # Already showing services
            elif choice == "3":
                destroy_service()
            elif choice == "4":
                view_deployment_history()
            elif choice == "5":
                service_operations()
            elif choice == "6":
                backup_service()
            elif choice == "7":
                list_backups()
            elif choice == "8":
                export_prometheus_metrics()
                print_status("Metrics exported to " + METRICS_FILE, "success")
                time.sleep(1)
            elif choice == "9":
                ats_doctor()
            elif choice == "0":
                print(f"\n{C_CYAN}Goodbye!{C_RESET}\n")
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

def view_deployment_history():
    """View deployment history"""
    print_header()
    print(f"{C_CYAN}{C_BOLD}═══ DEPLOYMENT HISTORY ═══{C_RESET}\n")
    
    deployments = db.query(
        "SELECT * FROM deployments ORDER BY timestamp DESC LIMIT 20", 
        fetch_all=True
    )
    
    if not deployments:
        print_status("No deployment history", "warning")
        time.sleep(1)
        return
    
    print(f"{C_BOLD}{'SERVICE':<15} {'STATUS':<10} {'DURATION':<12} {'TIMESTAMP'}{C_RESET}")
    print("="*70)
    
    for dep in deployments:
        status_color = C_GREEN if dep['status'] == 'success' else C_RED
        status_str = f"{status_color}{dep['status'].upper()}{C_RESET}"
        duration = f"{dep['duration_seconds']:.2f}s" if dep['duration_seconds'] else "N/A"
        timestamp = dep['timestamp'][:19]
        
        print(f"{dep['service_name']:<15} {status_str:<18} {duration:<12} {timestamp}")
        
        if dep['error_message']:
            print(f"  {C_YELLOW}└─ Error: {dep['error_message'][:50]}...{C_RESET}")
    
    input(f"\n{C_CYAN}Press Enter to continue...{C_RESET}")

# ==============================================================================
#   ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    # Privilege check
    if os.geteuid() != 0:
        print(f"{C_RED}ERROR: ATS requires root privileges.{C_RESET}")
        print(f"Run: sudo python3 {sys.argv[0]}")
        sys.exit(1)
    
    # Initialize
    if not os.path.exists(ATS_HOME):
        os.makedirs(ATS_HOME, exist_ok=True)
        os.chmod(ATS_HOME, 0o700)
    
    # Acquire lock
    lock = acquire_lock()
    
    # Welcome message
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
