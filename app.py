#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATS | AUTOMATED TECH STACK | SUPREMACY EDITION v6.1
Architect: Abinaav K
Status: STABLE / PRODUCTION
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
import glob

# --- DEPENDENCY SAFEGUARD ---
try:
    import yaml
except ImportError:
    print("CRITICAL: 'python3-yaml' is missing. Run: sudo apt install python3-yaml")
    sys.exit(1)

try:
    import psutil
except ImportError:
    psutil = None  # Graceful fallback

# ==============================================================================
#   CONFIGURATION KERNEL
# ==============================================================================

ATS_HOME = "/home/gaia/ats"
DB_FILE = os.path.join(ATS_HOME, "ats.db")
LOG_FILE = os.path.join(ATS_HOME, "ats.log")
AUDIT_FILE = os.path.join(ATS_HOME, "audit.trace")
LOCK_FILE = "/tmp/ats.lock"

# User Context
SERVICE_USER = "gaia"
SERVICE_GROUP = "gaia"

# Network Defaults
MAIN_DOMAIN = "gaiasentinel.online"
CLOUDFLARE_CONFIG = "/etc/cloudflared/config.yml"

# Storage Defaults
DEFAULT_STORAGE = "/opt/extra1_1tb"
BACKUP_DIR = os.path.join(DEFAULT_STORAGE, "backups")

# Security Blocklist
BLOCKED_PATHS = ["/", "/bin", "/boot", "/dev", "/etc", "/lib", "/root", "/run", "/sys", "/usr", "/var"]

# ==============================================================================
#   VISUAL STYLING
# ==============================================================================

C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_PURPLE = "\033[95m"
C_CYAN = "\033[96m"

def print_header():
    os.system('clear')
    print(f"{C_CYAN}{C_BOLD}")
    print(r"""
       _/_/    _/_/_/_/_/    _/_/_/   
    _/    _/      _/      _/          
   _/_/_/_/      _/        _/_/       
  _/    _/      _/            _/      
 _/    _/      _/      _/_/_/         
                                      
    AUTOMATED TECH STACK v6.1
    {0}
    """.format(C_RESET))
    print(f"{C_CYAN}{'='*60}{C_RESET}")

# ==============================================================================
#   LOGGING & AUDITING
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger()

def audit_log(action, target):
    """Writes an immutable audit record."""
    entry = f"{datetime.datetime.now().isoformat()} | ACTION: {action} | TARGET: {target} | USER: {os.getlogin()}\n"
    try:
        with open(AUDIT_FILE, "a") as f:
            f.write(entry)
    except:
        pass

# ==============================================================================
#   DATABASE ENGINE
# ==============================================================================

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            port INTEGER UNIQUE NOT NULL,
            domain TEXT UNIQUE NOT NULL,
            storage_path TEXT NOT NULL,
            repo_url TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT,
            filename TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    try:
        os.chmod(DB_FILE, 0o600)
    except:
        pass

def db_query(sql, args=(), fetch_all=False, fetch_one=False):
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(sql, args)
        res = None
        if fetch_one: res = cursor.fetchone()
        elif fetch_all: res = cursor.fetchall()
        else: conn.commit()
        conn.close()
        return res
    except sqlite3.Error as e:
        logger.error(f"DB Error: {e}")
        return None

# ==============================================================================
#   CORE UTILITIES
# ==============================================================================

def acquire_lock():
    """Prevents multiple instances of ATS running."""
    try:
        lock_fd = open(LOCK_FILE, 'w')
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        atexit.register(lambda: fcntl.flock(lock_fd, fcntl.LOCK_UN))
        return lock_fd
    except IOError:
        print(f"{C_RED}CRITICAL: ATS is locked. Another process is running.{C_RESET}")
        print(f"Run 'sudo rm {LOCK_FILE}' if you are sure it crashed.")
        sys.exit(1)

def run_as_gaia(cmd, cwd=None, timeout=300):
    """Runs a command as the service user (gaia)."""
    env = os.environ.copy()
    env["HOME"] = f"/home/{SERVICE_USER}"
    full_cmd = ["sudo", "-u", SERVICE_USER] + cmd
    logger.info(f"EXEC(GAIA): {' '.join(cmd)}")
    subprocess.check_call(full_cmd, cwd=cwd, env=env, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_root(cmd, timeout=60):
    """Runs a command as root."""
    logger.info(f"EXEC(ROOT): {' '.join(cmd)}")
    subprocess.check_call(cmd, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def get_service_path(storage, name):
    """Heuristic to find service location."""
    legacy = os.path.join(storage, "websites", name)
    if os.path.exists(legacy): return legacy
    return os.path.join(storage, "api", name)

# ==============================================================================
#   VALIDATION LOGIC
# ==============================================================================

def validate_storage(path):
    if not os.path.exists(path):
        raise ValueError(f"Path does not exist: {path}")
    clean = os.path.abspath(path)
    if clean in BLOCKED_PATHS:
        raise ValueError(f"Restricted system path: {clean}")
    return clean

def validate_domain(domain):
    if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
        raise ValueError("Invalid domain format.")
    if db_query("SELECT 1 FROM services WHERE domain=?", (domain,), fetch_one=True):
        raise ValueError(f"Domain {domain} already exists in DB.")
    return domain

def validate_port(port):
    try:
        p = int(port)
    except:
        raise ValueError("Port must be numeric.")
    if not (1024 <= p <= 65535):
        raise ValueError("Port out of range (1024-65535).")
    if db_query("SELECT 1 FROM services WHERE port=?", (p,), fetch_one=True):
        raise ValueError("Port already registered.")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', p))
    sock.close()
    if result == 0:
        raise ValueError(f"Port {p} is already in use by OS.")
    return p

# ==============================================================================
#   CLOUDFLARE MANAGER
# ==============================================================================

def manage_cloudflare(action, domain=None, port=0):
    """Safe YAML modification for Cloudflare Tunnels."""
    try:
        if not os.path.exists(CLOUDFLARE_CONFIG):
            raise FileNotFoundError("Config not found")

        # Backup
        shutil.copy(CLOUDFLARE_CONFIG, CLOUDFLARE_CONFIG + ".bak")

        with open(CLOUDFLARE_CONFIG, 'r') as f:
            config = yaml.safe_load(f)

        if not config or 'ingress' not in config:
            raise ValueError("Invalid YAML structure")

        ingress = config['ingress']

        if action == "ADD":
            if any(r.get('hostname') == domain for r in ingress): return
            new_rule = {'hostname': domain, 'service': f'http://localhost:{port}'}
            # Find 404 rule
            idx = next((i for i, r in enumerate(ingress) if r.get('service') == 'http_status:404'), -1)
            if idx != -1: ingress.insert(idx, new_rule)
            else: ingress.append(new_rule)

        elif action == "REMOVE":
            config['ingress'] = [r for r in ingress if r.get('hostname') != domain]

        with open(CLOUDFLARE_CONFIG, 'w') as f:
            yaml.dump(config, f, sort_keys=False)

        run_root(["systemctl", "restart", "cloudflared"])
        logger.info(f"Cloudflare updated: {action} {domain}")

    except Exception as e:
        logger.error(f"Cloudflare Error: {e}")
        # Restore backup
        if os.path.exists(CLOUDFLARE_CONFIG + ".bak"):
            shutil.copy(CLOUDFLARE_CONFIG + ".bak", CLOUDFLARE_CONFIG)
            run_root(["systemctl", "restart", "cloudflared"])
        raise

# ==============================================================================
#   SERVICE DEPLOYMENT
# ==============================================================================

def generate_systemd(name, api_dir, log_dir, port):
    """Creates a hardened Systemd service file."""
    content = f"""[Unit]
Description={name} [ATS MANAGED]
After=network.target

[Service]
User={SERVICE_USER}
Group={SERVICE_GROUP}
WorkingDirectory={api_dir}
Environment="PATH={api_dir}/venv/bin"
ExecStart={api_dir}/venv/bin/gunicorn -w 2 -b 127.0.0.1:{port} app:app
StandardOutput=append:{log_dir}/access.log
StandardError=append:{log_dir}/error.log
Restart=always

# --- SECURITY HARDENING ---
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
MemoryMax=512M
UMask=027

[Install]
WantedBy=multi-user.target
"""
    with open(f"/etc/systemd/system/{name}.service", "w") as f:
        f.write(content)

def health_check(name, port):
    """Verifies Systemd status and HTTP response."""
    # 1. Systemd Check
    res = subprocess.run(["systemctl", "is-active", name], stdout=subprocess.PIPE)
    if res.stdout.strip() != b"active": return False
    
    # 2. HTTP Check
    print(f"   >>> Checking http://127.0.0.1:{port}...", end='\r')
    for _ in range(5):
        try:
            subprocess.check_call(
                ["curl", "-s", "--fail", f"http://127.0.0.1:{port}"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2
            )
            return True
        except:
            time.sleep(1.5)
    return False

def deploy_service():
    print_header()
    print(f"{C_CYAN}INITIATING DEPLOYMENT{C_RESET}\n")

    try:
        # INPUTS
        name = input(f"{C_BOLD}SERVICE NAME:{C_RESET} ").strip()
        if not re.match(r"^[a-zA-Z0-9_-]+$", name): raise ValueError("Invalid Name")
        if db_query("SELECT 1 FROM services WHERE name=?", (name,), fetch_one=True):
            raise ValueError("Service Name Exists")

        storage_in = input(f"{C_BOLD}DISK [{DEFAULT_STORAGE}]:{C_RESET} ").strip() or DEFAULT_STORAGE
        storage = validate_storage(storage_in)

        dom_choice = input(f"{C_BOLD}1.Subdomain  2.Full Domain:{C_RESET} ").strip()
        if dom_choice == "1":
            prefix = input("   Prefix: ").strip()
            domain = validate_domain(f"{prefix}.{MAIN_DOMAIN}")
        else:
            domain = validate_domain(input("   Full Domain: ").strip())

        port = validate_port(input(f"{C_BOLD}PORT:{C_RESET} ").strip())
        
        repo_in = input(f"{C_BOLD}GIT URL:{C_RESET} ").strip()
        if not (repo_in.startswith("http") or repo_in.startswith("git@")):
            raise ValueError("Invalid Git URL")
        repo = repo_in

        # PATHS
        api_dir = os.path.join(storage, "api", name)
        db_dir = os.path.join(storage, "database", name)
        log_dir = os.path.join(api_dir, "logs")
        svc_file = f"/etc/systemd/system/{name}.service"

        print(f"\n{C_GREEN}>>> PROVISIONING...{C_RESET}")
        for d in [api_dir, db_dir, log_dir]:
            os.makedirs(d, exist_ok=True)
            shutil.chown(d, user=SERVICE_USER, group=SERVICE_GROUP)

        print(f"{C_BLUE}>>> CLONING...{C_RESET}")
        run_as_gaia(["git", "clone", repo, "."], cwd=api_dir)

        print(f"{C_BLUE}>>> ENVIRONMENT...{C_RESET}")
        run_as_gaia([sys.executable, "-m", "venv", "venv"], cwd=api_dir)
        pip = os.path.join(api_dir, "venv", "bin", "pip")
        
        # Install logic
        reqs = os.path.join(api_dir, "requirements.txt")
        if os.path.exists(reqs):
            run_as_gaia([pip, "install", "-r", "requirements.txt"], cwd=api_dir)
            run_as_gaia([pip, "install", "gunicorn"], cwd=api_dir)
        else:
            run_as_gaia([pip, "install", "gunicorn", "flask", "flask-cors"], cwd=api_dir)

        print(f"{C_PURPLE}>>> SYSTEMD...{C_RESET}")
        generate_systemd(name, api_dir, log_dir, port)
        run_root(["systemctl", "daemon-reload"])
        run_root(["systemctl", "enable", name])
        run_root(["systemctl", "start", name])

        print(f"{C_YELLOW}>>> HEALTH CHECK...{C_RESET}")
        time.sleep(3)
        if not health_check(name, port):
            raise Exception("Service failed to start")

        print(f"{C_CYAN}>>> CLOUDFLARE...{C_RESET}")
        manage_cloudflare("ADD", domain, port)

        # SAVE
        db_query(
            "INSERT INTO services (name, port, domain, storage_path, repo_url) VALUES (?, ?, ?, ?, ?)",
            (name, port, domain, storage, repo)
        )
        audit_log("DEPLOY", name)
        print(f"\n{C_GREEN}✅ SUCCESS: https://{domain}{C_RESET}")

    except Exception as e:
        logger.error(f"Deploy Fail: {e}")
        print(f"\n{C_RED}❌ FAILED: {e}{C_RESET}")
        print(">>> ROLLING BACK...")
        # Rollback
        try:
            if 'name' in locals():
                run_root(["systemctl", "stop", name])
                run_root(["systemctl", "disable", name])
                if os.path.exists(svc_file): os.remove(svc_file)
                run_root(["systemctl", "daemon-reload"])
            if 'api_dir' in locals() and os.path.exists(api_dir): shutil.rmtree(api_dir)
            if 'db_dir' in locals() and os.path.exists(db_dir): shutil.rmtree(db_dir)
            if 'domain' in locals(): manage_cloudflare("REMOVE", domain)
        except: pass
        print(">>> ROLLBACK DONE")

    input("\nPress Enter...")

# ==============================================================================
#   OPERATIONS
# ==============================================================================

def terminate_service():
    print_header()
    print(f"{C_RED}TERMINATION MODE{C_RESET}")
    name = input("SERVICE NAME: ").strip()
    svc = db_query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    if not svc:
        print("Not Found.")
        time.sleep(1); return

    if input("Type 'DELETE' to confirm: ") != "DELETE": return

    print(">>> STOPPING...")
    run_root(["systemctl", "stop", name])
    run_root(["systemctl", "disable", name])
    
    svc_path = f"/etc/systemd/system/{name}.service"
    if os.path.exists(svc_path): os.remove(svc_path)
    run_root(["systemctl", "daemon-reload"])

    print(">>> UNROUTING...")
    manage_cloudflare("REMOVE", svc['domain'])

    print(">>> WIPING...")
    service_root = get_service_path(svc['storage_path'], name)
    if os.path.exists(service_root): shutil.rmtree(service_root)

    db_query("DELETE FROM services WHERE id=?", (svc['id'],))
    audit_log("DESTROY", name)
    print(f"{C_GREEN}DESTROYED.{C_RESET}")
    time.sleep(2)

def view_logs():
    name = input("SERVICE NAME: ").strip()
    svc = db_query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    if not svc: return

    path = get_service_path(svc['storage_path'], name)
    log_file = os.path.join(path, "logs", "access.log")
    
    if not os.path.exists(log_file):
        print("No log file found.")
        return

    print(f"{C_CYAN}LOG STREAM (Ctrl+C to Stop)...{C_RESET}")
    try:
        subprocess.run(["tail", "-f", log_file])
    except KeyboardInterrupt: pass

def service_ops():
    name = input("SERVICE NAME: ").strip()
    svc = db_query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    if not svc: return
    
    print("1.RESTART  2.STOP  3.START  4.GIT PULL")
    op = input("OP: ")
    if op == "1": run_root(["systemctl", "restart", name])
    elif op == "2": run_root(["systemctl", "stop", name])
    elif op == "3": run_root(["systemctl", "start", name])
    elif op == "4":
        path = get_service_path(svc['storage_path'], name)
        run_as_gaia(["git", "pull"], cwd=path)
        run_root(["systemctl", "restart", name])
        print("Updated.")
        time.sleep(1)

# ==============================================================================
#   BACKUP & DIAGNOSTICS
# ==============================================================================

def backup_service():
    name = input("SERVICE TO BACKUP: ").strip()
    svc = db_query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    if not svc: return

    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)
        shutil.chown(BACKUP_DIR, user=SERVICE_USER, group=SERVICE_GROUP)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M")
    filename = f"{name}_{ts}"
    src = get_service_path(svc['storage_path'], name)
    dst = os.path.join(BACKUP_DIR, filename)

    print(">>> COMPRESSING...")
    shutil.make_archive(dst, 'zip', src)
    
    db_query("INSERT INTO backups (service_name, filename) VALUES (?, ?)", (name, filename+".zip"))
    print(f"{C_GREEN}BACKUP SAVED.{C_RESET}")
    time.sleep(2)

def diagnostics():
    print_header()
    print(f"{C_YELLOW}DIAGNOSTICS{C_RESET}")
    checks = [
        ("Root Access", os.geteuid() == 0),
        ("DB Writable", os.access(DB_FILE, os.W_OK)),
        ("Cloudflare Config", os.path.exists(CLOUDFLARE_CONFIG)),
        ("Internet", subprocess.call(["curl", "-I", "https://github.com"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0),
    ]
    for name, res in checks:
        print(f"{name:<20} {'✅ PASS' if res else '❌ FAIL'}")
    input("\nEnter...")

# ==============================================================================
#   DASHBOARD
# ==============================================================================

def get_telemetry():
    cpu = psutil.cpu_percent(interval=0.1) if psutil else 0
    mem = psutil.virtual_memory() if psutil else None
    disk = psutil.disk_usage('/') if psutil else None
    
    ram_str = f"{round(mem.used/1024**3,1)}/{round(mem.total/1024**3,1)} GB" if mem else "N/A"
    disk_str = f"{round(disk.used/1024**3,1)}/{round(disk.total/1024**3,1)} GB" if disk else "N/A"
    
    return cpu, ram_str, disk_str

def dashboard():
    while True:
        print_header()
        cpu, ram, disk = get_telemetry()
        print(f"{C_CYAN}CPU: {cpu}%  |  RAM: {ram}  |  DISK: {disk}{C_RESET}")
        print("="*60)
        
        services = db_query("SELECT * FROM services", fetch_all=True)
        print(f"{C_BOLD}{'NAME':<15} {'PORT':<6} {'STATUS':<10} {'DOMAIN'}{C_RESET}")
        print("-" * 60)
        
        if services:
            for s in services:
                res = subprocess.run(["systemctl", "is-active", s['name']], stdout=subprocess.PIPE)
                active = res.stdout.strip() == b"active"
                color = C_GREEN if active else C_RED
                print(f"{s['name']:<15} {s['port']:<6} {color}{'ONLINE' if active else 'OFFLINE':<10}{C_RESET} {s['domain']}")
        else:
            print("   No Active Services")
            
        print("="*60)
        print(" [1] DEPLOY      [4] LOGS")
        print(" [2] TERMINATE   [5] BACKUP")
        print(" [3] OPS         [6] DOCTOR")
        print(f" {C_RED}[0] EXIT{C_RESET}")
        
        ch = input(f"\n{C_PURPLE}ATS>{C_RESET} ")
        if ch == "1": deploy_service()
        elif ch == "2": terminate_service()
        elif ch == "3": service_ops()
        elif ch == "4": view_logs()
        elif ch == "5": backup_service()
        elif ch == "6": diagnostics()
        elif ch == "0": sys.exit()

# ==============================================================================
#   MAIN
# ==============================================================================

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("ROOT REQUIRED.")
        sys.exit(1)
    
    if not os.path.exists(ATS_HOME): os.makedirs(ATS_HOME)
    
    lock = acquire_lock()
    init_db()
    
    try:
        dashboard()
    except KeyboardInterrupt:
        print("\nBye.")
        sys.exit(0)
