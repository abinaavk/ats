#!/usr/bin/env python3
import os
import sys
import subprocess
import sqlite3
import shutil
import time
import re
import logging
import yaml
import fcntl
import socket
import atexit

# --- CONFIGURATION ---
ATS_HOME = "/home/gaia/ats"
DB_FILE = os.path.join(ATS_HOME, "ats.db")
LOG_FILE = os.path.join(ATS_HOME, "ats.log")
LOCK_FILE = "/tmp/ats.lock"
CLOUDFLARE_CONFIG = "/etc/cloudflared/config.yml"
SERVICE_USER = "gaia"
SERVICE_GROUP = "gaia"
MAIN_DOMAIN = "gaiasentinel.online"
DEFAULT_STORAGE = "/opt/extra1_1tb"

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger()

# --- COLORS ---
C_RESET = "\033[0m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"

# --- DATABASE ENGINE ---
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
            status TEXT DEFAULT 'deployed',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    # Security: Only root can read/write DB
    os.chmod(DB_FILE, 0o600)

def db_query(query, args=(), fetch_one=False, fetch_all=False):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, args)
    if fetch_one:
        res = cursor.fetchone()
    elif fetch_all:
        res = cursor.fetchall()
    else:
        res = None
        conn.commit()
    conn.close()
    return res

# --- LOCKING MECHANISM ---
def acquire_lock():
    """Prevents race conditions using atomic file locking."""
    lock_fd = open(LOCK_FILE, 'w')
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Auto-release on exit
        atexit.register(lambda: fcntl.flock(lock_fd, fcntl.LOCK_UN))
        return lock_fd
    except IOError:
        print(f"{C_RED}❌ ATS is currently busy (Lock Active). Please wait.{C_RESET}")
        sys.exit(1)

# --- STRICT VALIDATION ---
def validate_storage(path):
    if not os.path.exists(path):
        raise ValueError(f"Storage path {path} does not exist.")
    
    # Security: Block system root paths
    unsafe_paths = ["/", "/bin", "/boot", "/dev", "/etc", "/lib", "/proc", "/root", "/run", "/sbin", "/sys", "/usr", "/var"]
    clean_path = os.path.abspath(path)
    if clean_path in unsafe_paths:
        raise ValueError(f"CRITICAL: Cannot use system path {clean_path} for storage.")
    
    return clean_path

def validate_domain(domain):
    if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
        raise ValueError("Invalid domain format.")
    
    # Check DB uniqueness
    if db_query("SELECT 1 FROM services WHERE domain=?", (domain,), fetch_one=True):
        raise ValueError(f"Domain {domain} is already assigned in ATS DB.")
    
    return domain

def validate_port(port):
    try:
        port = int(port)
    except ValueError:
        raise ValueError("Port must be a number.")
    
    if port < 1024 or port > 65535:
        raise ValueError("Port must be between 1024 and 65535.")
    
    # Check DB
    if db_query("SELECT 1 FROM services WHERE port=?", (port,), fetch_one=True):
        raise ValueError(f"Port {port} already registered.")
    
    # Check OS Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    if result == 0:
        raise ValueError(f"Port {port} is active on OS level (Conflict).")
    return port

# --- HELPER FUNCTIONS ---
def run_as_gaia(cmd, cwd=None):
    """Executes command as 'gaia' user to prevent root escalation from repos."""
    env = os.environ.copy()
    env["HOME"] = f"/home/{SERVICE_USER}"
    full_cmd = ["sudo", "-u", SERVICE_USER] + cmd
    logger.info(f"Exec (Gaia): {' '.join(cmd)}")
    subprocess.check_call(full_cmd, cwd=cwd, env=env, timeout=300)

def check_http_health(port):
    """Real HTTP check to ensure app is responding."""
    print("💓 Checking HTTP Health...")
    for _ in range(5):
        try:
            # Curl local only, fail fast on error
            subprocess.check_call(
                ["curl", "-s", "--fail", f"http://127.0.0.1:{port}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
            return True
        except:
            time.sleep(2)
    return False

# --- CLOUDFLARE MANAGEMENT ---
def manage_cloudflare(action, domain=None, port=None):
    shutil.copy(CLOUDFLARE_CONFIG, CLOUDFLARE_CONFIG + ".bak")
    
    with open(CLOUDFLARE_CONFIG, 'r') as f:
        config = yaml.safe_load(f)

    # Validation: Ensure valid YAML structure
    if not config or 'ingress' not in config:
        raise ValueError("Invalid Cloudflare YAML: Missing 'ingress' block.")

    ingress_list = config['ingress']
    
    if action == 'add':
        if any(rule.get('hostname') == domain for rule in ingress_list):
            logger.info(f"Domain {domain} already in Cloudflare.")
            return

        new_rule = {'hostname': domain, 'service': f'http://localhost:{port}'}
        
        # Smart Insertion: Find the 404 rule
        insert_idx = -1
        for i, rule in enumerate(ingress_list):
            if rule.get('service') == 'http_status:404':
                insert_idx = i
                break
        
        if insert_idx != -1:
            ingress_list.insert(insert_idx, new_rule)
        else:
            ingress_list.append(new_rule)
            
    elif action == 'remove':
        config['ingress'] = [r for r in ingress_list if r.get('hostname') != domain]

    with open(CLOUDFLARE_CONFIG, 'w') as f:
        yaml.dump(config, f, sort_keys=False)
    
    subprocess.check_call(["systemctl", "restart", "cloudflared"], timeout=60)

# --- DEPLOYMENT ENGINE ---
def deploy_service():
    print(f"\n{C_CYAN}🚀 DEPLOY NEW SERVICE{C_RESET}")
    start_time = time.time()
    
    try:
        # 1. INPUT VALIDATION
        name = input(f"{C_YELLOW}🔹 Service Name: {C_RESET}").strip()
        if not re.match(r"^[a-zA-Z0-9_-]+$", name): raise ValueError("Invalid Name format.")
        if db_query("SELECT 1 FROM services WHERE name=?", (name,), fetch_one=True):
            print(f"{C_RED}❌ Exists.{C_RESET}"); return

        storage_in = input(f"{C_YELLOW}🔹 Disk [{DEFAULT_STORAGE}]: {C_RESET}").strip() or DEFAULT_STORAGE
        storage = validate_storage(storage_in)

        print("1. Subdomain | 2. Full Domain")
        if input("Select: ") == "1":
            domain = validate_domain(f"{input('Prefix: ').strip()}.{MAIN_DOMAIN}")
        else:
            domain = validate_domain(input("Full Domain: ").strip())

        port = validate_port(input(f"{C_YELLOW}🔹 Port: {C_RESET}").strip())
        
        repo_in = input(f"{C_YELLOW}🔹 GitHub URL: {C_RESET}").strip()
        if not (repo_in.startswith("https://") or repo_in.startswith("git@")):
            raise ValueError("Invalid Repo URL.")
        repo = repo_in

        # PATHS
        api_dir = os.path.join(storage, "api", name)
        db_dir = os.path.join(storage, "database", name)
        log_dir = os.path.join(api_dir, "logs")
        svc_file = f"/etc/systemd/system/{name}.service"

        # 2. EXECUTION
        print(f"\n{C_GREEN}⚙️  Deploying...{C_RESET}")
        
        for path in [api_dir, db_dir, log_dir]:
            os.makedirs(path, exist_ok=True)
            shutil.chown(path, user=SERVICE_USER, group=SERVICE_GROUP)

        # Clone and Setup Venv as Gaia (Privilege Drop)
        run_as_gaia(["git", "clone", repo, "."], cwd=api_dir)
        run_as_gaia([sys.executable, "-m", "venv", "venv"], cwd=api_dir)
        
        pip_bin = os.path.join(api_dir, "venv", "bin", "pip")
        
        # Install Gunicorn + Requirements
        pkgs = ["gunicorn", "flask", "flask-cors"]
        if os.path.exists(os.path.join(api_dir, "requirements.txt")):
            run_as_gaia([pip_bin, "install", "-r", "requirements.txt"], cwd=api_dir)
            # Ensure Gunicorn is present
            run_as_gaia([pip_bin, "install", "gunicorn"], cwd=api_dir)
        else:
            run_as_gaia([pip_bin, "install"] + pkgs, cwd=api_dir)

        # 3. SYSTEMD (Hardened + Gunicorn)
        with open(svc_file, "w") as f:
            f.write(f"""[Unit]
Description={name} (ATS Managed)
After=network.target

[Service]
User={SERVICE_USER}
Group={SERVICE_GROUP}
WorkingDirectory={api_dir}
Environment="PATH={api_dir}/venv/bin"
# Production Gunicorn Command
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
""")
        subprocess.check_call(["systemctl", "daemon-reload"])
        subprocess.check_call(["systemctl", "enable", name])
        subprocess.check_call(["systemctl", "start", name])

        # 4. VERIFICATION
        time.sleep(3)
        if subprocess.run(["systemctl", "is-active", name], stdout=subprocess.PIPE).stdout.strip() != b"active":
            raise Exception("Service process died immediately.")
        
        if not check_http_health(port):
            raise Exception("HTTP Health Check Failed.")

        # 5. FINALIZATION
        manage_cloudflare('add', domain=domain, port=port)
        
        db_query(
            "INSERT INTO services (name, port, domain, storage_path, repo_url) VALUES (?, ?, ?, ?, ?)",
            (name, port, domain, storage, repo)
        )
        
        duration = time.time() - start_time
        logger.info(f"Deployed {name} in {duration:.2f}s")
        print(f"{C_GREEN}✅ SUCCESS! {name} is live. ({duration:.2f}s){C_RESET}")

    except Exception as e:
        logger.error(f"DEPLOY FAIL: {e}")
        print(f"{C_RED}❌ FAILURE: {e}{C_RESET}")
        print("🔄 Rolling back...")
        
        # Comprehensive Rollback
        subprocess.run(["systemctl", "stop", name], stderr=subprocess.DEVNULL)
        subprocess.run(["systemctl", "disable", name], stderr=subprocess.DEVNULL)
        if os.path.exists(svc_file): os.remove(svc_file)
        subprocess.run(["systemctl", "daemon-reload"], stderr=subprocess.DEVNULL)
        
        if 'api_dir' in locals() and os.path.exists(api_dir): shutil.rmtree(api_dir)
        if 'db_dir' in locals() and os.path.exists(db_dir): shutil.rmtree(db_dir)
        if 'domain' in locals(): manage_cloudflare('remove', domain=domain)
        
        print("✅ Rollback complete.")
    
    input("Press Enter...")

def destroy_service():
    print(f"\n{C_RED}⚠️  DESTROY SERVICE{C_RESET}")
    name = input("Service Name: ").strip()
    svc = db_query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    if not svc: print("❌ Not found."); return

    if input("Type DELETE to confirm: ") != "DELETE": return

    print("🗑️  Cleaning up...")
    subprocess.run(["systemctl", "stop", name], stderr=subprocess.DEVNULL)
    subprocess.run(["systemctl", "disable", name], stderr=subprocess.DEVNULL)
    if os.path.exists(f"/etc/systemd/system/{name}.service"):
        os.remove(f"/etc/systemd/system/{name}.service")
    subprocess.run(["systemctl", "daemon-reload"], stderr=subprocess.DEVNULL)

    manage_cloudflare('remove', domain=svc['domain'])

    if os.path.exists(os.path.join(svc['storage_path'], "api", name)):
        shutil.rmtree(os.path.join(svc['storage_path'], "api", name))
    
    db_query("DELETE FROM services WHERE id=?", (svc['id'],))
    print(f"{C_GREEN}✅ Service Destroyed.{C_RESET}")

def view_logs():
    name = input("Service Name: ").strip()
    svc = db_query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
    if not svc: print("❌ Not found."); return

    log_file = os.path.join(svc['storage_path'], "api", name, "logs", "access.log")
    if not os.path.exists(log_file): print("Log file missing."); return
        
    print(f"{C_CYAN}📜 Log Stream (Ctrl+C to exit){C_RESET}")
    try:
        # Secure execution without shell
        subprocess.run(["tail", "-f", log_file])
    except KeyboardInterrupt:
        pass

def list_services():
    services = db_query("SELECT * FROM services", fetch_all=True)
    print(f"\n{C_CYAN}📋 ACTIVE SERVICES{C_RESET}")
    print(f"{'NAME':<15} {'PORT':<6} {'STATUS':<10} {'DOMAIN'}")
    print("-" * 60)
    for svc in services:
        res = subprocess.run(["systemctl", "is-active", svc['name']], stdout=subprocess.PIPE, text=True)
        color = C_GREEN if res.stdout.strip() == "active" else C_RED
        print(f"{svc['name']:<15} {svc['port']:<6} {color}{res.stdout.strip():<10}{C_RESET} {svc['domain']}")
    input("\nPress Enter...")

def ats_doctor():
    print(f"\n{C_GREEN}🚑 ATS DOCTOR DIAGNOSTICS{C_RESET}")
    checks = {
        "User 'gaia' exists": lambda: subprocess.run(["id", "gaia"], stdout=subprocess.DEVNULL).returncode == 0,
        "ATS DB Writable": lambda: os.access(DB_FILE, os.W_OK),
        "Cloudflare Config Valid": lambda: os.path.exists(CLOUDFLARE_CONFIG),
        "Cloudflared Running": lambda: subprocess.run(["systemctl", "is-active", "cloudflared"], stdout=subprocess.PIPE).stdout.strip() == b"active",
        "Systemd Access": lambda: subprocess.run(["systemctl", "--version"], stdout=subprocess.DEVNULL).returncode == 0,
        "Disk Mounted": lambda: os.path.ismount(DEFAULT_STORAGE) or os.path.exists(DEFAULT_STORAGE),
        "Internet Access": lambda: subprocess.run(["curl", "-I", "https://github.com"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    }

    for name, check in checks.items():
        try:
            status = "✅ PASS" if check() else "❌ FAIL"
        except:
            status = "❌ FAIL"
        print(f"{name:<30} {status}")
    input("\nPress Enter...")

def main():
    if os.geteuid() != 0:
        print(f"{C_RED}❌ MUST RUN AS ROOT{C_RESET}")
        sys.exit(1)
    
    lock_fd = acquire_lock()
    init_db()
    
    while True:
        os.system('clear')
        print(f"{C_CYAN}🚀 ATS v5.0 | PLATINUM EDITION{C_RESET}")
        print("1. Deploy Service")
        print("2. List Services")
        print("3. View Logs")
        print("4. Destroy Service")
        print("5. ATS Doctor")
        print("0. Exit")
        
        ch = input("\n>> ")
        if ch == "1": deploy_service()
        elif ch == "2": list_services()
        elif ch == "3": view_logs()
        elif ch == "4": destroy_service()
        elif ch == "5": ats_doctor()
        elif ch == "0": sys.exit()

if __name__ == "__main__":
    main()
