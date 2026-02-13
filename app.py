#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATS | AUTOMATED TECH STACK | SUPREMACY EDITION
Version: 6.0.0
Architect: Abinaav K
"""

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
import datetime
import platform
import threading
from typing import Optional, List, Dict, Tuple, Any

# --- DEPENDENCY CHECK & FALLBACKS ---
try:
    import psutil
except ImportError:
    psutil = None

# --- CONFIGURATION SUBSYSTEM ---
class Config:
    APP_NAME = "ATS SUPREMACY"
    VERSION = "6.0.0"
    HOME_DIR = "/home/gaia/ats"
    
    # Files renamed to ATS standard
    DB_PATH = os.path.join(HOME_DIR, "ats.db")
    LOG_PATH = os.path.join(HOME_DIR, "ats.log")
    AUDIT_PATH = os.path.join(HOME_DIR, "ats_audit.trace")
    LOCK_PATH = "/tmp/ats.lock"
    
    # User / Group
    SERVICE_USER = "gaia"
    SERVICE_GROUP = "gaia"
    
    # Network
    MAIN_DOMAIN = "gaiasentinel.online"
    CLOUDFLARE_CONFIG = "/etc/cloudflared/config.yml"
    
    # Storage
    DEFAULT_STORAGE = "/opt/extra1_1tb"
    BACKUP_DIR = os.path.join(DEFAULT_STORAGE, "backups")
    
    # Safety
    BLOCKED_PATHS = ["/", "/bin", "/boot", "/dev", "/etc", "/lib", "/root", "/run", "/sys", "/usr", "/var"]

# --- VISUAL STYLING ---
class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    
    @staticmethod
    def header():
        os.system('clear')
        print(f"{Style.CYAN}{Style.BOLD}")
        print(r"""
       _/_/    _/_/_/_/_/    _/_/_/   
    _/    _/      _/      _/          
   _/_/_/_/      _/        _/_/       
  _/    _/      _/            _/      
 _/    _/      _/      _/_/_/         
                                      
    AUTOMATED TECH STACK v{0}
    {Style.RESET}""".format(Config.VERSION))
        print(f"{Style.CYAN}{'='*60}{Style.RESET}")

# --- LOGGING & AUDITING ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.FileHandler(Config.LOG_PATH), logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger()

def audit_log(action: str, target: str):
    """Writes immutable audit trail."""
    timestamp = datetime.datetime.now().isoformat()
    entry = f"{timestamp} | ACTION: {action} | TARGET: {target} | USER: {os.getlogin()}\n"
    try:
        with open(Config.AUDIT_PATH, "a") as f:
            f.write(entry)
    except Exception as e:
        logger.error(f"Audit Log Failed: {e}")

# --- DATABASE KERNEL ---
class Database:
    @staticmethod
    def initialize():
        with sqlite3.connect(Config.DB_PATH) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    port INTEGER UNIQUE NOT NULL,
                    domain TEXT UNIQUE NOT NULL,
                    storage_path TEXT NOT NULL,
                    repo_url TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    health TEXT DEFAULT 'unknown',
                    deploy_count INTEGER DEFAULT 1,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS backups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    service_name TEXT,
                    filename TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
        # Security: Only owner can read/write DB
        os.chmod(Config.DB_PATH, 0o600)

    @staticmethod
    def query(sql: str, args: tuple = (), fetch_all: bool = False, fetch_one: bool = False):
        try:
            with sqlite3.connect(Config.DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(sql, args)
                if fetch_one: return cursor.fetchone()
                if fetch_all: return cursor.fetchall()
                return None
        except sqlite3.Error as e:
            logger.error(f"Database Error: {e}")
            return None

# --- UTILITIES ---
class Utils:
    @staticmethod
    def run_command(cmd: List[str], cwd: Optional[str] = None, as_user: Optional[str] = None, timeout: int = 300) -> bool:
        """Executes system commands with privilege handling."""
        env = os.environ.copy()
        if as_user:
            cmd = ["sudo", "-u", as_user] + cmd
            env["HOME"] = f"/home/{as_user}"
        
        try:
            logger.debug(f"EXEC: {' '.join(cmd)}")
            subprocess.check_call(cmd, cwd=cwd, env=env, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False
        except subprocess.TimeoutExpired:
            logger.error("Command timed out.")
            return False

    @staticmethod
    def check_socket(port: int) -> bool:
        """Returns True if port is IN USE."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            return sock.connect_ex(('127.0.0.1', port)) == 0

    @staticmethod
    def acquire_lock():
        """System-wide singleton lock."""
        lock_fd = open(Config.LOCK_PATH, 'w')
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            atexit.register(lambda: fcntl.flock(lock_fd, fcntl.LOCK_UN))
            return lock_fd
        except IOError:
            print(f"{Style.RED}CRITICAL: ATS is locked by another process.{Style.RESET}")
            sys.exit(1)

# --- SYSTEM MONITOR ---
class Telemetry:
    @staticmethod
    def get_status() -> dict:
        data = {
            "cpu": 0.0,
            "ram_used": 0,
            "ram_total": 0,
            "disk_used": 0,
            "disk_total": 0,
            "load": os.getloadavg()[0]
        }
        
        if psutil:
            data["cpu"] = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory()
            data["ram_used"] = round(mem.used / (1024**3), 1)
            data["ram_total"] = round(mem.total / (1024**3), 1)
            disk = psutil.disk_usage('/')
            data["disk_used"] = round(disk.used / (1024**3), 1)
            data["disk_total"] = round(disk.total / (1024**3), 1)
        else:
            # Fallback for RAM/Disk
            try:
                with os.popen("free -m | grep Mem | awk '{print $2,$3}'") as f:
                    total, used = map(int, f.read().split())
                    data["ram_total"] = round(total/1024, 1)
                    data["ram_used"] = round(used/1024, 1)
            except: pass
            
        return data

# --- CORE MODULES ---

class Validator:
    @staticmethod
    def storage(path: str) -> str:
        if not os.path.exists(path):
            raise ValueError(f"Path {path} does not exist.")
        clean = os.path.abspath(path)
        if clean in Config.BLOCKED_PATHS:
            raise ValueError(f"CRITICAL: Path {clean} is restricted.")
        return clean

    @staticmethod
    def domain(domain: str) -> str:
        if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
            raise ValueError("Invalid domain syntax.")
        if Database.query("SELECT 1 FROM services WHERE domain=?", (domain,), fetch_one=True):
            raise ValueError("Domain collision detected.")
        return domain

    @staticmethod
    def port(port_str: str) -> int:
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError("Port must be numeric.")
        if not (1024 <= port <= 65535):
            raise ValueError("Port out of safe range (1024-65535).")
        if Database.query("SELECT 1 FROM services WHERE port=?", (port,), fetch_one=True):
            raise ValueError("Port registered in Database.")
        if Utils.check_socket(port):
            raise ValueError("Port active on Interface (OS Conflict).")
        return port

class CloudflareManager:
    @staticmethod
    def update(action: str, domain: str, port: int = 0):
        """Transactional Cloudflare YAML modification."""
        try:
            shutil.copy(Config.CLOUDFLARE_CONFIG, Config.CLOUDFLARE_CONFIG + ".bak")
            
            with open(Config.CLOUDFLARE_CONFIG, 'r') as f:
                config = yaml.safe_load(f)

            if not config or 'ingress' not in config:
                raise ValueError("Corrupt Cloudflare Config.")

            ingress = config['ingress']
            
            if action == "ADD":
                if any(r.get('hostname') == domain for r in ingress): return
                new_rule = {'hostname': domain, 'service': f'http://localhost:{port}'}
                # Find 404 catch-all
                idx = next((i for i, r in enumerate(ingress) if r.get('service') == 'http_status:404'), -1)
                if idx != -1: ingress.insert(idx, new_rule)
                else: ingress.append(new_rule)
                
            elif action == "REMOVE":
                config['ingress'] = [r for r in ingress if r.get('hostname') != domain]

            with open(Config.CLOUDFLARE_CONFIG, 'w') as f:
                yaml.dump(config, f, sort_keys=False)

            Utils.run_command(["systemctl", "restart", "cloudflared"])
            logger.info(f"Cloudflare {action} {domain} success.")
            
        except Exception as e:
            logger.error(f"Cloudflare Error: {e}")
            # Auto-restore backup
            shutil.copy(Config.CLOUDFLARE_CONFIG + ".bak", Config.CLOUDFLARE_CONFIG)
            raise

class ServiceManager:
    @staticmethod
    def get_path(storage: str, name: str) -> str:
        # Heuristic path detection
        legacy = os.path.join(storage, "websites", name)
        return legacy if os.path.exists(legacy) else os.path.join(storage, "api", name)

    @staticmethod
    def generate_systemd(name: str, api_dir: str, log_dir: str, port: int):
        content = f"""[Unit]
Description={name} [ATS MANAGED]
After=network.target

[Service]
User={Config.SERVICE_USER}
Group={Config.SERVICE_GROUP}
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

    @staticmethod
    def health_check(name: str, port: int) -> bool:
        # 1. Systemd Check
        res = subprocess.run(["systemctl", "is-active", name], stdout=subprocess.PIPE)
        if res.stdout.strip() != b"active": return False
        
        # 2. HTTP Check
        print(f"{Style.YELLOW}   >>> PING CHECK: localhost:{port}...{Style.RESET}", end='\r')
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

    @staticmethod
    def deploy():
        Style.header()
        print(f"{Style.CYAN}INITIATING DEPLOYMENT PROTOCOL...{Style.RESET}\n")
        
        try:
            # --- INPUT PHASE ---
            name = input(f"{Style.BOLD}SERVICE IDENTIFIER:{Style.RESET} ").strip()
            if not re.match(r"^[a-zA-Z0-9_-]+$", name): raise ValueError("Invalid syntax.")
            if Database.query("SELECT 1 FROM services WHERE name=?", (name,), fetch_one=True):
                raise ValueError("Service ID exists.")

            store_in = input(f"{Style.BOLD}STORAGE TARGET [{Config.DEFAULT_STORAGE}]:{Style.RESET} ").strip() or Config.DEFAULT_STORAGE
            storage = Validator.storage(store_in)
            
            dom_in = input(f"{Style.BOLD}DOMAIN CONFIG (1=Sub, 2=Full):{Style.RESET} ").strip()
            if dom_in == "1":
                prefix = input("   SUBDOMAIN PREFIX: ").strip()
                domain = Validator.domain(f"{prefix}.{Config.MAIN_DOMAIN}")
            else:
                domain = Validator.domain(input("   FULL DOMAIN: ").strip())

            port = Validator.port(input(f"{Style.BOLD}INTERNAL PORT:{Style.RESET} ").strip())
            
            repo_in = input(f"{Style.BOLD}GIT SOURCE:{Style.RESET} ").strip()
            if not (repo_in.startswith("http") or repo_in.startswith("git@")):
                raise ValueError("Invalid Git URL.")
            repo = repo_in

            # --- PREPARATION PHASE ---
            api_dir = os.path.join(storage, "api", name)
            db_dir = os.path.join(storage, "database", name)
            log_dir = os.path.join(api_dir, "logs")
            svc_file = f"/etc/systemd/system/{name}.service"

            print(f"\n{Style.GREEN}>>> PROVISIONING RESOURCES...{Style.RESET}")
            for d in [api_dir, db_dir, log_dir]:
                os.makedirs(d, exist_ok=True)
                shutil.chown(d, user=Config.SERVICE_USER, group=Config.SERVICE_GROUP)

            # --- EXECUTION PHASE ---
            print(f"{Style.BLUE}>>> CLONING SOURCE CODE...{Style.RESET}")
            Utils.run_command(["git", "clone", repo, "."], cwd=api_dir, as_user=Config.SERVICE_USER)
            
            print(f"{Style.BLUE}>>> BUILDING ENVIRONMENT...{Style.RESET}")
            Utils.run_command([sys.executable, "-m", "venv", "venv"], cwd=api_dir, as_user=Config.SERVICE_USER)
            
            pip = os.path.join(api_dir, "venv", "bin", "pip")
            reqs = os.path.join(api_dir, "requirements.txt")
            install_cmd = [pip, "install", "gunicorn", "flask", "flask-cors"]
            
            if os.path.exists(reqs):
                Utils.run_command([pip, "install", "-r", "requirements.txt"], cwd=api_dir, as_user=Config.SERVICE_USER)
                Utils.run_command([pip, "install", "gunicorn"], cwd=api_dir, as_user=Config.SERVICE_USER)
            else:
                Utils.run_command(install_cmd, cwd=api_dir, as_user=Config.SERVICE_USER)

            # --- ACTIVATION PHASE ---
            print(f"{Style.PURPLE}>>> CONFIGURING SYSTEMD...{Style.RESET}")
            ServiceManager.generate_systemd(name, api_dir, log_dir, port)
            Utils.run_command(["systemctl", "daemon-reload"])
            Utils.run_command(["systemctl", "enable", name])
            Utils.run_command(["systemctl", "start", name])

            # --- VERIFICATION PHASE ---
            print(f"{Style.YELLOW}>>> PERFORMING HEALTH CHECKS...{Style.RESET}")
            time.sleep(3)
            if not ServiceManager.health_check(name, port):
                raise Exception("Service failed health checks.")

            # --- ROUTING PHASE ---
            print(f"{Style.CYAN}>>> UPDATING EDGE NETWORK...{Style.RESET}")
            CloudflareManager.update("ADD", domain, port)

            # --- FINALIZATION ---
            Database.query(
                "INSERT INTO services (name, port, domain, storage_path, repo_url) VALUES (?, ?, ?, ?, ?)",
                (name, port, domain, storage, repo)
            )
            audit_log("DEPLOY", name)
            print(f"\n{Style.GREEN}{Style.BOLD}✅ DEPLOYMENT SUCCESSFUL | https://{domain}{Style.RESET}")

        except Exception as e:
            logger.error(f"Deploy Failed: {e}")
            print(f"\n{Style.RED}❌ CRITICAL FAILURE: {e}{Style.RESET}")
            print(f"{Style.RED}>>> INITIATING ROLLBACK PROTOCOL...{Style.RESET}")
            # Rollback logic
            try:
                if 'name' in locals():
                    Utils.run_command(["systemctl", "stop", name])
                    Utils.run_command(["systemctl", "disable", name])
                    if os.path.exists(f"/etc/systemd/system/{name}.service"):
                        os.remove(f"/etc/systemd/system/{name}.service")
                    Utils.run_command(["systemctl", "daemon-reload"])
                if 'api_dir' in locals() and os.path.exists(api_dir): shutil.rmtree(api_dir)
                if 'db_dir' in locals() and os.path.exists(db_dir): shutil.rmtree(db_dir)
                if 'domain' in locals(): CloudflareManager.update("REMOVE", domain)
            except: pass
            print(">>> ROLLBACK COMPLETE.")

        input(f"\n{Style.DIM}Press Enter to return to Command...{Style.RESET}")

    @staticmethod
    def terminate():
        Style.header()
        print(f"{Style.RED}TERMINATION PROTOCOL{Style.RESET}\n")
        name = input("TARGET IDENTIFIER: ").strip()
        svc = Database.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
        
        if not svc:
            print("TARGET NOT FOUND.")
            time.sleep(1); return

        confirm = input(f"{Style.RED}TYPE 'DELETE' TO CONFIRM DESTRUCTION OF {name}:{Style.RESET} ")
        if confirm != "DELETE": return

        print(">>> STOPPING PROCESS...")
        Utils.run_command(["systemctl", "stop", name])
        Utils.run_command(["systemctl", "disable", name])
        
        print(">>> REMOVING CONFIGURATION...")
        svc_path = f"/etc/systemd/system/{name}.service"
        if os.path.exists(svc_path): os.remove(svc_path)
        Utils.run_command(["systemctl", "daemon-reload"])

        print(">>> CLEANING NETWORK...")
        CloudflareManager.update("REMOVE", svc['domain'])

        print(">>> WIPING DATA...")
        service_root = ServiceManager.get_path(svc['storage_path'], name)
        if os.path.exists(service_root): shutil.rmtree(service_root)
        
        Database.query("DELETE FROM services WHERE id=?", (svc['id'],))
        audit_log("DESTROY", name)
        print(f"{Style.GREEN}TARGET ELIMINATED.{Style.RESET}")
        time.sleep(2)

    @staticmethod
    def dashboard():
        while True:
            Style.header()
            
            # --- TELEMETRY PANEL ---
            stats = Telemetry.get_status()
            print(f"{Style.DIM}SYSTEM STATUS:{Style.RESET}")
            print(f" CPU: {stats['cpu']}%  |  RAM: {stats['ram_used']}/{stats['ram_total']} GB  |  DISK: {stats['disk_used']}/{stats['disk_total']} GB  |  LOAD: {stats['load']}")
            print(f"{Style.CYAN}{'='*60}{Style.RESET}")

            # --- SERVICES PANEL ---
            services = Database.query("SELECT * FROM services", fetch_all=True)
            print(f"{Style.BOLD}{'NAME':<15} {'PORT':<6} {'STATUS':<10} {'DOMAIN'}{Style.RESET}")
            print("-" * 60)
            
            if not services:
                print(f"{Style.DIM}   NO ACTIVE SIGNALS DETECTED{Style.RESET}")
            else:
                for s in services:
                    # Live check
                    res = subprocess.run(["systemctl", "is-active", s['name']], stdout=subprocess.PIPE)
                    is_active = res.stdout.strip() == b"active"
                    status_color = Style.GREEN if is_active else Style.RED
                    status_text = "ONLINE" if is_active else "OFFLINE"
                    print(f"{s['name']:<15} {s['port']:<6} {status_color}{status_text:<10}{Style.RESET} {s['domain']}")

            print(f"{Style.CYAN}{'='*60}{Style.RESET}")
            print(f"{Style.BOLD}COMMANDS:{Style.RESET}")
            print(" [1] DEPLOY NEW SERVICE      [4] VIEW LOGS")
            print(" [2] TERMINATE SERVICE       [5] BACKUP CENTER")
            print(" [3] SERVICE OPERATIONS      [6] SYSTEM DIAGNOSTICS")
            print(f" {Style.RED}[0] SHUTDOWN{Style.RESET}")

            choice = input(f"\n{Style.PURPLE}ATS>{Style.RESET} ")
            
            if choice == "1": ServiceManager.deploy()
            elif choice == "2": ServiceManager.terminate()
            elif choice == "3": ServiceManager.operations()
            elif choice == "4": ServiceManager.logs()
            elif choice == "5": BackupSystem.menu()
            elif choice == "6": Diagnostics.run()
            elif choice == "0": sys.exit()

    @staticmethod
    def operations():
        name = input("TARGET SERVICE: ").strip()
        svc = Database.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
        if not svc: return

        print("1.RESTART  2.STOP  3.START  4.GIT PULL")
        op = input("OP: ")
        if op == "1": Utils.run_command(["systemctl", "restart", name])
        elif op == "2": Utils.run_command(["systemctl", "stop", name])
        elif op == "3": Utils.run_command(["systemctl", "start", name])
        elif op == "4":
            path = ServiceManager.get_path(svc['storage_path'], name)
            Utils.run_command(["git", "pull"], cwd=path, as_user=Config.SERVICE_USER)
            Utils.run_command(["systemctl", "restart", name])
            audit_log("UPDATE", name)
            print("Updated.")
            time.sleep(1)

    @staticmethod
    def logs():
        name = input("TARGET SERVICE: ").strip()
        svc = Database.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
        if not svc: return
        
        path = ServiceManager.get_path(svc['storage_path'], name)
        log_file = os.path.join(path, "logs", "access.log")
        
        if not os.path.exists(log_file):
            print("NO LOGS FOUND.")
            time.sleep(1); return

        print(f"{Style.CYAN}STREAMING LOGS (CTRL+C TO EXIT)...{Style.RESET}")
        try:
            subprocess.run(["tail", "-f", log_file])
        except KeyboardInterrupt: pass

# --- BACKUP SUBSYSTEM ---
class BackupSystem:
    @staticmethod
    def create(name: str):
        svc = Database.query("SELECT * FROM services WHERE name=?", (name,), fetch_one=True)
        if not svc: return

        if not os.path.exists(Config.BACKUP_DIR):
            os.makedirs(Config.BACKUP_DIR)
            shutil.chown(Config.BACKUP_DIR, Config.SERVICE_USER, Config.SERVICE_GROUP)

        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M")
        filename = f"{name}_backup_{ts}"
        src = ServiceManager.get_path(svc['storage_path'], name)
        dst = os.path.join(Config.BACKUP_DIR, filename)
        
        print(">>> COMPRESSING ASSETS...")
        shutil.make_archive(dst, 'zip', src)
        
        Database.query("INSERT INTO backups (service_name, filename) VALUES (?, ?)", (name, filename + ".zip"))
        print(f"{Style.GREEN}BACKUP SECURED: {filename}.zip{Style.RESET}")
        
        # Rotation policy: Keep last 5
        backups = Database.query("SELECT id, filename FROM backups WHERE service_name=? ORDER BY timestamp DESC", (name,), fetch_all=True)
        if len(backups) > 5:
            for old in backups[5:]:
                f_path = os.path.join(Config.BACKUP_DIR, old['filename'])
                if os.path.exists(f_path): os.remove(f_path)
                Database.query("DELETE FROM backups WHERE id=?", (old['id'],))
            print(">>> ROTATION POLICY APPLIED.")

    @staticmethod
    def menu():
        name = input("TARGET SERVICE FOR BACKUP: ").strip()
        BackupSystem.create(name)
        time.sleep(2)

# --- DIAGNOSTICS ---
class Diagnostics:
    @staticmethod
    def run():
        Style.header()
        print(f"{Style.YELLOW}SYSTEM DIAGNOSTICS{Style.RESET}")
        
        checks = [
            ("Root Privileges", os.geteuid() == 0),
            ("Database Integrity", os.access(Config.DB_PATH, os.W_OK)),
            ("User 'gaia'", subprocess.call(["id", Config.SERVICE_USER], stdout=subprocess.DEVNULL) == 0),
            ("Cloudflare Config", os.path.exists(Config.CLOUDFLARE_CONFIG)),
            ("Cloudflare Service", subprocess.call(["systemctl", "is-active", "cloudflared"], stdout=subprocess.DEVNULL) == 0),
            ("Internet Connectivity", subprocess.call(["curl", "-I", "https://github.com"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0),
            ("Disk Mount", os.path.exists(Config.DEFAULT_STORAGE)),
        ]
        
        for name, result in checks:
            status = f"{Style.GREEN}PASS{Style.RESET}" if result else f"{Style.RED}FAIL{Style.RESET}"
            print(f"{name:<25} {status}")
        
        input("\nPress Enter...")

# --- MAIN KERNEL ---
def bootstrap():
    if os.geteuid() != 0:
        print(f"{Style.RED}FATAL: ROOT PRIVILEGES REQUIRED.{Style.RESET}")
        sys.exit(1)

    # Initialize components
    Utils.acquire_lock()
    if not os.path.exists(Config.HOME_DIR): os.makedirs(Config.HOME_DIR)
    Database.initialize()
    
    # Enter Main Loop
    try:
        ServiceManager.dashboard()
    except KeyboardInterrupt:
        print("\nSHUTDOWN.")
        sys.exit(0)

if __name__ == "__main__":
    bootstrap()
