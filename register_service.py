#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATS Service Registration Tool
Manually add deployed services to ATS database
"""

import os
import sys
import sqlite3
import subprocess
import re
from datetime import datetime

# Configuration
DB_FILE = "/home/gaia/ats/ats.db"
CLOUDFLARE_CONFIG = "/etc/cloudflared/config.yml"
SYSTEMD_PATH = "/etc/systemd/system"

# Colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_CYAN = "\033[96m"


def print_header():
    os.system('clear')
    print(f"{C_CYAN}{C_BOLD}")
    print("=" * 60)
    print("   ATS SERVICE REGISTRATION TOOL")
    print("=" * 60)
    print(f"{C_RESET}\n")


def print_status(msg, status="info"):
    colors = {"info": C_CYAN, "success": C_GREEN, "error": C_RED, "warning": C_YELLOW}
    symbols = {"info": "▶", "success": "✓", "error": "✗", "warning": "⚠"}
    color = colors.get(status, C_CYAN)
    symbol = symbols.get(status, "▶")
    print(f"{color}{symbol} {msg}{C_RESET}")


def get_systemd_services():
    """Get list of all systemd service files"""
    try:
        services = []
        for file in os.listdir(SYSTEMD_PATH):
            if file.endswith('.service') and '@' not in file:
                service_name = file.replace('.service', '')
                services.append(service_name)
        return sorted(services)
    except Exception as e:
        print_status(f"Error listing services: {e}", "error")
        return []


def get_port_from_service(service_name):
    """Extract port from systemd service file"""
    try:
        service_file = os.path.join(SYSTEMD_PATH, f"{service_name}.service")
        with open(service_file, 'r') as f:
            content = f.read()
            match = re.search(r'--bind\s+127\.0\.0\.1:(\d+)', content)
            if match:
                return int(match.group(1))
        return None
    except Exception as e:
        print_status(f"Error reading service file: {e}", "error")
        return None


def get_domain_from_cloudflare(port):
    """Extract domain from Cloudflare config by port"""
    try:
        with open(CLOUDFLARE_CONFIG, 'r') as f:
            lines = f.readlines()
            
        for i, line in enumerate(lines):
            if f"localhost:{port}" in line:
                # Look backwards for hostname
                for j in range(i-1, max(0, i-5), -1):
                    if 'hostname:' in lines[j]:
                        domain = lines[j].split('hostname:')[1].strip()
                        return domain
        return None
    except Exception as e:
        print_status(f"Error reading Cloudflare config: {e}", "error")
        return None


def check_service_exists(service_name):
    """Check if service already exists in database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM services WHERE name=?", (service_name,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        print_status(f"Database error: {e}", "error")
        return False


def get_service_from_db(service_name):
    """Get service details from database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM services WHERE name=?", (service_name,))
        result = cursor.fetchone()
        conn.close()
        return dict(result) if result else None
    except Exception as e:
        print_status(f"Database error: {e}", "error")
        return None


def insert_service(service_data):
    """Insert service into database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO services (name, port, domain, storage_path, repo_url, workers, max_memory_mb, cpu_quota, deployment_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (
            service_data['name'],
            service_data['port'],
            service_data['domain'],
            service_data['storage_path'],
            service_data['repo_url'],
            service_data['workers'],
            service_data['max_memory_mb'],
            service_data['cpu_quota'],
            service_data['deployment_hash']
        ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print_status(f"Database insert error: {e}", "error")
        return False


def update_service(service_data):
    """Update existing service in database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE services 
            SET port=?, domain=?, storage_path=?, repo_url=?, workers=?, max_memory_mb=?, cpu_quota=?, updated_at=datetime('now')
            WHERE name=?
        """, (
            service_data['port'],
            service_data['domain'],
            service_data['storage_path'],
            service_data['repo_url'],
            service_data['workers'],
            service_data['max_memory_mb'],
            service_data['cpu_quota'],
            service_data['name']
        ))
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print_status(f"Database update error: {e}", "error")
        return False


def verify_registration(service_name):
    """Verify service is in database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT name, port, domain, created_at FROM services WHERE name=?", (service_name,))
        result = cursor.fetchone()
        conn.close()
        return dict(result) if result else None
    except Exception as e:
        print_status(f"Verification error: {e}", "error")
        return None


def main():
    print_header()
    
    # Check root
    if os.geteuid() != 0:
        print_status("This script must be run as root (use sudo)", "error")
        sys.exit(1)
    
    # Check database exists
    if not os.path.exists(DB_FILE):
        print_status(f"ATS database not found: {DB_FILE}", "error")
        sys.exit(1)
    
    print(f"{C_CYAN}Available systemd services:{C_RESET}\n")
    
    services = get_systemd_services()
    if not services:
        print_status("No services found", "warning")
        sys.exit(1)
    
    # Display services
    for idx, svc in enumerate(services[:20], 1):
        print(f"  {idx}. {svc}")
    
    if len(services) > 20:
        print(f"  ... and {len(services) - 20} more")
    
    print()
    
    # Get service name
    service_name = input(f"{C_BOLD}Enter service name:{C_RESET} ").strip()
    
    if not service_name:
        print_status("Service name cannot be empty", "error")
        sys.exit(1)
    
    # Check if service file exists
    service_file = os.path.join(SYSTEMD_PATH, f"{service_name}.service")
    if not os.path.exists(service_file):
        print_status(f"Service file not found: {service_file}", "error")
        sys.exit(1)
    
    print()
    print_status(f"Analyzing service: {service_name}", "info")
    print()
    
    # Extract port
    port = get_port_from_service(service_name)
    if not port:
        print_status("Could not auto-detect port", "warning")
        port_input = input(f"{C_BOLD}Enter port manually:{C_RESET} ").strip()
        try:
            port = int(port_input)
        except:
            print_status("Invalid port", "error")
            sys.exit(1)
    else:
        print_status(f"Detected port: {port}", "success")
    
    # Extract domain
    domain = get_domain_from_cloudflare(port)
    if not domain:
        print_status("Could not auto-detect domain", "warning")
        domain = input(f"{C_BOLD}Enter domain (e.g., api.gaiasentinel.online):{C_RESET} ").strip()
    else:
        print_status(f"Detected domain: {domain}", "success")
    
    # Get additional info
    print()
    print(f"{C_CYAN}Additional Configuration:{C_RESET}\n")
    
    storage_path = input(f"Storage path [{C_CYAN}/opt/extra1_1tb{C_RESET}]: ").strip() or "/opt/extra1_1tb"
    repo_url = input(f"GitHub repository URL: ").strip() or "https://github.com/unknown/repo"
    
    workers_input = input(f"Workers [{C_CYAN}4{C_RESET}]: ").strip()
    workers = int(workers_input) if workers_input else 4
    
    memory_input = input(f"Max Memory MB [{C_CYAN}512{C_RESET}]: ").strip()
    max_memory = int(memory_input) if memory_input else 512
    
    cpu_input = input(f"CPU Quota % [{C_CYAN}50{C_RESET}]: ").strip()
    cpu_quota = int(cpu_input) if cpu_input else 50
    
    # Prepare service data
    service_data = {
        'name': service_name,
        'port': port,
        'domain': domain,
        'storage_path': storage_path,
        'repo_url': repo_url,
        'workers': workers,
        'max_memory_mb': max_memory,
        'cpu_quota': cpu_quota,
        'deployment_hash': 'manual'
    }
    
    # Display summary
    print()
    print(f"{C_GREEN}{'=' * 60}{C_RESET}")
    print(f"{C_GREEN}{C_BOLD}Service Summary{C_RESET}")
    print(f"{C_GREEN}{'=' * 60}{C_RESET}")
    print(f"  {C_BOLD}Name:{C_RESET}       {service_data['name']}")
    print(f"  {C_BOLD}Port:{C_RESET}       {service_data['port']}")
    print(f"  {C_BOLD}Domain:{C_RESET}     {service_data['domain']}")
    print(f"  {C_BOLD}Storage:{C_RESET}    {service_data['storage_path']}")
    print(f"  {C_BOLD}Repo:{C_RESET}       {service_data['repo_url']}")
    print(f"  {C_BOLD}Workers:{C_RESET}    {service_data['workers']}")
    print(f"  {C_BOLD}Memory:{C_RESET}     {service_data['max_memory_mb']}MB")
    print(f"  {C_BOLD}CPU Quota:{C_RESET}  {service_data['cpu_quota']}%")
    print(f"{C_GREEN}{'=' * 60}{C_RESET}")
    print()
    
    # Check if exists
    if check_service_exists(service_name):
        print_status(f"Service '{service_name}' already exists in database", "warning")
        existing = get_service_from_db(service_name)
        print()
        print(f"{C_YELLOW}Existing record:{C_RESET}")
        print(f"  Port: {existing['port']}")
        print(f"  Domain: {existing['domain']}")
        print()
        
        confirm = input(f"{C_BOLD}Update existing record? (yes/no):{C_RESET} ").strip().lower()
        
        if confirm != 'yes':
            print_status("Cancelled", "warning")
            sys.exit(0)
        
        print()
        print_status("Updating service...", "info")
        
        if update_service(service_data):
            print_status("Service updated successfully!", "success")
        else:
            print_status("Failed to update service", "error")
            sys.exit(1)
    else:
        confirm = input(f"{C_BOLD}Register this service? (yes/no):{C_RESET} ").strip().lower()
        
        if confirm != 'yes':
            print_status("Cancelled", "warning")
            sys.exit(0)
        
        print()
        print_status("Registering service...", "info")
        
        if insert_service(service_data):
            print_status("Service registered successfully!", "success")
        else:
            print_status("Failed to register service", "error")
            sys.exit(1)
    
    # Verify
    print()
    print_status("Verifying registration...", "info")
    print()
    
    verified = verify_registration(service_name)
    if verified:
        print(f"{C_GREEN}✓ Service verified in database:{C_RESET}")
        print(f"  Name:       {verified['name']}")
        print(f"  Port:       {verified['port']}")
        print(f"  Domain:     {verified['domain']}")
        print(f"  Created:    {verified['created_at']}")
    else:
        print_status("Verification failed - service not found", "error")
        sys.exit(1)
    
    print()
    print(f"{C_GREEN}{'=' * 60}{C_RESET}")
    print(f"{C_GREEN}{C_BOLD}✓ REGISTRATION COMPLETE{C_RESET}")
    print(f"{C_GREEN}{'=' * 60}{C_RESET}")
    print()
    print(f"{C_CYAN}Service should now appear in ATS!{C_RESET}")
    print(f"Run: {C_BOLD}sudo python3 /home/gaia/ats/ats.py{C_RESET}")
    print(f"Then choose: {C_BOLD}Option 2 (List Services){C_RESET}")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}Cancelled by user{C_RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{C_RED}Error: {e}{C_RESET}")
        sys.exit(1)
