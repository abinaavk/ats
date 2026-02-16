#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATS Service Registration Tool - ENHANCED
Intelligently detects service paths and validates configuration
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


def print_status(msg, status="info"):
    colors = {"info": C_CYAN, "success": C_GREEN, "error": C_RED, "warning": C_YELLOW}
    symbols = {"info": "▶", "success": "✓", "error": "✗", "warning": "⚠"}
    color = colors.get(status, C_CYAN)
    symbol = symbols.get(status, "▶")
    print(f"{color}{symbol} {msg}{C_RESET}")


def get_service_working_directory(service_name):
    """Extract WorkingDirectory from systemd service file"""
    try:
        result = subprocess.run(
            ["systemctl", "cat", service_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        for line in result.stdout.split('\n'):
            if 'WorkingDirectory=' in line:
                return line.split('WorkingDirectory=')[1].strip()
        
        return None
    except Exception as e:
        print_status(f"Error reading service: {e}", "error")
        return None


def extract_base_storage_path(working_dir):
    """Extract base storage path from full working directory"""
    if not working_dir:
        return None
    
    # Handle: /opt/extra1_1tb/api/myservice -> /opt/extra1_1tb
    if '/api/' in working_dir:
        return working_dir.split('/api/')[0]
    
    # Handle: /opt/extra1_1tb/websites/myservice -> /opt/extra1_1tb
    elif '/websites/' in working_dir:
        return working_dir.split('/websites/')[0]
    
    # Non-standard: use parent directory
    else:
        return os.path.dirname(working_dir)


def validate_storage_path(path, service_name):
    """
    Validate and normalize storage path.
    If user provides full service path, extract base.
    """
    if not path:
        return None
    
    path = path.rstrip('/')
    
    # Check if user provided the full service path by mistake
    # Example: /opt/extra1_1tb/api/myservice
    if path.endswith(f'/api/{service_name}'):
        base = path.replace(f'/api/{service_name}', '')
        print_status(f"Detected full service path, using base: {base}", "warning")
        return base
    
    if path.endswith(f'/websites/{service_name}'):
        base = path.replace(f'/websites/{service_name}', '')
        print_status(f"Detected full service path, using base: {base}", "warning")
        return base
    
    # Check if path ends with /api or /websites (remove them)
    if path.endswith('/api'):
        base = path[:-4]
        print_status(f"Removing /api suffix, using: {base}", "warning")
        return base
    
    if path.endswith('/websites'):
        base = path[:-9]
        print_status(f"Removing /websites suffix, using: {base}", "warning")
        return base
    
    # Path looks good as base storage
    return path


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
        return None


def get_domain_from_cloudflare(port):
    """Extract domain from Cloudflare config by port"""
    try:
        with open(CLOUDFLARE_CONFIG, 'r') as f:
            lines = f.readlines()
        
        for i, line in enumerate(lines):
            if f"localhost:{port}" in line:
                for j in range(i-1, max(0, i-5), -1):
                    if 'hostname:' in lines[j]:
                        domain = lines[j].split('hostname:')[1].strip()
                        return domain
        return None
    except Exception as e:
        return None


def check_service_exists(service_name):
    """Check if service exists in database"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM services WHERE name=?", (service_name,))
        result = cursor.fetchone()
        conn.close()
        return result is not None
    except Exception as e:
        return False


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
        print_status(f"Database error: {e}", "error")
        return False


def main():
    os.system('clear')
    print(f"{C_CYAN}{C_BOLD}{'=' * 60}")
    print("   ATS SERVICE REGISTRATION TOOL")
    print(f"{'=' * 60}{C_RESET}\n")
    
    if os.geteuid() != 0:
        print_status("Run with sudo", "error")
        sys.exit(1)
    
    # Get service name
    service_name = input(f"{C_BOLD}Service name:{C_RESET} ").strip()
    
    if not service_name:
        print_status("Service name required", "error")
        sys.exit(1)
    
    service_file = os.path.join(SYSTEMD_PATH, f"{service_name}.service")
    if not os.path.exists(service_file):
        print_status(f"Service not found: {service_file}", "error")
        sys.exit(1)
    
    print()
    print_status(f"Analyzing: {service_name}", "info")
    print()
    
    # Detect service location
    working_dir = get_service_working_directory(service_name)
    if working_dir:
        print_status(f"Service directory: {working_dir}", "success")
        
        base_storage = extract_base_storage_path(working_dir)
        print_status(f"Base storage: {base_storage}", "success")
        
        print()
        print(f"{C_CYAN}Storage path options:{C_RESET}")
        print(f"  1. Use detected path: {base_storage}")
        print(f"  2. Enter custom path")
        
        choice = input(f"\n{C_BOLD}Choice (1/2) [{C_CYAN}1{C_RESET}]:{C_RESET} ").strip()
        
        if choice == '2':
            custom_path = input(f"{C_BOLD}Enter storage path:{C_RESET} ").strip()
            storage_path = validate_storage_path(custom_path, service_name)
        else:
            storage_path = base_storage
    else:
        print_status("Could not detect service location", "warning")
        print()
        custom_path = input(f"{C_BOLD}Storage path [{C_CYAN}/opt/extra1_1tb{C_RESET}]:{C_RESET} ").strip() or "/opt/extra1_1tb"
        storage_path = validate_storage_path(custom_path, service_name)
    
    # Verify the computed path makes sense
    expected_service_dir = os.path.join(storage_path, "api", service_name)
    print()
    print_status(f"Computed service location: {expected_service_dir}", "info")
    
    if working_dir and working_dir != expected_service_dir:
        print_status(f"WARNING: Actual location is: {working_dir}", "warning")
        print()
        print(f"{C_YELLOW}Path mismatch detected!{C_RESET}")
        print(f"  Expected: {expected_service_dir}")
        print(f"  Actual:   {working_dir}")
        print()
        
        fix_choice = input(f"{C_BOLD}Use actual path? (yes/no) [{C_CYAN}yes{C_RESET}]:{C_RESET} ").strip().lower()
        
        if fix_choice in ['', 'yes', 'y']:
            # Use the actual working directory's base
            storage_path = extract_base_storage_path(working_dir)
            print_status(f"Updated to: {storage_path}", "success")
    
    # Get port
    print()
    port = get_port_from_service(service_name)
    if port:
        print_status(f"Port: {port}", "success")
    else:
        port = int(input(f"{C_BOLD}Enter port:{C_RESET} ").strip())
    
    # Get domain
    domain = get_domain_from_cloudflare(port)
    if domain:
        print_status(f"Domain: {domain}", "success")
    else:
        domain = input(f"{C_BOLD}Enter domain:{C_RESET} ").strip()
    
    # Additional info
    print()
    print(f"{C_CYAN}Additional configuration:{C_RESET}\n")
    repo_url = input(f"GitHub URL: ").strip() or "https://github.com/unknown/repo"
    workers = int(input(f"Workers [{C_CYAN}4{C_RESET}]: ").strip() or "4")
    max_memory = int(input(f"Memory MB [{C_CYAN}512{C_RESET}]: ").strip() or "512")
    cpu_quota = int(input(f"CPU % [{C_CYAN}50{C_RESET}]: ").strip() or "50")
    
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
    
    # Summary
    print()
    print(f"{C_GREEN}{'=' * 60}{C_RESET}")
    print(f"{C_GREEN}{C_BOLD}Service Registration Summary{C_RESET}")
    print(f"{C_GREEN}{'=' * 60}{C_RESET}")
    print(f"  {C_BOLD}Name:{C_RESET}       {service_data['name']}")
    print(f"  {C_BOLD}Port:{C_RESET}       {service_data['port']}")
    print(f"  {C_BOLD}Domain:{C_RESET}     {service_data['domain']}")
    print(f"  {C_BOLD}Storage:{C_RESET}    {service_data['storage_path']}")
    print(f"  {C_BOLD}Repo:{C_RESET}       {service_data['repo_url']}")
    print(f"  {C_BOLD}Workers:{C_RESET}    {service_data['workers']}")
    print(f"  {C_BOLD}Memory:{C_RESET}     {service_data['max_memory_mb']}MB")
    print(f"  {C_BOLD}CPU:{C_RESET}        {service_data['cpu_quota']}%")
    print(f"{C_GREEN}{'=' * 60}{C_RESET}")
    
    # Show what ATS will construct
    print()
    print(f"{C_CYAN}ATS will expect service at:{C_RESET}")
    print(f"  Code:     {storage_path}/api/{service_name}")
    print(f"  Database: {storage_path}/database/{service_name}")
    print(f"  Logs:     {storage_path}/api/{service_name}/logs")
    
    if working_dir:
        print()
        print(f"{C_CYAN}Actual service location:{C_RESET}")
        print(f"  {working_dir}")
        
        if working_dir == os.path.join(storage_path, "api", service_name):
            print(f"  {C_GREEN}✓ Paths match!{C_RESET}")
        else:
            print(f"  {C_YELLOW}⚠ Paths don't match - service may not work correctly{C_RESET}")
    
    print()
    
    if check_service_exists(service_name):
        print_status("Service already exists in database", "warning")
        sys.exit(1)
    
    confirm = input(f"{C_BOLD}Register this service? (yes/no):{C_RESET} ").strip().lower()
    if confirm != 'yes':
        print_status("Cancelled", "warning")
        sys.exit(0)
    
    print()
    if insert_service(service_data):
        print_status("✓ Service registered successfully!", "success")
        print()
        print(f"{C_CYAN}{'=' * 60}{C_RESET}")
        print(f"{C_GREEN}Service is now registered in ATS!{C_RESET}")
        print(f"{C_CYAN}{'=' * 60}{C_RESET}")
        print()
        print("Next steps:")
        print(f"  1. Run: {C_BOLD}sudo python3 /home/gaia/ats/ats.py{C_RESET}")
        print(f"  2. Choose: {C_BOLD}Option 2 (List Services){C_RESET}")
        print(f"  3. Verify your service appears in the list")
        print()
    else:
        print_status("Registration failed", "error")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C_YELLOW}Cancelled{C_RESET}")
        sys.exit(0)
