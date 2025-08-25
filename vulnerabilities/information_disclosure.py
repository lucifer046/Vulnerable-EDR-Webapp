"""
vulnerabilities/information_disclosure.py
-----------------------------------------
This file demonstrates Information Disclosure vulnerabilities.

VULNERABILITY TYPE: Information Disclosure
- System information exposure.
- User data disclosure.
- Error message information leakage.

EXPLOIT SCENARIOS:
- Attackers can learn about system internals, users, or sensitive data.
- Debug information or error messages may leak secrets.

This file is intentionally vulnerable for educational purposes.
See vulnerabilities/README.md for more details.
"""

from flask import session, redirect, url_for, flash
import sqlite3
import platform
import psutil
import socket

def vulnerable_dashboard_access(app):
    """
    VULNERABLE: Information Disclosure in Dashboard Access
    
    --- VULNERABILITY: Broken Access Control ---
    - Only checks if 'user_id' is in session, does not verify session integrity or role.
    - Exploit: If session is forged or stolen, attacker can access dashboard.
    - FIX: Use secure session management and verify user roles.
    
    --- VULNERABILITY: Information Disclosure ---
    - Admins can see all user data (except their own) in the admin panel.
    - Exploit: If a regular user is promoted to admin (via session tampering), they can view all users.
    - FIX: Enforce strict role checks and audit admin actions.
    """
    if 'user_id' not in session:
        flash("You must be logged in to view the dashboard.")
        return None
    
    # Collect system information for display (see system_info.py).
    system_info = get_vulnerable_system_info()
    users = []
    
    # If the logged-in user is an admin, fetch all users except the current admin for the admin panel.
    if session.get('user_role') == 'admin':
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute("SELECT id, firstname, lastname, email, phone, role FROM users WHERE id != ?", (session['user_id'],))
        users = cursor.fetchall()
        conn.close()
    
    return {'sys_info': system_info, 'users': users}

def get_vulnerable_system_info():
    """
    VULNERABLE: Information Disclosure in System Information Collection
    
    --- VULNERABILITY: Information Disclosure ---
    - Exposes detailed system information to any logged-in user.
    - Exploit: An attacker with access can learn about the host system, aiding further attacks.
    - FIX: Restrict system info to authorized users only, and limit detail in production.
    
    --- VULNERABILITY: Resource Exhaustion ---
    - Collecting and sorting all processes can be slow and resource-intensive.
    - Exploit: An attacker can repeatedly refresh the dashboard to cause high CPU usage.
    - FIX: Limit the number of processes returned and add rate limiting.
    """
    try:
        # Get basic OS and hardware info
        uname = platform.uname()
        # --- PERFORMANCE NOTE: interval=None is non-blocking, but less accurate on first call ---
        cpu_usage = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            hostname = "N/A"
            ip_address = "N/A"
        
        # Collect info on running processes (top 20 by CPU usage)
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'status']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        processes = sorted(processes, key=lambda p: p['cpu_percent'], reverse=True)[:20]
        
        sys_info = {
            'os': uname.system,
            'os_release': uname.release,
            'os_version': uname.version,
            'architecture': uname.machine,
            'hostname': hostname,
            'ip_address': ip_address,
            'processor': uname.processor,
            'cpu_cores': psutil.cpu_count(logical=False),
            'cpu_total_cores': psutil.cpu_count(logical=True),
            'cpu_usage': cpu_usage,
            'ram_total': f"{ram.total / (1024**3):.2f}",
            'ram_available': f"{ram.available / (1024**3):.2f}",
            'ram_percent': ram.percent,
            'disk_total': f"{disk.total / (1024**3):.2f}",
            'disk_used': f"{disk.used / (1024**3):.2f}",
            'disk_free': f"{disk.free / (1024**3):.2f}",
            'disk_percent': disk.percent,
            'processes': processes
        }
        return sys_info
    except Exception as e:
        print(f"Error collecting system info: {e}")
        return {}

def vulnerable_user_listing(app):
    """
    VULNERABLE: Information Disclosure in User Listing
    
    --- VULNERABILITY: Information Disclosure ---
    - Exposes all user information to admin users.
    - Exploit: Admin can see sensitive user data including emails and phone numbers.
    - FIX: Limit the information exposed and implement proper access controls.
    """
    if session.get('user_role') != 'admin':
        return []
    
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        # VULNERABLE: Exposes all user data including sensitive information
        cursor.execute("SELECT id, firstname, lastname, email, phone, role FROM users WHERE id != ?", (session['user_id'],))
        users = cursor.fetchall()
        conn.close()
        return users
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []

def vulnerable_error_disclosure():
    """
    VULNERABLE: Information Disclosure in Error Messages
    
    --- VULNERABILITY: Information Disclosure ---
    - Detailed error messages expose system information.
    - Exploit: Attacker can learn about system structure and potential attack vectors.
    - FIX: Use generic error messages in production.
    """
    try:
        # Simulate an error that exposes system information
        raise Exception("Database connection failed: Connection refused on localhost:5432")
    except Exception as e:
        # VULNERABLE: Exposing detailed error information
        error_message = f"Error: {str(e)}"
        error_details = {
            'error_type': type(e).__name__,
            'error_message': str(e),
            'stack_trace': 'Detailed stack trace would be here...'
        }
        return {'error_message': error_message, 'details': error_details}

def vulnerable_debug_information():
    """
    VULNERABLE: Debug Information Disclosure
    
    --- VULNERABILITY: Information Disclosure ---
    - Debug information is exposed in production.
    - Exploit: Attacker can learn about application structure and configuration.
    - FIX: Disable debug mode in production.
    """
    debug_info = {
        'app_name': 'PvtEDR Project',
        'version': '1.0.0',
        'debug_mode': True,  # VULNERABLE: Debug mode enabled
        'database_path': '/path/to/database.db',  # VULNERABLE: Exposing file paths
        'secret_key': 'weak_secret_key_123',  # VULNERABLE: Exposing secret key
        'environment': 'production',  # VULNERABLE: Exposing environment
        'installed_packages': ['flask', 'sqlite3', 'psutil'],  # VULNERABLE: Exposing dependencies
        'server_info': {
            'host': 'localhost',
            'port': 5000,
            'protocol': 'http'
        }
    }
    return debug_info 