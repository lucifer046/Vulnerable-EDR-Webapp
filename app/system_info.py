"""
app/system_info.py
-----------------
System Information Collection for the Modular EDR Flask App.

This module is responsible for gathering detailed system information from the server
where the Flask application is running. It collects data on the operating system,
CPU, RAM, disk usage, and running processes. This information is then displayed
on the EDR dashboard for monitoring purposes.

PERFORMANCE OPTIMIZATIONS:
------------------------
- **Caching:** Static system information (like OS details, hostname) that does not
  change during runtime is cached using `@lru_cache` to avoid redundant, expensive
  system calls on every request.
- **Optimized Process Collection:** Process collection is a heavy operation. It is
  disabled by default and can be enabled via a configuration flag. When enabled,
  it fetches a limited number of fields and sorts only the top 10 processes by
  CPU usage to minimize performance impact.
- **Efficient Data Fetching:** Uses non-blocking calls (`psutil.cpu_percent(interval=None)`)
  and specific field selection in `process_iter` to reduce overhead.

VULNERABILITY DETAILS:
---------------------
1.  **Information Disclosure:**
    - **Description:** The functions in this module (`get_system_info`, `get_static_system_info`)
      collect highly sensitive information, including the server's internal IP address,
      hostname, OS version, and a list of running processes. This information is exposed
      to any authenticated user via the dashboard.
    - **Risk:** An attacker with a low-privilege user account can gain a detailed
      understanding of the server's configuration, making it easier to find and
      exploit other vulnerabilities. For example, knowing the exact OS and kernel
      version helps in finding public exploits, and process lists can reveal running
      security software or misconfigured services.

2.  **Resource Exhaustion (Denial of Service):**
    - **Description:** Although optimized, the process collection function (`get_process_info_optimized`)
      still iterates over system processes. If the dashboard endpoint is not rate-limited,
      a malicious user could repeatedly request the page, triggering frequent and
      resource-intensive system scans.
    - **Risk:** This can lead to high CPU and memory usage on the server, potentially
      slowing down or crashing the application, resulting in a Denial of Service (DoS).
"""

import platform
import psutil
import socket
import time
import json
from functools import lru_cache
from flask import Blueprint, request, session, jsonify, current_app as app
import sqlite3

# Create a blueprint for system info API endpoints
system_info_bp = Blueprint('system_info', __name__)

# Configuration: Enable/disable process collection
# NOTE: Process collection is a heavy operation. It's recommended to keep this disabled
# in a production environment unless specifically required for monitoring.
ENABLE_PROCESS_COLLECTION = True  # Set to False to disable process collection globally

# =====================================================================================
#  System Information Collection
# =====================================================================================
# This section contains functions for gathering different types of system information.
# It separates static info (cached) from dynamic info (fetched on each call) to
# optimize performance.

@lru_cache(maxsize=1)
def get_static_system_info():
    """
    Gathers static system information that does not change during the application's runtime.
    This data is cached to prevent repeated system calls on every dashboard refresh.

    VULNERABILITY: Information Disclosure
    Concept: Exposes potentially sensitive host information (hostname, internal IP) that
             can aid an attacker in network reconnaissance and targeted attacks.
    Fix: Limit the information exposed. Avoid sending internal IP addresses and detailed
         processor info to the client. Only expose what is strictly necessary for the user.
    """
    try:
        uname = platform.uname()
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            hostname = "N/A"
            ip_address = "N/A"
        
        return {
            'os': uname.system,
            'os_release': uname.release,
            'os_version': uname.version,
            'architecture': uname.machine,
            'hostname': hostname,
            'ip_address': ip_address,
            'processor': uname.processor,
            'cpu_cores': psutil.cpu_count(logical=False),
            'cpu_total_cores': psutil.cpu_count(logical=True),
        }
    except Exception as e:
        print(f"Error collecting static system info: {e}")
        return {}

def get_dynamic_system_info():
    """
    Gathers dynamic system information that changes frequently, such as CPU, RAM, and disk usage.
    This data is fetched in real-time and is not cached.

    VULNERABILITY: Information Disclosure
    Concept: While less sensitive than static info, exposing real-time usage metrics can still
             give an attacker insights into system load and potential windows for attack
             (e.g., attacking when the system is under heavy load).
    Fix: Access to this information should be restricted to admin users. Regular users
         should not have access to detailed server performance metrics.
    """
    try:
        # VULNERABILITY: Information Disclosure
        # Reference: vulnerabilities/information_disclosure.py
        # Issue: Exposes detailed system information to any logged-in user
        
        # Get CPU usage (non-blocking)
        cpu_usage = psutil.cpu_percent(interval=None)
        
        # Get memory information
        ram = psutil.virtual_memory()
        
        # Get disk information
        disk = psutil.disk_usage('/')
        
        return {
            'cpu_usage': cpu_usage,
            'ram_total': f"{ram.total / (1024**3):.2f}",
            'ram_available': f"{ram.available / (1024**3):.2f}",
            'ram_percent': ram.percent,
            'disk_total': f"{disk.total / (1024**3):.2f}",
            'disk_used': f"{disk.used / (1024**3):.2f}",
            'disk_free': f"{disk.free / (1024**3):.2f}",
            'disk_percent': disk.percent,
        }
    except Exception as e:
        print(f"Error collecting dynamic system info: {e}")
        return {}

def get_process_info_optimized():
    """
    Gathers a list of the top 10 running processes sorted by CPU usage.
    This is an expensive operation and is disabled by default.

    VULNERABILITY: Information Disclosure & Resource Exhaustion
    - **Info Disclosure:** The process list reveals running applications, services, and usernames,
      which can expose security software, databases, or sensitive user activity.
    - **Resource Exhaustion (DoS):** Iterating through all system processes is CPU-intensive.
      Without rate limiting on the endpoint that calls this function, an attacker could
      force the server to perform this operation repeatedly, leading to a DoS.

    Fix:
    - **Access Control:** Strictly limit this functionality to trusted admin users.
    - **Rate Limiting:** Implement strong rate limiting on the dashboard endpoint.
    - **Default Off:** Keep this feature disabled (`ENABLE_PROCESS_COLLECTION = False`)
      unless absolutely necessary.
    """
    try:
        # VULNERABILITY: Resource Exhaustion
        # Reference: vulnerabilities/rate_limiting.py
        # Issue: Collecting and sorting all processes can be slow and resource-intensive
        
        if not ENABLE_PROCESS_COLLECTION:
            return []
        
        # Initialize CPU percentage collection for all processes
        psutil.cpu_percent(interval=None)
        time.sleep(0.05)  # Short sleep to get updated CPU usage
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                processes.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        # Sort by CPU usage and take top 10
        processes = sorted(processes, key=lambda p: p['cpu_percent'], reverse=True)[:10]
        return processes
    except Exception as e:
        print(f"Error collecting process info: {e}")
        return []

def get_system_info():
    """
    Aggregates all system information by calling the static, dynamic, and process
    collection functions. This is the main function used by the dashboard to get
    a complete snapshot of the system's state.

    VULNERABILITY: Information Disclosure
    Concept: This function aggregates and returns a comprehensive set of sensitive system
             data. If called by an endpoint accessible to non-admin users, it becomes
             a serious information disclosure vulnerability.
    Enumeration: Access the dashboard as a low-privilege user and observe the detailed
                 system information returned in the HTTP response or rendered on the page.
    Fix: Ensure the calling endpoint (e.g., the dashboard route) performs a strict
         role check and only allows administrators to access this data.
    """
    try:
        # Get cached static information
        static_info = get_static_system_info()
        
        # Get current dynamic information
        dynamic_info = get_dynamic_system_info()
        
        # Get optimized process information (disabled by default)
        processes = get_process_info_optimized()
        
        # VULNERABILITY: Information Disclosure
        # Reference: vulnerabilities/information_disclosure.py
        # Issue: Exposes sensitive system information including hostname, IP, and process details
        
        # Combine all information
        sys_info = {**static_info, **dynamic_info, 'processes': processes}
        
        return sys_info
        
    except Exception as e:
        print(f"Error collecting system info: {e}")
        return {}

def get_system_info_with_timing():
    """
    A utility function for performance monitoring, which wraps `get_system_info` and
    prints the execution time of each data collection step.
    This is intended for debugging and performance tuning, not for production use.
    """
    start_time = time.time()
    
    static_start = time.time()
    static_info = get_static_system_info()
    static_time = time.time() - static_start
    
    dynamic_start = time.time()
    dynamic_info = get_dynamic_system_info()
    dynamic_time = time.time() - dynamic_start
    
    process_start = time.time()
    processes = get_process_info_optimized()
    process_time = time.time() - process_start
    
    total_time = time.time() - start_time
    
    print(f"System info timing - Static: {static_time:.3f}s, Dynamic: {dynamic_time:.3f}s, Process: {process_time:.3f}s, Total: {total_time:.3f}s")
    
    return {**static_info, **dynamic_info, 'processes': processes}

# =====================================================================================
#  User System Info API
# =====================================================================================
@system_info_bp.route('/api/user_system_info', methods=['POST'])
def api_user_system_info():
    """
    Receives and stores client-side system information from the browser.
    This is called from the dashboard JavaScript to collect browser and client info.
    
    VULNERABILITY: Information Disclosure
    Reference: vulnerabilities/information_disclosure.py
    Issue: Stores sensitive client information without proper access controls
    """
    # VULNERABILITY: Broken Access Control
    # Reference: vulnerabilities/broken_access_control.py
    # Issue: Only checks if 'user_id' is in session, does not verify session integrity
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Get the client-side system information from the request
    client_info = request.get_json()
    
    # VULNERABILITY: No Input Validation
    # Reference: vulnerabilities/input_validation.py
    # Issue: Does not validate or sanitize client info before storing
    
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        
        # Convert the client info to a JSON string for storage
        info_json = json.dumps(client_info)
        
        # Check if we already have an entry for this user
        cursor.execute("SELECT COUNT(*) FROM user_system_info WHERE user_id = ?", (session['user_id'],))
        if cursor.fetchone()[0] > 0:
            # Update existing entry
            cursor.execute(
                "UPDATE user_system_info SET info = ?, last_updated = CURRENT_TIMESTAMP WHERE user_id = ?",
                (info_json, session['user_id'])
            )
        else:
            # Insert new entry
            cursor.execute(
                "INSERT INTO user_system_info (user_id, info) VALUES (?, ?)",
                (session['user_id'], info_json)
            )
        
        conn.commit()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()