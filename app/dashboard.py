"""
app/dashboard.py
----------------
Dashboard Blueprint for the Modular EDR Flask App.

This blueprint serves the main dashboard page, which is the central hub for users
after they log in. It displays system information collected from the server and,
for administrative users, a panel for user management.

VULNERABILITY DETAILS:
---------------------
1.  **Broken Access Control:**
    - The primary access control check (`if 'user_id' not in session:`) is weak.
      It only verifies the existence of a `user_id` in the session, without validating
      the session's integrity or tying it to a specific user agent or IP address.
      This makes the application vulnerable to session hijacking or fixation.
    - The admin panel's visibility is controlled by a simple check `session.get('user_role') == 'admin'`.
      If an attacker can manipulate their session cookie (e.g., via another vulnerability
      like XSS or if the session secret key is weak), they could escalate their privileges.

2.  **Information Disclosure:**
    - The `get_system_info()` function collects potentially sensitive system information
      (like OS version, running processes, disk usage) and displays it to *any* authenticated
      user. In a real-world EDR, this level of detail should be restricted to privileged
      administrators to prevent reconnaissance by low-privilege users or attackers.
    - Admins are shown a complete list of all other users, including their personal
      information (email, phone number). While necessary for management, this highlights
      the need for strong admin account security and logging.
"""

from flask import Blueprint, render_template, session, redirect, url_for, flash, current_app as app
import sqlite3
from .system_info import get_system_info

# =====================================================================================
#  Dashboard Blueprint Setup
# =====================================================================================
# This blueprint handles the main dashboard view. It's the core interface for the user
# after authentication, providing system monitoring and user management capabilities.

dashboard_bp = Blueprint('dashboard', __name__, template_folder='templates')

# =====================================================================================
#  Dashboard Route
# =====================================================================================
@dashboard_bp.route('/dashboard')
def dashboard():
    """
    Displays the main EDR dashboard.
    - Requires the user to be logged in.
    - Fetches and displays system information.
    - If the user is an admin, it fetches all other users for the management panel.
    """
    # --------------------------------------------------------------------------------
    # VULNERABILITY: Broken Access Control (Weak Session Validation)
    # --------------------------------------------------------------------------------
    # **Concept:** The application only checks for the presence of 'user_id' in the session.
    # It does not validate the session's integrity, check for session expiration, or tie the
    # session to the user's IP address or User-Agent. This makes it easier for an attacker
    # to hijack a valid session.
    #
    # **Enumeration:**
    # - Capture a valid session cookie from a logged-in user.
    # - Use that cookie from a different browser or IP address to access the dashboard.
    #
    # **Fix:**
    # - Implement session timeout.
    # - Regenerate the session ID upon login.
    # - (Advanced) Bind the session to the user's IP address or User-Agent, though this
    #   can have usability issues with dynamic IPs.
    # - Use a more robust session management framework.
    # --------------------------------------------------------------------------------
    if 'user_id' not in session:
        flash("You must be logged in to view the dashboard.")
        return redirect(url_for('auth.login'))
    
    # --------------------------------------------------------------------------------
    # VULNERABILITY: Sensitive Information Disclosure
    # --------------------------------------------------------------------------------
    # **Concept:** Detailed system information (OS, CPU, memory, running processes, etc.)
    # is exposed to any authenticated user. An attacker with a low-privilege account can use
    # this information for reconnaissance to plan further attacks.
    #
    # **Enumeration:**
    # - Log in with a non-admin test account.
    # - Access the dashboard and observe the detailed system information being displayed.
    # - Note the OS version, running services, and other details that could be useful for
    #   finding public exploits.
    #
    # **Fix:**
    # - Implement role-based access control (RBAC) for data visibility.
    # - Only display sensitive system information to users with the 'admin' role.
    # - For non-admin users, show a less detailed, generic dashboard.
    # --------------------------------------------------------------------------------
    system_info = get_system_info()
    users = []
    
    # --------------------------------------------------------------------------------
    # VULNERABILITY: Broken Access Control & Information Disclosure
    # --------------------------------------------------------------------------------
    # **Concept:** The check `session.get('user_role') == 'admin'` is the sole gatekeeper
    # for fetching and displaying the user list. As mentioned before, if the session can be
    # manipulated, an attacker could gain access. Furthermore, this query fetches PII
    # (personally identifiable information) for all users.
    #
    # **Enumeration:**
    # - As an admin, confirm you can see the list of all other users.
    # - Attempt to tamper with the session cookie to set `user_role` to 'admin'.
    #
    # **Fix:**
    # - Strengthen session security (e.g., strong, rotated secret key; signed cookies).
    # - Implement detailed audit logging for when admins access user lists.
    # - For highly sensitive systems, require a second factor of authentication before
    #   displaying sensitive user data.
    # --------------------------------------------------------------------------------
    if session.get('user_role') == 'admin':
        try:
            conn = sqlite3.connect(app.config['DATABASE'])
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            # Fetch all users except the current admin for the management panel.
            cursor.execute("SELECT id, firstname, lastname, email, phone, role FROM users WHERE id != ?", (session['user_id'],))
            users = cursor.fetchall()
        except sqlite3.Error as e:
            flash(f"Database error: {e}")
        finally:
            if conn:
                conn.close()

    # Render the dashboard, passing the collected data to the template.
    return render_template('dashboard.html', sys_info=system_info, users=users)