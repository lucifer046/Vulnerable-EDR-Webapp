# app/admin.py

"""
Module: app.admin
Description: This module contains all administrative functionalities for the EDR application.
It handles user management (removing users, changing roles), viewing audit logs, and other
admin-specific tasks. The routes defined here are critical from a security perspective
as they control access to sensitive operations.
"""

from flask import Blueprint, request, redirect, url_for, render_template, session, flash, current_app as app
import sqlite3

# =====================================================================================
#  Admin Blueprint Setup
# =====================================================================================

# FUNCTION: admin_bp
# DESCRIPTION: Creates a Flask Blueprint for admin-related routes.
# This helps in organizing the application into modular components.
# All routes defined in this file will be prefixed with '/admin'.

admin_bp = Blueprint('admin', __name__)

# =====================================================================================
#  Admin Action Logging Helper
# =====================================================================================

# FUNCTION: log_admin_action
# DESCRIPTION: Logs administrative actions to the database.
# This is a crucial security practice for creating an audit trail, which helps in
# incident response and tracking unauthorized activities.
def log_admin_action(admin_id, admin_email, action, details):
    """Logs an administrative action to the audit_log table."""
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO audit_log (admin_id, admin_email, action, details) VALUES (?, ?, ?, ?)",
            (admin_id, admin_email, action, details)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Failed to log admin action: {e}")

# =====================================================================================
#  Admin Panel Route
# =====================================================================================

# ROUTE: /admin/panel
# DESCRIPTION: Redirects to the main dashboard.
# The dashboard template is responsible for rendering admin-specific content based on the user's role.
# This is a simple redirect and contains no significant logic itself.
@admin_bp.route('/panel')
def admin_panel():
    """
    Redirects to the main dashboard, which will display admin features
    if the user has the 'admin' role.
    """
    if session.get('user_role') != 'admin':
        flash('You do not have permission to access the admin panel.')
        
    return redirect(url_for('dashboard.dashboard'))

# =====================================================================================
#  Admin Audit Log Page Route
# =====================================================================================

# ROUTE: /admin/audit_log
# DESCRIPTION: Displays the audit log of all administrative actions.
# This is a sensitive page that should only be accessible to authorized administrators.
@admin_bp.route('/audit_log')
def audit_log_page():
    """
    Displays a page with all administrative actions from the audit log.
    Only accessible to admins.
    """
    # VULNERABILITY: Broken Access Control
    # CONCEPT: The application relies on a session variable ('user_role') to enforce access control.
    # This is insecure if session management is weak, as an attacker could potentially forge or
    # manipulate their session to gain admin privileges.
    # ENUMERATION: An attacker would first need to find a way to compromise the session, for example,
    # through session fixation or if the secret key is weak and they can craft their own session cookie.
    

    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, admin_email, action, details FROM audit_log ORDER BY timestamp DESC")
    logs = cursor.fetchall()
    conn.close()

    return render_template('audit_log.html', audit_logs=logs)

# =====================================================================================
#  Admin Remove User Route
# =====================================================================================

# ROUTE: /admin/remove_user/<int:user_id>
# DESCRIPTION: Allows an administrator to remove a user account and all associated data.
# This is a destructive action and requires strong access control.
@admin_bp.route('/remove_user/<int:user_id>', methods=['POST'])
def admin_remove_user(user_id):
    """
    Allows an admin to remove a user and all their messages from the database.
    Only accessible to admins (checks session['user_role']).
    """
    # VULNERABILITY: Cross-Site Request Forgery (CSRF)
    # CONCEPT: This endpoint is not protected by a CSRF token because global CSRF protection
    # has been disabled. An attacker can create a malicious webpage with a hidden form that
    # targets this URL. If a logged-in admin visits the attacker's page, the form can be
    # auto-submitted, causing the admin to unknowingly delete a user.
    # ENUMERATION: Create an HTML page with a form:
    # <form action="http://127.0.0.1:5000/admin/remove_user/2" method="post"></form>
    # <script>document.forms[0].submit();</script>
    # If an admin visits this page, user with ID 2 will be deleted.
    # FIX: Re-enable global CSRF protection in `app/__init__.py` and ensure all state-changing
    # forms include a CSRF token.
    # VULNERABILITY: Broken Access Control & Privilege Escalation
    # CONCEPT: Any user with an 'admin' role can remove any other user, including other admins.
    # This is a privilege escalation risk, as a lower-privileged admin could potentially
    # remove a higher-privileged one. There is no check to prevent this.
    # ENUMERATION: An attacker who has compromised an admin account can use this functionality
    # to remove other admins, potentially covering their tracks or causing disruption.
    # FIX: Implement a hierarchical role system (e.g., super-admin vs. admin) where only
    # super-admins can remove other admins. Additionally, consider requiring a second factor
    # of authentication (like a password re-entry) for such a critical action.
    if session.get('user_role') != 'admin':
        flash('Unauthorized')
        return redirect(url_for('dashboard.dashboard'))
    
    # Prevent an admin from removing themselves
    if session.get('user_id') == user_id:
        flash("You cannot remove your own account.")
        return redirect(url_for('dashboard.dashboard'))

    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()

    # Get user details before deleting for logging
    cursor.execute("SELECT email FROM users WHERE id = ?", (user_id,))
    user_to_remove = cursor.fetchone()
    user_email_for_log = user_to_remove[0] if user_to_remove else f"ID {user_id}"

    # Check if the user to be removed is an admin
    cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
    user_role = cursor.fetchone()

    # Prevent removal of the last admin
    if user_role and user_role[0] == 'admin':
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        admin_count = cursor.fetchone()[0]
        if admin_count <= 1:
            flash("Cannot remove the last administrator.")
            conn.close()
            return redirect(url_for('dashboard.dashboard'))

    # VULNERABILITY: Uncontrolled Resource Deletion
    # CONCEPT: The code directly deletes the user and their messages from the database without
    # adequate checks. If an attacker finds a way to trigger this function with an arbitrary
    # user_id, they could cause significant data loss.
    # FIX: Implement a soft-delete mechanism where users are marked as 'inactive' instead of
    # being permanently deleted. This provides a safety net against accidental or malicious deletions.
    # Also, ensure that all foreign key relationships in the database are set up correctly with
    # cascading deletes to prevent orphaned records, which could lead to database integrity issues.
    # Remove all messages sent or received by the user.
    cursor.execute('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?', (user_id, user_id))
    # Remove the user from the users table.
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    # Log the action
    log_admin_action(
        admin_id=session['user_id'],
        admin_email=session['user_email'],
        action='remove_user',
        details=f"Removed user: {user_email_for_log} (ID: {user_id})"
    )
    flash('User and their data removed.')
    return redirect(url_for('dashboard.dashboard'))

# =====================================================================================
#  Admin Set User Role Route
# =====================================================================================

# ROUTE: /admin/set_role/<int:user_id>
# DESCRIPTION: Allows an administrator to change the role of a user (e.g., from 'user' to 'admin').
# This is one of the most critical functions in the application from a security standpoint.
@admin_bp.route('/set_role/<int:user_id>', methods=['POST'])
def admin_set_role(user_id):
    """
    Allows an admin to set a user's role to a specific value ('admin' or 'user').
    Only accessible to admins (checks session['user_role']).
    """
    # VULNERABILITY: Cross-Site Request Forgery (CSRF)
    # CONCEPT: Similar to user removal, this endpoint lacks CSRF protection. An attacker can
    # craft a malicious page to trick an admin's browser into submitting a request to change
    # a user's role, for example, promoting an attacker-controlled account to 'admin'.
    # ENUMERATION: Create a malicious page that auto-submits a form to this endpoint with
    # the target user ID and `role=admin`.
    # FIX: Enable and enforce CSRF token validation for all POST requests that change state.
    # VULNERABILITY: Privilege Escalation
    # CONCEPT: This is a classic privilege escalation vector. Any user with 'admin' role can promote
    # any other user to become an admin. There's no higher level of approval or check.
    # ENUMERATION: An attacker who compromises a low-level admin account can use this to create
    # another admin account for themselves, which they can use for further attacks while the
    # original compromised account might be discovered and disabled.
    # FIX: This action should be reserved for 'super-admins' only. Additionally, the system should
    # log this event prominently and perhaps even send a notification to all other admins to
    # alert them of a role change.
    if session.get('user_role') != 'admin':
        flash('Unauthorized')
        return redirect(url_for('dashboard.dashboard'))
    
    # Prevent an admin from changing their own role
    if session.get('user_id') == user_id:
        flash("You cannot change your own role.")
        return redirect(url_for('dashboard.dashboard'))
    
    # Get the new role from the form data
    new_role = request.form.get('role')
    if new_role not in ['admin', 'user']:
        flash('Invalid role specified.')
        return redirect(url_for('dashboard.dashboard'))
    
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()

        # Get user details before changing role for logging
        cursor.execute("SELECT email, role FROM users WHERE id = ?", (user_id,))
        user_to_change_data = cursor.fetchone()
        user_email_for_log = user_to_change_data[0] if user_to_change_data else f"ID {user_id}"
        old_role = user_to_change_data[1] if user_to_change_data else "unknown"

        # Prevent demotion of the last admin
        if new_role == 'user':
            cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
            user_to_change = cursor.fetchone()
            if user_to_change and user_to_change[0] == 'admin':
                cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                admin_count = cursor.fetchone()[0]
                if admin_count <= 1:
                    flash("Cannot demote the last administrator.")
                    conn.close()
                    return redirect(url_for('dashboard.dashboard'))
        
        # VULNERABILITY: Privilege Escalation
        # CONCEPT: Any admin can change another user's role.
        # FIX: Implement hierarchical roles (super-admin vs. admin)
        
        # Get the current role of the user
        cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        print(f"User query result: {user}")
        
        if user:
            cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
            conn.commit()
            
            # Log the action
            log_admin_action(
                admin_id=session['user_id'],
                admin_email=session['user_email'],
                action='set_role',
                details=f"Changed role for {user_email_for_log} (ID: {user_id}) from '{old_role}' to '{new_role}'"
            )
            print(f"User role set to {new_role} for user_id: {user_id}")
            flash(f'User role set to {new_role}.')
        else:
            print(f"User not found for user_id: {user_id}")
            flash('User not found.')
        
        conn.close()
        return redirect(url_for('dashboard.dashboard'))
    except Exception as e:
        print(f"Error in set_role: {str(e)}")
        flash(f'Error: {str(e)}')
        return redirect(url_for('dashboard.dashboard'))