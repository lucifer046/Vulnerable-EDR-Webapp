"""
vulnerabilities/privilege_escalation.py
---------------------------------------
This file demonstrates Privilege Escalation vulnerabilities.

VULNERABILITY TYPE: Privilege Escalation & Access Control
- Admin role bypass.
- Session elevation attacks.
- Unauthorized role assignment.

EXPLOIT SCENARIOS:
- Attackers can forge sessions or escalate privileges to gain admin access.
- Lack of proper role checks allows unauthorized actions.

This file is intentionally vulnerable for educational purposes.
See vulnerabilities/README.md for more details.
"""

from flask import session, flash, redirect, url_for
import sqlite3

def vulnerable_admin_remove_user(app, user_id):
    """
    VULNERABLE: Broken Access Control in Admin User Removal
    
    --- VULNERABILITY: Broken Access Control ---
    - Only checks if session['user_role'] == 'admin'.
    - Exploit: Attacker can forge session to become admin and remove users.
    - FIX: Use secure session management and verify admin privileges on the server.
    
    --- VULNERABILITY: Privilege Escalation ---
    - Any user with admin role can remove any other user.
    - Exploit: Attacker can remove admin accounts and take control.
    - FIX: Implement proper role-based access control and audit trails.
    """
    if session.get('user_role') != 'admin':
        flash('Unauthorized')
        return False
    
    # VULNERABLE: No additional verification of admin privileges
    # Attacker can forge session to become admin
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    
    # Remove all messages sent or received by the user.
    cursor.execute('DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?', (user_id, user_id))
    # Remove the user from the users table.
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    
    flash('User and their data removed.')
    return True

def vulnerable_role_assignment(app, user_id, new_role):
    """
    VULNERABLE: Privilege Escalation in Role Assignment
    
    --- VULNERABILITY: Privilege Escalation ---
    - No validation of role assignment permissions.
    - Exploit: Attacker can promote any user to admin role.
    - FIX: Implement strict role assignment controls and audit trails.
    """
    if session.get('user_role') != 'admin':
        flash('Unauthorized')
        return False
    
    # VULNERABLE: No validation of role assignment
    # Attacker can assign any role to any user
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
        conn.commit()
        conn.close()
        flash(f'User role updated to {new_role}')
        return True
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

def vulnerable_admin_bypass(app, email, password):
    """
    VULNERABLE: Admin Authentication Bypass
    
    --- VULNERABILITY: Authentication Bypass ---
    - Weak admin authentication allows privilege escalation.
    - Exploit: Attacker can bypass admin authentication and gain admin privileges.
    - FIX: Implement strong authentication and multi-factor authentication for admin accounts.
    """
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        # VULNERABLE: Weak admin authentication
        # No additional security measures for admin accounts
        cursor.execute("SELECT id, firstname, lastname, email, phone, role FROM users WHERE email = ? AND password = ? AND role = 'admin'", (email, password))
        user = cursor.fetchone()
        if user:
            # VULNERABLE: No additional verification for admin login
            session['user_id'] = user[0]
            session['user_email'] = user[3]
            session['user_role'] = user[5]
            print(f"Admin login successful for user: {session['user_email']}")
            return True
        else:
            flash("Invalid admin credentials.")
            return False
    except sqlite3.Error as e:
        print(f"Database error during admin login: {e}")
        return False
    finally:
        if conn:
            conn.close()

def vulnerable_session_elevation(app, user_id):
    """
    VULNERABLE: Session Elevation Attack
    
    --- VULNERABILITY: Session Manipulation ---
    - Session data can be manipulated to elevate privileges.
    - Exploit: Attacker can modify session to gain admin privileges.
    - FIX: Use secure session management and server-side role verification.
    """
    # VULNERABLE: Session can be manipulated client-side
    # Attacker can modify session data to become admin
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # VULNERABLE: Session role can be set to any value
            # No server-side validation of session role
            session['user_role'] = 'admin'  # Attacker can set this
            session['user_id'] = user_id
            return True
        return False
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False

def vulnerable_admin_registration_bypass(app, firstname, lastname, email, password, phone):
    """
    VULNERABLE: Admin Registration Bypass
    
    --- VULNERABILITY: Privilege Escalation ---
    - Anyone can register as admin without proper verification.
    - Exploit: Attacker can create admin accounts and gain full system access.
    - FIX: Implement secure admin registration with proper verification.
    """
    conn = None
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        
        # VULNERABLE: No verification required for admin registration
        # Anyone can register as admin
        cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
        if cursor.fetchone()[0] > 0:
            flash("Email already exists. Please use a different email.")
            return False
        
        # VULNERABLE: Direct admin role assignment without verification
        cursor.execute(
            "INSERT INTO users (firstname, lastname, email, password, phone, role) VALUES (?, ?, ?, ?, ?, ?)",
            (firstname, lastname, email, password, phone, 'admin')
        )
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Database error during admin registration: {e}")
        return False
    finally:
        if conn:
            conn.close() 