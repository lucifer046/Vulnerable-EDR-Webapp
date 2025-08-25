"""
vulnerabilities/password_vulnerabilities.py
-------------------------------------------
This file demonstrates Password-related vulnerabilities.

VULNERABILITY TYPE: Password Security
- Plaintext password storage.
- No password hashing.
- Weak password requirements.
- No unique constraint on email.

EXPLOIT SCENARIOS:
- Attackers who access the database can read all passwords.
- Weak passwords are easily guessable.
- Duplicate emails can lead to privilege escalation.

This file is intentionally vulnerable for educational purposes.
See vulnerabilities/README.md for more details.
"""

from flask import request, session, flash
import sqlite3

def vulnerable_user_registration(app, firstname, lastname, email, password, phone, role='user'):
    """
    VULNERABLE: No Password Hashing in User Registration
    
    --- VULNERABILITY: No Password Hashing ---
    - Passwords are stored in plaintext in the database.
    - If the database is compromised, all user passwords are exposed.
    - FIX: Use a password hashing library (e.g., werkzeug.security.generate_password_hash).
    
    --- VULNERABILITY: No Input Validation ---
    - User input is not validated or sanitized.
    - An attacker can submit malicious scripts, SQL, or overly long data.
    - FIX: Validate and sanitize all user input (e.g., with WTForms or custom checks).
    
    --- VULNERABILITY: No UNIQUE Constraint on Email ---
    - The database allows multiple users with the same email.
    - This can lead to account confusion and privilege escalation.
    - FIX: Add a UNIQUE constraint to the email column in the users table.
    """
    conn = None
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        # Check if email already exists (no UNIQUE constraint in DB).
        cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
        if cursor.fetchone()[0] > 0:
            flash("Email already exists. Please use a different email.")
            return False
        # --- VULNERABILITY: Plaintext Passwords ---
        # Passwords are stored in plaintext.
        # Exploit: Attacker who gains DB access can read all passwords.
        # FIX: Use password hashing.
        cursor.execute(
            "INSERT INTO users (firstname, lastname, email, password, phone) VALUES (?, ?, ?, ?, ?)",
            (firstname, lastname, email, password, phone)
        )
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Database error during registration: {e}")
        return False
    finally:
        if conn:
            conn.close()

def vulnerable_admin_registration(app, firstname, lastname, email, password, phone):
    """
    VULNERABLE: No Password Hashing in Admin Registration
    
    --- VULNERABILITY: No Password Hashing ---
    - Passwords are stored in plaintext in the database.
    - Exploit: If the database is compromised, all admin passwords are exposed.
    - FIX: Use a password hashing library.
    
    --- VULNERABILITY: No Input Validation ---
    - User input is not validated or sanitized.
    - Exploit: Attacker can submit malicious scripts, SQL, or overly long data.
    - FIX: Validate and sanitize all user input.
    
    --- VULNERABILITY: No UNIQUE Constraint on Email ---
    - The database allows multiple admins with the same email.
    - Exploit: Multiple admin accounts with the same email can cause confusion and privilege escalation.
    - FIX: Add a UNIQUE constraint to the email column in the users table.
    """
    conn = None
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        # Check if email already exists (no UNIQUE constraint in DB).
        cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
        if cursor.fetchone()[0] > 0:
            flash("Email already exists. Please use a different email.")
            return False
        # --- VULNERABILITY: Plaintext Passwords ---
        # Passwords are stored in plaintext.
        # Exploit: Attacker who gains DB access can read all passwords.
        # FIX: Use password hashing.
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

def vulnerable_password_change(app, user_id, new_password):
    """
    VULNERABLE: No Password Hashing in Password Change
    
    --- VULNERABILITY: No Password Hashing ---
    - New passwords are stored in plaintext.
    - Exploit: If the database is compromised, all passwords are exposed.
    - FIX: Use password hashing before storing.
    
    --- VULNERABILITY: No Password Complexity Requirements ---
    - No requirements for password strength.
    - Exploit: Users can set weak passwords that are easily guessable.
    - FIX: Implement password complexity requirements.
    """
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        # --- VULNERABILITY: Plaintext Passwords ---
        # New password is stored in plaintext.
        # Exploit: Attacker who gains DB access can read all passwords.
        # FIX: Use password hashing.
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user_id))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Database error during password change: {e}")
        return False
    finally:
        if conn:
            conn.close()

def vulnerable_password_reset(app, email, new_password):
    """
    VULNERABLE: No Password Hashing in Password Reset
    
    --- VULNERABILITY: No Password Hashing ---
    - Reset passwords are stored in plaintext.
    - Exploit: If the database is compromised, reset passwords are exposed.
    - FIX: Use password hashing before storing.
    
    --- VULNERABILITY: No Token Validation ---
    - No secure token is required for password reset.
    - Exploit: Attacker can reset any user's password.
    - FIX: Implement secure token-based password reset.
    """
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        # --- VULNERABILITY: Plaintext Passwords ---
        # Reset password is stored in plaintext.
        # Exploit: Attacker who gains DB access can read all passwords.
        # FIX: Use password hashing.
        cursor.execute("UPDATE users SET password = ? WHERE email = ?", (new_password, email))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Database error during password reset: {e}")
        return False
    finally:
        if conn:
            conn.close()

def vulnerable_database_schema():
    """
    VULNERABLE: Database Schema with Password Vulnerabilities
    
    --- VULNERABILITY: Plaintext Passwords ---
    - Passwords are stored in plaintext.
    - Exploit: If the database is compromised, all user/admin passwords are exposed.
    - FIX: Use password hashing.
    
    --- VULNERABILITY: No UNIQUE Constraint on Email ---
    - Allows multiple users with the same email.
    - Exploit: Multiple accounts with the same email can cause confusion and privilege escalation.
    - FIX: Add a UNIQUE constraint to the email column in the users table.
    """
    # This represents the vulnerable database schema
    schema = '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            firstname TEXT NOT NULL,
            lastname TEXT NOT NULL,
            email TEXT NOT NULL,  -- VULNERABLE: No UNIQUE constraint
            password TEXT NOT NULL,  -- VULNERABLE: Plaintext passwords
            phone TEXT,
            role TEXT DEFAULT 'user'
        )
    '''
    return schema 