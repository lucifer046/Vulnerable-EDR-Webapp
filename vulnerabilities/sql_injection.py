"""
vulnerabilities/sql_injection.py
--------------------------------
This file demonstrates SQL Injection vulnerabilities.

VULNERABILITY TYPE: SQL Injection
- User login SQL injection.
- Admin login SQL injection.
- User search SQL injection.

EXPLOIT SCENARIOS:
- Attackers can inject SQL to bypass authentication or extract/modify data.
- Lack of parameterized queries enables exploitation.

This file is intentionally vulnerable for educational purposes.
See vulnerabilities/README.md for more details.
"""

from flask import request, session, redirect, url_for, flash
import sqlite3

def vulnerable_user_login(app, email, password):
    """
    VULNERABLE: SQL Injection in User Login
    
    --- VULNERABILITY: SQL Injection ---
    - The SQL query is constructed using f-strings with user input.
    - Exploit: An attacker can enter ' OR 1=1 -- as the email to bypass authentication.
    - FIX: Use parameterized queries (cursor.execute with ? placeholders).
    
    --- VULNERABILITY: No Account Lockout ---
    - Unlimited login attempts are allowed.
    - Exploit: Brute-force attacks are possible.
    - FIX: Implement account lockout or rate limiting.
    
    --- VULNERABILITY: Weak Session Management ---
    - Session data is stored client-side, signed with a weak secret key.
    - Exploit: If the secret key is leaked, sessions can be forged.
    - FIX: Use a strong, random secret key and secure session storage.
    """
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        # --- VULNERABILITY: SQL Injection ---
        # The query is constructed using f-strings with user input.
        # Exploit: ' OR 1=1 -- as email will log in as the first user.
        query = f"SELECT id, firstname, lastname, email, phone, role FROM users WHERE email = '{email}' AND password = '{password}'"
        print(f"Executing vulnerable query: {query}")
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            # Store user info in session (client-side, signed with weak secret key).
            session['user_id'] = user[0]
            session['user_email'] = user[3]
            session['user_role'] = user[5]
            return True
        else:
            flash("Invalid email or password.")
            return False
    except sqlite3.Error as e:
        print(f"Database error during login: {e}")
        flash("An error occurred. Please try again.")
        return False
    finally:
        if conn:
            conn.close()

def vulnerable_admin_login(app, email, password):
    """
    VULNERABLE: SQL Injection in Admin Login
    
    --- VULNERABILITY: SQL Injection ---
    - The SQL query is constructed using f-strings with user input.
    - Exploit: An attacker can enter ' OR 1=1 -- as the email to bypass authentication.
    - FIX: Use parameterized queries (cursor.execute with ? placeholders).
    
    --- VULNERABILITY: No Account Lockout ---
    - Unlimited login attempts are allowed.
    - Exploit: Brute-force attacks are possible.
    - FIX: Implement account lockout or rate limiting.
    
    --- VULNERABILITY: Weak Session Management ---
    - Session data is stored client-side, signed with a weak secret key.
    - Exploit: If the secret key is leaked, sessions can be forged.
    - FIX: Use a strong, random secret key and secure session storage.
    """
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        # --- VULNERABILITY: SQL Injection ---
        # The query is constructed using f-strings with user input.
        # Exploit: ' OR 1=1 -- as email will log in as the first admin.
        query = f"SELECT id, firstname, lastname, email, phone, role FROM users WHERE email = '{email}' AND password = '{password}' AND role = 'admin'"
        print(f"Executing vulnerable admin login query: {query}")
        cursor.execute(query)
        user = cursor.fetchone()
        if user:
            # Store admin info in session (client-side, signed with weak secret key).
            session['user_id'] = user[0]
            session['user_email'] = user[3]
            session['user_role'] = user[5]
            print(f"Admin login successful for user: {session['user_email']}")
            return True
        else:
            flash("Invalid admin credentials.")
            print("Admin login failed.")
            return False
    except sqlite3.Error as e:
        print(f"Database error during admin login: {e}")
        flash("An error occurred. Please try again.")
        return False
    finally:
        if conn:
            conn.close()

def vulnerable_user_search(app, search_term):
    """
    VULNERABLE: SQL Injection in User Search (Hypothetical)
    
    --- VULNERABILITY: SQL Injection ---
    - The SQL query is constructed using f-strings with user input.
    - Exploit: An attacker can inject malicious SQL to extract data or modify the query.
    - FIX: Use parameterized queries (cursor.execute with ? placeholders).
    """
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        # --- VULNERABILITY: SQL Injection ---
        # The query is constructed using f-strings with user input.
        # Exploit: ' UNION SELECT * FROM users -- will extract all user data
        query = f"SELECT id, firstname, lastname, email FROM users WHERE firstname LIKE '%{search_term}%' OR lastname LIKE '%{search_term}%'"
        print(f"Executing vulnerable search query: {query}")
        cursor.execute(query)
        users = cursor.fetchall()
        return users
    except sqlite3.Error as e:
        print(f"Database error during search: {e}")
        return []
    finally:
        if conn:
            conn.close() 