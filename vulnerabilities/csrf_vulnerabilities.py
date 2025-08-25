"""
vulnerabilities/csrf_vulnerabilities.py
---------------------------------------
This file demonstrates Cross-Site Request Forgery (CSRF) vulnerabilities.

VULNERABILITY TYPE: CSRF (Cross-Site Request Forgery)
- No CSRF tokens on message sending.
- No CSRF protection on admin broadcasts.
- Vulnerable GET endpoints.

EXPLOIT SCENARIOS:
- Attackers can trick users into performing actions without their consent.
- Lack of CSRF protection allows unauthorized state changes.

This file is intentionally vulnerable for educational purposes.
See vulnerabilities/README.md for more details.
"""

from flask import request, session, jsonify
import sqlite3

def vulnerable_send_message_no_csrf(app, data):
    """
    VULNERABLE: No CSRF Protection in Message Sending
    
    --- VULNERABILITY: No CSRF Protection ---
    - Accepts POST requests without CSRF tokens.
    - Exploit: Attacker can trick a logged-in user into sending messages via CSRF.
    - FIX: Implement CSRF protection (e.g., Flask-WTF).
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    receiver_id = data.get('receiver_id')
    message = data.get('message')
    
    if not receiver_id or not message:
        return jsonify({'error': 'Missing receiver_id or message'}), 400
    
    # VULNERABLE: No CSRF token validation
    # Attacker can create a malicious form that submits to this endpoint
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)
        ''', (session['user_id'], receiver_id, message))
        conn.commit()
        return jsonify({'success': True})
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

def vulnerable_admin_broadcast_no_csrf(app, data):
    """
    VULNERABLE: No CSRF Protection in Admin Broadcast
    
    --- VULNERABILITY: No CSRF Protection ---
    - Accepts POST requests without CSRF tokens.
    - Exploit: Attacker can trick an admin into broadcasting messages via CSRF.
    - FIX: Implement CSRF protection for admin endpoints.
    """
    if session.get('user_role') != 'admin':
        return {'error': 'Unauthorized'}, 403
    
    message = data.get('message')
    if not message:
        return {'error': 'Missing message'}, 400
    
    # VULNERABLE: No CSRF token validation
    # Attacker can trick admin into broadcasting malicious messages
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE role != "admin"')
    user_ids = [row[0] for row in cursor.fetchall()]
    
    for uid in user_ids:
        cursor.execute('INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)', 
                      (session['user_id'], uid, message))
    
    conn.commit()
    conn.close()
    return {'success': True}

def vulnerable_user_enumeration_no_csrf(app):
    """
    VULNERABLE: No CSRF Protection in User Enumeration
    
    --- VULNERABILITY: No CSRF Protection ---
    - GET endpoint, but still vulnerable to CSRF if used in forms.
    - Exploit: Attacker can trick user into revealing user list via CSRF.
    - FIX: Implement CSRF protection for sensitive GET endpoints.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: No CSRF protection on user enumeration
    # Even though it's a GET request, it could be vulnerable if used in forms
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute("SELECT id, firstname, lastname, email FROM users WHERE id != ?", (session['user_id'],))
        users = [
            {'id': row[0], 'name': f"{row[1]} {row[2]}", 'email': row[3]}
            for row in cursor.fetchall()
        ]
        return jsonify({'users': users})
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

def vulnerable_message_retrieval_no_csrf(app, user_id):
    """
    VULNERABLE: No CSRF Protection in Message Retrieval
    
    --- VULNERABILITY: No CSRF Protection ---
    - GET endpoint, but could be vulnerable if used in forms.
    - Exploit: Attacker can trick user into revealing messages via CSRF.
    - FIX: Implement CSRF protection for sensitive data retrieval.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: No CSRF protection on message retrieval
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute('''
            SELECT sender_id, receiver_id, message, timestamp FROM messages
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
            ORDER BY timestamp ASC
        ''', (session['user_id'], user_id, user_id, session['user_id']))
        
        messages = [
            {
                'sender_id': row[0],
                'receiver_id': row[1],
                'message': row[2],
                'timestamp': row[3]
            }
            for row in cursor.fetchall()
        ]
        return jsonify({'messages': messages})
    except sqlite3.Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close() 