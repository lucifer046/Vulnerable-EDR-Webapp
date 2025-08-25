"""
vulnerabilities/input_validation.py
-----------------------------------
This file demonstrates Input Validation vulnerabilities.

VULNERABILITY TYPE: Input Validation
- No message content validation or sanitization.
- No user ID validation.
- Weak session validation.

EXPLOIT SCENARIOS:
- Attackers can inject scripts or SQL via unvalidated input.
- Forged sessions can bypass weak checks.

This file is intentionally vulnerable for educational purposes.
See vulnerabilities/README.md for more details.
"""

from flask import request, session, jsonify
import sqlite3

def vulnerable_message_validation(app, data):
    """
    VULNERABLE: No Input Validation in Message Sending
    
    --- VULNERABILITY: No Input Validation ---
    - Does not validate or sanitize message content (XSS risk).
    - Exploit: Attacker can send a message with a script tag.
    - FIX: Sanitize/escape message content before storing or rendering.
    
    --- VULNERABILITY: No User Existence Check ---
    - Does not check if receiver_id is a valid user.
    - FIX: Validate receiver_id before sending message.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    receiver_id = data.get('receiver_id')
    message = data.get('message')
    
    # VULNERABLE: Only checks if values exist, not if they're valid
    if not receiver_id or not message:
        return jsonify({'error': 'Missing receiver_id or message'}), 400
    
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

def vulnerable_user_id_validation(app, user_id):
    """
    VULNERABLE: No Input Validation in User ID Parameter
    
    --- VULNERABILITY: No Input Validation ---
    - Does not check if user_id is valid or if the user is allowed to chat with this user.
    - Exploit: Attacker can request messages with any user_id.
    - FIX: Validate user_id and check permissions.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: No validation of user_id parameter
    # Could be any integer, even for non-existent users
    
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

def vulnerable_admin_message_validation(app, data):
    """
    VULNERABLE: No Input Validation in Admin Broadcast
    
    --- VULNERABILITY: No Input Validation ---
    - Does not validate or sanitize broadcast message content.
    - Exploit: Admin can broadcast malicious content to all users.
    - FIX: Validate and sanitize message content before broadcasting.
    """
    if session.get('user_role') != 'admin':
        return {'error': 'Unauthorized'}, 403
    
    message = data.get('message')
    
    # VULNERABLE: Only checks if message exists, not if it's valid/safe
    if not message:
        return {'error': 'Missing message'}, 400
    
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

def vulnerable_session_validation(app):
    """
    VULNERABLE: Weak Session Validation
    
    --- VULNERABILITY: Weak Session Validation ---
    - Only checks if 'user_id' exists in session, doesn't validate session integrity.
    - Exploit: Attacker can forge session with any user_id.
    - FIX: Use secure session management with proper validation.
    """
    # VULNERABLE: Only checks existence, not validity
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
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