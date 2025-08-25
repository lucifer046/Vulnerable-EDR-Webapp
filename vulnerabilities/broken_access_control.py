"""
vulnerabilities/broken_access_control.py
----------------------------------------
This file demonstrates Broken Access Control vulnerabilities.

VULNERABILITY TYPE: Broken Access Control
- Weak session validation and insufficient access controls.
- User enumeration without proper validation.
- Admin broadcast without proper role verification.
- Message access without permission checks.

EXPLOIT SCENARIOS:
- Attackers can forge sessions to enumerate users or access admin functionality.
- Lack of role checks allows privilege escalation.
- No rate limiting enables brute-force enumeration.

This file is intentionally vulnerable for educational purposes.
See vulnerabilities/README.md for more details.
"""

from flask import session, jsonify
import sqlite3

def vulnerable_api_get_users(app):
    """
    VULNERABLE: Broken Access Control in User Enumeration
    
    --- VULNERABILITY: Broken Access Control ---
    - Only checks if 'user_id' is in session, does not verify session integrity or role.
    - Exploit: Attacker with a forged session can enumerate users.
    - FIX: Use secure session management and verify user roles.
    
    --- VULNERABILITY: User Enumeration ---
    - No rate limiting or anti-enumeration protection.
    - Exploit: Attacker can enumerate all users via repeated API calls.
    - FIX: Add rate limiting and anti-enumeration controls.
    """
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

def vulnerable_admin_broadcast(app, data):
    """
    VULNERABLE: Broken Access Control in Admin Broadcast
    
    --- VULNERABILITY: Broken Access Control ---
    - Only checks if session['user_role'] == 'admin'.
    - Exploit: Attacker can forge session to become admin and broadcast messages.
    - FIX: Use secure session management and verify admin privileges on the server.
    """
    if session.get('user_role') != 'admin':
        return {'error': 'Unauthorized'}, 403
    
    message = data.get('message')
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

def vulnerable_message_access(app, user_id):
    """
    VULNERABLE: Broken Access Control in Message Access
    
    --- VULNERABILITY: No Input Validation ---
    - Does not check if user_id is valid or if the user is allowed to chat with this user.
    - Exploit: Attacker can request messages with any user_id.
    - FIX: Validate user_id and check permissions.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
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