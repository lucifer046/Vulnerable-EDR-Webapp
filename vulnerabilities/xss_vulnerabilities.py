"""
vulnerabilities/xss_vulnerabilities.py
--------------------------------------
This file demonstrates Cross-Site Scripting (XSS) vulnerabilities.

VULNERABILITY TYPE: XSS (Cross-Site Scripting)
- Stored XSS in message content.
- Unsanitized message rendering.
- Admin broadcast XSS.

EXPLOIT SCENARIOS:
- Attackers can inject scripts into messages, which execute in other users' browsers.
- Lack of input sanitization allows persistent XSS.
- Admin broadcast can be abused for mass XSS.

This file is intentionally vulnerable for educational purposes.
See vulnerabilities/README.md for more details.
"""

from flask import request, session, jsonify
import sqlite3

def vulnerable_send_message(app, data):
    """
    VULNERABLE: Stored XSS in Message Sending
    
    --- VULNERABILITY: No Input Validation ---
    - Does not validate or sanitize message content (XSS risk).
    - Exploit: Attacker can send a message with a script tag.
    - FIX: Sanitize/escape message content before storing or rendering.
    
    --- VULNERABILITY: No CSRF Protection ---
    - Accepts POST requests without CSRF tokens.
    - Exploit: Attacker can trick a logged-in user into sending messages via CSRF.
    - FIX: Implement CSRF protection (e.g., Flask-WTF).
    
    --- VULNERABILITY: No Rate Limiting ---
    - Allows unlimited messages (spam/DoS risk).
    - FIX: Add rate limiting to API endpoints.
    
    --- VULNERABILITY: No User Existence Check ---
    - Does not check if receiver_id is a valid user.
    - FIX: Validate receiver_id before sending message.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    receiver_id = data.get('receiver_id')
    message = data.get('message')
    
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

def vulnerable_message_retrieval(app, user_id):
    """
    VULNERABLE: Stored XSS in Message Retrieval
    
    --- VULNERABILITY: Stored XSS ---
    - Messages are not sanitized or encoded.
    - Exploit: Attacker can send a message with a script tag, which will execute in the recipient's browser.
    - FIX: Sanitize/escape message content before rendering.
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
                'message': row[2],  # --- VULNERABILITY: XSS ---
                # Messages are not sanitized or encoded, allowing stored XSS.
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

def vulnerable_admin_broadcast_xss(app, data):
    """
    VULNERABLE: Stored XSS in Admin Broadcast
    
    --- VULNERABILITY: Stored XSS ---
    - Admin broadcast messages are not sanitized.
    - Exploit: Admin can broadcast malicious scripts to all users.
    - FIX: Sanitize/escape message content before storing or rendering.
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