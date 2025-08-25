"""
vulnerabilities/rate_limiting.py
--------------------------------
This file demonstrates Rate Limiting vulnerabilities.

VULNERABILITY TYPE: Missing Rate Limiting
- Unlimited message sending.
- Unlimited user enumeration.
- Unlimited admin broadcasts.

EXPLOIT SCENARIOS:
- Attackers can spam endpoints, causing DoS or brute-force attacks.
- No controls to prevent abuse of API endpoints.

This file is intentionally vulnerable for educational purposes.
See vulnerabilities/README.md for more details.
"""

from flask import request, session, jsonify
import sqlite3

def vulnerable_user_enumeration_no_rate_limit(app):
    """
    VULNERABLE: No Rate Limiting on User Enumeration
    
    --- VULNERABILITY: User Enumeration ---
    - No rate limiting or anti-enumeration protection.
    - Exploit: Attacker can enumerate all users via repeated API calls.
    - FIX: Add rate limiting and anti-enumeration controls.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: No rate limiting - attacker can call this repeatedly
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

def vulnerable_message_sending_no_rate_limit(app, data):
    """
    VULNERABLE: No Rate Limiting on Message Sending
    
    --- VULNERABILITY: No Rate Limiting ---
    - Allows unlimited messages (spam/DoS risk).
    - FIX: Add rate limiting to API endpoints.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    receiver_id = data.get('receiver_id')
    message = data.get('message')
    
    if not receiver_id or not message:
        return jsonify({'error': 'Missing receiver_id or message'}), 400
    
    # VULNERABLE: No rate limiting - attacker can spam messages
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

def vulnerable_admin_broadcast_no_rate_limit(app, data):
    """
    VULNERABLE: No Rate Limiting on Admin Broadcast
    
    --- VULNERABILITY: No Rate Limiting ---
    - Admin can broadcast unlimited messages (spam/DoS risk).
    - FIX: Add rate limiting to admin broadcast endpoint.
    """
    if session.get('user_role') != 'admin':
        return {'error': 'Unauthorized'}, 403
    
    message = data.get('message')
    if not message:
        return {'error': 'Missing message'}, 400
    
    # VULNERABLE: No rate limiting - admin can spam broadcasts
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

def vulnerable_message_retrieval_no_rate_limit(app, user_id):
    """
    VULNERABLE: No Rate Limiting on Message Retrieval
    
    --- VULNERABILITY: No Rate Limiting ---
    - No rate limiting on message retrieval (DoS risk).
    - FIX: Add rate limiting to message retrieval endpoint.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: No rate limiting - attacker can repeatedly request messages
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