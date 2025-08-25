"""
vulnerabilities/pagination_vulnerabilities.py
---------------------------------------------
This file demonstrates Pagination vulnerabilities.

VULNERABILITY TYPE: Missing Pagination
- Returning all messages or users at once.
- Processing all users in broadcasts.

EXPLOIT SCENARIOS:
- Attackers can cause Denial of Service (DoS) by requesting large datasets.
- Lack of pagination can overwhelm server resources.

This file is intentionally vulnerable for educational purposes.
See vulnerabilities/README.md for more details.
"""

from flask import request, session, jsonify
import sqlite3

def vulnerable_message_retrieval_no_pagination(app, user_id):
    """
    VULNERABLE: No Pagination in Message Retrieval
    
    --- VULNERABILITY: No Pagination ---
    - Returns all messages at once, which can be abused for DoS.
    - FIX: Add pagination to API responses.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: No pagination - returns ALL messages at once
    # This can lead to DoS if there are many messages
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

def vulnerable_user_enumeration_no_pagination(app):
    """
    VULNERABLE: No Pagination in User Enumeration
    
    --- VULNERABILITY: No Pagination ---
    - Returns all users at once, which can be abused for DoS.
    - FIX: Add pagination to user enumeration endpoint.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: No pagination - returns ALL users at once
    # This can lead to DoS if there are many users
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

def vulnerable_admin_broadcast_no_pagination(app, data):
    """
    VULNERABLE: No Pagination in Admin Broadcast
    
    --- VULNERABILITY: No Pagination ---
    - Processes all users at once, which can be slow with many users.
    - FIX: Add pagination to admin broadcast processing.
    """
    if session.get('user_role') != 'admin':
        return {'error': 'Unauthorized'}, 403
    
    message = data.get('message')
    if not message:
        return {'error': 'Missing message'}, 400
    
    # VULNERABLE: No pagination - processes ALL users at once
    # This can be slow and resource-intensive with many users
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

def vulnerable_message_search_no_pagination(app, search_term):
    """
    VULNERABLE: No Pagination in Message Search (Hypothetical)
    
    --- VULNERABILITY: No Pagination ---
    - Returns all matching messages at once, which can be abused for DoS.
    - FIX: Add pagination to search results.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABLE: No pagination - returns ALL matching messages at once
    # This can lead to DoS if there are many matching messages
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        cursor.execute('''
            SELECT sender_id, receiver_id, message, timestamp FROM messages
            WHERE ((sender_id = ? OR receiver_id = ?) AND message LIKE ?)
            ORDER BY timestamp DESC
        ''', (session['user_id'], session['user_id'], f'%{search_term}%'))
        
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