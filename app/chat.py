"""
app/chat.py
-----------
Chat API Blueprint for the Modular EDR Flask App.
Provides RESTful API endpoints for user chat, message retrieval, and admin broadcast.

VULNERABILITY REFERENCES:
- Broken Access Control: vulnerabilities/broken_access_control.py
- XSS Vulnerabilities: vulnerabilities/xss_vulnerabilities.py
- Input Validation: vulnerabilities/input_validation.py
- CSRF Vulnerabilities: vulnerabilities/csrf_vulnerabilities.py
- Rate Limiting: vulnerabilities/rate_limiting.py
- Pagination Vulnerabilities: vulnerabilities/pagination_vulnerabilities.py
"""

from flask import Blueprint, request, session, jsonify, current_app as app
import sqlite3

# =====================================================================================
#  Chat API Blueprint Setup
# =====================================================================================
# This blueprint provides RESTful API endpoints for user chat, message retrieval,
# and admin broadcast functionality.

chat_bp = Blueprint('chat', __name__)

# =====================================================================================
#  Get Users API
# =====================================================================================
@chat_bp.route('/api/users')
def api_get_users():
    """
    Returns a list of all users except the current user (for chat user list).
    Requires user to be logged in (checks session['user_id']).
    """
    # VULNERABILITY: Broken Access Control
    # Reference: vulnerabilities/broken_access_control.py
    # Issue: Only checks if 'user_id' is in session, does not verify session integrity
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABILITY: User Enumeration
    # Reference: vulnerabilities/rate_limiting.py
    # Issue: No rate limiting or anti-enumeration protection
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

# =====================================================================================
#  Get Messages API
# =====================================================================================
@chat_bp.route('/api/messages/<int:user_id>')
def api_get_messages(user_id):
    """
    Returns chat history between the current user and another user (user_id).
    Requires user to be logged in.
    """
    # VULNERABILITY: Broken Access Control
    # Reference: vulnerabilities/broken_access_control.py
    # Issue: Only checks if 'user_id' is in session, does not verify session integrity
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # VULNERABILITY: No Input Validation
    # Reference: vulnerabilities/input_validation.py
    # Issue: Does not check if user_id is valid or if the user is allowed to chat with this user
    
    # VULNERABILITY: No Pagination
    # Reference: vulnerabilities/pagination_vulnerabilities.py
    # Issue: Returns all messages at once, which can be abused for DoS
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
                'message': row[2],  # VULNERABILITY: Stored XSS
                # Reference: vulnerabilities/xss_vulnerabilities.py
                # Issue: Messages are not sanitized or encoded, allowing stored XSS
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

# =====================================================================================
#  Send Message API
# =====================================================================================
@chat_bp.route('/api/send_message', methods=['POST'])
def api_send_message():
    """
    Sends a message from the current user to another user.
    Accepts POST with JSON body: {receiver_id, message}.
    Requires user to be logged in.
    """
    # VULNERABILITY: Broken Access Control
    # Reference: vulnerabilities/broken_access_control.py
    # Issue: Only checks if 'user_id' is in session, does not verify session integrity
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.get_json()
    
    # VULNERABILITY: No Input Validation
    # Reference: vulnerabilities/input_validation.py
    # Issue: Does not validate or sanitize message content (XSS risk)
    receiver_id = data.get('receiver_id')
    message = data.get('message')
    if not receiver_id or not message:
        return jsonify({'error': 'Missing receiver_id or message'}), 400
    
    # VULNERABILITY: No CSRF Protection
    # Reference: vulnerabilities/csrf_vulnerabilities.py
    # Issue: Accepts POST requests without CSRF tokens
    
    # VULNERABILITY: No Rate Limiting
    # Reference: vulnerabilities/rate_limiting.py
    # Issue: Allows unlimited messages (spam/DoS risk)
    
    # VULNERABILITY: No User Existence Check
    # Reference: vulnerabilities/input_validation.py
    # Issue: Does not check if receiver_id is a valid user
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

# =====================================================================================
#  Admin Broadcast API
# =====================================================================================
@chat_bp.route('/api/send_message_all', methods=['POST'])
def api_send_message_all():
    """
    Allows admin to send a message to all users (broadcast).
    Requires admin privileges.
    """
    # VULNERABILITY: Broken Access Control
    # Reference: vulnerabilities/broken_access_control.py
    # Issue: Only checks if session['user_role'] == 'admin'
    if session.get('user_role') != 'admin':
        return {'error': 'Unauthorized'}, 403
    
    # VULNERABILITY: No CSRF Protection
    # Reference: vulnerabilities/csrf_vulnerabilities.py
    # Issue: This admin-only endpoint accepts POST requests without CSRF tokens, making it
    # vulnerable to attacks where an attacker tricks an admin's browser into broadcasting a message.
    
    data = request.get_json()
    
    # VULNERABILITY: No Input Validation
    # Reference: vulnerabilities/input_validation.py
    # Issue: Does not validate or sanitize broadcast message content
    message = data.get('message')
    if not message:
        return {'error': 'Missing message'}, 400
    
    # VULNERABILITY: No Rate Limiting
    # Reference: vulnerabilities/rate_limiting.py
    # Issue: Admin can broadcast unlimited messages
    
    # VULNERABILITY: No Pagination
    # Reference: vulnerabilities/pagination_vulnerabilities.py
    # Issue: Processes all users at once, which can be slow with many users
    conn = sqlite3.connect(app.config['DATABASE'])
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE role != "admin"')
    user_ids = [row[0] for row in cursor.fetchall()]
    for uid in user_ids:
        cursor.execute('INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)', (session['user_id'], uid, message))
    conn.commit()
    conn.close()
    return {'success': True} 