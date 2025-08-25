"""
app/__init__.py
--------------
Flask App Factory for the Modular EDR Flask App.
Sets up configuration, registers blueprints, and returns the app instance.

Security Context:
- Demonstrates hardcoded secret key and insecure config for educational purposes.
- DO NOT use this code in production.
"""

import os
from flask import Flask
# from flask_wtf.csrf import CSRFProtect # CSRF protection has been removed
from .auth import auth_bp
from .dashboard import dashboard_bp
from .chat import chat_bp
from .admin import admin_bp
from .system_info import system_info_bp

# =====================================================================================
#  Flask App Factory
# =====================================================================================
# This function creates and configures the Flask application instance.
# It sets up configuration, registers all blueprints, and returns the app object.

def create_app():
    """
    Application factory for the EDR Flask app.
    - Sets secret key and database path.
    - Registers all feature blueprints (auth, dashboard, chat, admin).

    --- VULNERABILITY: Hardcoded Secret Key ---
    - The secret key is hardcoded and simple.
    - Exploit: If the secret key is leaked, attackers can forge sessions and cookies.
    - FIX: Use a strong, random secret key loaded from an environment variable.
    """
    app = Flask(__name__)
    # --- VULNERABILITY: Hardcoded Secret Key ---
    # CONCEPT: The secret key is hardcoded and simple. This key is used by Flask to sign session cookies
    # and other security-sensitive values. A weak or leaked secret key allows attackers to forge
    # session cookies, leading to session hijacking and privilege escalation.
    # ENUMERATION:
    # 1. **Direct Observation:** The key is visible in the source code (`'a-very-insecure-secret-key-for-dev'`).
    # 2. **Session Tampering:** An attacker can use tools like `flask-unsign` to decode and re-encode
    #    session cookies if they know or can guess the secret key. This allows them to change session
    #    data (e.g., `user_id`, `user_role`) to gain unauthorized access or impersonate other users.
    #    Example: `flask-unsign --decode --cookie 'eyJ1c2VyX2lkIjoxfQ.Y...' --secret 'a-very-insecure-secret-key-for-dev'`
    # FIX:
    # 1. **Environment Variables:** Load the secret key from an environment variable (`os.environ.get('SECRET_KEY')`).
    #    This prevents the key from being committed to version control.
    # 2. **Strong Random Key:** Generate a long, random, and unpredictable key (e.g., `secrets.token_hex(32)` in Python).
    # 3. **Key Rotation:** Implement a mechanism to rotate the secret key periodically.
    # 4. **Secure Storage:** Ensure the environment variable is stored securely on the deployment server.
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-insecure-secret-key-for-dev')
    app.config['DATABASE'] = os.environ.get('DATABASE_PATH', 'vulnerable_edr.db')

    # --- VULNERABILITY: CSRF Protection Disabled ---
    # CONCEPT: CSRF protection has been globally disabled for this application. This means that no forms
    # are protected against Cross-Site Request Forgery attacks. An attacker can create a malicious
    # website that tricks a logged-in user into submitting a form on their behalf without their knowledge.
    # This affects login, registration, user removal, role changes, and messaging.
    # FIX: Re-enable CSRF protection by uncommenting `from flask_wtf.csrf import CSRFProtect` and `CSRFProtect(app)`.
    # CSRFProtect(app)

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(system_info_bp)
    return app