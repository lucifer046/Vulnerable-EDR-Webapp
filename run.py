"""
run.py
------
Main Application Entry Point for the Modular EDR Flask App.
Creates the app, initializes the database, and starts the server.

Security Context:
- Demonstrates insecure debug mode and startup practices for educational purposes.
- DO NOT use this code in production.
"""

from app import create_app
from app.db import init_db

# =====================================================================================
#  Main Application Entry Point
# =====================================================================================
# This script is the entry point for running the modular EDR Flask application.
# It creates the Flask app using the factory, initializes the database, and starts the server.

if __name__ == '__main__':
    """
    Main entry point for the EDR Flask app.
    - Creates the Flask app instance using the factory pattern.
    - Initializes the database and creates tables if they do not exist.
    - Starts the Flask development server.

    --- VULNERABILITY: Debug Mode ---
    - Running with debug=True is insecure for production.
    - Exploit: If an error occurs, the Werkzeug debugger allows arbitrary code execution.
    - FIX: Set debug=False in production and use a production-ready WSGI server.
    """
    app = create_app()
    # Initialize the database and create tables if they do not exist.
    # This must be run within the app context so Flask config is available.
    with app.app_context():
        init_db()
    # --- VULNERABILITY: Debug Mode ---
    # Running with debug=True is insecure for production.
    # FIX: Set debug=False in production. Use a production-grade WSGI server
    # like Gunicorn or Waitress instead of the Flask development server.
    # The 'debug' flag should ideally be loaded from an environment variable.
    app.run(host='0.0.0.0', port=5000, debug=True)

