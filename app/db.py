"""
app/db.py
---------
Database Initialization and Helpers for the Modular EDR Flask App.

This script is responsible for setting up the application's SQLite database.
It defines the schema for all necessary tables: `users`, `messages`, and
`user_system_info`. This function is typically called once at application
startup to ensure the database is ready.

VULNERABILITY DETAILS:
---------------------
1.  **Plaintext Password Storage:**
    - The `users` table schema defines the `password` column as `TEXT NOT NULL`.
      This design leads to storing user passwords in plaintext, which is a
      critical security flaw. If the database is compromised, all user
      passwords will be exposed.

2.  **No UNIQUE Constraint on Email:**
    - The `email` column in the `users` table lacks a `UNIQUE` constraint.
      This allows multiple user accounts to be registered with the same email
      address, which can lead to account enumeration issues, confusion, and
      potential security bypasses depending on how password resets or other
      features are implemented.

3.  **Lack of Input Validation (Implicit):**
    - While not directly in this file, the database schema's lack of strict
      constraints (e.g., on string length, format) places the full burden of
      validation on the application logic. A robust schema should act as a
      second line of defense against invalid or malicious data.
"""

import sqlite3
from flask import current_app as app

# =====================================================================================
#  Database Initialization and Helpers
# =====================================================================================
# This module provides a centralized function (`init_db`) to initialize the database.
# It ensures that all required tables are created with the correct schema before the
# application starts handling requests.

def init_db():
    """
    Initializes the SQLite database and creates the required tables if they do not exist:
    - `users`: Stores user and admin account information.
    - `messages`: Stores chat messages between users.
    - `user_system_info`: Stores system information submitted by each user's client.
    """
    try:
        conn = sqlite3.connect(app.config['DATABASE'])
        cursor = conn.cursor()
        print("Database connection successful.")

        # --------------------------------------------------------------------------------
        # VULNERABILITY: Plaintext Password Storage & No UNIQUE Email Constraint
        # --------------------------------------------------------------------------------
        # **Concept (Plaintext Password):** Storing passwords as clear text in the database
        # is extremely dangerous. One SQL injection vulnerability or a database breach would
        # instantly expose all user credentials, leading to widespread account takeovers.
        #
        # **Concept (No UNIQUE Email):** Allowing multiple accounts with the same email address
        # can break business logic (e.g., password resets) and be abused. An attacker could
        # register an account with a victim's email, potentially intercepting communications
        # or causing denial of service.
        #
        # **Enumeration:**
        # - Register multiple accounts using the exact same email address.
        # - If you gain database access (e.g., via SQLi), query the `users` table and observe
        #   that passwords are fully readable.
        #
        # **Fix:**
        # - **Passwords:** NEVER store plaintext passwords. Store a salted hash of the password
        #   using a strong, modern hashing algorithm like Argon2 or bcrypt.
        # - **Email:** Add a `UNIQUE` constraint to the `email` column (`email TEXT NOT NULL UNIQUE`).
        # --------------------------------------------------------------------------------
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                firstname TEXT NOT NULL,
                lastname TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL, -- VULNERABLE: Should be a salted hash
                phone TEXT,
                role TEXT DEFAULT 'user'
            )
        ''')
        conn.commit()
        print("Users table created or already exists.")
        
        # Messages table for chat functionality
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id)
            )
        ''')
        conn.commit()
        print("Messages table created or already exists.")
        
        # Table for storing per-user system info
        # NOTE: Storing this as a JSON string is flexible but makes querying specific
        # info difficult. In a large-scale system, you might normalize this into
        # separate columns or use a database that supports JSON natively (like PostgreSQL).
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_system_info (
                user_id INTEGER PRIMARY KEY,
                info TEXT, -- Storing as JSON string blob
                last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()
        print("User system info table created or already exists.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        if conn:
            conn.close()