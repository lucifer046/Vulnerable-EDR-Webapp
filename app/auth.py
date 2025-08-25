"""
app/auth.py
------------
Authentication Blueprint for the Modular EDR Flask App.
Handles user registration, login, logout, and the root route.

VULNERABILITY REFERENCES:
- SQL Injection: vulnerabilities/sql_injection.py
- Password Vulnerabilities: vulnerabilities/password_vulnerabilities.py
- Input Validation: vulnerabilities/input_validation.py
- Broken Access Control: vulnerabilities/broken_access_control.py
"""

from flask import Blueprint, request, redirect, url_for, render_template, session, flash, current_app as app
import sqlite3
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo

# =====================================================================================
#  Authentication Blueprint Setup
# =====================================================================================

# BLUEPRINT: auth_bp
# DESCRIPTION: This blueprint is the central point for all user authentication-related
# functionalities. It manages how users register, log in, and log out of the system.
# The security of this blueprint is critical to the integrity of the entire application.

auth_bp = Blueprint('auth', __name__, template_folder='templates')

# =====================================================================================
#  Root Route
# =====================================================================================
@auth_bp.route('/')
def index():
    """
    Root route for the app. Redirects to the login page.
    This is the landing page for the app.
    """
    return redirect(url_for('auth.login'))

# =====================================================================================
#  User Registration Route
# =====================================================================================

class RegistrationForm(FlaskForm):
    firstname = StringField('First Name', validators=[DataRequired()])
    lastname = StringField('Last Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm', message='Passwords must match')])
    confirm = PasswordField('Repeat Password')
    phone = StringField('Phone Number')
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')])

# ROUTE: /register
# DESCRIPTION: Handles the creation of new user accounts. It accepts user details via a POST
# request and inserts them into the database.
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles user registration.
    GET: Renders the registration form.
    POST: Processes registration data and creates a new user.
    """
    form = RegistrationForm()
    # VULNERABILITY: CSRF Protection Removed
    # By changing `if form.validate_on_submit():` to `if request.method == 'POST':`,
    # we have disabled the built-in CSRF protection from Flask-WTF. The form now
    # accepts any POST request, making it vulnerable to CSRF attacks where an attacker
    # tricks a user into submitting a registration form on their behalf.
    # This change also bypasses all WTForms validators (e.g., Email, EqualTo),
    # making the "Lack of Input Validation" vulnerability fully exploitable from the server-side.
    if request.method == 'POST':
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        email = request.form.get('email')
        password = request.form.get('password')
        phone = request.form.get('phone')

        # VULNERABILITY: Privilege Escalation
        # CONCEPT: The user's role is determined by the 'role' parameter sent in the form data. Since
        # this is a client-controlled value, a user can set their role to 'admin'.
        # ENUMERATION: An attacker can use a web proxy (like Burp Suite) to intercept the registration
        # request and add or modify the 'role' parameter to 'admin'.
        # FIX: User roles should never be assigned based on direct user input. By default, all new
        # registrations should be assigned the lowest privilege role (e.g., 'user'). Role elevation
        # should be a separate, admin-only function with strict access controls.
        role = request.form.get('role')
        conn = None
        try:
            conn = sqlite3.connect(app.config['DATABASE'])
            cursor = conn.cursor()

            # Check if email already exists (no UNIQUE constraint in DB).
            cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
            if cursor.fetchone()[0] > 0:
                flash("Email already exists. Please use a different email.")
                return render_template('register.html', form=form)

            # VULNERABILITY: Plaintext Password Storage
            # CONCEPT: Storing passwords in plaintext is one of the most severe security flaws. If the
            # database is ever compromised, all user passwords will be exposed, leading to widespread
            # account takeovers, not just in this application but potentially on other services where
            # users have reused their passwords.
            # ENUMERATION: An attacker who gains read access to the database (e.g., via SQL Injection)
            # can simply dump the 'users' table to retrieve all usernames and passwords.
            # FIX: Never store passwords directly. Always use a strong, salted, and adaptive hashing
            # algorithm like Argon2, scrypt, or at a minimum, bcrypt. When a user registers or changes
            # their password, hash it before storing it. During login, hash the submitted password and
            # compare it with the stored hash.
            cursor.execute(
                "INSERT INTO users (firstname, lastname, email, password, phone, role) VALUES (?, ?, ?, ?, ?, ?)",
                (firstname, lastname, email, password, phone, role)
            )
            conn.commit()
        except sqlite3.Error as e:
            print(f"Database error during registration: {e}")
        finally:
            if conn:
                conn.close()
        return redirect(url_for('auth.login'))
    # GET request: show registration form.
    return render_template('register.html', form=form)

# =====================================================================================
#  Authentication Forms
# =====================================================================================

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])

# =====================================================================================
#  User Login Route
# =====================================================================================

# ROUTE: /login
# DESCRIPTION: Authenticates users based on their email and password. On successful
# authentication, it creates a user session.
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    print("Accessed the login route.")
    form = LoginForm()
    # VULNERABILITY: CSRF Protection Removed
    # Similar to the registration form, replacing `form.validate_on_submit()` with
    # `if request.method == 'POST':` disables CSRF protection on the login form.
    # This makes Login CSRF attacks possible.
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            conn = None
            conn = sqlite3.connect(app.config['DATABASE'])
            cursor = conn.cursor()

            # VULNERABILITY: SQL Injection (in original code, now mitigated)
            # CONCEPT: The original version of this code likely used f-strings or string concatenation to build
            # the SQL query, like: f"SELECT ... WHERE email = '{email}' AND password = '{password}'".
            # This allows an attacker to manipulate the query logic.
            # ENUMERATION: An attacker could enter `' OR '1'='1` in the password field to bypass authentication
            # for any user. For example, the query would become `... WHERE email = 'someuser@example.com' AND password = '' OR '1'='1'`, which is always true.
            # FIX: The current code correctly uses parameterized queries (the '?' placeholders). This is the
            # standard and most effective way to prevent SQL Injection. The database driver handles the safe substitution of parameters.
            query = "SELECT id, firstname, lastname, email, phone, role FROM users WHERE email = ? AND password = ?"
            cursor.execute(query, (email, password))
            user = cursor.fetchone()

            if user:
                # VULNERABILITY: Weak Session Management
                # CONCEPT: The security of the user's session depends entirely on the secrecy and strength
                # of the Flask `SECRET_KEY`. In this application, the secret key is hardcoded and weak.
                # This makes the session cookies predictable and easy to forge.
                # ENUMERATION: An attacker could use a tool like 'flask-unsign' to crack the secret key offline.
                # Once they have the key, they can create a valid session cookie for any user (including admins)
                # without needing their password, granting them full access to that user's account.
                # FIX: Use a long, random, and unpredictable string for the `SECRET_KEY`. This key should be
                # stored securely as an environment variable and not hardcoded in the source code.
                session['user_id'] = user[0]
                session['user_email'] = user[3]
                session['user_role'] = user[5]
                return redirect(url_for('dashboard.dashboard'))
            else:
                flash("Invalid email or password.")
                return redirect(url_for('auth.login'))
        except sqlite3.Error as e:
            print(f"Database error during login: {e}")
            flash("An error occurred. Please try again.")
            return redirect(url_for('auth.login'))
        finally:
            if conn:
                conn.close()
    # GET request: show login form.
    print("Rendering login.html")
    return render_template('login.html', form=form)

# =====================================================================================
#  User Logout Route
# =====================================================================================
@auth_bp.route('/logout')
def logout():
    """
    Logs the user out by clearing the session.
    This removes all session data and redirects to the login page.
    """
    session.clear()
    print("User logged out.")
    return redirect(url_for('auth.login'))