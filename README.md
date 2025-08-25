# Vulnerable EDR Project (Modular Flask Version)

This project is a purposely vulnerable Endpoint Detection and Response (EDR) web application, refactored into a modular Flask project. It demonstrates common security flaws for educational and research purposes. The codebase has been extensively commented to explain the functionality, vulnerabilities, and potential fixes for each component.

**WARNING: This application is insecure by design. Do NOT deploy in a production environment.**

---

## Table of Contents
- [Features](#features)
- [Project Structure](#project-structure)
- [Setup Instructions](#setup-instructions)
- [Identified Vulnerabilities](#identified-vulnerabilities)
- [Blueprints & Modules](#blueprints--modules)
- [Vulnerability Modules](#vulnerability-modules)
- [Database](#database)
- [License](#license)

---

## Features
- **User Authentication:** Standard user registration, login, and logout.
- **Admin Functionality:** Separate registration/login for admins, with capabilities for user management and audit logging.
- **Dashboard:** A central view displaying system information (OS, CPU, RAM, disk, running processes).
- **Chat System:** A basic chat for users, with a global broadcast feature for admins.
- **Audit Logging:** Admins can view a log of administrative actions.
- **RESTful APIs:** Endpoints for chat, user information, and system data.

---

## Project Structure

```
PvtEDR Project/
│
├── app/
│   ├── __init__.py         # App factory, blueprint registration, configuration.
│   ├── admin.py            # Admin blueprint: User management, audit logs.
│   ├── auth.py             # Auth blueprint: Login, registration, logout.
│   ├── chat.py             # Chat API blueprint: Messaging and user info.
│   ├── dashboard.py        # Dashboard blueprint: System info display.
│   ├── db.py               # Database initialization and schema.
│   ├── system_info.py      # System information collection logic.
│   └── templates/          # HTML templates for the frontend.
│       ├── admin_login.html
│       ├── admin_panel.html
│       ├── admin_register.html
│       ├── audit_log.html
│       ├── dashboard.html
│       ├── login.html
│       └── register.html
│
├── run.py                  # Main entry point to run the application.
├── requirements.txt        # Python dependencies.
├── README.md               # This file.
├── vulnerabilities/        # Modules demonstrating specific vulnerabilities.
└── vulnerable_edr.db       # SQLite database file (auto-created).
```

---

## Setup Instructions

1.  **Clone the repository** (if you haven't already).

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the application:**
    ```bash
    python run.py
    ```

4.  **Access the application:**
    Open your browser and navigate to `http://127.0.0.1:5000`.

---

## Identified Vulnerabilities

This application is riddled with security flaws. The code files (`.py` and `.html`) have been commented in detail to explain each vulnerability, how to enumerate it, and what the conceptual fix is. Below is a summary of the major issues.

### Authentication & Session Management
- **Plaintext Password Storage (`db.py`, `auth.py`):** Passwords are stored in the database without any hashing or salting.
- **Weak Session Management (`auth.py`):** The Flask secret key is hardcoded and weak. Session cookies are not flagged as `Secure` or `HttpOnly`.
- **Open Admin Registration (`auth.py`, `register.html`):** The public registration form allows any user to create an account with the 'Admin' role.
- **Login CSRF (`login.html`):** The login form lacks CSRF protection, allowing an attacker to log a user into an attacker-controlled account.

### Access Control
- **Broken Access Control (Throughout):** Most routes only check for the presence of `user_id` in the session, failing to validate the session's integrity or the user's role correctly. Admins can remove other admins.
- **Privilege Escalation (`admin.py`, `auth.py`):** Users can self-assign the admin role upon registration. Admins can change user roles without restriction.

### Input Validation & Sanitization
- **Stored Cross-Site Scripting (XSS) (`chat.py`, `dashboard.html`, `audit_log.html`):** User-supplied data (chat messages, user names, etc.) is rendered directly into HTML templates without proper escaping.
- **Lack of Input Validation (`auth.py`, `chat.py`):** No server-side validation on registration, login, or messaging inputs.

### Information Disclosure & Enumeration
- **User Enumeration (`chat.py`):** An API endpoint exposes a list of all registered users to any authenticated user.
- **Sensitive Information Disclosure (`dashboard.py`, `system_info.py`):** Detailed system and process information is exposed to all authenticated users, not just admins.

### Other
- **Cross-Site Request Forgery (CSRF) (All Forms):** No CSRF tokens are used on any state-changing forms (registration, login, user removal, etc.).
- **Denial of Service (DoS) (`chat.py`, `system_info.py`):** Lack of rate limiting, pagination, and inefficient database queries present significant DoS risks.
- **Insecure Database Schema (`db.py`):** The `users` table lacks a `UNIQUE` constraint on the email field.

---

## Blueprints & Modules

-   **`admin.py`**: Manages all admin-related functionality, including user management (removal, role changes) and viewing the audit log. Contains critical access control flaws.
-   **`auth.py`**: Handles user authentication (registration, login, logout). Contains major vulnerabilities like plaintext password handling and open admin registration.
-   **`chat.py`**: Powers the chat functionality via API endpoints. Riddled with XSS, access control, and DoS issues.
-   **`dashboard.py`**: Renders the main user dashboard, exposing sensitive system information.
-   **`db.py`**: Defines the database schema and initialization logic. Highlights insecure practices like storing plaintext passwords.
-   **`system_info.py`**: Collects and returns detailed system information, leading to information disclosure and potential DoS.

## Vulnerability Modules

This project includes a dedicated `vulnerabilities/` directory, where each file represents a specific type of vulnerability demonstrated within the application. These modules are designed to showcase common security flaws and provide a structured way to explore and understand them.

-   **`broken_access_control.py`**: Demonstrates flaws where users can access resources or perform actions they are not authorized for.
-   **`csrf_vulnerabilities.py`**: Highlights Cross-Site Request Forgery issues, where an attacker can trick a user into executing unwanted actions.
-   **`information_disclosure.py`**: Illustrates how sensitive data can be unintentionally exposed to unauthorized parties.
-   **`input_validation.py`**: Shows the consequences of inadequate input validation, leading to various injection attacks.
-   **`insecure_logging.py`**: Focuses on vulnerabilities related to logging sensitive information insecurely.
-   **`pagination_vulnerabilities.py`**: Explores issues in pagination implementations that can lead to information disclosure or denial of service.
-   **`password_vulnerabilities.py`**: Demonstrates weak password handling practices, such as plaintext storage or weak hashing.
-   **`privilege_escalation.py`**: Showcases methods by which a user can gain higher-level access than they are authorized for.
-   **`rate_limiting.py`**: Illustrates the impact of missing or insufficient rate limiting, leading to brute-force attacks or resource exhaustion.
-   **`sql_injection.py`**: Provides examples of SQL Injection flaws, allowing attackers to interfere with database queries.
-   **`xss_vulnerabilities.py`**: Contains examples of Cross-Site Scripting, where malicious scripts are injected into trusted websites.

---

## Database

-   **File:** `vulnerable_edr.db` (auto-created on first run).
-   **Tables:**
    -   `users`: Stores user credentials and roles. **(VULNERABILITY: Plaintext passwords, no unique email constraint)**.
    -   `messages`: Stores all chat messages. **(VULNERABILITY: Content is not sanitized, leading to Stored XSS)**.
    -   `user_system_info`: Stores system information snapshots.
    -   `admin_actions_log`: Stores a log of actions performed by admins.

---

## License

This project is for educational and research purposes only. Use at your own risk.