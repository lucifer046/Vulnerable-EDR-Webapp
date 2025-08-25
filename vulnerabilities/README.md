# Vulnerability Modules

This directory contains intentionally vulnerable code for educational purposes in the PvtEDR Project. Each module focuses on specific types of security vulnerabilities found in web applications.

## ⚠️ SECURITY WARNING

**ALL CODE IN THIS DIRECTORY IS INTENTIONALLY VULNERABLE FOR EDUCATIONAL PURPOSES.**
**DO NOT USE IN PRODUCTION ENVIRONMENTS.**

## Module Structure

### 1. `broken_access_control.py`
**Focus**: Weak session validation and insufficient access controls

**Vulnerabilities**:
- User enumeration without proper validation
- Admin broadcast without proper role verification  
- Message access without permission checks

**Key Functions**:
- `vulnerable_api_get_users()` - Weak session validation
- `vulnerable_admin_broadcast()` - Insufficient role checking
- `vulnerable_message_access()` - No permission validation

### 2. `xss_vulnerabilities.py`
**Focus**: Cross-Site Scripting (XSS) vulnerabilities in message handling

**Vulnerabilities**:
- Stored XSS in message content
- Unsanitized message rendering
- Admin broadcast XSS

**Key Functions**:
- `vulnerable_send_message()` - No message sanitization
- `vulnerable_message_retrieval()` - Unsanitized message display
- `vulnerable_admin_broadcast_xss()` - Admin broadcast XSS

### 3. `input_validation.py`
**Focus**: Lack of proper input validation and sanitization

**Vulnerabilities**:
- No message content validation
- No user ID validation
- Weak session validation

**Key Functions**:
- `vulnerable_message_validation()` - No input sanitization
- `vulnerable_user_id_validation()` - No parameter validation
- `vulnerable_session_validation()` - Weak session checking

### 4. `rate_limiting.py`
**Focus**: Missing rate limiting on API endpoints

**Vulnerabilities**:
- Unlimited message sending
- Unlimited user enumeration
- Unlimited admin broadcasts

**Key Functions**:
- `vulnerable_user_enumeration_no_rate_limit()` - No rate limiting
- `vulnerable_message_sending_no_rate_limit()` - Unlimited messages
- `vulnerable_admin_broadcast_no_rate_limit()` - Unlimited broadcasts

### 5. `csrf_vulnerabilities.py`
**Focus**: Missing CSRF protection on state-changing operations

**Vulnerabilities**:
- No CSRF tokens on message sending
- No CSRF protection on admin broadcasts
- Vulnerable GET endpoints

**Key Functions**:
- `vulnerable_send_message_no_csrf()` - No CSRF protection
- `vulnerable_admin_broadcast_no_csrf()` - Admin CSRF vulnerability
- `vulnerable_user_enumeration_no_csrf()` - GET endpoint CSRF

### 6. `pagination_vulnerabilities.py`
**Focus**: Missing pagination leading to potential DoS

**Vulnerabilities**:
- Returning all messages at once
- Returning all users at once
- Processing all users in broadcasts

**Key Functions**:
- `vulnerable_message_retrieval_no_pagination()` - All messages at once
- `vulnerable_user_enumeration_no_pagination()` - All users at once
- `vulnerable_admin_broadcast_no_pagination()` - All users processing

### 7. `insecure_logging.py`
**Focus**: Insecure logging practices

**Vulnerabilities**:
- Logging sensitive information
- Debug level logging in production
- Console output of sensitive data

**Key Functions**:
- `enable_insecure_logging()` - Debug level logging

### 8. `sql_injection.py`
**Focus**: SQL injection vulnerabilities in database queries

**Vulnerabilities**:
- User login SQL injection
- Admin login SQL injection
- User search SQL injection

**Key Functions**:
- `vulnerable_user_login()` - SQL injection in user authentication
- `vulnerable_admin_login()` - SQL injection in admin authentication
- `vulnerable_user_search()` - SQL injection in user search

### 9. `password_vulnerabilities.py`
**Focus**: Password-related security vulnerabilities

**Vulnerabilities**:
- Plaintext password storage
- No password hashing
- Weak password requirements

**Key Functions**:
- `vulnerable_user_registration()` - No password hashing
- `vulnerable_admin_registration()` - Admin password vulnerabilities
- `vulnerable_password_change()` - Password change vulnerabilities

### 10. `information_disclosure.py`
**Focus**: Information disclosure vulnerabilities

**Vulnerabilities**:
- System information exposure
- User data disclosure
- Error message information leakage

**Key Functions**:
- `vulnerable_dashboard_access()` - Dashboard information disclosure
- `get_vulnerable_system_info()` - System information exposure
- `vulnerable_user_listing()` - User data disclosure

### 11. `privilege_escalation.py`
**Focus**: Privilege escalation and access control vulnerabilities

**Vulnerabilities**:
- Admin role bypass
- Session elevation attacks
- Unauthorized role assignment

**Key Functions**:
- `vulnerable_admin_remove_user()` - Admin privilege escalation
- `vulnerable_role_assignment()` - Unauthorized role assignment
- `vulnerable_session_elevation()` - Session manipulation attacks

## Usage

Each module can be imported and used independently:

```python
from vulnerabilities import broken_access_control
from vulnerabilities import xss_vulnerabilities

# Use specific vulnerability functions
result = broken_access_control.vulnerable_api_get_users(app)
```

## Educational Purpose

These modules are designed to:

1. **Demonstrate** common web application vulnerabilities
2. **Show** how vulnerabilities can be exploited
3. **Provide** examples for security testing and training
4. **Highlight** the importance of secure coding practices

## Security Fixes

Each vulnerability includes comments explaining:
- What the vulnerability is
- How it can be exploited
- How to fix it

## Contributing

When adding new vulnerability modules:

1. Follow the existing naming convention
2. Include detailed vulnerability documentation
3. Add the module to `__init__.py`
4. Update this README with module information

## Related Files

- `app/chat.py` - Original vulnerable chat implementation
- `app/auth.py` - Authentication vulnerabilities
- `app/admin.py` - Admin panel vulnerabilities 