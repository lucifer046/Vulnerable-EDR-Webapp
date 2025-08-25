"""
vulnerabilities/__init__.py
---------------------------
Vulnerability modules index for the PvtEDR Project.

This package contains intentionally vulnerable code for educational purposes.
Each module focuses on specific types of security vulnerabilities.

SECURITY WARNING: All code in this package is intentionally vulnerable.
DO NOT use in production environments.

Available vulnerability modules:
- broken_access_control.py: Broken access control vulnerabilities
- xss_vulnerabilities.py: Cross-Site Scripting (XSS) vulnerabilities  
- input_validation.py: Input validation vulnerabilities
- rate_limiting.py: Rate limiting vulnerabilities
- csrf_vulnerabilities.py: Cross-Site Request Forgery (CSRF) vulnerabilities
- pagination_vulnerabilities.py: Pagination vulnerabilities
- insecure_logging.py: Insecure logging vulnerabilities
- sql_injection.py: SQL injection vulnerabilities
- password_vulnerabilities.py: Password-related vulnerabilities
- information_disclosure.py: Information disclosure vulnerabilities
- privilege_escalation.py: Privilege escalation vulnerabilities
"""

from . import broken_access_control
from . import xss_vulnerabilities
from . import input_validation
from . import rate_limiting
from . import csrf_vulnerabilities
from . import pagination_vulnerabilities
from . import insecure_logging
from . import sql_injection
from . import password_vulnerabilities
from . import information_disclosure
from . import privilege_escalation

__all__ = [
    'broken_access_control',
    'xss_vulnerabilities', 
    'input_validation',
    'rate_limiting',
    'csrf_vulnerabilities',
    'pagination_vulnerabilities',
    'insecure_logging',
    'sql_injection',
    'password_vulnerabilities',
    'information_disclosure',
    'privilege_escalation'
]

# Vulnerability summary for quick reference
VULNERABILITY_SUMMARY = {
    'broken_access_control': {
        'description': 'Weak session validation and insufficient access controls',
        'examples': [
            'User enumeration without proper validation',
            'Admin broadcast without proper role verification',
            'Message access without permission checks'
        ]
    },
    'xss_vulnerabilities': {
        'description': 'Cross-Site Scripting vulnerabilities in message handling',
        'examples': [
            'Stored XSS in message content',
            'Unsanitized message rendering',
            'Admin broadcast XSS'
        ]
    },
    'input_validation': {
        'description': 'Lack of proper input validation and sanitization',
        'examples': [
            'No message content validation',
            'No user ID validation',
            'Weak session validation'
        ]
    },
    'rate_limiting': {
        'description': 'Missing rate limiting on API endpoints',
        'examples': [
            'Unlimited message sending',
            'Unlimited user enumeration',
            'Unlimited admin broadcasts'
        ]
    },
    'csrf_vulnerabilities': {
        'description': 'Missing CSRF protection on state-changing operations',
        'examples': [
            'No CSRF tokens on message sending',
            'No CSRF protection on admin broadcasts',
            'Vulnerable GET endpoints'
        ]
    },
    'pagination_vulnerabilities': {
        'description': 'Missing pagination leading to potential DoS',
        'examples': [
            'Returning all messages at once',
            'Returning all users at once',
            'Processing all users in broadcasts'
        ]
    },
    'insecure_logging': {
        'description': 'Insecure logging practices',
        'examples': [
            'Logging sensitive information',
            'Debug level logging in production',
            'Console output of sensitive data'
        ]
    },
    'sql_injection': {
        'description': 'SQL injection vulnerabilities in database queries',
        'examples': [
            'User login SQL injection',
            'Admin login SQL injection',
            'User search SQL injection'
        ]
    },
    'password_vulnerabilities': {
        'description': 'Password-related security vulnerabilities',
        'examples': [
            'Plaintext password storage',
            'No password hashing',
            'Weak password requirements'
        ]
    },
    'information_disclosure': {
        'description': 'Information disclosure vulnerabilities',
        'examples': [
            'System information exposure',
            'User data disclosure',
            'Error message information leakage'
        ]
    },
    'privilege_escalation': {
        'description': 'Privilege escalation and access control vulnerabilities',
        'examples': [
            'Admin role bypass',
            'Session elevation attacks',
            'Unauthorized role assignment'
        ]
    }
} 