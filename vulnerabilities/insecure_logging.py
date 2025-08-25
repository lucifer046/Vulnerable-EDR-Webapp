"""
vulnerabilities/insecure_logging.py
-----------------------------------
This file demonstrates Insecure Logging vulnerabilities.

VULNERABILITY TYPE: Insecure Logging
- Logging sensitive information.
- Debug level logging in production.
- Console output of sensitive data.

EXPLOIT SCENARIOS:
- Attackers or insiders can access logs to steal sensitive data.
- Debug logs may expose secrets or internal state.

This file is intentionally vulnerable for educational purposes.
See vulnerabilities/README.md for more details.
"""
import logging

def enable_insecure_logging(app):
    """
    Enables insecure logging by printing log messages directly to the console.
    This is vulnerable because sensitive information in logs may be exposed.
    """
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all levels