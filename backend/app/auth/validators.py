import re

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Only Google email accounts are accepted.
ALLOWED_EMAIL_DOMAINS = ["gmail.com", "googlemail.com"]


def is_valid_email(email: str) -> bool:
    if not EMAIL_RE.match(email or ""):
        return False
    domain = email.rsplit("@", 1)[-1].lower()
    return domain in ALLOWED_EMAIL_DOMAINS


def is_valid_password(password: str) -> bool:
    """At least 10 characters, containing upper, lower, digit, and symbol."""
    if not password or len(password) < 10:
        return False
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    return has_lower and has_upper and has_digit and has_symbol


def is_valid_username(username: str) -> bool:
    return bool(username) and 3 <= len(username) <= 80 and bool(re.match(r"^[A-Za-z0-9_.-]+$", username))