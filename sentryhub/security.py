"""Password hashing (salt + pepper), one-time codes and CSRF protection.

How passwords are protected
---------------------------
* salt   - a random 16-byte value generated per user and stored in the database.
* pepper - one secret value kept ONLY in an environment variable, never in the database.
* The password is first run through HMAC-SHA256 keyed with the pepper, then hashed with
  scrypt using the per-user salt. A stolen database alone is therefore not enough to
  start guessing passwords: the attacker would also need the pepper.
"""
import hashlib
import hmac
import re
import secrets

from flask import request, session

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 14, 8, 1
HASH_VERSION = 1
_DUMMY_SALT = "00" * 16


def new_salt():
    return secrets.token_hex(16)


def _prehash(password, pepper):
    return hmac.new(pepper.encode("utf-8"), password.encode("utf-8"), hashlib.sha256).digest()


def hash_password(password, salt_hex, pepper):
    return hashlib.scrypt(
        _prehash(password, pepper),
        salt=bytes.fromhex(salt_hex),
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
        dklen=32,
        maxmem=64 * 1024 * 1024,
    ).hex()


def verify_password(password, salt_hex, expected_hex, pepper):
    return hmac.compare_digest(hash_password(password, salt_hex, pepper), expected_hex)


def burn_time(password, pepper):
    """Spend the same time as a real check so unknown usernames can't be detected by timing."""
    hash_password(password, _DUMMY_SALT, pepper)


def validate_password(password):
    if len(password) < 10:
        return "Password must be at least 10 characters long."
    if len(password) > 128:
        return "Password must be 128 characters or fewer."
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        return "Password must include at least one letter and one number."
    return None


# --- one-time email codes -------------------------------------------------------------

def new_otp():
    return f"{secrets.randbelow(10 ** 6):06d}"


def hash_otp(code, salt_hex, pepper):
    return hmac.new(pepper.encode("utf-8"), bytes.fromhex(salt_hex) + code.encode("utf-8"), hashlib.sha256).hexdigest()


def otp_matches(code, salt_hex, expected_hex, pepper):
    return hmac.compare_digest(hash_otp(code, salt_hex, pepper), expected_hex)


# --- one-time links (invites, password reset) ---------------------------------------------

def new_token():
    return secrets.token_urlsafe(32)


def hash_token(token, pepper):
    return hmac.new(pepper.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


# --- CSRF ------------------------------------------------------------------------------

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def csrf_valid():
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    expected = session.get("_csrf", "")
    return bool(expected) and hmac.compare_digest(sent, expected)
