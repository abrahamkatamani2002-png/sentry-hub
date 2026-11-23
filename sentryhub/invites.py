"""One-time links for setting a password: invitations for new members and "forgot password".

The link contains a random token. Only a keyed hash of it (using the pepper) is stored, so a
database leak does not reveal usable links. Each link works once and expires.
"""
import time

from flask import url_for

from . import security

INVITE_TTL = 48 * 3600
RESET_TTL = 3600
MAX_PER_HOUR = 5


class TokenLimit(Exception):
    """Too many links were requested for this account in the last hour."""


def issue_token(conn, cfg, user_id, purpose, created_by=None):
    now = int(time.time())
    recent = conn.one(
        "SELECT COUNT(*) AS n FROM password_tokens WHERE user_id = %s AND created_at > %s", (user_id, now - 3600)
    )
    if recent["n"] >= MAX_PER_HOUR:
        raise TokenLimit()
    # a new link replaces any older, unused one
    conn.run("UPDATE password_tokens SET used = %s WHERE user_id = %s AND used = %s", (True, user_id, False))
    token = security.new_token()
    ttl = INVITE_TTL if purpose == "invite" else RESET_TTL
    conn.insert(
        "INSERT INTO password_tokens (user_id, token_hash, purpose, expires_at, used, created_by, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (user_id, security.hash_token(token, cfg["PEPPER"]), purpose, now + ttl, False, created_by, now),
    )
    return token


def find_valid(conn, cfg, token):
    """Return the token row (with its user's details) if the link can still be used, else None."""
    row = conn.one(
        "SELECT t.id AS token_id, t.user_id, t.purpose, t.used, t.expires_at, "
        "u.is_deleted, u.username, u.full_name FROM password_tokens t JOIN users u ON u.id = t.user_id "
        "WHERE t.token_hash = %s",
        (security.hash_token(token[:200], cfg["PEPPER"]),),
    )
    if not row or row["used"] or row["expires_at"] < int(time.time()) or row["is_deleted"]:
        return None
    return row


def consume(conn, user_id):
    conn.run("UPDATE password_tokens SET used = %s WHERE user_id = %s", (True, user_id))


def link(cfg, token):
    path = url_for("auth.set_password", token=token)
    base = (cfg.get("PUBLIC_URL") or "").rstrip("/")
    if base:
        return base + path
    return url_for("auth.set_password", token=token, _external=True)
