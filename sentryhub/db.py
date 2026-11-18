"""Database access.

Production uses Postgres (Neon) through psycopg. For local development and tests a
`sqlite:///file.db` URL works too, so the same SQL (written with %s placeholders) runs on both.
Timestamps are stored as Unix epoch seconds to keep the SQL portable.

Upgrades: new tables are created with CREATE TABLE IF NOT EXISTS, and new columns on tables that
already exist are added by `migrate()` at start-up. Existing rows are never touched.
"""
import sqlite3
import time

from flask import current_app, g

from . import security

try:  # psycopg is only needed for Postgres
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover
    psycopg = None
    dict_row = None


class IntegrityError(Exception):
    """A UNIQUE / constraint violation (e.g. username already taken)."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id {ID},
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'staff', 'user')),
    salt TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    hash_version INTEGER NOT NULL DEFAULT 1,
    is_deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at BIGINT,
    deleted_by BIGINT,
    is_pending BOOLEAN NOT NULL DEFAULT FALSE,
    job_title TEXT NOT NULL DEFAULT '',
    bio TEXT NOT NULL DEFAULT '',
    avatar_color INTEGER,
    password_changed_at BIGINT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until BIGINT NOT NULL DEFAULT 0,
    last_login_at BIGINT,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_challenges (
    id {ID},
    user_id BIGINT NOT NULL REFERENCES users (id),
    code_salt TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_challenges_user ON login_challenges (user_id, created_at);

CREATE TABLE IF NOT EXISTS backups (
    id {ID},
    created_at BIGINT NOT NULL,
    triggered_by TEXT NOT NULL,
    status TEXT NOT NULL,
    s3_key TEXT,
    size_bytes BIGINT,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS password_tokens (
    id {ID},
    user_id BIGINT NOT NULL REFERENCES users (id),
    token_hash TEXT NOT NULL UNIQUE,
    purpose TEXT NOT NULL,
    expires_at BIGINT NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_by BIGINT,
    created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tokens_user ON password_tokens (user_id, created_at);

CREATE TABLE IF NOT EXISTS activity_log (
    id {ID},
    created_at BIGINT NOT NULL,
    actor_id BIGINT,
    actor_name TEXT NOT NULL,
    action TEXT NOT NULL,
    target_id BIGINT,
    target_name TEXT,
    detail TEXT
);

CREATE INDEX IF NOT EXISTS idx_activity_target ON activity_log (target_id, action, id);

CREATE TABLE IF NOT EXISTS announcements (
    id {ID},
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    pinned BOOLEAN NOT NULL DEFAULT FALSE,
    author_id BIGINT,
    author_name TEXT NOT NULL,
    author_role TEXT NOT NULL,
    created_at BIGINT NOT NULL
);
"""

# Columns added after the first release. (table, column, definition)
MIGRATIONS = [
    ("users", "is_pending", "BOOLEAN NOT NULL DEFAULT FALSE"),
    ("users", "job_title", "TEXT NOT NULL DEFAULT ''"),
    ("users", "bio", "TEXT NOT NULL DEFAULT ''"),
    ("users", "avatar_color", "INTEGER"),
    ("users", "password_changed_at", "BIGINT"),
]

_ID_PG = "BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY"
_ID_SQLITE = "INTEGER PRIMARY KEY AUTOINCREMENT"


def schema_sql(kind):
    return SCHEMA.replace("{ID}", _ID_SQLITE if kind == "sqlite" else _ID_PG)


def migration_sql_postgres():
    """The same upgrade as migrate(), as plain SQL you can paste into Neon's SQL editor."""
    return "\n".join(f"ALTER TABLE {t} ADD COLUMN IF NOT EXISTS {c} {d};" for t, c, d in MIGRATIONS)


class Conn:
    """Thin wrapper giving Postgres and SQLite the same small API."""

    def __init__(self, raw, kind):
        self.raw = raw
        self.kind = kind

    def _exec(self, sql, params):
        if self.kind == "sqlite":
            sql = sql.replace("%s", "?")
        try:
            return self.raw.execute(sql, tuple(params))
        except Exception as exc:
            if isinstance(exc, sqlite3.IntegrityError) or (
                psycopg is not None and isinstance(exc, psycopg.errors.IntegrityError)
            ):
                self.raw.rollback()
                raise IntegrityError(str(exc)) from exc
            raise

    def all(self, sql, params=()):
        return [dict(r) for r in self._exec(sql, params).fetchall()]

    def one(self, sql, params=()):
        row = self._exec(sql, params).fetchone()
        return dict(row) if row is not None else None

    def run(self, sql, params=()):
        """Run a write; returns the number of rows affected."""
        return self._exec(sql, params).rowcount

    def insert(self, sql, params=()):
        """Run an INSERT and return the new row's id."""
        row = self._exec(sql + " RETURNING id", params).fetchone()
        return dict(row)["id"]

    def script(self, sql):
        if self.kind == "sqlite":
            self.raw.executescript(sql)
        else:
            for statement in sql.split(";"):
                if statement.strip():
                    self.raw.execute(statement)
            self.raw.commit()

    def columns(self, table):
        if self.kind == "sqlite":
            return {r["name"] for r in self.all(f"PRAGMA table_info({table})")}
        return {
            r["column_name"]
            for r in self.all(
                "SELECT column_name FROM information_schema.columns WHERE table_name = %s AND table_schema = current_schema()",
                (table,),
            )
        }

    def commit(self):
        self.raw.commit()

    def rollback(self):
        self.raw.rollback()

    def close(self):
        self.raw.close()


def connect(url):
    if url.startswith("sqlite:///"):
        raw = sqlite3.connect(url[len("sqlite:///"):], timeout=10)
        raw.row_factory = sqlite3.Row
        raw.execute("PRAGMA foreign_keys = ON")
        return Conn(raw, "sqlite")
    if psycopg is None:
        raise RuntimeError("psycopg is not installed; add it to requirements.txt")
    # prepare_threshold=None keeps this compatible with Neon's pooled (PgBouncer) connections.
    raw = psycopg.connect(url, row_factory=dict_row, connect_timeout=10, prepare_threshold=None)
    return Conn(raw, "postgres")


def migrate(conn):
    """Add any columns that older databases are missing. Safe to run every start-up."""
    for table, column, definition in MIGRATIONS:
        if column not in conn.columns(table):
            conn.script(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


# --- per-request connection ----------------------------------------------------------------

_READY = set()


def ensure_ready(app):
    """Create/upgrade tables (idempotent) and the first admin, once per server process."""
    url = app.config["DATABASE_URL"]
    if url in _READY:
        return
    conn = connect(url)
    try:
        conn.script(schema_sql(conn.kind))
        migrate(conn)
        ensure_admin(conn, app.config)
        conn.commit()
    finally:
        conn.close()
    _READY.add(url)


def ensure_admin(conn, cfg):
    username, email, password = cfg.get("ADMIN_USERNAME"), cfg.get("ADMIN_EMAIL"), cfg.get("ADMIN_PASSWORD")
    if not (username and email and password):
        return
    if conn.one("SELECT id FROM users WHERE role = 'admin' LIMIT 1"):
        return
    problem = security.validate_password(password)
    if problem:
        raise RuntimeError("ADMIN_PASSWORD rejected: " + problem)

    now = int(time.time())
    salt = security.new_salt()
    try:
        conn.insert(
            "INSERT INTO users (username, email, full_name, role, salt, password_hash, hash_version, "
            "password_changed_at, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (
                username.strip().lower(), email.strip().lower(), "Administrator", "admin", salt,
                security.hash_password(password, salt, cfg["PEPPER"]), security.HASH_VERSION, now, now,
            ),
        )
    except IntegrityError:
        pass  # another instance created it first


def get_db():
    if "db" not in g:
        ensure_ready(current_app)
        g.db = connect(current_app.config["DATABASE_URL"])
    return g.db


def close_db(exc=None):
    conn = g.pop("db", None)
    if conn is None:
        return
    try:
        if exc is None:
            conn.commit()
        else:
            conn.rollback()
    finally:
        conn.close()
