-- Sentry Hub schema for Neon (Postgres). Safe to run more than once.
-- The app also creates these tables automatically on first start; run this once to be sure.
CREATE TABLE IF NOT EXISTS users (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
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
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until BIGINT NOT NULL DEFAULT 0,
    last_login_at BIGINT,
    created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS login_challenges (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
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
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at BIGINT NOT NULL,
    triggered_by TEXT NOT NULL,
    status TEXT NOT NULL,
    s3_key TEXT,
    size_bytes BIGINT,
    detail TEXT
);
