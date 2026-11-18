-- Sentry Hub schema for Neon (Postgres). Safe to run more than once.
-- The app also creates and upgrades these tables itself on start-up; run this by hand only if you prefer to.

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

CREATE TABLE IF NOT EXISTS password_tokens (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
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
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
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
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    pinned BOOLEAN NOT NULL DEFAULT FALSE,
    author_id BIGINT,
    author_name TEXT NOT NULL,
    author_role TEXT NOT NULL,
    created_at BIGINT NOT NULL
);

-- Upgrade for databases created by the first version (adds the new columns; existing data is kept)
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_pending BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS job_title TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS bio TEXT NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_color INTEGER;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at BIGINT;
