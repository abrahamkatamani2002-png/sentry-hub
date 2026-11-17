"""Configuration, read from environment variables.

On Vercel, set these under Project -> Settings -> Environment Variables.
Locally, copy .env.example to .env and run `python dev.py`.
"""
import os


class ConfigError(RuntimeError):
    """Raised at startup when a required setting is missing or too weak."""


def _int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def load_config(overrides=None):
    env = os.environ.get
    cfg = {
        "APP_NAME": "Sentry Hub",
        "ENV": env("SENTRYHUB_ENV", "production"),
        "DATABASE_URL": env("DATABASE_URL", ""),
        "SECRET_KEY": env("SECRET_KEY", ""),
        "PEPPER": env("PEPPER", ""),
        "SESSION_HOURS": _int("SESSION_HOURS", 2),
        # Email (Gmail SMTP by default)
        "MAIL_BACKEND": env("MAIL_BACKEND", "smtp"),
        "SMTP_HOST": env("SMTP_HOST", "smtp.gmail.com"),
        "SMTP_PORT": _int("SMTP_PORT", 465),
        "SMTP_USER": env("SMTP_USER", ""),
        "SMTP_PASSWORD": env("SMTP_PASSWORD", ""),
        "MAIL_FROM": env("MAIL_FROM", "") or env("SMTP_USER", ""),
        # Cloud backup (AWS S3). Vercel reserves the plain AWS_* names, so we use BACKUP_AWS_*.
        "BACKUP_S3_BUCKET": env("BACKUP_S3_BUCKET", ""),
        "BACKUP_S3_PREFIX": env("BACKUP_S3_PREFIX", "sentry-hub/backups/"),
        "BACKUP_AWS_REGION": env("BACKUP_AWS_REGION", "us-east-1"),
        "BACKUP_AWS_ACCESS_KEY_ID": env("BACKUP_AWS_ACCESS_KEY_ID", ""),
        "BACKUP_AWS_SECRET_ACCESS_KEY": env("BACKUP_AWS_SECRET_ACCESS_KEY", ""),
        "BACKUP_PASSPHRASE": env("BACKUP_PASSPHRASE", ""),
        "CRON_SECRET": env("CRON_SECRET", ""),
        # Optional: the first admin account, created automatically if no admin exists yet.
        "ADMIN_USERNAME": env("ADMIN_USERNAME", ""),
        "ADMIN_EMAIL": env("ADMIN_EMAIL", ""),
        "ADMIN_PASSWORD": env("ADMIN_PASSWORD", ""),
    }
    if overrides:
        cfg.update(overrides)
    return cfg


def validate(cfg):
    problems = []
    if not cfg["DATABASE_URL"]:
        problems.append("DATABASE_URL is not set")
    if len(cfg["SECRET_KEY"]) < 32:
        problems.append("SECRET_KEY must be at least 32 characters")
    if len(cfg["PEPPER"]) < 32:
        problems.append("PEPPER must be at least 32 characters")
    if problems:
        raise ConfigError("Sentry Hub is not configured: " + "; ".join(problems))
