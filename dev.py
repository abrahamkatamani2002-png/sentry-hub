"""Run Sentry Hub locally:  python dev.py   ->  http://localhost:5000

Uses a local SQLite file, prints verification emails to this terminal, and creates a throwaway
admin (admin / Admin12345!) unless you set your own values in .env.
"""
import os
import secrets
from pathlib import Path

ROOT = Path(__file__).parent


def load_env_file(path):
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


load_env_file(ROOT / ".env")

# Development defaults (only used when the value isn't already set)
os.environ.setdefault("SENTRYHUB_ENV", "development")
os.environ.setdefault("MAIL_BACKEND", "console")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{ROOT / 'dev.db'}")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_EMAIL", "admin@example.com")
os.environ.setdefault("ADMIN_PASSWORD", "Admin12345!")

# Keep dev secrets stable between runs so existing dev accounts keep working.
secrets_file = ROOT / ".dev-secrets"
if not secrets_file.exists():
    secrets_file.write_text(f"SECRET_KEY={secrets.token_hex(32)}\nPEPPER={secrets.token_hex(32)}\n")
load_env_file(secrets_file)

from sentryhub import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    print("\n  Sentry Hub (development)  ->  http://localhost:5000")
    print("  Admin login: admin / Admin12345!   (verification codes are printed below)\n")
    app.run(debug=True, port=5000)
