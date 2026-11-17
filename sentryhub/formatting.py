"""Small display helpers used by templates and JSON responses."""
from datetime import datetime, timezone


def fmt_date(ts):
    if not ts:
        return "—"
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%d %b %Y")


def fmt_dt(ts):
    if not ts:
        return "Never"
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%d %b %Y, %H:%M UTC")


def initials(name):
    parts = [p for p in (name or "").split() if p]
    if not parts:
        return "?"
    if len(parts) == 1:
        return parts[0][:2].upper()
    return (parts[0][0] + parts[-1][0]).upper()


def mask_email(email):
    local, _, domain = (email or "").partition("@")
    if not domain:
        return email or ""
    return f"{local[:1]}{'•' * max(len(local) - 1, 2)}@{domain}"
