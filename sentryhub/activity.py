"""The activity log: who did what, and when."""
import re
import time

# action -> (label, category)
ACTIONS = {
    "login": ("Signed in", "signin"),
    "login_failed": ("Failed sign-in", "signin"),
    "password_changed": ("Password changed", "security"),
    "reset_requested": ("Password reset requested", "security"),
    "password_reset": ("Password reset", "security"),
    "invite_accepted": ("Invite accepted", "members"),
    "member_added": ("Member added", "members"),
    "invite_resent": ("Invite resent", "members"),
    "member_deleted": ("Member deleted", "members"),
    "member_restored": ("Member restored", "members"),
    "role_changed": ("Role changed", "members"),
    "backup": ("Backup", "backup"),
    "notice_posted": ("Announcement posted", "notice"),
    "notice_deleted": ("Announcement deleted", "notice"),
}

CATEGORIES = [
    ("signin", "Sign-ins"),
    ("security", "Security"),
    ("members", "Members"),
    ("backup", "Backups"),
    ("notice", "Notices"),
]


def describe(action):
    return ACTIONS.get(action, (action.replace("_", " ").capitalize(), "other"))


def log_event(conn, actor, action, target=None, detail=None):
    """Record an event. `actor` is a user row, a plain name such as "scheduled", or None."""
    if isinstance(actor, dict):
        actor_id, actor_name = actor["id"], actor["username"]
    else:
        actor_id, actor_name = None, actor or "system"
    conn.insert(
        "INSERT INTO activity_log (created_at, actor_id, actor_name, action, target_id, target_name, detail) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (
            int(time.time()), actor_id, actor_name, action,
            target["id"] if target else None, target["username"] if target else None,
            (detail or None) and str(detail)[:300],
        ),
    )


def describe_agent(user_agent):
    """Turn a User-Agent header into something readable like "Chrome on Windows"."""
    ua = user_agent or ""
    browser = next(
        (name for pattern, name in (
            (r"Edg/", "Edge"), (r"OPR/|Opera", "Opera"), (r"Firefox/|FxiOS/", "Firefox"),
            (r"Chrome/|CriOS/", "Chrome"), (r"Safari/", "Safari"),
        ) if re.search(pattern, ua)),
        None,
    )
    system = next(
        (name for pattern, name in (
            (r"Windows", "Windows"), (r"Android", "Android"), (r"iPhone|iPad|iPod", "iOS"),
            (r"Mac OS X|Macintosh", "macOS"), (r"CrOS", "ChromeOS"), (r"Linux", "Linux"),
        ) if re.search(pattern, ua)),
        None,
    )
    if browser and system:
        return f"{browser} on {system}"
    return browser or system or "Unknown device"
