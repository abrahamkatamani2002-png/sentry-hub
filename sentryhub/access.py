"""Role checks shared by every dashboard."""
from functools import wraps

from flask import abort, flash, g, redirect, url_for


def role_required(*roles):
    """Allow only signed-in users whose role is in `roles`."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not g.user:
                flash("Please sign in to continue.", "info")
                return redirect(url_for("auth.login"))
            if g.user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator
