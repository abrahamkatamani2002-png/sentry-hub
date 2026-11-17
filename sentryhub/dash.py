"""The three role dashboards and their actions."""
import hmac
import time
from functools import wraps

from flask import Blueprint, abort, current_app, flash, g, jsonify, redirect, render_template, request, url_for

from . import backup, db, security
from .roles import ADMIN, ASSIGNABLE, STAFF, USER, home_endpoint

bp = Blueprint("dash", __name__)


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


def _target_user(user_id):
    user = db.get_db().one("SELECT * FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    return user


# --- user dashboard --------------------------------------------------------------------

@bp.route("/dashboard")
@role_required(USER, STAFF, ADMIN)
def overview():
    # Staff and admins have their own dashboards; this is the plain "user" experience.
    if g.user["role"] != USER:
        return redirect(url_for(home_endpoint(g.user["role"])))
    return render_template("dash_user.html")


@bp.post("/dashboard/password")
@role_required(USER, STAFF, ADMIN)
def change_password():
    cfg = current_app.config
    current, new, confirm = (request.form.get(k, "") for k in ("current", "new", "confirm"))
    target = url_for("dash.overview") if g.user["role"] == USER else url_for(home_endpoint(g.user["role"]))
    if not security.verify_password(current, g.user["salt"], g.user["password_hash"], cfg["PEPPER"]):
        flash("Your current password is incorrect.", "error")
    elif security.validate_password(new):
        flash(security.validate_password(new), "error")
    elif new != confirm:
        flash("The new passwords don't match.", "error")
    else:
        salt = security.new_salt()  # fresh salt every time the password changes
        db.get_db().run(
            "UPDATE users SET salt = %s, password_hash = %s, hash_version = %s WHERE id = %s",
            (salt, security.hash_password(new, salt, cfg["PEPPER"]), security.HASH_VERSION, g.user["id"]),
        )
        flash("Password updated.", "success")
    return redirect(target)


# --- staff dashboard -------------------------------------------------------------------

@bp.route("/staff")
@role_required(STAFF)
def staff():
    users = db.get_db().all(
        "SELECT id, username, full_name, email, created_at, last_login_at FROM users "
        "WHERE role = %s AND is_deleted = %s ORDER BY created_at DESC",
        (USER, False),
    )
    return render_template("dash_staff.html", users=users)


@bp.post("/staff/users/<int:user_id>/delete")
@role_required(STAFF)
def staff_delete(user_id):
    conn = db.get_db()
    target = _target_user(user_id)
    if target["role"] != USER or target["is_deleted"]:
        abort(403)  # staff may only remove active, regular users
    conn.run(
        "UPDATE users SET is_deleted = %s, deleted_at = %s, deleted_by = %s WHERE id = %s",
        (True, int(time.time()), g.user["id"], target["id"]),
    )
    flash(f"{target['full_name']} was deleted. An administrator can restore the account.", "success")
    return redirect(url_for("dash.staff"))


# --- admin dashboard -------------------------------------------------------------------

@bp.route("/admin")
@role_required(ADMIN)
def admin():
    conn = db.get_db()
    users = conn.all(
        "SELECT u.*, d.username AS deleted_by_name FROM users u "
        "LEFT JOIN users d ON d.id = u.deleted_by ORDER BY u.is_deleted, u.created_at DESC"
    )
    stats = {
        "total": len(users),
        "active": sum(1 for u in users if not u["is_deleted"]),
        "staff": sum(1 for u in users if u["role"] == STAFF and not u["is_deleted"]),
        "deleted": sum(1 for u in users if u["is_deleted"]),
    }
    last = conn.one("SELECT * FROM backups ORDER BY id DESC LIMIT 1")
    last_ok = conn.one("SELECT created_at FROM backups WHERE status = %s ORDER BY id DESC LIMIT 1", ("success",))
    return render_template("dash_admin.html", users=users, stats=stats, last_backup=last, last_ok=last_ok, assignable=ASSIGNABLE)


@bp.post("/admin/users/<int:user_id>/role")
@role_required(ADMIN)
def admin_set_role(user_id):
    conn = db.get_db()
    target = _target_user(user_id)
    new_role = request.form.get("role", "")
    if new_role not in ASSIGNABLE or target["role"] not in ASSIGNABLE:
        flash("Only users and staff can have their role changed.", "error")
    elif target["role"] == new_role:
        flash("No change — that is already their role.", "info")
    else:
        conn.run("UPDATE users SET role = %s WHERE id = %s", (new_role, target["id"]))
        flash(f"{target['full_name']} is now {new_role}.", "success")
    return redirect(url_for("dash.admin"))


@bp.post("/admin/users/<int:user_id>/restore")
@role_required(ADMIN)
def admin_restore(user_id):
    conn = db.get_db()
    target = _target_user(user_id)
    if not target["is_deleted"]:
        flash("That account isn't deleted.", "info")
    else:
        conn.run("UPDATE users SET is_deleted = %s, deleted_at = NULL, deleted_by = NULL WHERE id = %s", (False, target["id"]))
        flash(f"{target['full_name']} was restored.", "success")
    return redirect(url_for("dash.admin"))


@bp.post("/admin/backup")
@role_required(ADMIN)
def admin_backup():
    conn = db.get_db()
    result = backup.run_backup(conn, current_app.config, g.user["username"], current_app.config.get("BACKUP_UPLOADER"))
    return jsonify(result), (200 if result["ok"] else 502)


# --- scheduled backup (Vercel Cron) ----------------------------------------------------

api = Blueprint("api", __name__)


@api.get("/api/cron/backup")
def cron_backup():
    secret = current_app.config["CRON_SECRET"]
    sent = request.headers.get("Authorization", "")
    if not secret or not hmac.compare_digest(sent, f"Bearer {secret}"):
        abort(401)
    result = backup.run_backup(db.get_db(), current_app.config, "scheduled", current_app.config.get("BACKUP_UPLOADER"))
    return jsonify(result), (200 if result["ok"] else 500)
