"""The three role dashboards and their actions."""
import hmac
import secrets
import time

from flask import Blueprint, abort, current_app, flash, g, jsonify, redirect, render_template, request, url_for

from . import activity, backup, db, invites, mailer, notices, security
from .access import role_required
from .auth import EMAIL_RE, USERNAME_RE
from .mailer import MailError
from .roles import ADMIN, ASSIGNABLE, STAFF, USER, home_endpoint

bp = Blueprint("dash", __name__)
api = Blueprint("api", __name__)

PASSWORD_MAX_AGE_DAYS = 90


def _home():
    return redirect(url_for(home_endpoint(g.user["role"])))


def _target_user(user_id):
    user = db.get_db().one("SELECT * FROM users WHERE id = %s", (user_id,))
    if not user:
        abort(404)
    return user


# --- account health (the user dashboard's progress ring) ------------------------------------

def account_health(user, now=None):
    now = now or time.time()
    changed = user.get("password_changed_at") or user["created_at"]
    items = [
        {"label": "Two-step sign-in is on", "points": 40, "done": True, "hint": ""},
        {
            "label": f"Password changed in the last {PASSWORD_MAX_AGE_DAYS} days", "points": 30,
            "done": now - changed <= PASSWORD_MAX_AGE_DAYS * 86400,
            "hint": "Change your password below to refresh your score.",
        },
        {
            "label": "Profile completed", "points": 20,
            "done": bool((user.get("job_title") or "").strip() and (user.get("bio") or "").strip()),
            "hint": "Add your job title and a short bio.",
        },
        {
            "label": "Avatar colour chosen", "points": 10,
            "done": user.get("avatar_color") is not None,
            "hint": "Pick your colour in the profile card.",
        },
    ]
    score = sum(i["points"] for i in items if i["done"])
    todo = next((i for i in items if not i["done"]), None)
    level = "Excellent" if score >= 90 else "Good" if score >= 70 else "Needs attention"
    tip = todo["hint"] if todo else "You're all set. Nothing to improve right now."
    return {"score": score, "items": items, "level": level, "tip": tip}


# --- user dashboard --------------------------------------------------------------------

@bp.route("/dashboard")
@role_required(USER, STAFF, ADMIN)
def overview():
    # Staff and admins have their own dashboards; this is the member experience.
    if g.user["role"] != USER:
        return _home()
    conn = db.get_db()
    signins = conn.all(
        "SELECT created_at, detail FROM activity_log WHERE target_id = %s AND action = %s ORDER BY id DESC LIMIT 5",
        (g.user["id"], "login"),
    )
    days = max(1, int((time.time() - g.user["created_at"]) // 86400) + 1)
    return render_template(
        "dash_user.html", health=account_health(g.user), signins=signins, days=days, notices=notices.list_all(conn),
    )


@bp.post("/dashboard/profile")
@role_required(USER, STAFF, ADMIN)
def update_profile():
    job_title = " ".join(request.form.get("job_title", "").split())
    bio = request.form.get("bio", "").replace("\r\n", "\n").strip()
    colour = request.form.get("avatar_color", "")
    error = None
    if len(job_title) > 60:
        error = "Job title can be up to 60 characters."
    elif len(bio) > 240:
        error = "Your bio can be up to 240 characters."
    elif colour not in {"0", "1", "2", "3", "4", "5"}:
        error = "Choose one of the avatar colours."
    if error:
        flash(error, "error")
    else:
        db.get_db().run(
            "UPDATE users SET job_title = %s, bio = %s, avatar_color = %s WHERE id = %s",
            (job_title, bio, int(colour), g.user["id"]),
        )
        flash("Profile saved.", "success")
    return _home()


@bp.post("/dashboard/password")
@role_required(USER, STAFF, ADMIN)
def change_password():
    cfg = current_app.config
    current, new, confirm = (request.form.get(k, "") for k in ("current", "new", "confirm"))
    if not security.verify_password(current, g.user["salt"], g.user["password_hash"], cfg["PEPPER"]):
        flash("Your current password is incorrect.", "error")
    elif security.validate_password(new):
        flash(security.validate_password(new), "error")
    elif new != confirm:
        flash("The new passwords don't match.", "error")
    else:
        conn = db.get_db()
        salt = security.new_salt()  # fresh salt every time the password changes
        conn.run(
            "UPDATE users SET salt = %s, password_hash = %s, hash_version = %s, password_changed_at = %s WHERE id = %s",
            (salt, security.hash_password(new, salt, cfg["PEPPER"]), security.HASH_VERSION, int(time.time()), g.user["id"]),
        )
        activity.log_event(conn, g.user, "password_changed", target=g.user)
        flash("Password updated.", "success")
    return _home()


# --- staff dashboard -------------------------------------------------------------------

@bp.route("/staff")
@role_required(STAFF)
def staff():
    conn = db.get_db()
    users = conn.all(
        "SELECT id, username, full_name, email, avatar_color, is_pending, created_at, last_login_at FROM users "
        "WHERE role = %s AND is_deleted = %s ORDER BY created_at DESC",
        (USER, False),
    )
    return render_template("dash_staff.html", users=users, notices=notices.list_all(conn))


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
    activity.log_event(conn, g.user, "member_deleted", target=target, detail="Deleted by staff")
    flash(f"{target['full_name']} was deleted. An administrator can restore the account.", "success")
    return redirect(url_for("dash.staff"))


# --- admin dashboard -------------------------------------------------------------------

def _counts(conn):
    return {
        "deleted": conn.one("SELECT COUNT(*) AS n FROM users WHERE is_deleted = %s", (True,))["n"],
        "pending": conn.one("SELECT COUNT(*) AS n FROM users WHERE is_pending = %s AND is_deleted = %s", (True, False))["n"],
    }


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
        "active": sum(1 for u in users if not u["is_deleted"] and not u["is_pending"]),
        "staff": sum(1 for u in users if u["role"] == STAFF and not u["is_deleted"]),
        "pending": sum(1 for u in users if u["is_pending"] and not u["is_deleted"]),
        "deleted": sum(1 for u in users if u["is_deleted"]),
    }
    last = conn.one("SELECT * FROM backups ORDER BY id DESC LIMIT 1")
    last_ok = conn.one("SELECT created_at FROM backups WHERE status = %s ORDER BY id DESC LIMIT 1", ("success",))
    return render_template(
        "dash_admin.html", users=users, stats=stats, counts=_counts(conn), last_backup=last, last_ok=last_ok,
        assignable=ASSIGNABLE, notices=notices.list_all(conn),
    )


@bp.route("/admin/members/new", methods=["GET", "POST"])
@role_required(ADMIN)
def admin_new_member():
    conn = db.get_db()
    cfg = current_app.config
    form = {"full_name": "", "username": "", "email": "", "role": USER}
    errors = []
    if request.method == "POST":
        form["full_name"] = " ".join(request.form.get("full_name", "").split())
        form["username"] = request.form.get("username", "").strip().lower()
        form["email"] = request.form.get("email", "").strip().lower()
        form["role"] = request.form.get("role", "")

        if not 2 <= len(form["full_name"]) <= 80:
            errors.append("Enter the member's full name (2–80 characters).")
        if not USERNAME_RE.match(form["username"]):
            errors.append("Username must be 3–30 characters: letters, numbers, dot, dash or underscore.")
        if len(form["email"]) > 254 or not EMAIL_RE.match(form["email"]):
            errors.append("Enter a valid email address. The invitation is sent there.")
        if form["role"] not in ASSIGNABLE:
            errors.append("Choose a role: staff or user.")

        if not errors:
            now = int(time.time())
            salt = security.new_salt()
            # The member picks their real password from the emailed link. Until then the
            # account holds a random password nobody knows, and sign-in is blocked.
            unusable = security.hash_password(secrets.token_hex(32), salt, cfg["PEPPER"])
            try:
                member_id = conn.insert(
                    "INSERT INTO users (username, email, full_name, role, salt, password_hash, hash_version, "
                    "is_pending, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (form["username"], form["email"], form["full_name"], form["role"], salt, unusable,
                     security.HASH_VERSION, True, now),
                )
            except db.IntegrityError:
                errors.append("That username or email is already in use.")
            else:
                member = conn.one("SELECT * FROM users WHERE id = %s", (member_id,))
                activity.log_event(conn, g.user, "member_added", target=member, detail=f"Role: {form['role']}")
                try:
                    token = invites.issue_token(conn, cfg, member_id, "invite", created_by=g.user["id"])
                    mailer.send_invite(cfg, member, invites.link(cfg, token), g.user["full_name"])
                except MailError as exc:
                    current_app.logger.error("Could not send invite: %s", exc)
                    flash(f"{member['full_name']} was added, but the invitation email couldn't be sent. "
                          "Use “Resend invite” once email is working.", "error")
                else:
                    flash(f"{member['full_name']} was added as {member['role']}. An invitation was sent to {member['email']}.", "success")
                return redirect(url_for("dash.admin") + "#accounts")
        return render_template("admin_new_member.html", form=form, errors=errors, counts=_counts(conn), assignable=ASSIGNABLE), 400
    return render_template("admin_new_member.html", form=form, errors=errors, counts=_counts(conn), assignable=ASSIGNABLE)


@bp.post("/admin/users/<int:user_id>/invite")
@role_required(ADMIN)
def admin_resend_invite(user_id):
    conn = db.get_db()
    cfg = current_app.config
    target = _target_user(user_id)
    if not target["is_pending"] or target["is_deleted"]:
        flash("That member has already activated their account.", "info")
        return redirect(url_for("dash.admin") + "#accounts")
    try:
        token = invites.issue_token(conn, cfg, target["id"], "invite", created_by=g.user["id"])
        mailer.send_invite(cfg, target, invites.link(cfg, token), g.user["full_name"])
    except invites.TokenLimit:
        flash("Too many invitations were sent to this member recently. Try again in an hour.", "error")
    except MailError as exc:
        current_app.logger.error("Could not send invite: %s", exc)
        flash("The invitation email couldn't be sent. Please try again shortly.", "error")
    else:
        activity.log_event(conn, g.user, "invite_resent", target=target)
        flash(f"A new invitation was sent to {target['email']}.", "success")
    return redirect(url_for("dash.admin") + "#accounts")


@bp.post("/admin/users/<int:user_id>/role")
@role_required(ADMIN)
def admin_set_role(user_id):
    conn = db.get_db()
    target = _target_user(user_id)
    new_role = request.form.get("role", "")
    if target["is_deleted"]:
        flash("Restore this account before changing its role.", "error")
    elif new_role not in ASSIGNABLE or target["role"] not in ASSIGNABLE:
        flash("Only users and staff can have their role changed.", "error")
    elif target["role"] == new_role:
        flash("No change — that is already their role.", "info")
    else:
        conn.run("UPDATE users SET role = %s WHERE id = %s", (new_role, target["id"]))
        activity.log_event(conn, g.user, "role_changed", target=target, detail=f"{target['role']} → {new_role}")
        flash(f"{target['full_name']} is now {new_role}.", "success")
    return redirect(url_for("dash.admin") + "#accounts")


@bp.post("/admin/users/<int:user_id>/delete")
@role_required(ADMIN)
def admin_delete(user_id):
    conn = db.get_db()
    target = _target_user(user_id)
    if target["id"] == g.user["id"] or target["role"] == ADMIN:
        flash("Admin accounts can't be deleted.", "error")
    elif target["is_deleted"]:
        flash("That account is already deleted.", "info")
    else:
        conn.run(
            "UPDATE users SET is_deleted = %s, deleted_at = %s, deleted_by = %s WHERE id = %s",
            (True, int(time.time()), g.user["id"], target["id"]),
        )
        activity.log_event(conn, g.user, "member_deleted", target=target, detail=f"Role: {target['role']}")
        flash(f"{target['full_name']} was moved to Deleted members. You can restore them at any time.", "success")
    return redirect(url_for("dash.admin") + "#accounts")


@bp.post("/admin/users/<int:user_id>/restore")
@role_required(ADMIN)
def admin_restore(user_id):
    conn = db.get_db()
    target = _target_user(user_id)
    if not target["is_deleted"]:
        flash("That account isn't deleted.", "info")
    else:
        conn.run("UPDATE users SET is_deleted = %s, deleted_at = NULL, deleted_by = NULL WHERE id = %s", (False, target["id"]))
        activity.log_event(conn, g.user, "member_restored", target=target, detail=f"Role: {target['role']}")
        flash(f"{target['full_name']} was restored with the role {target['role']}.", "success")
    return redirect(url_for("dash.admin_deleted") if request.form.get("from") == "bin" else url_for("dash.admin") + "#accounts")


@bp.route("/admin/deleted")
@role_required(ADMIN)
def admin_deleted():
    conn = db.get_db()
    members = conn.all(
        "SELECT u.*, d.username AS deleted_by_name FROM users u LEFT JOIN users d ON d.id = u.deleted_by "
        "WHERE u.is_deleted = %s ORDER BY u.deleted_at DESC",
        (True,),
    )
    return render_template("admin_deleted.html", members=members, counts=_counts(conn))


@bp.route("/admin/activity")
@role_required(ADMIN)
def admin_activity():
    conn = db.get_db()
    events = conn.all("SELECT * FROM activity_log ORDER BY id DESC LIMIT 200")
    for event in events:
        event["label"], event["category"] = activity.describe(event["action"])
    return render_template("admin_activity.html", events=events, categories=activity.CATEGORIES, counts=_counts(conn))


@bp.post("/admin/backup")
@role_required(ADMIN)
def admin_backup():
    conn = db.get_db()
    result = backup.run_backup(conn, current_app.config, g.user["username"], current_app.config.get("BACKUP_UPLOADER"))
    activity.log_event(conn, g.user, "backup", detail=result["message"])
    return jsonify(result), (200 if result["ok"] else 502)


# --- scheduled backup (Vercel Cron) ----------------------------------------------------

@api.get("/api/cron/backup")
def cron_backup():
    secret = current_app.config["CRON_SECRET"]
    sent = request.headers.get("Authorization", "")
    if not secret or not hmac.compare_digest(sent, f"Bearer {secret}"):
        abort(401)
    conn = db.get_db()
    result = backup.run_backup(conn, current_app.config, "scheduled", current_app.config.get("BACKUP_UPLOADER"))
    activity.log_event(conn, "scheduled", "backup", detail=result["message"])
    return jsonify(result), (200 if result["ok"] else 500)
