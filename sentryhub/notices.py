"""The notice board: announcements posted by admins and staff, read by everyone."""
import time

from flask import Blueprint, abort, flash, g, redirect, request, url_for

from . import activity, db
from .access import role_required
from .roles import ADMIN, STAFF, home_endpoint

bp = Blueprint("notices", __name__)


def list_all(conn, limit=20):
    return conn.all(
        "SELECT * FROM announcements ORDER BY pinned DESC, created_at DESC, id DESC LIMIT %s", (limit,)
    )


def _back():
    return redirect(url_for(home_endpoint(g.user["role"])) + "#notices")


def _editable(notice_id):
    """Admins can manage any announcement; staff only their own."""
    notice = db.get_db().one("SELECT * FROM announcements WHERE id = %s", (notice_id,))
    if not notice:
        abort(404)
    if g.user["role"] != ADMIN and notice["author_id"] != g.user["id"]:
        abort(403)
    return notice


@bp.post("/notices/new")
@role_required(ADMIN, STAFF)
def create():
    title = " ".join(request.form.get("title", "").split())
    body = request.form.get("body", "").replace("\r\n", "\n").strip()
    if not 3 <= len(title) <= 80:
        flash("Give the announcement a title of 3–80 characters.", "error")
    elif not 3 <= len(body) <= 600:
        flash("The message must be 3–600 characters.", "error")
    else:
        conn = db.get_db()
        conn.insert(
            "INSERT INTO announcements (title, body, pinned, author_id, author_name, author_role, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (title, body, request.form.get("pinned") == "on", g.user["id"], g.user["full_name"], g.user["role"], int(time.time())),
        )
        activity.log_event(conn, g.user, "notice_posted", detail=title)
        flash("Announcement posted.", "success")
    return _back()


@bp.post("/notices/<int:notice_id>/pin")
@role_required(ADMIN, STAFF)
def pin(notice_id):
    notice = _editable(notice_id)
    db.get_db().run("UPDATE announcements SET pinned = %s WHERE id = %s", (not notice["pinned"], notice["id"]))
    flash("Unpinned." if notice["pinned"] else "Pinned to the top.", "success")
    return _back()


@bp.post("/notices/<int:notice_id>/delete")
@role_required(ADMIN, STAFF)
def delete(notice_id):
    notice = _editable(notice_id)
    conn = db.get_db()
    conn.run("DELETE FROM announcements WHERE id = %s", (notice["id"],))
    activity.log_event(conn, g.user, "notice_deleted", detail=notice["title"])
    flash("Announcement deleted.", "success")
    return _back()
