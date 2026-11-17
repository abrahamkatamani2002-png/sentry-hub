"""Registration, sign-in with emailed one-time code, and sign-out."""
import re
import time

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for

from . import db, security
from .formatting import mask_email
from .mailer import MailError, send_login_code
from .roles import home_endpoint

bp = Blueprint("auth", __name__)

LOCK_AFTER = 5            # wrong passwords before a temporary lock
LOCK_SECONDS = 15 * 60
CODE_TTL = 10 * 60        # a code is valid for 10 minutes
CODE_MAX_ATTEMPTS = 5     # wrong guesses before the code is cancelled
RESEND_COOLDOWN = 30      # seconds between "resend" clicks
MAX_CODES_PER_WINDOW = 5  # codes per user per window
CODE_WINDOW = 15 * 60

USERNAME_RE = re.compile(r"^[a-z0-9_.-]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")
GENERIC_LOGIN_ERROR = "Invalid username or password, or the account is temporarily locked."


class CodeError(Exception):
    def __init__(self, message, status=429):
        super().__init__(message)
        self.status = status


def issue_challenge(conn, user):
    """Create a fresh emailed code for this user and return the challenge id."""
    cfg = current_app.config
    now = int(time.time())
    recent = conn.one(
        "SELECT COUNT(*) AS n FROM login_challenges WHERE user_id = %s AND created_at > %s",
        (user["id"], now - CODE_WINDOW),
    )
    if recent["n"] >= MAX_CODES_PER_WINDOW:
        raise CodeError("Too many codes requested. Please wait a few minutes and try again.")

    conn.run("UPDATE login_challenges SET used = %s WHERE user_id = %s AND used = %s", (True, user["id"], False))
    code = security.new_otp()
    salt = security.new_salt()
    cid = conn.insert(
        "INSERT INTO login_challenges (user_id, code_salt, code_hash, expires_at, created_at) VALUES (%s, %s, %s, %s, %s)",
        (user["id"], salt, security.hash_otp(code, salt, cfg["PEPPER"]), now + CODE_TTL, now),
    )
    try:
        send_login_code(cfg, user, code, ttl_minutes=CODE_TTL // 60)
    except MailError as exc:
        current_app.logger.error("Could not send verification email: %s", exc)
        conn.run("UPDATE login_challenges SET used = %s WHERE id = %s", (True, cid))
        raise CodeError("We couldn't send your verification email. Please try again shortly.", 503)
    return cid


@bp.route("/")
def landing():
    if g.user:
        return redirect(url_for(home_endpoint(g.user["role"])))
    return render_template("landing.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for(home_endpoint(g.user["role"])))
    form = {"full_name": "", "username": "", "email": ""}
    errors = []
    if request.method == "POST":
        form["full_name"] = " ".join(request.form.get("full_name", "").split())
        form["username"] = request.form.get("username", "").strip().lower()
        form["email"] = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not 2 <= len(form["full_name"]) <= 80:
            errors.append("Enter your full name (2–80 characters).")
        if not USERNAME_RE.match(form["username"]):
            errors.append("Username must be 3–30 characters: letters, numbers, dot, dash or underscore.")
        if len(form["email"]) > 254 or not EMAIL_RE.match(form["email"]):
            errors.append("Enter a valid email address — your sign-in codes are sent there.")
        problem = security.validate_password(password)
        if problem:
            errors.append(problem)
        elif password != confirm:
            errors.append("The two passwords don't match.")

        if not errors:
            salt = security.new_salt()
            try:
                db.get_db().insert(
                    "INSERT INTO users (username, email, full_name, role, salt, password_hash, hash_version, created_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (
                        form["username"], form["email"], form["full_name"], "user", salt,
                        security.hash_password(password, salt, current_app.config["PEPPER"]),
                        security.HASH_VERSION, int(time.time()),
                    ),
                )
            except db.IntegrityError:
                errors.append("That username or email is already in use.")
            else:
                flash("Account created. Sign in to continue.", "success")
                return redirect(url_for("auth.login"))
        return render_template("register.html", form=form, errors=errors), 400
    return render_template("register.html", form=form, errors=errors)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for(home_endpoint(g.user["role"])))
    if request.method == "GET":
        return render_template("login.html", identifier="", error=None)

    conn = db.get_db()
    cfg = current_app.config
    ident = request.form.get("identifier", "").strip().lower()[:254]
    password = request.form.get("password", "")[:200]
    now = int(time.time())

    user = conn.one("SELECT * FROM users WHERE username = %s OR email = %s", (ident, ident)) if ident else None
    if user is None or user["locked_until"] > now:
        security.burn_time(password, cfg["PEPPER"])
        return render_template("login.html", identifier=ident, error=GENERIC_LOGIN_ERROR), 401

    if not security.verify_password(password, user["salt"], user["password_hash"], cfg["PEPPER"]):
        failed = user["failed_attempts"] + 1
        if failed >= LOCK_AFTER:
            conn.run("UPDATE users SET failed_attempts = 0, locked_until = %s WHERE id = %s", (now + LOCK_SECONDS, user["id"]))
        else:
            conn.run("UPDATE users SET failed_attempts = %s WHERE id = %s", (failed, user["id"]))
        return render_template("login.html", identifier=ident, error=GENERIC_LOGIN_ERROR), 401

    conn.run("UPDATE users SET failed_attempts = 0 WHERE id = %s", (user["id"],))
    if user["is_deleted"]:
        return render_template(
            "login.html", identifier=ident,
            error="This account has been deactivated. Please contact an administrator.",
        ), 403

    try:
        cid = issue_challenge(conn, user)
    except CodeError as exc:
        return render_template("login.html", identifier=ident, error=str(exc)), exc.status

    session.clear()
    session["pending"] = {"uid": user["id"], "cid": cid, "exp": now + CODE_TTL}
    return redirect(url_for("auth.verify"))


def _pending():
    pending = session.get("pending")
    if not pending or pending.get("exp", 0) < time.time():
        session.pop("pending", None)
        return None
    return pending


@bp.route("/verify", methods=["GET", "POST"])
def verify():
    pending = _pending()
    if pending is None:
        flash("Your verification session expired. Please sign in again.", "info")
        return redirect(url_for("auth.login"))

    conn = db.get_db()
    cfg = current_app.config
    now = int(time.time())
    user = conn.one("SELECT * FROM users WHERE id = %s", (pending["uid"],))
    challenge = conn.one("SELECT * FROM login_challenges WHERE id = %s AND user_id = %s", (pending["cid"], pending["uid"]))
    if not user or user["is_deleted"] or not challenge:
        session.clear()
        return redirect(url_for("auth.login"))

    def page(error=None, status=200):
        wait = max(0, RESEND_COOLDOWN - (now - challenge["created_at"]))
        return render_template("verify.html", email=mask_email(user["email"]), error=error, wait=wait), status

    if request.method == "GET":
        return page()

    code = re.sub(r"\D", "", request.form.get("code", ""))[:6]
    if challenge["used"] or challenge["expires_at"] < now:
        session.pop("pending", None)
        flash("That code has expired. Sign in again to get a new one.", "error")
        return redirect(url_for("auth.login"))

    attempts = challenge["attempts"] + 1
    if not security.otp_matches(code, challenge["code_salt"], challenge["code_hash"], cfg["PEPPER"]):
        if attempts >= CODE_MAX_ATTEMPTS:
            conn.run("UPDATE login_challenges SET attempts = %s, used = %s WHERE id = %s", (attempts, True, challenge["id"]))
            session.pop("pending", None)
            flash("Too many incorrect codes. Please sign in again.", "error")
            return redirect(url_for("auth.login"))
        conn.run("UPDATE login_challenges SET attempts = %s WHERE id = %s", (attempts, challenge["id"]))
        challenge["attempts"] = attempts
        return page("That code isn't right. Check your email and try again.", 401)

    conn.run("UPDATE login_challenges SET attempts = %s, used = %s WHERE id = %s", (attempts, True, challenge["id"]))
    conn.run("UPDATE users SET last_login_at = %s WHERE id = %s", (now, user["id"]))
    session.clear()  # new session on privilege change
    session["uid"] = user["id"]
    session.permanent = True
    flash(f"Welcome back, {user['full_name'].split()[0]}.", "success")
    return redirect(url_for(home_endpoint(user["role"])))


@bp.post("/verify/resend")
def resend():
    pending = _pending()
    if pending is None:
        return redirect(url_for("auth.login"))
    conn = db.get_db()
    now = int(time.time())
    user = conn.one("SELECT * FROM users WHERE id = %s", (pending["uid"],))
    challenge = conn.one("SELECT * FROM login_challenges WHERE id = %s", (pending["cid"],))
    if not user or user["is_deleted"] or not challenge:
        session.clear()
        return redirect(url_for("auth.login"))
    if now - challenge["created_at"] < RESEND_COOLDOWN:
        flash("Please wait a few seconds before requesting another code.", "info")
        return redirect(url_for("auth.verify"))
    try:
        cid = issue_challenge(conn, user)
    except CodeError as exc:
        flash(str(exc), "error")
        return redirect(url_for("auth.verify"))
    session["pending"] = {"uid": user["id"], "cid": cid, "exp": now + CODE_TTL}
    flash("A new code is on its way.", "success")
    return redirect(url_for("auth.verify"))


@bp.post("/logout")
def logout():
    session.clear()
    flash("You've been signed out.", "info")
    return redirect(url_for("auth.landing"))
