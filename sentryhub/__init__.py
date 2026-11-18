"""Sentry Hub - role-based login system with emailed one-time codes."""
import logging
from datetime import timedelta

from flask import Flask, abort, g, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

from . import auth, config, dash, db, formatting, notices, security

NO_STORE = ("auth.verify", "auth.login", "auth.set_password", "auth.forgot")


def create_app(overrides=None):
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.update(config.load_config(overrides))
    config.validate(app.config)

    production = app.config["ENV"] == "production"
    if production:
        # Vercel terminates HTTPS in front of the app; trust its forwarded host/protocol headers.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.secret_key = app.config["SECRET_KEY"]
    app.permanent_session_lifetime = timedelta(hours=app.config["SESSION_HOURS"])
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=production,
        SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    logging.basicConfig(level=logging.INFO)

    app.register_blueprint(auth.bp)
    app.register_blueprint(dash.bp)
    app.register_blueprint(dash.api)
    app.register_blueprint(notices.bp)
    app.teardown_appcontext(db.close_db)

    app.jinja_env.filters["date"] = formatting.fmt_date
    app.jinja_env.filters["datetime"] = formatting.fmt_dt
    app.jinja_env.filters["initials"] = formatting.initials

    @app.before_request
    def load_user():
        g.user = None
        if request.endpoint in (None, "static"):
            return
        uid = session.get("uid")
        if uid:
            user = db.get_db().one("SELECT * FROM users WHERE id = %s", (uid,))
            if user and not user["is_deleted"]:
                g.user = user
            else:
                session.clear()  # deleted or removed while signed in -> signed out immediately

    @app.before_request
    def protect_forms():
        if request.method == "POST" and not security.csrf_valid():
            abort(400)

    @app.context_processor
    def inject():
        return {"csrf_token": security.csrf_token, "app_name": app.config["APP_NAME"], "current_user": g.get("user")}

    @app.after_request
    def secure_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; script-src 'self'; frame-ancestors 'none'; form-action 'self'",
        )
        if g.get("user") or request.endpoint in NO_STORE:
            resp.headers["Cache-Control"] = "no-store"
        if production:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp

    @app.errorhandler(400)
    def bad_request(_):
        return render_template("error.html", code=400, title="That didn't work",
                               message="Your form expired or was invalid. Go back, refresh the page and try again."), 400

    @app.errorhandler(401)
    def unauthorised(_):
        return render_template("error.html", code=401, title="Not authorised", message="You need to sign in first."), 401

    @app.errorhandler(403)
    def forbidden(_):
        return render_template("error.html", code=403, title="Access denied",
                               message="Your role doesn't have permission to open this page."), 403

    @app.errorhandler(404)
    def not_found(_):
        return render_template("error.html", code=404, title="Page not found",
                               message="We couldn't find what you were looking for."), 404

    @app.errorhandler(500)
    def server_error(_):
        return render_template("error.html", code=500, title="Something went wrong",
                               message="We hit a problem on our side. Please try again in a moment."), 500

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    return app
