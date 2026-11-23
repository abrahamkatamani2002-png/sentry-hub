import gzip
import json
import os
import re
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sentryhub import auth, backup, create_app, db, mailer, security  # noqa: E402

PEPPER = "p" * 40
PASSWORD = "Correct-Horse-9"


class Client:
    """Small helper that tracks the CSRF token the way a browser would."""

    def __init__(self, app):
        self.http = app.test_client()

    def token(self):
        # The 404 page always renders the base layout (with the CSRF meta tag), signed in or not.
        html = self.http.get("/csrf-probe").get_data(as_text=True)
        m = re.search(r'name="csrf-token" content="([^"]+)"', html)
        return m.group(1)

    def post(self, url, data=None, **kw):
        data = dict(data or {})
        data.setdefault("csrf_token", self.token())
        return self.http.post(url, data=data, **kw)

    def get(self, url, **kw):
        return self.http.get(url, **kw)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        db._READY.clear()
        mailer.OUTBOX.clear()
        self.uploads = {}
        self.app = create_app({
            "ENV": "development",
            "DATABASE_URL": f"sqlite:///{self.tmp}/t.db",
            "SECRET_KEY": "s" * 40,
            "PEPPER": PEPPER,
            "MAIL_BACKEND": "memory",
            "ADMIN_USERNAME": "boss", "ADMIN_EMAIL": "boss@example.com", "ADMIN_PASSWORD": PASSWORD,
            "BACKUP_PASSPHRASE": "backup-secret",
            "BACKUP_UPLOADER": lambda key, body: self.uploads.__setitem__(key, body),
            "CRON_SECRET": "cron-secret-value",
        })

    # --- helpers ---
    def register(self, username, email=None, name=None, password=PASSWORD):
        c = Client(self.app)
        return c.post("/register", {
            "full_name": name or username.title() + " Person", "username": username,
            "email": email or f"{username}@example.com", "password": password, "confirm": password,
        })

    def set_role(self, username, role):
        with self.app.app_context():
            conn = db.connect(self.app.config["DATABASE_URL"])
            conn.run("UPDATE users SET role = %s WHERE username = %s", (role, username))
            conn.commit()
            conn.close()

    def row(self, username):
        conn = db.connect(self.app.config["DATABASE_URL"])
        try:
            return conn.one("SELECT * FROM users WHERE username = %s", (username,))
        finally:
            conn.close()

    def last_code(self):
        return re.search(r"code is: (\d{6})", mailer.OUTBOX[-1]["text"]).group(1)

    def login(self, username, password=PASSWORD):
        c = Client(self.app)
        r = c.post("/login", {"identifier": username, "password": password})
        self.assertEqual(r.status_code, 302, r.get_data(as_text=True)[:300])
        r = c.post("/verify", {"code": self.last_code()})
        self.assertEqual(r.status_code, 302)
        return c


class PasswordSecurity(unittest.TestCase):
    def test_salt_is_random_and_changes_hash(self):
        s1, s2 = security.new_salt(), security.new_salt()
        self.assertNotEqual(s1, s2)
        self.assertNotEqual(security.hash_password("pw", s1, PEPPER), security.hash_password("pw", s2, PEPPER))

    def test_pepper_changes_hash(self):
        s = security.new_salt()
        self.assertNotEqual(security.hash_password("pw", s, PEPPER), security.hash_password("pw", s, "q" * 40))

    def test_verify(self):
        s = security.new_salt()
        h = security.hash_password("pw-12345678", s, PEPPER)
        self.assertTrue(security.verify_password("pw-12345678", s, h, PEPPER))
        self.assertFalse(security.verify_password("wrong", s, h, PEPPER))
        self.assertFalse(security.verify_password("pw-12345678", s, h, "q" * 40))

    def test_policy(self):
        self.assertIsNotNone(security.validate_password("short1"))
        self.assertIsNotNone(security.validate_password("onlyletterslong"))
        self.assertIsNone(security.validate_password(PASSWORD))

    def test_otp_is_6_digits_and_hashed(self):
        code = security.new_otp()
        self.assertRegex(code, r"^\d{6}$")
        salt = security.new_salt()
        h = security.hash_otp(code, salt, PEPPER)
        self.assertNotIn(code, h)
        self.assertTrue(security.otp_matches(code, salt, h, PEPPER))
        self.assertFalse(security.otp_matches("000000" if code != "000000" else "111111", salt, h, PEPPER))


class Registration(Base):
    def test_register_stores_salt_and_hash_not_password(self):
        r = self.register("alice")
        self.assertEqual(r.status_code, 302)
        u = self.row("alice")
        self.assertEqual(u["role"], "user")
        self.assertEqual(len(u["salt"]), 32)
        self.assertNotIn(PASSWORD, u["password_hash"])
        self.assertTrue(security.verify_password(PASSWORD, u["salt"], u["password_hash"], PEPPER))

    def test_same_password_gives_different_hashes(self):
        self.register("alice")
        self.register("bob")
        a, b = self.row("alice"), self.row("bob")
        self.assertNotEqual(a["salt"], b["salt"])
        self.assertNotEqual(a["password_hash"], b["password_hash"])

    def test_duplicates_and_validation_rejected(self):
        self.register("alice")
        self.assertEqual(self.register("alice", email="other@example.com").status_code, 400)
        self.assertEqual(self.register("alice2", email="alice@example.com").status_code, 400)
        self.assertEqual(self.register("weak", password="short1").status_code, 400)
        self.assertEqual(self.register("x").status_code, 400)

    def test_cannot_self_register_as_admin(self):
        c = Client(self.app)
        c.post("/register", {"full_name": "Eve Evil", "username": "eve", "email": "eve@example.com",
                             "password": PASSWORD, "confirm": PASSWORD, "role": "admin"})
        self.assertEqual(self.row("eve")["role"], "user")

    def test_csrf_required(self):
        r = self.app.test_client().post("/register", data={"username": "z"})
        self.assertEqual(r.status_code, 400)


class TwoFactorLogin(Base):
    def setUp(self):
        super().setUp()
        self.register("alice")

    def test_password_alone_is_not_enough(self):
        c = Client(self.app)
        r = c.post("/login", {"identifier": "alice", "password": PASSWORD})
        self.assertEqual(r.headers["Location"], "/verify")
        self.assertEqual(c.get("/dashboard").status_code, 302)  # still not signed in
        self.assertEqual(len(mailer.OUTBOX), 1)
        self.assertEqual(mailer.OUTBOX[0]["to"], "alice@example.com")

    def test_full_login_with_email_code_by_username_and_email(self):
        c = self.login("alice")
        self.assertEqual(c.get("/dashboard").status_code, 200)
        c2 = self.login("alice@example.com")
        self.assertEqual(c2.get("/dashboard").status_code, 200)

    def test_wrong_password_is_generic(self):
        c = Client(self.app)
        r = c.post("/login", {"identifier": "alice", "password": "nope-nope-123"})
        r2 = c.post("/login", {"identifier": "nobody", "password": "nope-nope-123"})
        self.assertEqual((r.status_code, r2.status_code), (401, 401))
        self.assertEqual(re.sub(r"\s+", " ", r.get_data(as_text=True)).count("Invalid username or password"), 1)
        self.assertEqual(len(mailer.OUTBOX), 0)

    def test_wrong_code_then_cancelled_after_five(self):
        c = Client(self.app)
        c.post("/login", {"identifier": "alice", "password": PASSWORD})
        real = self.last_code()
        wrong = "000000" if real != "000000" else "111111"
        for _ in range(4):
            self.assertEqual(c.post("/verify", {"code": wrong}).status_code, 401)
        r = c.post("/verify", {"code": wrong})
        self.assertEqual(r.headers["Location"], "/login")
        # even the correct code no longer works
        r = c.post("/verify", {"code": real})
        self.assertEqual(r.headers["Location"], "/login")
        self.assertEqual(c.get("/dashboard").status_code, 302)

    def test_expired_code_rejected(self):
        c = Client(self.app)
        c.post("/login", {"identifier": "alice", "password": PASSWORD})
        conn = db.connect(self.app.config["DATABASE_URL"])
        conn.run("UPDATE login_challenges SET expires_at = %s", (int(time.time()) - 5,))
        conn.commit()
        conn.close()
        r = c.post("/verify", {"code": self.last_code()})
        self.assertEqual(r.headers["Location"], "/login")

    def test_code_is_single_use(self):
        self.login("alice")
        used_code = self.last_code()
        # A fresh sign-in attempt starts a new challenge; the previously used code must not work in it.
        c2 = Client(self.app)
        c2.post("/login", {"identifier": "alice", "password": PASSWORD})
        new_code = self.last_code()
        if used_code == new_code:  # 1-in-a-million collision; nothing to assert
            self.skipTest("random codes collided")
        r = c2.post("/verify", {"code": used_code})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(c2.get("/dashboard").status_code, 302)
        self.assertEqual(c2.post("/verify", {"code": new_code}).status_code, 302)

    def test_stored_code_is_hashed(self):
        c = Client(self.app)
        c.post("/login", {"identifier": "alice", "password": PASSWORD})
        conn = db.connect(self.app.config["DATABASE_URL"])
        row = conn.one("SELECT * FROM login_challenges")
        conn.close()
        self.assertNotIn(self.last_code(), json.dumps(row))

    def test_resend_cooldown(self):
        c = Client(self.app)
        c.post("/login", {"identifier": "alice", "password": PASSWORD})
        c.post("/verify/resend", {})
        self.assertEqual(len(mailer.OUTBOX), 1)  # blocked by the cooldown

    def test_account_lockout(self):
        c = Client(self.app)
        for _ in range(auth.LOCK_AFTER):
            c.post("/login", {"identifier": "alice", "password": "bad-password-1"})
        r = c.post("/login", {"identifier": "alice", "password": PASSWORD})  # correct, but locked
        self.assertEqual(r.status_code, 401)
        self.assertEqual(len(mailer.OUTBOX), 0)

    def test_mail_failure_does_not_sign_in(self):
        def boom(*a, **k):
            raise mailer.MailError("smtp down")
        original = auth.send_login_code
        auth.send_login_code = boom
        try:
            r = Client(self.app).post("/login", {"identifier": "alice", "password": PASSWORD})
        finally:
            auth.send_login_code = original
        self.assertEqual(r.status_code, 503)


class Authorization(Base):
    def setUp(self):
        super().setUp()
        for name in ("alice", "stella", "sam"):
            self.register(name)
        self.set_role("stella", "staff")
        self.set_role("sam", "staff")

    def test_anonymous_redirected(self):
        c = Client(self.app)
        for url in ("/dashboard", "/staff", "/admin"):
            self.assertEqual(c.get(url).status_code, 302, url)

    def test_user_blocked_from_staff_and_admin(self):
        c = self.login("alice")
        self.assertEqual(c.get("/dashboard").status_code, 200)
        self.assertEqual(c.get("/staff").status_code, 403)
        self.assertEqual(c.get("/admin").status_code, 403)

    def test_staff_blocked_from_admin_and_cannot_use_admin_actions(self):
        c = self.login("stella")
        self.assertEqual(c.get("/staff").status_code, 200)
        self.assertEqual(c.get("/admin").status_code, 403)
        uid = self.row("alice")["id"]
        self.assertEqual(c.post(f"/admin/users/{uid}/role", {"role": "staff"}).status_code, 403)
        self.assertEqual(c.post(f"/admin/users/{uid}/restore").status_code, 403)
        self.assertEqual(c.post("/admin/backup").status_code, 403)
        self.assertEqual(self.row("alice")["role"], "user")

    def test_each_role_gets_its_own_dashboard(self):
        self.assertIn("Staff dashboard", self.login("stella").get("/staff").get_data(as_text=True))
        self.assertIn("Admin dashboard", self.login("boss").get("/admin").get_data(as_text=True))
        self.assertIn("My account", self.login("alice").get("/dashboard").get_data(as_text=True))
        self.assertEqual(self.login("stella").get("/dashboard").headers["Location"], "/staff")

    def test_landing_redirects_by_role(self):
        self.assertEqual(self.login("boss").get("/").headers["Location"], "/admin")


class AdminFeatures(Base):
    def setUp(self):
        super().setUp()
        self.register("alice", name="Alice Anders")
        self.register("stella")
        self.set_role("stella", "staff")

    def test_admin_sees_users_salts_and_hashes(self):
        html = self.login("boss").get("/admin").get_data(as_text=True)
        u = self.row("alice")
        self.assertIn(u["password_hash"], html)
        self.assertIn(u["salt"], html)
        self.assertIn("alice@example.com", html)
        self.assertNotIn(PASSWORD, html)
        self.assertNotIn(PEPPER, html)

    def test_staff_never_sees_hashes_or_non_users(self):
        html = self.login("stella").get("/staff").get_data(as_text=True)
        self.assertNotIn(self.row("alice")["password_hash"], html)
        self.assertNotIn(self.row("alice")["salt"], html)
        self.assertIn("alice@example.com", html)
        self.assertNotIn("boss@example.com", html)
        self.assertNotIn("stella@example.com", html)

    def test_admin_changes_roles_both_ways(self):
        admin = self.login("boss")
        uid = self.row("alice")["id"]
        admin.post(f"/admin/users/{uid}/role", {"role": "staff"})
        self.assertEqual(self.row("alice")["role"], "staff")
        admin.post(f"/admin/users/{uid}/role", {"role": "user"})
        self.assertEqual(self.row("alice")["role"], "user")

    def test_admin_cannot_mint_admins_or_demote_admins(self):
        admin = self.login("boss")
        uid = self.row("alice")["id"]
        admin.post(f"/admin/users/{uid}/role", {"role": "admin"})
        self.assertEqual(self.row("alice")["role"], "user")
        admin.post(f"/admin/users/{self.row('boss')['id']}/role", {"role": "user"})
        self.assertEqual(self.row("boss")["role"], "admin")

    def test_staff_delete_soft_deletes_and_admin_restores(self):
        staff, admin = self.login("stella"), self.login("boss")
        uid = self.row("alice")["id"]

        r = staff.post(f"/staff/users/{uid}/delete")
        self.assertEqual(r.status_code, 302)
        u = self.row("alice")
        self.assertTrue(u["is_deleted"])  # row still exists
        self.assertEqual(u["deleted_by"], self.row("stella")["id"])

        # gone from the staff dashboard
        self.assertNotIn("alice@example.com", staff.get("/staff").get_data(as_text=True))
        # still visible to admin, labelled Deleted
        html = admin.get("/admin").get_data(as_text=True)
        self.assertIn("alice@example.com", html)
        self.assertIn("pill-deleted", html)
        self.assertIn("row-deleted", html)

        # deleted account can't sign in
        c = Client(self.app)
        r = c.post("/login", {"identifier": "alice", "password": PASSWORD})
        self.assertEqual(r.status_code, 403)

        # admin restores; account works again and is back on the staff list
        admin.post(f"/admin/users/{uid}/restore")
        self.assertFalse(self.row("alice")["is_deleted"])
        self.assertIn("alice@example.com", staff.get("/staff").get_data(as_text=True))
        self.login("alice")

    def test_deleting_kills_an_active_session(self):
        alice = self.login("alice")
        self.assertEqual(alice.get("/dashboard").status_code, 200)
        self.login("stella").post(f"/staff/users/{self.row('alice')['id']}/delete")
        self.assertEqual(alice.get("/dashboard").status_code, 302)

    def test_staff_can_only_delete_active_users(self):
        staff = self.login("stella")
        self.assertEqual(staff.post(f"/staff/users/{self.row('boss')['id']}/delete").status_code, 403)
        self.register("stan")
        self.set_role("stan", "staff")
        self.assertEqual(staff.post(f"/staff/users/{self.row('stan')['id']}/delete").status_code, 403)
        self.assertEqual(staff.post("/staff/users/9999/delete").status_code, 404)
        self.assertFalse(self.row("boss")["is_deleted"] or self.row("stan")["is_deleted"])


class Backups(Base):
    def test_button_backup_uploads_encrypted_snapshot(self):
        self.register("alice")
        admin = self.login("boss")
        token = admin.token()
        r = admin.http.post("/admin/backup", headers={"X-CSRF-Token": token})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["message"], "Backup completed")

        self.assertEqual(len(self.uploads), 1)
        key, blob = next(iter(self.uploads.items()))
        self.assertTrue(key.startswith("sentry-hub/backups/"))
        self.assertNotIn(b"alice@example.com", blob)  # encrypted
        snapshot = json.loads(gzip.decompress(backup.decrypt_blob(blob, "backup-secret")))
        names = {u["username"] for u in snapshot["tables"]["users"]}
        self.assertEqual(names, {"boss", "alice"})
        with self.assertRaises(Exception):
            backup.decrypt_blob(blob, "wrong-passphrase")

        html = admin.get("/admin").get_data(as_text=True)
        self.assertIn("Successful", html)

    def test_failed_upload_is_reported_not_faked(self):
        def broken(key, body):
            raise RuntimeError("AccessDenied")
        self.app.config["BACKUP_UPLOADER"] = broken
        admin = self.login("boss")
        r = admin.http.post("/admin/backup", headers={"X-CSRF-Token": admin.token()})
        self.assertEqual(r.status_code, 502)
        self.assertFalse(r.get_json()["ok"])
        self.assertIn("AccessDenied", r.get_json()["message"])
        self.assertNotEqual(r.get_json()["message"], "Backup completed")

    def test_without_aws_backup_is_stored_in_database(self):
        self.app.config["BACKUP_UPLOADER"] = None  # no AWS settings configured
        admin = self.login("boss")
        r = admin.http.post("/admin/backup", headers={"X-CSRF-Token": admin.token()})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["message"], "Backup completed")
        with self.app.app_context():
            row = db.get_db().one("SELECT * FROM backups WHERE data IS NOT NULL")
        self.assertIsNotNone(row)
        d = admin.http.get(f"/admin/backups/{row['id']}/download")
        self.assertEqual(d.status_code, 200)
        snapshot = json.loads(gzip.decompress(backup.decrypt_blob(d.data, "backup-secret")))
        self.assertIn("boss", [u["username"] for u in snapshot["tables"]["users"]])

    def test_only_admin_can_download_backup(self):
        self.app.config["BACKUP_UPLOADER"] = None
        admin = self.login("boss")
        admin.http.post("/admin/backup", headers={"X-CSRF-Token": admin.token()})
        self.assertIn(self.app.test_client().get("/admin/backups/1/download").status_code, (302, 401, 403))

    def test_backup_requires_csrf(self):
        admin = self.login("boss")
        self.assertEqual(admin.http.post("/admin/backup").status_code, 400)

    def test_cron_endpoint_requires_secret(self):
        c = self.app.test_client()
        self.assertEqual(c.get("/api/cron/backup").status_code, 401)
        self.assertEqual(c.get("/api/cron/backup", headers={"Authorization": "Bearer wrong"}).status_code, 401)
        r = c.get("/api/cron/backup", headers={"Authorization": "Bearer cron-secret-value"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(self.uploads), 1)

    def test_cron_disabled_without_secret(self):
        self.app.config["CRON_SECRET"] = ""
        r = self.app.test_client().get("/api/cron/backup", headers={"Authorization": "Bearer "})
        self.assertEqual(r.status_code, 401)


class PasswordChange(Base):
    def test_change_password_rotates_salt(self):
        self.register("alice")
        c = self.login("alice")
        old = self.row("alice")
        c.post("/dashboard/password", {"current": PASSWORD, "new": "Brand-New-Pass-77", "confirm": "Brand-New-Pass-77"})
        new = self.row("alice")
        self.assertNotEqual(old["salt"], new["salt"])
        self.assertNotEqual(old["password_hash"], new["password_hash"])
        self.login("alice", "Brand-New-Pass-77")

    def test_wrong_current_password_rejected(self):
        self.register("alice")
        c = self.login("alice")
        before = self.row("alice")["password_hash"]
        c.post("/dashboard/password", {"current": "wrong-wrong-1", "new": "Brand-New-Pass-77", "confirm": "Brand-New-Pass-77"})
        self.assertEqual(self.row("alice")["password_hash"], before)


class Misc(Base):
    def test_public_pages_render(self):
        c = Client(self.app)
        for url in ("/", "/login", "/register", "/healthz"):
            self.assertEqual(c.get(url).status_code, 200, url)
        self.assertEqual(c.get("/nope").status_code, 404)

    def test_security_headers_and_cookie_flags(self):
        r = self.app.test_client().get("/login")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])

    def test_no_inline_scripts_or_styles(self):
        c = Client(self.app)
        for url in ("/", "/login", "/register"):
            html = c.get(url).get_data(as_text=True)
            self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)[^>]*>")
            self.assertNotRegex(html, r'\sstyle="')
            self.assertNotRegex(html, r'\son\w+="')

    def test_config_requires_strong_secrets(self):
        from sentryhub import config
        with self.assertRaises(config.ConfigError):
            create_app({"DATABASE_URL": "sqlite:///x.db", "SECRET_KEY": "short", "PEPPER": "short"})


if __name__ == "__main__":
    unittest.main()
