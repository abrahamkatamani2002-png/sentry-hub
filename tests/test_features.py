"""Tests for member management, restore bin, password links, activity log, notices and the user page."""
import json
import os
import re
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from test_app import PASSWORD, PEPPER, Base, Client  # noqa: E402

from sentryhub import activity, create_app, dash, db, mailer, security  # noqa: E402

CHROME_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


class Feat(Base):
    """Shared helpers."""

    def rows(self, sql, params=()):
        conn = db.connect(self.app.config["DATABASE_URL"])
        try:
            return conn.all(sql, params)
        finally:
            conn.close()

    def add_member(self, admin, username="nina", name="Nina Park", email=None, role="user"):
        return admin.post("/admin/members/new", {
            "full_name": name, "username": username, "email": email or f"{username}@example.com", "role": role,
        })

    def link_path(self):
        return re.search(r"/set-password/[\w-]+", mailer.OUTBOX[-1]["text"]).group(0)

    def activate(self, username="nina", password=PASSWORD):
        c = Client(self.app)
        r = c.post(self.link_path(), {"password": password, "confirm": password})
        self.assertEqual(r.status_code, 302)
        return c

    def mails_to(self, address):
        return [m for m in mailer.OUTBOX if m["to"] == address]

    def mark(self, username, **fields):
        conn = db.connect(self.app.config["DATABASE_URL"])
        for key, value in fields.items():
            conn.run(f"UPDATE users SET {key} = %s WHERE username = %s", (value, username))
        conn.commit()
        conn.close()


class AddMember(Feat):
    def test_admin_adds_member_and_invite_flow(self):
        admin = self.login("boss")
        r = self.add_member(admin, role="staff")
        self.assertEqual(r.status_code, 302)

        u = self.row("nina")
        self.assertEqual(u["role"], "staff")
        self.assertTrue(u["is_pending"])
        mail = mailer.OUTBOX[-1]
        self.assertEqual(mail["to"], "nina@example.com")
        self.assertIn("invited", mail["subject"].lower())
        self.assertIn("staff", mail["text"])

        # only a keyed hash of the link's token is stored
        path = self.link_path()
        token = path.rsplit("/", 1)[1]
        self.assertNotIn(token, json.dumps(self.rows("SELECT * FROM password_tokens")))

        # cannot sign in before choosing a password
        r = Client(self.app).post("/login", {"identifier": "nina", "password": PASSWORD})
        self.assertEqual(r.status_code, 401)

        c = Client(self.app)
        self.assertEqual(c.get(path).status_code, 200)
        self.assertEqual(c.post(path, {"password": PASSWORD, "confirm": PASSWORD}).status_code, 302)
        u = self.row("nina")
        self.assertFalse(u["is_pending"])
        self.assertTrue(security.verify_password(PASSWORD, u["salt"], u["password_hash"], PEPPER))

        # the link works once
        self.assertEqual(Client(self.app).get(path).status_code, 400)
        self.assertEqual(Client(self.app).post(path, {"password": PASSWORD, "confirm": PASSWORD}).status_code, 400)

        # then a normal 2FA sign-in lands on the staff dashboard
        self.assertEqual(self.login("nina").get("/staff").status_code, 200)

    def test_only_staff_or_user_can_be_assigned(self):
        admin = self.login("boss")
        self.assertEqual(self.add_member(admin, role="admin").status_code, 400)
        self.assertEqual(self.add_member(admin, role="").status_code, 400)
        self.assertIsNone(self.row("nina"))

    def test_validation_and_duplicates(self):
        admin = self.login("boss")
        self.assertEqual(self.add_member(admin).status_code, 302)
        self.assertEqual(self.add_member(admin, email="other@example.com").status_code, 400)   # username taken
        self.assertEqual(self.add_member(admin, username="nina2", email="nina@example.com").status_code, 400)  # email taken
        self.assertEqual(self.add_member(admin, username="bad name!", email="x@example.com").status_code, 400)
        self.assertEqual(self.add_member(admin, username="nina3", email="not-an-email").status_code, 400)
        self.assertEqual(len(self.rows("SELECT id FROM users WHERE username LIKE 'nina%'")), 1)

    def test_only_admin_can_add_members(self):
        self.register("alice")
        self.register("stella")
        self.set_role("stella", "staff")
        for who in ("alice", "stella"):
            c = self.login(who)
            self.assertEqual(c.get("/admin/members/new").status_code, 403)
            self.assertEqual(self.add_member(c).status_code, 403)
        self.assertEqual(self.app.test_client().get("/admin/members/new").status_code, 302)
        self.assertIsNone(self.row("nina"))

    def test_resend_invalidates_old_link_and_is_rate_limited(self):
        admin = self.login("boss")
        self.add_member(admin)
        old = self.link_path()
        uid = self.row("nina")["id"]
        admin.post(f"/admin/users/{uid}/invite")
        new = self.link_path()
        self.assertNotEqual(old, new)
        self.assertEqual(Client(self.app).get(old).status_code, 400)
        self.assertEqual(Client(self.app).get(new).status_code, 200)
        for _ in range(6):
            admin.post(f"/admin/users/{uid}/invite")
        self.assertEqual(len(self.mails_to("nina@example.com")), 5)

    def test_resend_only_for_pending_members(self):
        admin = self.login("boss")
        self.add_member(admin)
        self.activate()
        before = len(mailer.OUTBOX)
        admin.post(f"/admin/users/{self.row('nina')['id']}/invite")
        self.assertEqual(len(mailer.OUTBOX), before)

    def test_mail_failure_keeps_member_and_reports_it(self):
        admin = self.login("boss")
        original = mailer.send_invite

        def boom(*a, **k):
            raise mailer.MailError("smtp down")
        mailer.send_invite = boom
        try:
            r = self.add_member(admin)
            self.assertEqual(r.status_code, 302)
            page = admin.get("/admin").get_data(as_text=True)
        finally:
            mailer.send_invite = original
        self.assertIsNotNone(self.row("nina"))
        self.assertIn("invitation email couldn", page)

    def test_expired_invite_and_weak_password(self):
        admin = self.login("boss")
        self.add_member(admin)
        path = self.link_path()
        c = Client(self.app)
        self.assertEqual(c.post(path, {"password": "short1", "confirm": "short1"}).status_code, 400)
        self.assertEqual(c.post(path, {"password": PASSWORD, "confirm": "different-Pass-1"}).status_code, 400)
        self.assertTrue(self.row("nina")["is_pending"])
        conn = db.connect(self.app.config["DATABASE_URL"])
        conn.run("UPDATE password_tokens SET expires_at = %s", (int(time.time()) - 1,))
        conn.commit()
        conn.close()
        self.assertEqual(c.get(path).status_code, 400)

    def test_public_url_is_used_in_emailed_links(self):
        self.app.config["PUBLIC_URL"] = "https://hub.example.com/"
        self.add_member(self.login("boss"))
        self.assertIn("https://hub.example.com/set-password/", mailer.OUTBOX[-1]["text"])

    def test_pending_member_shows_as_invited_to_admin_and_staff(self):
        admin = self.login("boss")
        self.add_member(admin)  # a pending *user*
        self.register("stella")
        self.set_role("stella", "staff")
        page = admin.get("/admin").get_data(as_text=True)
        self.assertIn("pill-warn", page)
        self.assertIn("Resend invite", page)
        self.assertIn("nina@example.com", self.login("stella").get("/staff").get_data(as_text=True))


class DeleteAndRestore(Feat):
    def setUp(self):
        super().setUp()
        self.register("alice", name="Alice Anders")
        self.register("stella")
        self.set_role("stella", "staff")

    def test_admin_deletes_user_and_restores_with_same_role(self):
        admin = self.login("boss")
        uid = self.row("alice")["id"]
        admin.post(f"/admin/users/{uid}/delete")
        u = self.row("alice")
        self.assertTrue(u["is_deleted"])
        self.assertEqual(u["deleted_by"], self.row("boss")["id"])
        self.assertEqual(u["role"], "user")

        bin_page = admin.get("/admin/deleted").get_data(as_text=True)
        self.assertIn("alice@example.com", bin_page)
        self.assertIn("@boss", bin_page)
        self.assertIn("Restore", bin_page)
        self.assertNotIn("alice@example.com", self.login("stella").get("/staff").get_data(as_text=True))
        main = admin.get("/admin").get_data(as_text=True)
        self.assertIn("row-deleted", main)

        r = Client(self.app).post("/login", {"identifier": "alice", "password": PASSWORD})
        self.assertEqual(r.status_code, 403)

        r = admin.post(f"/admin/users/{uid}/restore", {"from": "bin"})
        self.assertEqual(r.headers["Location"], "/admin/deleted")
        u = self.row("alice")
        self.assertFalse(u["is_deleted"])
        self.assertIsNone(u["deleted_by"])
        self.assertEqual(u["role"], "user")
        self.login("alice")  # same password still works

    def test_admin_can_delete_and_restore_staff(self):
        admin = self.login("boss")
        sid = self.row("stella")["id"]
        stella = self.login("stella")
        admin.post(f"/admin/users/{sid}/delete")
        self.assertTrue(self.row("stella")["is_deleted"])
        self.assertEqual(stella.get("/staff").status_code, 302)  # open session ended
        admin.post(f"/admin/users/{sid}/restore")
        self.assertEqual(self.row("stella")["role"], "staff")
        self.assertEqual(self.login("stella").get("/staff").status_code, 200)

    def test_admins_cannot_be_deleted(self):
        admin = self.login("boss")
        admin.post(f"/admin/users/{self.row('boss')['id']}/delete")
        self.assertFalse(self.row("boss")["is_deleted"])
        self.assertEqual(admin.get("/admin").status_code, 200)

    def test_non_admins_cannot_use_admin_delete_or_restore(self):
        alice = self.login("alice")
        stella = self.login("stella")
        sid = self.row("stella")["id"]
        self.assertEqual(alice.post(f"/admin/users/{sid}/delete").status_code, 403)
        self.assertEqual(stella.post(f"/admin/users/{self.row('alice')['id']}/delete").status_code, 403)
        self.assertEqual(stella.get("/admin/deleted").status_code, 403)
        self.assertFalse(self.row("stella")["is_deleted"])

    def test_cannot_change_role_of_deleted_member(self):
        admin = self.login("boss")
        uid = self.row("alice")["id"]
        admin.post(f"/admin/users/{uid}/delete")
        admin.post(f"/admin/users/{uid}/role", {"role": "staff"})
        self.assertEqual(self.row("alice")["role"], "user")

    def test_staff_deletions_also_land_in_the_bin(self):
        stella = self.login("stella")
        stella.post(f"/staff/users/{self.row('alice')['id']}/delete")
        page = self.login("boss").get("/admin/deleted").get_data(as_text=True)
        self.assertIn("alice@example.com", page)
        self.assertIn("@stella", page)

    def test_empty_bin_message(self):
        self.assertIn("The bin is empty", self.login("boss").get("/admin/deleted").get_data(as_text=True))

    def test_deleting_a_pending_member_blocks_their_invite_until_restored(self):
        admin = self.login("boss")
        self.add_member(admin)
        path = self.link_path()
        uid = self.row("nina")["id"]
        admin.post(f"/admin/users/{uid}/delete")
        self.assertEqual(Client(self.app).get(path).status_code, 400)
        admin.post(f"/admin/users/{uid}/restore")
        self.assertEqual(Client(self.app).get(path).status_code, 200)


class ForgotPassword(Feat):
    def setUp(self):
        super().setUp()
        self.register("alice")
        mailer.OUTBOX.clear()

    def test_same_response_for_known_and_unknown_addresses(self):
        c = Client(self.app)
        unknown = c.post("/forgot", {"email": "nobody@example.com"})
        self.assertEqual(len(mailer.OUTBOX), 0)
        known = c.post("/forgot", {"email": "alice@example.com"})
        self.assertEqual(len(mailer.OUTBOX), 1)
        self.assertEqual(unknown.status_code, known.status_code)
        for r in (unknown, known):
            self.assertIn("If that address belongs", r.get_data(as_text=True))

    def test_reset_flow_changes_password_and_unlocks_account(self):
        c = Client(self.app)
        for _ in range(5):
            c.post("/login", {"identifier": "alice", "password": "bad-password-1"})
        self.assertGreater(self.row("alice")["locked_until"], time.time())
        old_hash = self.row("alice")["password_hash"]

        c.post("/forgot", {"email": "alice@example.com"})
        self.assertIn("Reset your", mailer.OUTBOX[-1]["subject"])
        path = self.link_path()
        r = Client(self.app).post(path, {"password": "Brand-New-Pass-77", "confirm": "Brand-New-Pass-77"})
        self.assertEqual(r.status_code, 302)
        u = self.row("alice")
        self.assertNotEqual(u["password_hash"], old_hash)
        self.assertEqual(u["locked_until"], 0)
        self.login("alice", "Brand-New-Pass-77")
        self.assertEqual(Client(self.app).get(path).status_code, 400)  # single use

    def test_old_password_stops_working(self):
        Client(self.app).post("/forgot", {"email": "alice@example.com"})
        Client(self.app).post(self.link_path(), {"password": "Brand-New-Pass-77", "confirm": "Brand-New-Pass-77"})
        r = Client(self.app).post("/login", {"identifier": "alice", "password": PASSWORD})
        self.assertEqual(r.status_code, 401)

    def test_requests_are_rate_limited(self):
        c = Client(self.app)
        for _ in range(8):
            c.post("/forgot", {"email": "alice@example.com"})
        self.assertEqual(len(self.mails_to("alice@example.com")), 5)

    def test_deleted_accounts_get_no_email(self):
        self.mark("alice", is_deleted=True)
        Client(self.app).post("/forgot", {"email": "alice@example.com"})
        self.assertEqual(len(mailer.OUTBOX), 0)

    def test_garbage_links_are_rejected(self):
        c = Client(self.app)
        for path in ("/set-password/nonsense", "/set-password/" + "a" * 500):
            self.assertEqual(c.get(path).status_code, 400)


class ActivityLog(Feat):
    def setUp(self):
        super().setUp()
        self.register("alice")

    def test_management_events_are_recorded_and_visible_to_admin(self):
        admin = self.login("boss")
        self.add_member(admin, role="staff")
        uid = self.row("alice")["id"]
        admin.post(f"/admin/users/{uid}/role", {"role": "staff"})
        admin.post(f"/admin/users/{uid}/delete")
        admin.post(f"/admin/users/{uid}/restore")
        admin.http.post("/admin/backup", headers={"X-CSRF-Token": admin.token()})
        actions = {r["action"] for r in self.rows("SELECT action FROM activity_log")}
        self.assertTrue({"login", "member_added", "role_changed", "member_deleted", "member_restored", "backup"} <= actions)
        page = admin.get("/admin/activity").get_data(as_text=True)
        for label in ("Member added", "Role changed", "Member deleted", "Member restored", "Signed in"):
            self.assertIn(label, page)
        self.assertIn("user → staff", page)

    def test_log_contains_no_secrets(self):
        admin = self.login("boss")
        self.add_member(admin)
        token = self.link_path().rsplit("/", 1)[1]
        self.assertNotIn(token, json.dumps(self.rows("SELECT * FROM activity_log")))
        page = admin.get("/admin/activity").get_data(as_text=True)
        self.assertNotIn(self.row("alice")["password_hash"], page)
        self.assertNotIn(PEPPER, page)

    def test_only_admin_can_read_the_log(self):
        self.register("stella")
        self.set_role("stella", "staff")
        for who in ("alice", "stella"):
            self.assertEqual(self.login(who).get("/admin/activity").status_code, 403)
        self.assertEqual(self.app.test_client().get("/admin/activity").status_code, 302)

    def test_failed_sign_ins_are_logged_for_real_accounts_only(self):
        c = Client(self.app)
        c.post("/login", {"identifier": "alice", "password": "bad-password-1"})
        c.post("/login", {"identifier": "ghost", "password": "bad-password-1"})
        failed = self.rows("SELECT * FROM activity_log WHERE action = 'login_failed'")
        self.assertEqual([r["target_name"] for r in failed], ["alice"])

    def test_sign_in_records_browser(self):
        c = Client(self.app)
        c.post("/login", {"identifier": "alice", "password": PASSWORD})
        c.post("/verify", {"code": self.last_code()}, headers={"User-Agent": CHROME_WIN})
        row = self.rows("SELECT * FROM activity_log WHERE action = 'login'")[0]
        self.assertEqual(row["detail"], "Chrome on Windows")

    def test_agent_descriptions(self):
        cases = {
            CHROME_WIN: "Chrome on Windows",
            "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120.0 Safari/537.36 Edg/120.0": "Edge on Windows",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0": "Firefox on Linux",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1": "Safari on iOS",
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36": "Chrome on Android",
            "": "Unknown device",
            "curl/8.4.0": "Unknown device",
        }
        for ua, expected in cases.items():
            self.assertEqual(activity.describe_agent(ua), expected, ua)


class Notices(Feat):
    def setUp(self):
        super().setUp()
        for name in ("alice", "stella", "sam"):
            self.register(name)
        self.set_role("stella", "staff")
        self.set_role("sam", "staff")

    def post(self, client, title="Office closed Friday", body="The office is closed on Friday.", pinned=False):
        data = {"title": title, "body": body}
        if pinned:
            data["pinned"] = "on"
        return client.post("/notices/new", data)

    def test_admin_and_staff_can_post_users_cannot(self):
        self.assertEqual(self.post(self.login("boss")).status_code, 302)
        self.assertEqual(self.post(self.login("stella"), title="Staff note").status_code, 302)
        self.assertEqual(self.post(self.login("alice"), title="Sneaky").status_code, 403)
        self.assertEqual(self.post(self.app.test_client() and Client(self.app), title="Anon").status_code, 302)
        titles = {r["title"] for r in self.rows("SELECT title FROM announcements")}
        self.assertEqual(titles, {"Office closed Friday", "Staff note"})

    def test_members_see_announcements_and_html_is_escaped(self):
        self.post(self.login("boss"), title="<script>alert(1)</script>", body="<b>bold</b> & more")
        page = self.login("alice").get("/dashboard").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("&lt;b&gt;bold&lt;/b&gt; &amp; more", page)

    def test_validation(self):
        admin = self.login("boss")
        self.post(admin, title="ab")
        self.post(admin, body="x")
        self.post(admin, body="x" * 601)
        self.assertEqual(self.rows("SELECT id FROM announcements"), [])

    def test_pinned_posts_come_first(self):
        admin = self.login("boss")
        self.post(admin, title="Pinned item", pinned=True)
        self.post(admin, title="Newer item")
        page = self.login("alice").get("/dashboard").get_data(as_text=True)
        self.assertLess(page.index("Pinned item"), page.index("Newer item"))

    def test_staff_manage_only_their_own_admin_manages_all(self):
        stella, sam, admin = self.login("stella"), self.login("sam"), self.login("boss")
        self.post(stella, title="Stella's note")
        self.post(admin, title="Admin note")
        stella_id, admin_id = [r["id"] for r in self.rows("SELECT id FROM announcements ORDER BY id")]

        page = stella.get("/staff").get_data(as_text=True)
        self.assertIn(f"/notices/{stella_id}/delete", page)
        self.assertNotIn(f"/notices/{admin_id}/delete", page)

        self.assertEqual(sam.post(f"/notices/{stella_id}/delete").status_code, 403)
        self.assertEqual(stella.post(f"/notices/{admin_id}/delete").status_code, 403)
        self.assertEqual(stella.post(f"/notices/{admin_id}/pin").status_code, 403)
        self.assertEqual(self.login("alice").post(f"/notices/{stella_id}/delete").status_code, 403)

        stella.post(f"/notices/{stella_id}/pin")
        self.assertTrue(self.rows("SELECT pinned FROM announcements WHERE id = %s", (stella_id,))[0]["pinned"])
        admin.post(f"/notices/{stella_id}/delete")  # admin can remove any
        stella.post(f"/notices/{admin_id}/delete")  # refused above; still there
        self.assertEqual([r["id"] for r in self.rows("SELECT id FROM announcements")], [admin_id])
        self.assertEqual(admin.post("/notices/9999/delete").status_code, 404)


class UserPage(Feat):
    def setUp(self):
        super().setUp()
        self.register("alice", name="Alice Anders")

    def test_health_score_grows_as_profile_is_completed(self):
        alice = self.login("alice")
        page = alice.get("/dashboard").get_data(as_text=True)
        self.assertIn("Account health", page)
        self.assertRegex(page, r'stroke-dasharray="[\d.]+ 326\.7"')
        self.assertEqual(dash.account_health(self.row("alice"))["score"], 70)

        alice.post("/dashboard/profile", {"job_title": "Designer", "bio": "I make things.", "avatar_color": "3"})
        u = self.row("alice")
        self.assertEqual((u["job_title"], u["bio"], u["avatar_color"]), ("Designer", "I make things.", 3))
        self.assertEqual(dash.account_health(u)["score"], 100)
        page = alice.get("/dashboard").get_data(as_text=True)
        self.assertIn("Designer", page)
        self.assertIn("avatar-xl", page)
        self.assertRegex(page, r"av-3 avatar-xl")

    def test_health_pieces(self):
        user = {"created_at": 0, "password_changed_at": None, "job_title": "", "bio": "", "avatar_color": None}
        self.assertEqual(dash.account_health(user, now=100 * 86400)["score"], 40)      # old password, nothing filled in
        self.assertEqual(dash.account_health(user, now=10 * 86400)["score"], 70)       # fresh password
        user["password_changed_at"] = 95 * 86400
        self.assertEqual(dash.account_health(user, now=100 * 86400)["score"], 70)      # changed 5 days ago
        user.update(job_title="Dev", bio="Hi")
        self.assertEqual(dash.account_health(user, now=100 * 86400)["score"], 90)
        user["avatar_color"] = 0                                                       # 0 is a real colour
        self.assertEqual(dash.account_health(user, now=100 * 86400)["score"], 100)

    def test_changing_password_refreshes_health_and_is_logged(self):
        self.mark("alice", password_changed_at=int(time.time()) - 200 * 86400, created_at=int(time.time()) - 200 * 86400)
        alice = self.login("alice")
        self.assertEqual(dash.account_health(self.row("alice"))["score"], 40)
        alice.post("/dashboard/password", {"current": PASSWORD, "new": "Brand-New-Pass-77", "confirm": "Brand-New-Pass-77"})
        self.assertEqual(dash.account_health(self.row("alice"))["score"], 70)
        self.assertIn("password_changed", {r["action"] for r in self.rows("SELECT action FROM activity_log")})

    def test_profile_validation(self):
        alice = self.login("alice")
        before = self.row("alice")
        alice.post("/dashboard/profile", {"job_title": "x" * 61, "bio": "ok", "avatar_color": "1"})
        alice.post("/dashboard/profile", {"job_title": "ok", "bio": "x" * 241, "avatar_color": "1"})
        alice.post("/dashboard/profile", {"job_title": "ok", "bio": "ok", "avatar_color": "9"})
        alice.post("/dashboard/profile", {"job_title": "ok", "bio": "ok", "avatar_color": "red"})
        after = self.row("alice")
        self.assertEqual((before["job_title"], before["bio"], before["avatar_color"]), (after["job_title"], after["bio"], after["avatar_color"]))

    def test_profile_text_is_escaped(self):
        alice = self.login("alice")
        alice.post("/dashboard/profile", {"job_title": "<i>boss</i>", "bio": "<script>x()</script>", "avatar_color": "2"})
        page = alice.get("/dashboard").get_data(as_text=True)
        self.assertNotIn("<script>x()</script>", page)
        self.assertIn("&lt;script&gt;x()&lt;/script&gt;", page)

    def test_recent_sign_ins_listed_with_browser(self):
        for _ in range(7):
            # the app allows 5 emailed codes per 15 minutes, so clear that counter between sign-ins
            conn = db.connect(self.app.config["DATABASE_URL"])
            conn.run("DELETE FROM login_challenges")
            conn.commit()
            conn.close()
            c = Client(self.app)
            c.post("/login", {"identifier": "alice", "password": PASSWORD})
            c.post("/verify", {"code": self.last_code()}, headers={"User-Agent": CHROME_WIN})
        page = c.get("/dashboard").get_data(as_text=True)
        self.assertEqual(page.count("Chrome on Windows"), 5)  # last five only
        self.assertIn("Latest", page)

    def test_only_own_sign_ins_are_shown(self):
        self.register("bob")
        bob = self.login("bob")
        self.login("alice")
        self.assertEqual(len(self.rows("SELECT id FROM activity_log WHERE action = 'login'")), 2)
        self.assertEqual(bob.get("/dashboard").get_data(as_text=True).count("class=\"si-icon\""), 1)

    def test_greeting_and_notice_board_present(self):
        page = self.login("alice").get("/dashboard").get_data(as_text=True)
        self.assertIn("data-greeting", page)
        self.assertIn("Notice board", page)
        self.assertIn("No announcements yet", page)

    def test_staff_and_admin_avatars_use_chosen_colour(self):
        admin = self.login("boss")
        admin.post("/dashboard/profile", {"job_title": "", "bio": "", "avatar_color": "4"})
        self.assertIn("av-4", admin.get("/admin").get_data(as_text=True))


class PagesAreCspClean(Feat):
    def test_no_inline_scripts_styles_or_handlers_on_any_page(self):
        self.register("alice")
        self.register("stella")
        self.set_role("stella", "staff")
        admin = self.login("boss")
        self.add_member(admin, username="nina")
        link = self.link_path()
        pages = {
            "admin": (admin, ["/admin", "/admin/members/new", "/admin/deleted", "/admin/activity"]),
            "staff": (self.login("stella"), ["/staff"]),
            "user": (self.login("alice"), ["/dashboard"]),
            "anon": (Client(self.app), ["/forgot", link, "/set-password/bad"]),
        }
        for who, (client, urls) in pages.items():
            for url in urls:
                r = client.get(url)
                self.assertIn(r.status_code, (200, 400), f"{who} {url}")
                html = r.get_data(as_text=True)
                self.assertNotRegex(html, r"<script(?![^>]*\bsrc=)[^>]*>", f"{who} {url}")
                self.assertNotRegex(html, r'\sstyle="', f"{who} {url}")
                self.assertNotRegex(html, r'\son\w+="', f"{who} {url}")

    def test_password_pages_are_not_cached(self):
        self.register("alice")
        self.assertEqual(Client(self.app).get("/forgot").headers["Cache-Control"], "no-store")


class UpgradeFromFirstRelease(unittest.TestCase):
    """A database created by the first version keeps its data and gains the new columns."""

    OLD_SCHEMA = """
    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE,
        full_name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'staff', 'user')),
        salt TEXT NOT NULL, password_hash TEXT NOT NULL, hash_version INTEGER NOT NULL DEFAULT 1,
        is_deleted BOOLEAN NOT NULL DEFAULT FALSE, deleted_at BIGINT, deleted_by BIGINT,
        failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until BIGINT NOT NULL DEFAULT 0,
        last_login_at BIGINT, created_at BIGINT NOT NULL);
    CREATE TABLE login_challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id BIGINT NOT NULL REFERENCES users (id),
        code_salt TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at BIGINT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0, used BOOLEAN NOT NULL DEFAULT FALSE, created_at BIGINT NOT NULL);
    CREATE TABLE backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT, created_at BIGINT NOT NULL, triggered_by TEXT NOT NULL,
        status TEXT NOT NULL, s3_key TEXT, size_bytes BIGINT, detail TEXT);
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = f"{self.tmp}/old.db"
        db._READY.clear()
        mailer.OUTBOX.clear()
        raw = sqlite3.connect(self.path)
        raw.executescript(self.OLD_SCHEMA)
        for name, role in (("oldadmin", "admin"), ("olduser", "user")):
            salt = security.new_salt()
            raw.execute(
                "INSERT INTO users (username, email, full_name, role, salt, password_hash, created_at) VALUES (?,?,?,?,?,?,?)",
                (name, f"{name}@example.com", name.title(), role, salt, security.hash_password(PASSWORD, salt, PEPPER), 1700000000),
            )
        raw.commit()
        raw.close()
        self.app = create_app({
            "ENV": "development", "DATABASE_URL": f"sqlite:///{self.path}", "SECRET_KEY": "s" * 40, "PEPPER": PEPPER,
            "MAIL_BACKEND": "memory", "CRON_SECRET": "c" * 20,
        })

    def test_columns_added_and_data_kept(self):
        with self.app.app_context():
            db.ensure_ready(self.app)
            db._READY.clear()
            db.ensure_ready(self.app)  # running it twice is harmless
        conn = db.connect(f"sqlite:///{self.path}")
        cols = conn.columns("users")
        self.assertTrue({"is_pending", "job_title", "bio", "avatar_color", "password_changed_at"} <= cols)
        rows = conn.all("SELECT username, role, is_pending, job_title FROM users ORDER BY id")
        conn.close()
        self.assertEqual([r["username"] for r in rows], ["oldadmin", "olduser"])
        self.assertEqual([r["is_pending"] for r in rows], [0, 0])
        self.assertEqual([r["job_title"] for r in rows], ["", ""])

    def test_existing_accounts_still_work_end_to_end(self):
        c = Client(self.app)
        self.assertEqual(c.post("/login", {"identifier": "oldadmin", "password": PASSWORD}).status_code, 302)
        code = re.search(r"code is: (\d{6})", mailer.OUTBOX[-1]["text"]).group(1)
        self.assertEqual(c.post("/verify", {"code": code}).status_code, 302)
        for url in ("/admin", "/admin/deleted", "/admin/activity", "/admin/members/new"):
            self.assertEqual(c.get(url).status_code, 200, url)

        u = Client(self.app)
        u.post("/login", {"identifier": "olduser", "password": PASSWORD})
        code = re.search(r"code is: (\d{6})", mailer.OUTBOX[-1]["text"]).group(1)
        u.post("/verify", {"code": code})
        page = u.get("/dashboard")
        self.assertEqual(page.status_code, 200)

    def test_postgres_migration_sql_is_generated(self):
        sql = db.migration_sql_postgres()
        self.assertIn("ALTER TABLE users ADD COLUMN IF NOT EXISTS is_pending BOOLEAN NOT NULL DEFAULT FALSE;", sql)
        self.assertEqual(sql.count("ADD COLUMN IF NOT EXISTS"), 6)


if __name__ == "__main__":
    unittest.main()
