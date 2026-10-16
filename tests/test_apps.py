"""Her açığın zafiyetli sürümde çalıştığını, güvenli sürümde engellendiğini doğrular.

Çalıştırmak için proje klasöründe: python -m unittest -v
"""
import re
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

import db  # noqa: E402
import secure  # noqa: E402
import vulnerable  # noqa: E402

SQLI = "' OR '1'='1"
XSS = "<script>alert(1)</script>"
ADMIN_SECRET = "LAB-FAKE-0001"


class LabTestCase(unittest.TestCase):
    app = None
    hash_passwords = False

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.tmp.name) / "lab.db"
        db.init_db(hash_passwords=self.hash_passwords)
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def form_token(self):
        return None

    def post(self, url, data, token=True):
        data = dict(data)
        if token and self.form_token():
            data["csrf_token"] = self.form_token()
        return self.client.post(url, data=data)

    def login(self, username, password):
        return self.post("/login", {"username": username, "password": password})

    def logged_in_user(self):
        with self.client.session_transaction() as s:
            return s.get("user")

    def stored(self, column, username):
        con = sqlite3.connect(db.DB_PATH)
        value = con.execute(f"SELECT {column} FROM users WHERE username = ?", (username,)).fetchone()[0]
        con.close()
        return value

    def text(self, resp):
        return resp.get_data(as_text=True)


class VulnerableAppTests(LabTestCase):
    """Açıklar zafiyetli sürümde gerçekten var mı?"""
    app = vulnerable.app

    def test_sqli_bypasses_login(self):
        self.login("admin", SQLI)
        self.assertEqual(self.logged_in_user(), "admin")

    def test_xss_payload_reflected_raw(self):
        self.assertIn(XSS, self.text(self.client.get("/search", query_string={"q": XSS})))

    def test_idor_reads_other_users_secret_without_login(self):
        self.assertIn(ADMIN_SECRET, self.text(self.client.get("/profile?id=1")))

    def test_csrf_note_change_without_token(self):
        self.login("yusuf", "parola1")
        self.post("/note", {"note": "CSRF ile degisti"}, token=False)
        self.assertEqual(self.stored("secret_note", "yusuf"), "CSRF ile degisti")

    def test_passwords_stored_in_plaintext(self):
        self.assertEqual(self.stored("password", "yusuf"), "parola1")

    def test_secret_key_hardcoded(self):
        self.assertEqual(vulnerable.app.secret_key, "lab-only-not-secret")

    def test_no_login_rate_limit(self):
        for _ in range(10):
            self.login("yusuf", "yanlis")
        self.login("yusuf", "parola1")
        self.assertEqual(self.logged_in_user(), "yusuf")


class SecureAppTests(LabTestCase):
    """Aynı saldırılar güvenli sürümde engelleniyor mu?"""
    app = secure.app
    hash_passwords = True

    def setUp(self):
        super().setUp()
        secure.FAILED_LOGINS.clear()

    def form_token(self):
        body = self.text(self.client.get("/"))
        return re.search(r'name="csrf_token" value="([0-9a-f]+)"', body).group(1)

    def test_sqli_does_not_bypass_login(self):
        self.login("admin", SQLI)
        self.assertIsNone(self.logged_in_user())

    def test_valid_login_still_works(self):
        self.login("yusuf", "parola1")
        self.assertEqual(self.logged_in_user(), "yusuf")

    def test_xss_payload_escaped(self):
        body = self.text(self.client.get("/search", query_string={"q": XSS}))
        self.assertNotIn(XSS, body)
        self.assertIn("&lt;script&gt;", body)

    def test_profile_requires_login(self):
        self.assertNotIn(ADMIN_SECRET, self.text(self.client.get("/profile?id=1")))

    def test_user_cannot_read_other_profile(self):
        self.login("yusuf", "parola1")
        self.assertEqual(self.client.get("/profile?id=1").status_code, 403)

    def test_user_can_read_own_profile(self):
        self.login("yusuf", "parola1")
        resp = self.client.get("/profile?id=2")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("4242", self.text(resp))

    def test_admin_can_read_any_profile(self):
        self.login("admin", "admin123")
        self.assertEqual(self.client.get("/profile?id=2").status_code, 200)

    def test_non_numeric_id_rejected(self):
        self.login("yusuf", "parola1")
        self.assertEqual(self.client.get("/profile?id=1 OR 1=1").status_code, 400)

    def test_csrf_post_without_token_rejected(self):
        self.login("yusuf", "parola1")
        resp = self.post("/note", {"note": "CSRF ile degisti"}, token=False)
        self.assertEqual(resp.status_code, 400)
        self.assertNotEqual(self.stored("secret_note", "yusuf"), "CSRF ile degisti")

    def test_note_change_with_token_works(self):
        self.login("yusuf", "parola1")
        self.post("/note", {"note": "yeni not"})
        self.assertEqual(self.stored("secret_note", "yusuf"), "yeni not")

    def test_passwords_stored_as_hash(self):
        stored = self.stored("password", "yusuf")
        self.assertNotEqual(stored, "parola1")
        self.assertNotIn("parola1", stored)

    def test_secret_key_not_hardcoded(self):
        self.assertNotEqual(secure.app.secret_key, "lab-only-not-secret")
        self.assertGreaterEqual(len(secure.app.secret_key), 32)

    def test_login_locked_after_too_many_failures(self):
        for _ in range(secure.MAX_FAILED_LOGINS):
            self.login("yusuf", "yanlis")
        resp = self.login("yusuf", "parola1")
        self.assertEqual(resp.status_code, 429)
        self.assertIsNone(self.logged_in_user())


if __name__ == "__main__":
    unittest.main()
