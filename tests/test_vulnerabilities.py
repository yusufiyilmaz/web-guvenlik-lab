"""Her açığın zafiyetli modda çalıştığını, güvenli modda engellendiğini doğrular.

Çalıştırmak için proje klasöründe: python -m unittest -v
"""
import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from notes_app import create_app

ADMIN_SECRET = "LAB-FAKE-0001"       # 1 numaralı kullanıcının notundaki sahte sır
REFLECTED = "<script>alert(1)</script>"
STORED = "<img src=x onerror=alert(1)>"
SQLI_PW = "' OR '1'='1"


class NotesTestCase(unittest.TestCase):
    mode = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "notes.db"
        self.app = create_app(self.mode, db_path=self.db_path)
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def text(self, resp):
        return resp.get_data(as_text=True)

    def token(self, page="/login"):
        m = re.search(r'name="csrf_token" value="([0-9a-f]*)"', self.text(self.client.get(page)))
        return m.group(1) if m else ""

    def login(self, username, password):
        return self.client.post("/login", data={
            "username": username, "password": password, "csrf_token": self.token()})

    def current_user(self):
        with self.client.session_transaction() as s:
            return s.get("username")

    def stored(self, column, where):
        con = sqlite3.connect(self.db_path)
        value = con.execute(f"SELECT {column} FROM users WHERE {where}").fetchone()
        con.close()
        return value[0] if value else None


class VulnerableModeTests(NotesTestCase):
    """Açıklar zafiyetli modda gerçekten var mı?"""
    mode = "vulnerable"

    def test_sqli_login_bypass(self):
        self.login("admin", SQLI_PW)
        self.assertEqual(self.current_user(), "admin")

    def test_idor_reads_other_users_note(self):
        self.login("yusuf", "parola1")           # yusuf, admin'in notunu görmemeli
        body = self.text(self.client.get("/notes/1"))
        self.assertIn(ADMIN_SECRET, body)

    def test_reflected_xss_in_search(self):
        self.login("yusuf", "parola1")
        body = self.text(self.client.get("/search", query_string={"q": REFLECTED}))
        self.assertIn(REFLECTED, body)

    def test_stored_xss_in_note(self):
        self.login("yusuf", "parola1")
        self.client.post("/notes/new", data={"title": "x", "body": STORED, "csrf_token": ""})
        # notu aç: içerik ham basılmalı
        con = sqlite3.connect(self.db_path)
        nid = con.execute("SELECT id FROM notes WHERE title='x'").fetchone()[0]
        con.close()
        self.assertIn(STORED, self.text(self.client.get(f"/notes/{nid}")))

    def test_csrf_has_no_token(self):
        self.login("yusuf", "parola1")
        # zafiyetli modda formda token yok; token'sız POST kabul edilir
        r = self.client.post("/notes/new", data={"title": "t", "body": "b"})
        self.assertEqual(r.status_code, 302)

    def test_passwords_plaintext(self):
        self.assertEqual(self.stored("password", "username='yusuf'"), "parola1")

    def test_secret_key_hardcoded(self):
        self.assertEqual(self.app.secret_key, "dev-secret-key")

    def test_no_login_rate_limit(self):
        for _ in range(10):
            self.login("yusuf", "wrong")
        self.login("yusuf", "parola1")
        self.assertEqual(self.current_user(), "yusuf")


class SecureModeTests(NotesTestCase):
    """Aynı saldırılar güvenli modda engelleniyor mu? Normal kullanım bozulmuyor mu?"""
    mode = "secure"

    def test_sqli_login_bypass_blocked(self):
        self.login("admin", SQLI_PW)
        self.assertIsNone(self.current_user())

    def test_valid_login_works(self):
        self.login("yusuf", "parola1")
        self.assertEqual(self.current_user(), "yusuf")

    def test_idor_blocked_with_404(self):
        self.login("yusuf", "parola1")
        r = self.client.get("/notes/1")          # admin'in notu
        self.assertEqual(r.status_code, 404)
        self.assertNotIn(ADMIN_SECRET, self.text(r))

    def test_user_sees_own_note(self):
        self.login("yusuf", "parola1")
        self.assertEqual(self.client.get("/notes/3").status_code, 200)

    def test_admin_sees_any_note(self):
        self.login("admin", "admin123")
        self.assertEqual(self.client.get("/notes/3").status_code, 200)

    def test_reflected_xss_escaped(self):
        self.login("yusuf", "parola1")
        body = self.text(self.client.get("/search", query_string={"q": REFLECTED}))
        self.assertNotIn(REFLECTED, body)
        self.assertIn("&lt;script&gt;", body)

    def test_stored_xss_escaped(self):
        self.login("yusuf", "parola1")
        self.client.post("/notes/new", data={"title": "x", "body": STORED, "csrf_token": self.token("/notes")})
        con = sqlite3.connect(self.db_path)
        nid = con.execute("SELECT id FROM notes WHERE title='x'").fetchone()[0]
        con.close()
        self.assertNotIn(STORED, self.text(self.client.get(f"/notes/{nid}")))

    def test_csrf_without_token_rejected(self):
        self.login("yusuf", "parola1")
        r = self.client.post("/notes/new", data={"title": "t", "body": "b"})
        self.assertEqual(r.status_code, 400)

    def test_csrf_with_token_works(self):
        self.login("yusuf", "parola1")
        r = self.client.post("/notes/new",
                             data={"title": "t", "body": "b", "csrf_token": self.token("/notes")})
        self.assertEqual(r.status_code, 302)

    def test_passwords_hashed(self):
        value = self.stored("password", "username='yusuf'")
        self.assertNotEqual(value, "parola1")
        self.assertNotIn("parola1", value)

    def test_secret_key_not_hardcoded(self):
        self.assertNotEqual(self.app.secret_key, "dev-secret-key")
        self.assertGreaterEqual(len(self.app.secret_key), 32)

    def test_login_locked_after_too_many_failures(self):
        for _ in range(5):
            self.login("yusuf", "wrong")
        r = self.login("yusuf", "parola1")
        self.assertEqual(r.status_code, 429)
        self.assertIsNone(self.current_user())


if __name__ == "__main__":
    unittest.main()
