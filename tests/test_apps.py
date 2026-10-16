"""Her açığın zafiyetli sürümde çalıştığını, güvenli sürümde engellendiğini doğrular.

Çalıştırmak için proje klasöründe: python -m unittest -v
"""
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

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        db.DB_PATH = Path(self.tmp.name) / "lab.db"
        db.init_db()
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def login(self, username, password):
        return self.client.post("/login", data={"username": username, "password": password})

    def logged_in_user(self):
        with self.client.session_transaction() as s:
            return s.get("user")

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


class SecureAppTests(LabTestCase):
    """Aynı saldırılar güvenli sürümde engelleniyor mu?"""
    app = secure.app

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


if __name__ == "__main__":
    unittest.main()
