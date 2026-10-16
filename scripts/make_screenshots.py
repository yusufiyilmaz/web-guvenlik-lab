"""README için ekran görüntüleri üretir (headless Edge ile).

    python scripts/make_screenshots.py

Çıktı: docs/screenshots/*.png
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from notes_app import create_app  # noqa: E402

OUT = ROOT / "docs" / "screenshots"
CSS = (ROOT / "notes_app" / "static" / "style.css").read_text(encoding="utf-8")
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"


def inline(html):
    """CSS linkini gömülü stile çevirir (dosya yolu olmadan açılabilsin)."""
    return re.sub(r'<link rel="stylesheet"[^>]*>', f"<style>{CSS}</style>", html)


def shot(html, name, height):
    tmp = Path(tempfile.gettempdir()) / f"wlab_{name}.html"
    tmp.write_text(inline(html), encoding="utf-8")
    out = OUT / f"{name}.png"
    subprocess.run([EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                    f"--window-size=1100,{height}", f"--screenshot={out}", tmp.as_uri()],
                   check=True, capture_output=True)
    print("yazıldı:", out.name)


def build(mode, actions):
    app = create_app(mode, db_path=Path(tempfile.mkdtemp()) / "s.db")
    client = app.test_client()
    return client, actions(client)


def main():
    OUT.mkdir(parents=True, exist_ok=True)

    # 1) Güvenli mod: giriş ekranı
    c, html = build("secure", lambda c: c.get("/login").get_data(as_text=True))
    shot(html, "01-login", 600)

    # 2) Güvenli mod: not listesi (giriş yaptıktan sonra)
    def notes_page(c):
        tok = re.search(r'value="([0-9a-f]+)"', c.get("/login").get_data(as_text=True)).group(1)
        c.post("/login", data={"username": "yusuf", "password": "parola1", "csrf_token": tok})
        return c.get("/notes").get_data(as_text=True)
    c, html = build("secure", notes_page)
    shot(html, "02-notes", 560)

    # 3) Zafiyetli mod: aramada reflected XSS'in ham basılması (kanıt)
    def xss_page(c):
        tok = re.search(r'value="([0-9a-f]*)"', c.get("/login").get_data(as_text=True))
        c.post("/login", data={"username": "yusuf", "password": "parola1",
                               "csrf_token": tok.group(1) if tok else ""})
        return c.get("/search", query_string={"q": "<b>INJECTED</b>"}).get_data(as_text=True)
    c, html = build("vulnerable", xss_page)
    shot(html, "03-xss-vulnerable", 430)


if __name__ == "__main__":
    main()
