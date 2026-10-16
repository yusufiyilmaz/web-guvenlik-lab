"""GÜVENLI sürüm — vulnerable.py'deki açıkların düzeltilmiş hali.

Aynı uygulama, aynı sayfalar; fark yalnızca güvenlik düzeltmelerinde.
Çalıştırma:  python secure.py   ->  http://127.0.0.1:5001
"""
import os
import secrets
import time
from collections import defaultdict, deque

from flask import Flask, request, redirect, session, render_template_string, abort
from markupsafe import escape
from werkzeug.security import check_password_hash

import db

app = Flask(__name__)
# Düzeltme 6: gizli anahtar koda yazılmaz; ortam değişkeninden okunur,
# yoksa her başlatmada rastgele üretilir.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# Düzeltme 7: giriş deneme sınırı (IP başına, pencere içinde)
MAX_FAILED_LOGINS = 5
LOCKOUT_WINDOW = 10 * 60  # saniye
FAILED_LOGINS = defaultdict(deque)

PAGE = """
<!doctype html><html lang="tr"><head><meta charset="utf-8">
<title>Güvenli Lab</title>
<style>body{font-family:system-ui;max-width:640px;margin:40px auto;padding:0 16px}
input{padding:6px;margin:4px 0}.box{border:1px solid #ccc;border-radius:8px;padding:16px;margin:12px 0}
.ok{background:#efe;border:1px solid #0a0;color:#060;padding:8px;border-radius:6px}</style></head>
<body>
<p class="ok">✅ Düzeltilmiş sürüm. Sadece localhost.</p>
<h1>Lab</h1>
{% if user %}<p>Giriş: <b>{{ user }}</b> ({{ role }}) · <a href="/logout">çıkış</a></p>{% endif %}
{{ body|safe }}
</body></html>
"""


def page(body, **kw):
    return render_template_string(PAGE, body=body, user=session.get("user"),
                                  role=session.get("role"), **kw)


# --- Düzeltme 4: CSRF → oturuma bağlı token ---
# Her form, oturumda saklanan rastgele bir token taşır. POST isteği bu token'ı
# getirmezse reddedilir; başka bir site token'ı bilemeyeceği için sahte form gönderemez.
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def csrf_field():
    return f'<input type="hidden" name="csrf_token" value="{csrf_token()}">'


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        # Token eksikse de reddet: boş == boş eşleşmesi saldırıya kapı açar
        if not sent or not expected or not secrets.compare_digest(sent, expected):
            abort(400)


@app.route("/")
def home():
    return page(f"""
      <div class="box"><h3>Giriş</h3>
        <form method="post" action="/login">{csrf_field()}
          Kullanıcı: <input name="username"><br>
          Parola: <input name="password" type="password"><br>
          <button>Giriş</button>
        </form></div>
      <div class="box"><h3>Kullanıcı ara</h3>
        <form action="/search"><input name="q" placeholder="kullanıcı adı">
        <button>Ara</button></form></div>
      <div class="box"><h3>Profil</h3>
        <form action="/profile"><input name="id" placeholder="kullanıcı id">
        <button>Göster</button></form></div>
      <div class="box"><h3>Özel notumu değiştir</h3>
        <form method="post" action="/note">{csrf_field()}<input name="note" placeholder="yeni not">
        <button>Kaydet</button></form></div>
    """)


def too_many_failures(ip):
    attempts = FAILED_LOGINS[ip]
    now = time.monotonic()
    while attempts and attempts[0] < now - LOCKOUT_WINDOW:
        attempts.popleft()
    return len(attempts) >= MAX_FAILED_LOGINS


# --- Düzeltme 1: SQL Injection → parametreli sorgu ---
# --- Düzeltme 5: düz metin parola → hash karşılaştırması ---
@app.route("/login", methods=["POST"])
def login():
    ip = request.remote_addr
    if too_many_failures(ip):
        return page("<p>Çok fazla başarısız deneme. Daha sonra tekrar deneyin.</p>"), 429
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    con = db.connect()
    row = con.execute("SELECT * FROM users WHERE username = ?", (u,)).fetchone()
    con.close()
    if row and check_password_hash(row["password"], p):
        FAILED_LOGINS.pop(ip, None)
        session.clear()  # oturum sabitlemeye karşı giriş sonrası yeni oturum
        session["user"] = row["username"]
        session["role"] = row["role"]
        return redirect("/")
    FAILED_LOGINS[ip].append(time.monotonic())
    return page("<p>Giriş başarısız.</p>")


# --- Düzeltme 2: XSS → çıktı kaçışlama (escape) ---
@app.route("/search")
def search():
    q = request.args.get("q", "")
    con = db.connect()
    rows = con.execute("SELECT username, role FROM users WHERE username LIKE ?",
                       (f"%{q}%",)).fetchall()
    con.close()
    items = "".join(f"<li>{escape(r['username'])} ({escape(r['role'])})</li>" for r in rows)
    return page(f"<h3>{escape(q)} için sonuçlar</h3><ul>{items}</ul>")


# --- Düzeltme 3: IDOR → yetki kontrolü ---
@app.route("/profile")
def profile():
    if "user" not in session:
        return page("<p>Önce giriş yapın.</p>")
    uid = request.args.get("id", "")
    if not uid.isdigit():
        abort(400)
    con = db.connect()
    row = con.execute("SELECT * FROM users WHERE id = ?", (int(uid),)).fetchone()
    con.close()
    if not row:
        return page("<p>Kullanıcı yok.</p>")
    if row["username"] != session["user"] and session.get("role") != "admin":
        abort(403)
    return page(f"<h3>{escape(row['username'])}</h3><p>Rol: {escape(row['role'])}</p>"
                f"<p>Özel not: {escape(row['secret_note'])}</p>")


@app.route("/note", methods=["POST"])
def note():
    if "user" not in session:
        return page("<p>Önce giriş yapın.</p>")
    con = db.connect()
    con.execute("UPDATE users SET secret_note = ? WHERE username = ?",
                (request.form.get("note", ""), session["user"]))
    con.commit()
    con.close()
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    db.init_db(hash_passwords=True)
    app.run(host="127.0.0.1", port=5001, debug=False)
