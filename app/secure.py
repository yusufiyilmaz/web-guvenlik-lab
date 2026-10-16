"""GÜVENLI sürüm — vulnerable.py'deki üç açığın düzeltilmiş hali.

Aynı uygulama, aynı sayfalar; fark yalnızca güvenlik düzeltmelerinde.
Çalıştırma:  python secure.py   ->  http://127.0.0.1:5001
"""
from flask import Flask, request, redirect, session, render_template_string, abort
from markupsafe import escape

import db

app = Flask(__name__)
app.secret_key = "lab-only-not-secret"

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


@app.route("/")
def home():
    return page("""
      <div class="box"><h3>Giriş</h3>
        <form method="post" action="/login">
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
    """)


# --- Düzeltme 1: SQL Injection → parametreli sorgu ---
# Girdi sorguya yapıştırılmaz; ? yer tutucusuyla ayrı gönderilir.
@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    con = db.connect()
    row = con.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?", (u, p)
    ).fetchone()
    con.close()
    if row:
        session["user"] = row["username"]
        session["role"] = row["role"]
        return redirect("/")
    return page("<p>Giriş başarısız.</p>")


# --- Düzeltme 2: XSS → çıktı kaçışlama (escape) ---
# Kullanıcı girdisi sayfaya basılmadan önce HTML olarak kaçışlanır.
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
# Kullanıcı yalnızca giriş yaptığı kendi profilini görebilir.
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
    # Başkasının profilini istemek yasak (admin herkesi görebilir)
    if row["username"] != session["user"] and session.get("role") != "admin":
        abort(403)
    return page(f"<h3>{escape(row['username'])}</h3><p>Rol: {escape(row['role'])}</p>"
                f"<p>Özel not: {escape(row['secret_note'])}</p>")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    db.init_db()
    app.run(host="127.0.0.1", port=5001, debug=False)
