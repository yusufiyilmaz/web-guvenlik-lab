"""ZAFIYETLI sürüm — bilerek güvensiz yazılmıştır.

Bu uygulama yalnızca eğitim amaçlıdır ve SADECE localhost'ta çalışır.
İçinde kasıtlı güvenlik açıkları vardır (SQLi, XSS, IDOR). ASLA internete açmayın.

Her açığın güvenli hali için secure.py dosyasına bakın.
Çalıştırma:  python vulnerable.py   ->  http://127.0.0.1:5000
"""
from flask import Flask, request, redirect, session, render_template_string

import db

app = Flask(__name__)
app.secret_key = "lab-only-not-secret"

PAGE = """
<!doctype html><html lang="tr"><head><meta charset="utf-8">
<title>Zafiyetli Lab</title>
<style>body{font-family:system-ui;max-width:640px;margin:40px auto;padding:0 16px}
input{padding:6px;margin:4px 0}.box{border:1px solid #ccc;border-radius:8px;padding:16px;margin:12px 0}
.warn{background:#fee;border:1px solid #c00;color:#900;padding:8px;border-radius:6px}</style></head>
<body>
<p class="warn">⚠️ Bilerek zafiyetli lab uygulaması. Sadece localhost.</p>
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
      <div class="box"><h3>Özel notumu değiştir</h3>
        <form method="post" action="/note"><input name="note" placeholder="yeni not">
        <button>Kaydet</button></form></div>
    """)


# --- Açık 1: SQL Injection ---
# Kullanıcı girdisi doğrudan SQL sorgusuna yapıştırılıyor.
@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    con = db.connect()
    query = f"SELECT * FROM users WHERE username = '{u}' AND password = '{p}'"
    row = con.execute(query).fetchone()
    con.close()
    if row:
        session["user"] = row["username"]
        session["role"] = row["role"]
        return redirect("/")
    return page(f"<p>Giriş başarısız.</p><p>Çalışan sorgu: <code>{query}</code></p>")


# --- Açık 2: Reflected XSS ---
# Arama terimi sayfaya hiç temizlenmeden basılıyor.
@app.route("/search")
def search():
    q = request.args.get("q", "")
    con = db.connect()
    rows = con.execute("SELECT username, role FROM users WHERE username LIKE ?",
                       (f"%{q}%",)).fetchall()
    con.close()
    items = "".join(f"<li>{r['username']} ({r['role']})</li>" for r in rows)
    return page(f"<h3>'{q}' için sonuçlar</h3><ul>{items}</ul>")


# --- Açık 3: IDOR ---
# Herhangi bir id ile herkesin özel notu görülebiliyor; yetki kontrolü yok.
@app.route("/profile")
def profile():
    uid = request.args.get("id", "")
    con = db.connect()
    row = con.execute(f"SELECT * FROM users WHERE id = {uid or 0}").fetchone()
    con.close()
    if not row:
        return page("<p>Kullanıcı yok.</p>")
    return page(f"<h3>{row['username']}</h3><p>Rol: {row['role']}</p>"
                f"<p>Özel not: {row['secret_note']}</p>")


# --- Açık 4: CSRF ---
# Form, isteğin bu siteden geldiğini doğrulamıyor. Başka bir site, giriş yapmış
# kullanıcının tarayıcısına bu formu gönderterek notunu değiştirebilir.
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


# Açık 5 (düz metin parola) ve 6 (koddaki gizli anahtar) yukarıda:
# db.init_db() parolaları olduğu gibi saklar, secret_key koda yazılmıştır.
# Açık 7 (deneme sınırı yok): /login sınırsız sayıda denenebilir.

if __name__ == "__main__":
    db.init_db()
    # Yalnızca localhost'a bağlanır; dışarıdan erişilemez.
    app.run(host="127.0.0.1", port=5000, debug=False)
