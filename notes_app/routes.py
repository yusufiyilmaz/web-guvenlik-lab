"""Uygulamanın sayfaları.

Bir açık barındıran her yerde iki dal vardır:
    if vuln():   # ZAFİYETLİ — açığın kendisi
    else:        # GÜVENLİ   — düzeltilmiş hali
"""
from functools import wraps

from flask import (Blueprint, abort, current_app, flash, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash

from .db import get_db

bp = Blueprint("notes", __name__)


def vuln():
    return current_app.config["VULNERABLE"]


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("notes.login"))
        return view(*args, **kwargs)
    return wrapped


@bp.route("/")
def index():
    return redirect(url_for("notes.list_notes" if "user_id" in session else "notes.login"))


# --- Açık 1: SQL Injection (giriş) · Açık 5: düz metin parola · Açık 7: deneme sınırı yok ---
@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    db = get_db()

    if vuln():
        # ZAFİYETLİ: girdi SQL'e yapıştırılıyor, parola düz metin karşılaştırılıyor,
        # deneme sayısı sınırsız.
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = db.execute(query).fetchone()
    else:
        # GÜVENLİ: deneme sınırı, parametreli sorgu, parola hash karşılaştırması.
        limiter = current_app.extensions["login_limiter"]
        if limiter.is_locked(request.remote_addr):
            return render_template("login.html",
                                   error="Too many failed attempts. Try again later."), 429
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and not check_password_hash(user["password"], password):
            user = None
        if user:
            limiter.reset(request.remote_addr)
        else:
            limiter.record_failure(request.remote_addr)

    if not user:
        return render_template("login.html", error="Invalid username or password."), 401

    if not vuln():
        session.clear()  # oturum sabitlemeye karşı, girişte yeni oturum
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    return redirect(url_for("notes.list_notes"))


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("notes.login"))


@bp.route("/notes")
@login_required
def list_notes():
    notes = get_db().execute(
        "SELECT id, title FROM notes WHERE user_id = ? ORDER BY id DESC", (session["user_id"],)
    ).fetchall()
    return render_template("notes.html", notes=notes)


# --- Açık 3: IDOR ---
@bp.route("/notes/<int:note_id>")
@login_required
def view_note(note_id):
    db = get_db()
    if vuln():
        # ZAFİYETLİ: not, sahibine bakılmadan id ile getiriliyor.
        note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    else:
        # GÜVENLİ: yalnızca giriş yapan kullanıcının notu (admin hepsini görebilir).
        if session.get("role") == "admin":
            note = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
        else:
            note = db.execute("SELECT * FROM notes WHERE id = ? AND user_id = ?",
                              (note_id, session["user_id"])).fetchone()
    if not note:
        abort(404)  # var olmayan ile başkasına ait olanı ayırt ettirmez
    return render_template("note.html", note=note)


# --- Açık 2b: Stored XSS (not içeriği) · Açık 4: CSRF ---
# Not içeriği şablonda (note.html) zafiyetli modda |safe ile basılır.
# CSRF koruması güvenli modda security.check_csrf içinde tüm POST'lara uygulanır.
@bp.route("/notes/new", methods=["POST"])
@login_required
def create_note():
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    if not title or not body:
        flash("Title and body are required.")
        return redirect(url_for("notes.list_notes"))
    db = get_db()
    cur = db.execute("INSERT INTO notes (user_id, title, body) VALUES (?, ?, ?)",
                     (session["user_id"], title, body))
    db.commit()
    return redirect(url_for("notes.view_note", note_id=cur.lastrowid))


@bp.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id):
    db = get_db()
    db.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, session["user_id"]))
    db.commit()
    return redirect(url_for("notes.list_notes"))


# --- Açık 1b: SQL Injection (arama) · Açık 2a: Reflected XSS (arama terimi) ---
@bp.route("/search")
@login_required
def search():
    q = request.args.get("q", "")
    db = get_db()
    if vuln():
        # ZAFİYETLİ: arama terimi SQL'e yapıştırılıyor.
        query = (f"SELECT id, title FROM notes WHERE user_id = {session['user_id']} "
                 f"AND title LIKE '%{q}%'")
        results = db.execute(query).fetchall()
    else:
        # GÜVENLİ: parametreli sorgu.
        results = db.execute("SELECT id, title FROM notes WHERE user_id = ? AND title LIKE ?",
                             (session["user_id"], f"%{q}%")).fetchall()
    # Arama terimi şablonda (search.html) zafiyetli modda |safe ile basılır.
    return render_template("search.html", q=q, results=results)
