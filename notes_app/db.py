"""SQLite veritabanı ve sahte örnek veriler.

Tüm kullanıcılar, parolalar ve notlar sahtedir; yalnızca lab içindir.
"""
import sqlite3

from flask import current_app, g
from werkzeug.security import generate_password_hash

SCHEMA = """
CREATE TABLE users (
    id       INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role     TEXT NOT NULL DEFAULT 'user'
);
CREATE TABLE notes (
    id      INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    title   TEXT NOT NULL,
    body    TEXT NOT NULL
);
"""

SEED_USERS = [
    # id, kullanıcı adı, parola, rol
    (1, "admin", "admin123", "admin"),
    (2, "yusuf", "parola1", "user"),
    (3, "ayse", "deneme5", "user"),
]

SEED_NOTES = [
    # id, sahibi, başlık, içerik
    (1, 1, "Server backup", "Backup encryption key: LAB-FAKE-0001"),
    (2, 1, "Admin todo", "Rotate the VPN certificates before Friday."),
    (3, 2, "Shopping list", "Milk, bread, coffee."),
    (4, 2, "Exam dates", "Network security exam: 12 January."),
    (5, 3, "Private", "Home address: Sample St. 5 (fake)."),
]


def init_db(path, hash_passwords):
    """Veritabanını sıfırdan oluşturur.

    hash_passwords=False: parolalar düz metin saklanır (zafiyetli mod).
    hash_passwords=True:  parolalar tuzlu hash olarak saklanır (güvenli mod).
    """
    con = sqlite3.connect(path)
    con.executescript("DROP TABLE IF EXISTS notes; DROP TABLE IF EXISTS users;" + SCHEMA)
    con.executemany(
        "INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)",
        [(i, u, generate_password_hash(p) if hash_passwords else p, r) for i, u, p, r in SEED_USERS],
    )
    con.executemany("INSERT INTO notes (id, user_id, title, body) VALUES (?, ?, ?, ?)", SEED_NOTES)
    con.commit()
    con.close()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None):
    con = g.pop("db", None)
    if con is not None:
        con.close()
