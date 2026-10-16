"""Lab için küçük bir SQLite veritabanı. Veriler tamamen sahtedir."""
import sqlite3
from pathlib import Path

from werkzeug.security import generate_password_hash

DB_PATH = Path(__file__).parent / "lab.db"

# Sahte kullanıcılar (parolalar yalnızca lab içindir, gerçek değildir)
SEED_USERS = [
    # id, kullanıcı adı, parola, rol, özel not
    (1, "admin", "admin123", "admin", "Sunucu yedek anahtarı: LAB-FAKE-0001"),
    (2, "yusuf", "parola1", "user", "Kredi kartı son 4 hane: 4242 (sahte)"),
    (3, "ayse", "deneme5", "user", "Ev adresi: Örnek Mah. (sahte)"),
]


def init_db(hash_passwords=False):
    """Veritabanını sıfırdan oluşturur ve sahte verilerle doldurur.

    hash_passwords=False: parolalar düz metin saklanır (zafiyetli sürüm).
    hash_passwords=True:  parolalar tuzlu hash olarak saklanır (güvenli sürüm).
    """
    if DB_PATH.exists():
        DB_PATH.unlink()
    con = sqlite3.connect(DB_PATH)
    con.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            secret_note TEXT
        );
        """
    )
    rows = [
        (uid, name, generate_password_hash(pw) if hash_passwords else pw, role, note)
        for uid, name, pw, role, note in SEED_USERS
    ]
    con.executemany(
        "INSERT INTO users (id, username, password, role, secret_note) VALUES (?, ?, ?, ?, ?)",
        rows,
    )
    con.commit()
    con.close()


def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con
