"""Lab için küçük bir SQLite veritabanı. Veriler tamamen sahtedir."""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "lab.db"

# Sahte kullanıcılar (parolalar yalnızca lab içindir, gerçek değildir)
SEED_USERS = [
    # id, kullanıcı adı, parola, rol, özel not
    (1, "admin", "admin123", "admin", "Sunucu yedek anahtarı: LAB-FAKE-0001"),
    (2, "yusuf", "parola1", "user", "Kredi kartı son 4 hane: 4242 (sahte)"),
    (3, "ayse", "deneme5", "user", "Ev adresi: Örnek Mah. (sahte)"),
]


def init_db():
    """Veritabanını sıfırdan oluşturur ve sahte verilerle doldurur."""
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
    con.executemany(
        "INSERT INTO users (id, username, password, role, secret_note) VALUES (?, ?, ?, ?, ?)",
        SEED_USERS,
    )
    con.commit()
    con.close()


def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


if __name__ == "__main__":
    init_db()
    print(f"Veritabanı oluşturuldu: {DB_PATH}")
