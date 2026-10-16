"""Notes: bilerek zafiyetli bir not uygulaması ve güvenli hali.

Aynı kod tabanı iki modda çalışır:
  vulnerable  açıklar açık
  secure      her açık düzeltilmiş
Her açığın iki hali routes.py içinde yan yana durur.

Yalnızca localhost'ta çalıştırın; asla internete açmayın.
"""
import os
import secrets
from pathlib import Path

from flask import Flask

from . import db, routes, security

MODES = ("vulnerable", "secure")


def create_app(mode="secure", db_path=None):
    if mode not in MODES:
        raise ValueError(f"mode {MODES} içinden biri olmalı")
    vulnerable = mode == "vulnerable"

    app = Flask(__name__)
    app.config.update(
        MODE=mode,
        VULNERABLE=vulnerable,
        DB_PATH=str(db_path or Path(app.instance_path) / f"notes-{mode}.db"),
    )

    # Açık 6: gizli anahtar koda yazılmış (zafiyetli) / ortamdan ya da rastgele (güvenli)
    if vulnerable:
        app.secret_key = "dev-secret-key"
    else:
        app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    Path(app.config["DB_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    db.init_db(app.config["DB_PATH"], hash_passwords=not vulnerable)

    app.extensions["login_limiter"] = security.LoginLimiter()
    app.teardown_appcontext(db.close_db)
    app.before_request(security.check_csrf)
    app.jinja_env.globals["csrf_token"] = security.csrf_token
    app.register_blueprint(routes.bp)
    return app
