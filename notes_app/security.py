"""Güvenli modda kullanılan korumalar: CSRF token ve giriş deneme sınırı."""
import secrets
import time
from collections import defaultdict, deque

from flask import abort, current_app, request, session

MAX_FAILED_LOGINS = 5
LOCKOUT_WINDOW = 10 * 60  # saniye


# --- CSRF ---
def csrf_token():
    """Şablonlardaki formlara eklenen token. Zafiyetli modda boş döner."""
    if current_app.config["VULNERABLE"]:
        return ""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def check_csrf():
    """Güvenli modda her POST isteğinin geçerli bir token taşımasını şart koşar."""
    if current_app.config["VULNERABLE"] or request.method != "POST":
        return
    sent = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    # Token eksikse de reddet: boş == boş eşleşmesi korumayı delik bırakır
    if not sent or not expected or not secrets.compare_digest(sent, expected):
        abort(400)


# --- Giriş deneme sınırı ---
class LoginLimiter:
    """IP başına, kayan pencere içindeki başarısız girişleri sayar.

    Bellekte tutulur ve tek süreç içindir; gerçek bir uygulamada Redis gibi
    paylaşılan bir depoya taşınmalıdır.
    """

    def __init__(self, limit=MAX_FAILED_LOGINS, window=LOCKOUT_WINDOW):
        self.limit, self.window = limit, window
        self.failures = defaultdict(deque)

    def _prune(self, ip):
        q, now = self.failures[ip], time.monotonic()
        while q and q[0] < now - self.window:
            q.popleft()
        return q

    def is_locked(self, ip):
        return len(self._prune(ip)) >= self.limit

    def record_failure(self, ip):
        self._prune(ip).append(time.monotonic())

    def reset(self, ip):
        self.failures.pop(ip, None)
