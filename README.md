# web-guvenlik-lab

[![tests](https://github.com/yusufiyilmaz/web-guvenlik-lab/actions/workflows/tests.yml/badge.svg)](https://github.com/yusufiyilmaz/web-guvenlik-lab/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3-black)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-red)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**English** | [Türkçe](README.tr.md)

**Notes** is a small, realistic note-taking web app, built twice from one codebase:
a **vulnerable** version with seven common web flaws, and a **secure** version where
every flaw is fixed. For each issue the repo shows **where** it is, **how** it is
exploited, and **how** it is fixed — with a test proving both the exploit and the fix.

![The notes app, secure mode](docs/screenshots/02-notes.png)

> ⚠️ **Security notice**
> This app is intentionally insecure in vulnerable mode and runs **on localhost only** (`127.0.0.1`).
> Never deploy it or expose it to a network. All users and data are fake.

## Contents

- [How it works](#how-it-works)
- [Run it](#run-it)
- [The seven vulnerabilities](#the-seven-vulnerabilities)
- [Testing](#testing)
- [Project structure](#project-structure)
- [License](#license)

## How it works

The same application factory builds the app in one of two modes. Every place that
contains a flaw has two branches next to each other, so the vulnerable and the secure
behaviour live side by side and are easy to compare:

```python
if vuln():
    # VULNERABLE — the flaw itself
    user = db.execute(f"SELECT * FROM users WHERE username = '{username}' ...")
else:
    # SECURE — the fix
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,))
```

| | Vulnerable mode | Secure mode |
|---|---|---|
| Start | `python run.py --mode vulnerable` | `python run.py --mode secure` |
| URL | http://127.0.0.1:5000 | http://127.0.0.1:5001 |
| Banner | 🔴 red | 🟢 green |

The red/green banner at the top of every page always shows which mode you are in.

## Run it

```bash
pip install -r requirements.txt
python run.py --mode secure       # http://127.0.0.1:5001
```

Sign in with a demo account such as `yusuf` / `parola1`. The database is reset with
fake data on every start.

|  |  |
|---|---|
| ![Sign in](docs/screenshots/01-login.png) | ![Reflected XSS running in vulnerable mode](docs/screenshots/03-xss-vulnerable.png) |
| Sign in page | Reflected XSS: in vulnerable mode the search term `<b>INJECTED</b>` is rendered as HTML, not text |

## The seven vulnerabilities

| # | Vulnerability | OWASP 2021 | Fix |
|---|---|---|---|
| 1 | SQL Injection (login & search) | A03 Injection | Parameterized queries |
| 2 | XSS — reflected (search) & stored (note body) | A03 Injection | Output escaping (autoescape, no `\|safe`) |
| 3 | IDOR (reading another user's note) | A01 Broken Access Control | Ownership check, `404` on miss |
| 4 | CSRF (note create/delete) | A01 Broken Access Control | Per-session CSRF token on every POST |
| 5 | Plaintext passwords | A02 Cryptographic Failures | Salted password hashing |
| 6 | Hardcoded secret key | A05 Security Misconfiguration | Key from env var, else random per start |
| 7 | No login rate limiting | A07 Auth Failures | 5 failures / 10 min per IP → `429` |

Each fix follows the same principles: **treat input as data, not code**, and
**check authorization on every request**.

### A note on the CSRF fix

The first version of the CSRF check compared the sent token with the stored one
directly. When no token existed yet, "empty == empty" matched and let the request
through. The tests caught this, and the check now also rejects an empty token — a
small reminder of why tests matter.

## Testing

```bash
python -m unittest -v
```

20 tests, one pair per flaw: each proves the exploit **works in vulnerable mode** and
is **blocked in secure mode** without breaking normal use (valid login, a user reading
their own note, admin reading any note, token-protected forms succeeding).

[GitHub Actions](.github/workflows/tests.yml) runs them on Python 3.10, 3.12 and 3.13
on every push.

## Project structure

```text
notes_app/
  __init__.py        Application factory (vulnerable / secure mode)
  routes.py          Pages; each flaw's two branches side by side
  db.py              SQLite schema + fake seed data
  security.py        CSRF token and login rate limiter (secure mode)
  templates/         Jinja2 templates
  static/style.css   Styling
run.py               Launcher (--mode vulnerable | secure)
tests/               Exploit-and-fix tests
scripts/             Screenshot generator
```

## Disclaimer

These techniques are for this lab and other authorized environments only. Using them
against systems you do not own or have permission to test is illegal.

## License

[MIT](LICENSE)
