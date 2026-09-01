# Vaultline — Secure Login System

A Flask web app for Project 4: **Secure Login System**. Implements user
registration and login with hashed passwords, input validation, session
management, and optional two-factor authentication (2FA).

## Features (mapped to the brief)

| Requirement | Implementation |
|---|---|
| Hashed passwords | `bcrypt`, 12 salt rounds, in `hash_password()` / `verify_password()` |
| Input validation | Regex checks on username/email/password in `register()` |
| SQL injection protection | `sqlite3` with `?` parameterized queries everywhere — no string-built SQL |
| Session management | Flask signed, HTTP-only cookies, 30-minute lifetime |
| Logout | `POST /logout` clears the session |
| Optional 2FA | TOTP via `pyotp`, QR provisioning via `qrcode`, enable/disable from the dashboard |
| Bonus: brute-force protection | Account locks for 15 minutes after 5 failed login attempts |
| Bonus: CSRF protection | Per-session token required on every POST form |

## Project structure

```
secure-login-system/
├── app.py                  # Flask app, routes, DB & security logic
├── requirements.txt
├── instance/
│   └── app.db               # SQLite database (created automatically)
├── static/
│   └── css/style.css        # App styling
└── templates/
    ├── base.html             # Nav, flash messages, footer
    ├── index.html            # Landing page
    ├── register.html
    ├── login.html
    ├── verify_2fa.html       # 2FA code entry at login
    ├── setup_2fa.html        # 2FA enrollment with QR code
    ├── dashboard.html
    └── error.html            # 400 / 404 / 500 pages
```

## Setup

```bash
cd secure-login-system
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Then open **http://127.0.0.1:5000**. The SQLite database is created
automatically on first run at `instance/app.db`.

## Using it

1. **Sign up** at `/register` — username (3–20 chars, letters/numbers/underscore),
   a valid email, and a password with at least 8 characters, one uppercase,
   one lowercase, one digit, and one symbol.
2. **Log in** at `/login`.
3. From the **dashboard**, click **Enable 2FA** to scan a QR code with an
   authenticator app (Google Authenticator, Authy, etc.) and confirm a code.
   From then on, login requires that code as a second step.
4. **Log out** any time from the nav bar or dashboard — this clears the session.

## Security notes

- Passwords are never stored or logged in plain text.
- Login uses a constant-time password check and always hits the hashing
  function (even for unknown usernames) to reduce username-enumeration via timing.
- Every database query uses parameterized placeholders (`?`), so user input
  is never concatenated into SQL.
- Every state-changing form (register, login, 2FA setup, logout) carries a
  per-session CSRF token that's verified on submit.
- Sessions are signed and `HttpOnly`, and expire after 30 minutes.

## Notes for demoing / grading

- To reset all data, stop the app and delete `instance/app.db` — it will be
  recreated empty on the next run.
- `app.run(debug=True)` is for local development only; disable debug mode
  before deploying anywhere public.
