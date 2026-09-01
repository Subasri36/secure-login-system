"""
Secure Login System
--------------------
A Flask web application implementing:
  - User registration & login with bcrypt-hashed passwords
  - Input validation & parameterized SQL (no SQL injection)
  - Session-based auth with logout
  - Optional Two-Factor Authentication (TOTP, e.g. Google Authenticator)
  - Basic brute-force protection (account lockout after repeated failures)
  - CSRF protection on all state-changing forms

Run with:  python app.py
Then open: http://127.0.0.1:5000
"""

import os
import re
import io
import base64
import sqlite3
import secrets
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
import pyotp
import qrcode
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, g, abort
)

# --------------------------------------------------------------------------- #
# App configuration
# --------------------------------------------------------------------------- #

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "app.db")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,      # JS can't read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",     # basic CSRF/mitigation for cookies
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# At least 8 chars, 1 upper, 1 lower, 1 digit, 1 special character
PASSWORD_RE = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$"
)


# --------------------------------------------------------------------------- #
# Database helpers  (sqlite3 + parameterized queries => no SQL injection)
# --------------------------------------------------------------------------- #

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT UNIQUE NOT NULL,
            email           TEXT UNIQUE NOT NULL,
            password_hash   TEXT NOT NULL,
            totp_secret     TEXT,
            totp_enabled    INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until    TEXT,
            created_at      TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------- #
# CSRF protection (lightweight, dependency-free)
# --------------------------------------------------------------------------- #

def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.context_processor
def inject_csrf():
    return {"csrf_token": get_csrf_token}


def csrf_protect():
    if request.method == "POST":
        form_token = request.form.get("csrf_token", "")
        session_token = session.get("csrf_token", "")
        if not form_token or not secrets.compare_digest(form_token, session_token):
            abort(400, description="Invalid or missing CSRF token.")


@app.before_request
def before_request():
    csrf_protect()


# --------------------------------------------------------------------------- #
# Auth helpers
# --------------------------------------------------------------------------- #

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


def get_user_by_username(username: str):
    db = get_db()
    return db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()


def get_user_by_id(user_id: int):
    db = get_db()
    return db.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def is_locked(user) -> bool:
    if not user["locked_until"]:
        return False
    return datetime.utcnow() < datetime.fromisoformat(user["locked_until"])


def register_failed_attempt(user):
    db = get_db()
    attempts = user["failed_attempts"] + 1
    locked_until = None
    if attempts >= MAX_LOGIN_ATTEMPTS:
        locked_until = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    db.execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
        (attempts, locked_until, user["id"]),
    )
    db.commit()
    return attempts, locked_until


def clear_failed_attempts(user_id):
    db = get_db()
    db.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (user_id,),
    )
    db.commit()


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        errors = []
        if not USERNAME_RE.match(username):
            errors.append("Username must be 3-20 characters: letters, numbers, underscores only.")
        if not EMAIL_RE.match(email):
            errors.append("Please enter a valid email address.")
        if not PASSWORD_RE.match(password):
            errors.append(
                "Password needs at least 8 characters, including an uppercase letter, "
                "a lowercase letter, a number, and a special character."
            )
        if password != confirm:
            errors.append("Passwords do not match.")

        db = get_db()
        if not errors:
            existing = db.execute(
                "SELECT id FROM users WHERE username = ? OR email = ?",
                (username, email),
            ).fetchone()
            if existing:
                errors.append("That username or email is already registered.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("register.html", username=username, email=email)

        db.execute(
            "INSERT INTO users (username, email, password_hash, created_at) "
            "VALUES (?, ?, ?, ?)",
            (username, email, hash_password(password), datetime.utcnow().isoformat()),
        )
        db.commit()
        flash("Account created. You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html", username="", email="")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_user_by_username(username)

        # Always compare against a dummy hash when the user doesn't exist,
        # so response timing doesn't reveal whether the account is real.
        dummy_hash = "$2b$12$CkK2f8ZM0nQeYVh3z0e6XeQpV1yQKZ0z0lF8yqTz3H6b0m9V0s7Wa"
        candidate_hash = user["password_hash"] if user else dummy_hash
        password_ok = verify_password(password, candidate_hash)

        if user and is_locked(user):
            unlock_time = datetime.fromisoformat(user["locked_until"]).strftime("%H:%M UTC")
            flash(f"Account temporarily locked due to failed attempts. Try again after {unlock_time}.", "error")
            return render_template("login.html", username=username)

        if not user or not password_ok:
            if user:
                attempts, locked_until = register_failed_attempt(user)
                if locked_until:
                    flash("Too many failed attempts. Account locked for 15 minutes.", "error")
                else:
                    remaining = MAX_LOGIN_ATTEMPTS - attempts
                    flash(f"Invalid username or password. {remaining} attempt(s) left before lockout.", "error")
            else:
                flash("Invalid username or password.", "error")
            return render_template("login.html", username=username)

        # Credentials correct
        clear_failed_attempts(user["id"])

        if user["totp_enabled"]:
            session["pending_user_id"] = user["id"]
            return redirect(url_for("verify_2fa"))

        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        flash(f"Welcome back, {user['username']}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html", username="")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    pending_id = session.get("pending_user_id")
    if not pending_id:
        return redirect(url_for("login"))
    user = get_user_by_id(pending_id)
    if not user:
        session.pop("pending_user_id", None)
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        totp = pyotp.TOTP(user["totp_secret"])
        if totp.verify(code, valid_window=1):
            session.clear()
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid authentication code. Please try again.", "error")

    return render_template("verify_2fa.html", username=user["username"])


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_user_by_id(session["user_id"])
    return render_template("dashboard.html", user=user)


@app.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = get_user_by_id(session["user_id"])
    db = get_db()

    if user["totp_enabled"]:
        flash("Two-factor authentication is already enabled.", "success")
        return redirect(url_for("dashboard"))

    if "setup_secret" not in session:
        session["setup_secret"] = pyotp.random_base32()

    secret = session["setup_secret"]
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user["username"], issuer_name="Secure Login System")

    qr_img = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    qr_img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        if totp.verify(code, valid_window=1):
            db.execute(
                "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
                (secret, user["id"]),
            )
            db.commit()
            session.pop("setup_secret", None)
            flash("Two-factor authentication is now enabled.", "success")
            return redirect(url_for("dashboard"))
        flash("That code didn't match. Scan the QR code again and try once more.", "error")

    return render_template(
        "setup_2fa.html", qr_b64=qr_b64, secret=secret, username=user["username"]
    )


@app.route("/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    db = get_db()
    db.execute(
        "UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?",
        (session["user_id"],),
    )
    db.commit()
    flash("Two-factor authentication has been disabled.", "success")
    return redirect(url_for("dashboard"))


# --------------------------------------------------------------------------- #
# Error handlers
# --------------------------------------------------------------------------- #

@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, message="Bad request. Please try again."), 400


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="That page doesn't exist."), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Something went wrong on our end."), 500


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
else:
    init_db()
