"""Authentification de l'administration : scrypt, sessions serveur, CSRF, verrouillage.

Aucun mot de passe par défaut : le compte est créé par l'administrateur lui-même
lors de la « première configuration ». Les sessions sont persistées en SQLite
(seul le SHA-256 du jeton est stocké) : logout et changement de mot de passe les
invalident réellement.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import timedelta
from functools import wraps

from flask import current_app, g, redirect, request, url_for

from . import db

SESSION_COOKIE = "hub_session"
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
PASSWORD_MIN_BYTES = 12
PASSWORD_MAX_BYTES = 1024
LOCK_THRESHOLD = 5
LOCK_SECONDS = 15 * 60


# --- Mots de passe -----------------------------------------------------------


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=32,
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(stored: str, password: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(digest_hex)),
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def validate_password(password: str) -> tuple[bool, str | None]:
    if not isinstance(password, str) or not password:
        return False, "Le mot de passe est obligatoire."
    size = len(password.encode("utf-8"))
    if size < PASSWORD_MIN_BYTES:
        return False, f"Le mot de passe doit contenir au moins {PASSWORD_MIN_BYTES} octets."
    if size > PASSWORD_MAX_BYTES:
        return False, f"Le mot de passe ne doit pas dépasser {PASSWORD_MAX_BYTES} octets."
    return True, None


# --- Compte administrateur ---------------------------------------------------


def has_admin(connection) -> bool:
    return connection.execute("SELECT 1 FROM admin_users WHERE id = 1").fetchone() is not None


def admin_username(connection) -> str | None:
    row = connection.execute("SELECT username FROM admin_users WHERE id = 1").fetchone()
    return row["username"] if row else None


def create_admin(connection, username: str, password: str) -> bool:
    """Crée le compte unique. Retourne False s'il existe déjà (course sérialisée par contrainte)."""
    now = db.now_iso()
    try:
        connection.execute(
            "INSERT INTO admin_users (id, username, password_hash, password_changed_at, created_at) "
            "VALUES (1, ?, ?, ?, ?)",
            (username, hash_password(password), now, now),
        )
        connection.commit()
        return True
    except Exception:  # sqlite3.IntegrityError si un compte existe déjà
        connection.rollback()
        return False


def verify_admin(connection, username: str, password: str) -> bool:
    row = connection.execute(
        "SELECT username, password_hash FROM admin_users WHERE id = 1"
    ).fetchone()
    if row is None:
        return False
    if not hmac.compare_digest(row["username"], username):
        return False
    return verify_password(row["password_hash"], password)


def update_password(connection, password: str) -> None:
    connection.execute(
        "UPDATE admin_users SET password_hash = ?, password_changed_at = ? WHERE id = 1",
        (hash_password(password), db.now_iso()),
    )
    connection.commit()


# --- Sessions ----------------------------------------------------------------


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def create_session(connection, username: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = db.utc_now()
    ttl = int(current_app.config["SESSION_TTL_SECONDS"])
    connection.execute(
        "INSERT INTO sessions (token_hash, username, csrf_token, created_at, last_seen_at, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            _hash_token(token),
            username,
            csrf,
            now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            (now + timedelta(seconds=ttl)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
    )
    connection.commit()
    return token, csrf


def destroy_session(connection, token: str) -> None:
    connection.execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),))
    connection.commit()


def destroy_all_sessions(connection) -> None:
    connection.execute("DELETE FROM sessions")
    connection.commit()


def purge_expired_sessions(connection) -> None:
    connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (db.now_iso(),))
    connection.commit()


def _request_token() -> str | None:
    return request.cookies.get(SESSION_COOKIE)


def load_session() -> dict | None:
    """Session courante (mise en cache par requête) ou None."""
    if "session_row" in g:
        return g.session_row
    g.session_row = None
    token = _request_token()
    if not token:
        return None
    connection = db_connection()
    row = connection.execute(
        "SELECT token_hash, username, csrf_token, expires_at FROM sessions WHERE token_hash = ?",
        (_hash_token(token),),
    ).fetchone()
    if row is None:
        return None
    if row["expires_at"] <= db.now_iso():
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
        connection.commit()
        return None
    connection.execute(
        "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
        (db.now_iso(), row["token_hash"]),
    )
    connection.commit()
    g.session_row = {
        "token_hash": row["token_hash"],
        "username": row["username"],
        "csrf_token": row["csrf_token"],
        "token": token,
    }
    return g.session_row


def set_session_cookie(response, token: str):
    ttl = int(current_app.config["SESSION_TTL_SECONDS"])
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=ttl,
        httponly=True,
        secure=bool(request.is_secure or _behind_https()),
        samesite="Strict",
        path="/",
    )
    return response


def _behind_https() -> bool:
    from .security import is_https

    trusted = current_app.extensions.get("hub_trusted_proxies", [])
    return is_https(request, trusted)


def clear_session_cookie(response):
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# --- Limitation des tentatives ----------------------------------------------


def _attempt_key(scope: str, value: str) -> str:
    return f"{scope}:{value}"


def lock_remaining(connection, username: str, ip: str) -> int:
    now = db.now_iso()
    remaining = 0
    for key in (_attempt_key("user", username.lower()), _attempt_key("ip", ip)):
        row = connection.execute(
            "SELECT locked_until FROM login_attempts WHERE key = ?", (key,)
        ).fetchone()
        if row and row["locked_until"] and row["locked_until"] > now:
            delta = db.parse_iso(row["locked_until"]) - db.parse_iso(now)
            remaining = max(remaining, int(delta.total_seconds()))
    return remaining


def register_failure(connection, username: str, ip: str) -> None:
    now = db.utc_now()
    now_s = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    for key in (_attempt_key("user", username.lower()), _attempt_key("ip", ip)):
        row = connection.execute(
            "SELECT failures, first_at FROM login_attempts WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            connection.execute(
                "INSERT INTO login_attempts (key, failures, first_at, last_at, locked_until) "
                "VALUES (?, 1, ?, ?, NULL)",
                (key, now_s, now_s),
            )
            continue
        failures = row["failures"] + 1
        locked_until = None
        if failures >= LOCK_THRESHOLD:
            locked_until = (now + timedelta(seconds=LOCK_SECONDS)).strftime("%Y-%m-%dT%H:%M:%SZ")
            failures = 0 if locked_until else failures
        connection.execute(
            "UPDATE login_attempts SET failures = ?, last_at = ?, locked_until = ? WHERE key = ?",
            (failures, now_s, locked_until, key),
        )
    connection.commit()


def clear_failures(connection, username: str, ip: str) -> None:
    connection.execute(
        "DELETE FROM login_attempts WHERE key IN (?, ?)",
        (_attempt_key("user", username.lower()), _attempt_key("ip", ip)),
    )
    connection.commit()


# --- Helpers de requête ------------------------------------------------------


def db_connection():
    from flask import current_app as app

    if "hub_db" not in g:
        g.hub_db = db.connect(app.config["DB_PATH"])
    return g.hub_db


def close_db(_exception=None) -> None:
    connection = g.pop("hub_db", None)
    if connection is not None:
        connection.close()


def csrf_ok(session: dict, submitted: str | None) -> bool:
    return bool(
        session
        and isinstance(submitted, str)
        and hmac.compare_digest(session["csrf_token"], submitted)
    )


def require_session() -> dict:
    """Session administrateur garantie (à utiliser après admin_required)."""
    session_row = load_session()
    if session_row is None:  # défensif : ne doit pas arriver après admin_required
        from flask import abort

        abort(401)
    return session_row


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        session = load_session()
        if session is None:
            return redirect(url_for("admin.login"))
        return view(*args, **kwargs)

    return wrapped
