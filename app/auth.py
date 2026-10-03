"""Authentification de l'administration : scrypt, sessions serveur, CSRF, verrouillage.

Deux rôles fixes (V1.7) :
- **admin** : le compte principal (id = 1), unique, non supprimable, non
  désactivable ; il gère tout, y compris les certificats, la sécurité et les
  comptes modérateurs ;
- **moderator** : comptes nominatifs créés par le principal, limités au
  catalogue (applications, captures, catégories, ordre, visibilité) et à leur
  propre mot de passe.

Aucun mot de passe par défaut : le compte principal est créé par
l'administrateur lui-même lors de la « première configuration ». Les sessions
sont persistées en SQLite (seul le SHA-256 du jeton est stocké) et liées à
l'identité (`user_id`) : désactivation, suppression, réinitialisation ou
changement de mot de passe les invalident réellement ; le rôle et l'état du
compte sont revérifiés côté serveur à chaque requête.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import timedelta
from functools import wraps

from flask import abort, current_app, g, redirect, request, url_for

from . import db

SESSION_COOKIE = "hub_session"
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
PASSWORD_MIN_BYTES = 12
PASSWORD_MAX_BYTES = 1024
USERNAME_MIN = 3
USERNAME_MAX = 64
LOCK_THRESHOLD = 5
LOCK_SECONDS = 15 * 60

ROLE_ADMIN = "admin"
ROLE_MODERATOR = "moderator"
ROLES = (ROLE_ADMIN, ROLE_MODERATOR)

# Hash factice (jamais un secret, jamais accepté) : péréquation de temps quand
# l'identifiant est inconnu ou le compte désactivé, pour ne pas révéler
# l'existence d'un compte par le temps de réponse.
_DUMMY_PASSWORD_HASH = "scrypt$16384$8$1$" + "00" * 16 + "$" + "00" * 32


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


# --- Comptes ------------------------------------------------------------------


USERNAME_ERROR = f"Identifiant invalide ({USERNAME_MIN} à {USERNAME_MAX} caractères)."


def validate_username(username) -> tuple[bool, str | None]:
    """Identifiant de compte : borné, sans espace ni caractère de contrôle."""
    if not isinstance(username, str):
        return False, USERNAME_ERROR
    value = username.strip()
    if not (USERNAME_MIN <= len(value) <= USERNAME_MAX):
        return False, USERNAME_ERROR
    if any(character.isspace() or not character.isprintable() for character in value):
        return False, USERNAME_ERROR
    return True, None


def has_admin(connection) -> bool:
    return connection.execute("SELECT 1 FROM admin_users WHERE id = 1").fetchone() is not None


def admin_username(connection) -> str | None:
    row = connection.execute("SELECT username FROM admin_users WHERE id = 1").fetchone()
    return row["username"] if row else None


def create_admin(connection, username: str, password: str) -> bool:
    """Crée le compte principal unique. False s'il existe déjà (course sérialisée)."""
    now = db.now_iso()
    try:
        connection.execute(
            "INSERT INTO admin_users (id, username, password_hash, role, is_active, "
            "password_changed_at, created_at) VALUES (1, ?, ?, ?, 1, ?, ?)",
            (username, hash_password(password), ROLE_ADMIN, now, now),
        )
        connection.commit()
        return True
    except sqlite3.IntegrityError:  # un compte existe déjà (id = 1 ou identifiant pris)
        connection.rollback()
        return False


def verify_admin(connection, username: str, password: str) -> bool:
    """Authentifie strictement le compte principal (compatibilité CLI)."""
    row = connection.execute(
        "SELECT username, password_hash FROM admin_users WHERE id = 1"
    ).fetchone()
    if row is None:
        return False
    if not hmac.compare_digest(row["username"], username):
        return False
    return verify_password(row["password_hash"], password)


def authenticate(connection, username: str, password: str) -> dict | None:
    """Résout un identifiant + mot de passe, comptes actifs uniquement.

    Retourne `{id, username, role}` (jamais le hash) ou None. Un compte inexistant
    ou désactivé suit le même chemin coûteux qu'un mot de passe erroné.
    """
    row = connection.execute(
        "SELECT id, username, role, is_active, password_hash FROM admin_users "
        "WHERE username = ? COLLATE NOCASE",
        (username,),
    ).fetchone()
    if row is None or not row["is_active"]:
        verify_password(_DUMMY_PASSWORD_HASH, password)
        return None
    if not verify_password(row["password_hash"], password):
        return None
    return {"id": int(row["id"]), "username": row["username"], "role": row["role"]}


def get_account(connection, user_id: int):
    """Compte par identifiant (colonnes publiques, jamais le hash)."""
    return connection.execute(
        "SELECT id, username, role, is_active, password_changed_at, created_at "
        "FROM admin_users WHERE id = ?",
        (user_id,),
    ).fetchone()


def list_accounts(connection):
    return connection.execute(
        "SELECT id, username, role, is_active, password_changed_at, created_at "
        "FROM admin_users ORDER BY id ASC"
    ).fetchall()


def create_moderator(connection, username: str, password: str):
    """Crée un compte modérateur. Retourne (compte, None) ou (None, erreur).

    Le rôle n'est jamais lu d'un formulaire : un second compte principal ne peut
    pas exister.
    """
    now = db.now_iso()
    try:
        cursor = connection.execute(
            "INSERT INTO admin_users (username, password_hash, role, is_active, "
            "password_changed_at, created_at) VALUES (?, ?, ?, 1, ?, ?)",
            (username, hash_password(password), ROLE_MODERATOR, now, now),
        )
        connection.commit()
    except sqlite3.IntegrityError:
        connection.rollback()
        return None, "Cet identifiant est déjà utilisé."
    return get_account(connection, int(cursor.lastrowid or 0)), None


def set_account_active(connection, user_id: int, active: bool) -> None:
    """Active/désactive un compte ; la désactivation révoque ses sessions."""
    connection.execute(
        "UPDATE admin_users SET is_active = ? WHERE id = ?", (1 if active else 0, user_id)
    )
    if not active:
        connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    connection.commit()


def delete_account(connection, user_id: int) -> None:
    """Supprime un compte et ses sessions ; l'identifiant libéré ne ressuscite rien."""
    connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    connection.execute("DELETE FROM admin_users WHERE id = ?", (user_id,))
    connection.commit()


def update_password(connection, user_id: int, password: str) -> None:
    connection.execute(
        "UPDATE admin_users SET password_hash = ?, password_changed_at = ? WHERE id = ?",
        (hash_password(password), db.now_iso(), user_id),
    )
    # Changement et révocation atomiques : aucun lecteur ne voit le nouveau
    # mot de passe avec les anciennes sessions encore valides.
    connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    connection.commit()


def verify_user_password(connection, user_id: int, password: str) -> bool:
    row = connection.execute(
        "SELECT password_hash FROM admin_users WHERE id = ?", (user_id,)
    ).fetchone()
    return row is not None and verify_password(row["password_hash"], password)


def is_principal(session_row: dict | None) -> bool:
    return bool(session_row) and session_row.get("role") == ROLE_ADMIN


# --- Sessions ----------------------------------------------------------------


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def create_session(connection, user_id: int, username: str) -> tuple[str, str]:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = db.utc_now()
    ttl = int(current_app.config["SESSION_TTL_SECONDS"])
    connection.execute(
        "INSERT INTO sessions (token_hash, user_id, username, csrf_token, created_at, "
        "last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            _hash_token(token),
            user_id,
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


def destroy_user_sessions(connection, user_id: int) -> None:
    connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
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
    """Session courante (mise en cache par requête) ou None.

    Le compte est résolu à chaque requête : compte supprimé, désactivé ou
    session orpheline ⇒ session purgée et refusée. Le rôle vient de la base,
    jamais du cookie.
    """
    if "session_row" in g:
        return g.session_row
    g.session_row = None
    token = _request_token()
    if not token:
        return None
    connection = db_connection()
    row = connection.execute(
        "SELECT s.token_hash, s.user_id, s.csrf_token, s.expires_at, "
        "u.username AS account_username, u.role, u.is_active "
        "FROM sessions s LEFT JOIN admin_users u ON u.id = s.user_id "
        "WHERE s.token_hash = ?",
        (_hash_token(token),),
    ).fetchone()
    if row is None:
        return None
    if row["expires_at"] <= db.now_iso():
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
        connection.commit()
        return None
    if row["user_id"] is None or row["account_username"] is None or not row["is_active"]:
        # compte supprimé ou désactivé : la session ne survit pas
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
        "user_id": int(row["user_id"]),
        "username": row["account_username"],
        "role": row["role"],
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
    """Session active garantie (à utiliser après admin_required / principal_required)."""
    session_row = load_session()
    if session_row is None:  # défensif : ne doit pas arriver après le décorateur
        abort(401)
    return session_row


def admin_required(view):
    """Toute session active (principal ou modérateur)."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        session = load_session()
        if session is None:
            return redirect(url_for("admin.login"))
        return view(*args, **kwargs)

    return wrapped


def principal_required(view):
    """Réservé à l'administrateur principal (config sensible, comptes).

    Refus serveur (403) même sur URL directe ou POST forgé par un modérateur.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        session = load_session()
        if session is None:
            return redirect(url_for("admin.login"))
        if not is_principal(session):
            abort(403)
        return view(*args, **kwargs)

    return wrapped
