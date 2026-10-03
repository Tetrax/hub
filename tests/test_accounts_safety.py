"""Compléments de recette V1.7 : matrice exhaustive, concurrence et rollback."""
from concurrent.futures import ThreadPoolExecutor
import fcntl
import multiprocessing
import sqlite3
from pathlib import Path

import pytest

from app import auth, config, db, manage
from conftest import ADMIN_PASSWORD, ADMIN_USERNAME, create_catalog_app, login, session_csrf
from test_accounts import (
    MODERATOR_PASSWORD, MODERATOR_USERNAME, OLD_ACCOUNTS_SCHEMA,
    create_moderator, moderator_client, moderator_id,
)


def sensitive_routes(app):
    for rule in app.url_map.iter_rules():
        if (rule.endpoint.startswith(("cert.", "security."))
                or rule.rule.startswith("/admin/accounts")
                or rule.rule == "/admin/settings/preferences"):
            path = rule.rule.replace("<int:user_id>", "1")
            for method in sorted(rule.methods - {"HEAD", "OPTIONS"}):
                yield method, path


def test_complete_sensitive_matrix_and_csrf(app, admin):
    create_moderator(admin, app)
    moderator = moderator_client(app)
    anonymous = app.test_client()
    csrf = session_csrf(moderator, app)
    principal_csrf = session_csrf(admin, app)
    routes = list(sensitive_routes(app))
    assert len(routes) == 18  # ajout d'une route sensible => matrice à réexaminer
    for method, path in routes:
        assert anonymous.open(path, method=method).status_code == 302, (method, path)
        assert moderator.open(path, method=method, data={
            "_csrf": csrf, "role": "admin", "user_id": "1", "account_id": "1",
        }).status_code == 403, (method, path)
        if method == "POST":
            assert admin.post(path).status_code == 403, path
            assert admin.post(path, data={"_csrf": principal_csrf}, headers={
                "Origin": "https://foreign.example",
            }).status_code == 403, path
        else:
            assert admin.get(path).status_code == 200, path
    target = moderator_id(app)
    admin.post(f"/admin/accounts/{target}/deactivate", data={"_csrf": principal_csrf})
    for method, path in routes:
        assert moderator.open(path, method=method, data={"_csrf": csrf}).status_code == 302


def test_session_resolves_live_identity_not_cached_username(app, admin):
    create_moderator(admin, app)
    moderator = moderator_client(app)
    target = moderator_id(app)
    with db.connect(app.config["DB_PATH"]) as connection:
        connection.execute("UPDATE sessions SET username = ? WHERE user_id = ?", (ADMIN_USERNAME, target))
    assert moderator.get("/admin/accounts").status_code == 403
    with db.connect(app.config["DB_PATH"]) as connection:
        # Défense en profondeur : même une session non supprimée ne suffit pas.
        connection.execute("UPDATE admin_users SET is_active = 0 WHERE id = ?", (target,))
    assert moderator.get("/admin/").status_code == 302


def test_self_password_ignores_forged_target(app, admin):
    create_moderator(admin, app)
    moderator = moderator_client(app)
    csrf = session_csrf(moderator, app)
    response = moderator.post("/admin/settings/password", data={
        "_csrf": csrf, "user_id": "1", "account_id": "1", "role": "admin",
        "current_password": MODERATOR_PASSWORD,
        "new_password": "Nouveau-password-modo-123", "confirmation": "Nouveau-password-modo-123",
    })
    assert response.status_code == 302
    with db.connect(app.config["DB_PATH"]) as connection:
        assert auth.verify_admin(connection, ADMIN_USERNAME, ADMIN_PASSWORD)
    assert admin.get("/admin/accounts").status_code == 200


def test_password_and_revocation_are_one_transaction(app, admin):
    create_moderator(admin, app)
    moderator_client(app)
    target = moderator_id(app)
    with db.connect(app.config["DB_PATH"]) as connection:
        auth.update_password(connection, target, "nouveau-password-123")
        assert connection.execute("SELECT COUNT(*) FROM sessions WHERE user_id = ?", (target,)).fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM sessions WHERE user_id = 1").fetchone()[0] == 1


def test_login_serializes_password_check_and_session_creation(app, admin, monkeypatch):
    original = auth.authenticate

    def authenticate(connection, username, password):
        # Un reset/désactivation concurrent ne peut s'intercaler après vérification.
        contender = sqlite3.connect(app.config["DB_PATH"], timeout=0)
        try:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                contender.execute("BEGIN IMMEDIATE")
        finally:
            contender.close()
        return original(connection, username, password)

    monkeypatch.setattr(auth, "authenticate", authenticate)
    assert login(app.test_client(), app).status_code == 302


def test_secret_key_concurrent_initialization(tmp_path, monkeypatch):
    """Deux workers au premier boot doivent signer avec la même clé, sans la rendre."""
    import time
    original_exists = Path.exists
    key_file = tmp_path / ".secret_key"

    def synchronized_exists(path):
        result = original_exists(path)
        if path == key_file and not result:
            time.sleep(0.1)  # élargit la course premier boot sans bloquer un verrou
        return result

    monkeypatch.delenv("HUB_SECRET_KEY", raising=False)
    monkeypatch.setattr(Path, "exists", synchronized_exists)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(config.ensure_secret_key, {"SECRET_KEY_FILE": key_file}) for _ in range(2)]
        values = [future.result(timeout=10) for future in futures]
    same_key = values[0] == values[1]
    assert same_key, "les workers n'utilisent pas la même clé"
    assert key_file.stat().st_mode & 0o777 == 0o600


def _init_worker(path, ready, done):
    ready.set()
    db.init_db(path)
    done.set()


def test_init_waits_for_process_lock(tmp_path):
    path = tmp_path / "hub.sqlite"
    ctx = multiprocessing.get_context("fork")
    ready, done = ctx.Event(), ctx.Event()
    process = ctx.Process(target=_init_worker, args=(path, ready, done))
    with Path(str(path) + ".init.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        process.start()
        assert ready.wait(5)
        assert not done.wait(0.2)
        fcntl.flock(lock, fcntl.LOCK_UN)
    process.join(10)
    assert process.exitcode == 0
    assert done.is_set()
    with db.connect(path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_v3_migration_and_offline_rollback_preserve_data(app, admin, monkeypatch):
    create_catalog_app(app)
    path = Path(app.config["DB_PATH"])
    upload = Path(app.config["UPLOADS_DIR"]) / "fixture.png"
    upload.write_bytes(b"fixture-non-secret")
    with db.connect(path) as connection:
        principal = tuple(connection.execute(
            "SELECT id, username, password_hash, password_changed_at, created_at FROM admin_users"
        ).fetchone())
        connection.execute("UPDATE apps SET image = ?", (upload.name,))
        db.set_setting(connection, "fixture", "preserved")
        connection.execute("INSERT INTO security_state (id, run_id) VALUES (1, 'fixture-run')")
        connection.execute("INSERT INTO security_events (created_at, kind, summary) VALUES ('2026-01-01', 'baseline', 'fixture')")
        connection.commit()
        snapshots = {name: [tuple(row) for row in connection.execute(f"SELECT * FROM {name}")]
                     for name in ("apps", "categories", "settings", "security_state", "security_events")}
        connection.executescript("DROP TABLE sessions; DROP TABLE admin_users;" + OLD_ACCOUNTS_SCHEMA)
        connection.execute("INSERT INTO admin_users VALUES (?, ?, ?, ?, ?)", principal)
        connection.execute("PRAGMA user_version = 3")
    db.init_db(path)
    db.init_db(path)
    with app.app_context(), db.connect(path) as connection:
        assert tuple(connection.execute(
            "SELECT id, username, password_hash, password_changed_at, created_at FROM admin_users"
        ).fetchone()) == principal
        for name, snapshot in snapshots.items():
            assert [tuple(row) for row in connection.execute(f"SELECT * FROM {name}")] == snapshot
        assert upload.read_bytes() == b"fixture-non-secret"
        row, error = auth.create_moderator(connection, MODERATOR_USERNAME, MODERATOR_PASSWORD)
        assert error is None
        token, _ = auth.create_session(connection, row["id"], row["username"])
        # Une ancienne version accepterait cette session sans vérifier le rôle.
        assert connection.execute("SELECT 1 FROM sessions WHERE token_hash = ?", (auth._hash_token(token),)).fetchone()
        # Aucun serveur concurrent : commande d'exploitation sur la copie arrêtée.
        assert manage._invalidate_sessions() == 0
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        # INSERT de session de l'ancienne version : user_id absent/NULL sur base migrée.
        legacy_token = "legacy-token-fixture"
        connection.execute("INSERT INTO sessions (token_hash, username, csrf_token, created_at, last_seen_at, expires_at) "
                           "VALUES (?, ?, 'fixture', '2026-01-01', '2026-01-01', '2999-01-01')",
                           (auth._hash_token(legacy_token), ADMIN_USERNAME))
        assert auth.verify_admin(connection, ADMIN_USERNAME, ADMIN_PASSWORD)
        assert not auth.verify_admin(connection, MODERATOR_USERNAME, MODERATOR_PASSWORD)
    db.init_db(path)  # retour V1.7 : aucun rattachement automatique des sessions NULL
    client = app.test_client()
    client.set_cookie(auth.SESSION_COOKIE, legacy_token)
    assert client.get("/admin/").status_code == 302
    with db.connect(path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_fresh_v4_does_not_accept_legacy_session_insert(app):
    with db.connect(app.config["DB_PATH"]) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="NOT NULL"):
            connection.execute("INSERT INTO sessions (token_hash, username, csrf_token, created_at, last_seen_at, expires_at) "
                               "VALUES ('fixture', 'admin', 'fixture', '2026-01-01', '2026-01-01', '2999-01-01')")
