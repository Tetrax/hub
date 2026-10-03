"""Comptes modérateurs (V1.7) : rôles, permissions serveur, gestion, révocation.

Matrice d'accès : anonyme → redirection ; modérateur → catalogue seulement ;
administrateur principal → tout ; compte désactivé/supprimé → session révoquée.
La migration v3 → v4 doit préserver le compte principal, son hash et les
sessions existantes (seul le compte principal existait avant V1.7).
"""

from __future__ import annotations

import sqlite3

from conftest import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    login,
    session_csrf,
    setup_admin,
)

MODERATOR_USERNAME = "moderateur"
MODERATOR_PASSWORD = "motdepasse-modo-123"
NEW_MODERATOR_PASSWORD = "nouveau-modo-456"


# --- Aides --------------------------------------------------------------------


def _db(app):
    return sqlite3.connect(app.config["DB_PATH"])


def _row(app, sql: str, params=()):
    connection = _db(app)
    try:
        return connection.execute(sql, params).fetchone()
    finally:
        connection.close()


def _count(app, sql: str, params=()) -> int:
    row = _row(app, sql, params)
    return int(row[0]) if row else 0


def moderator_id(app, username: str = MODERATOR_USERNAME) -> int:
    row = _row(app, "SELECT id FROM admin_users WHERE username = ?", (username,))
    assert row is not None, "compte modérateur absent"
    return int(row[0])


def create_moderator(
    admin_client,
    app,
    username: str = MODERATOR_USERNAME,
    password: str = MODERATOR_PASSWORD,
    confirmation: str | None = None,
    **extra,
):
    csrf = session_csrf(admin_client, app)
    data = {
        "_csrf": csrf,
        "username": username,
        "password": password,
        "confirmation": password if confirmation is None else confirmation,
    }
    data.update(extra)
    return admin_client.post("/admin/accounts/create", data=data, follow_redirects=False)


def moderator_client(app, username: str = MODERATOR_USERNAME, password: str = MODERATOR_PASSWORD):
    client = app.test_client()
    response = login(client, app, username=username, password=password)
    assert response.status_code == 302, f"connexion modérateur refusée ({response.status_code})"
    return client


# --- Migration v3 → v4 --------------------------------------------------------

OLD_ACCOUNTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS admin_users (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    password_changed_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
"""


def test_migration_v3_to_v4_preserves_admin_identity_and_sessions(tmp_path):
    from app import auth as auth_module
    from app import db as db_module

    path = tmp_path / "hub.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(OLD_ACCOUNTS_SCHEMA)
    now = "2026-01-01T00:00:00Z"
    connection.execute(
        "INSERT INTO admin_users VALUES (1, ?, ?, ?, ?)",
        (ADMIN_USERNAME, auth_module.hash_password(ADMIN_PASSWORD), now, now),
    )
    connection.execute(
        "INSERT INTO sessions VALUES ('jeton-hash', ?, 'csrf-v3', ?, ?, ?)",
        (ADMIN_USERNAME, now, now, "2999-01-01T00:00:00Z"),
    )
    connection.commit()
    connection.close()

    db_module.init_db(path)
    db_module.init_db(path)  # idempotente : une seconde exécution ne casse rien

    connection = db_module.connect(path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == db_module.SCHEMA_VERSION
        assert db_module.SCHEMA_VERSION == 4
        rows = connection.execute(
            "SELECT id, username, role, is_active, password_hash FROM admin_users"
        ).fetchall()
        assert len(rows) == 1
        row = rows[0]
        assert row["id"] == 1
        assert row["username"] == ADMIN_USERNAME
        assert row["role"] == "admin"
        assert row["is_active"] == 1
        assert auth_module.verify_password(row["password_hash"], ADMIN_PASSWORD)
        session = connection.execute(
            "SELECT user_id, username FROM sessions WHERE token_hash = 'jeton-hash'"
        ).fetchone()
        assert session is not None
        assert session["user_id"] == 1
        assert session["username"] == ADMIN_USERNAME
    finally:
        connection.close()


def test_migration_keeps_catalog_and_accounts_on_repeated_init(app, admin):
    """Une base déjà en v4 (compte, modérateur, catalogue) survit à init_db répété."""
    from app import db as db_module

    create_moderator(admin, app)
    connection = _db(app)
    connection.execute(
        "INSERT INTO categories (name, slug, position, is_fallback, created_at, updated_at) "
        "VALUES ('Survie', 'survie', 10, 0, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
    )
    connection.commit()
    connection.close()

    db_module.init_db(app.config["DB_PATH"])
    db_module.init_db(app.config["DB_PATH"])

    assert _count(app, "SELECT COUNT(*) FROM admin_users") == 2
    assert _count(app, "SELECT COUNT(*) FROM admin_users WHERE role = 'moderator'") == 1
    assert _count(app, "SELECT COUNT(*) FROM categories WHERE slug = 'survie'") == 1


# --- Création et validation ---------------------------------------------------


def test_admin_creates_moderator_with_scrypt_password(app, admin):
    response = create_moderator(admin, app)
    assert response.status_code == 302
    row = _row(
        app,
        "SELECT id, username, role, is_active, password_hash FROM admin_users "
        "WHERE username = ?",
        (MODERATOR_USERNAME,),
    )
    assert row is not None
    assert int(row[0]) != 1
    assert row[1] == MODERATOR_USERNAME
    assert row[2] == "moderator"
    assert row[3] == 1
    assert row[4].startswith("scrypt$")
    assert MODERATOR_PASSWORD not in row[4]


def test_collisions_with_existing_accounts_are_refused(app, admin):
    create_moderator(admin, app)
    for candidate in (MODERATOR_USERNAME, MODERATOR_USERNAME.upper()):
        create_moderator(admin, app, username=candidate)
        assert _count(
            app, "SELECT COUNT(*) FROM admin_users WHERE username = ?", (candidate,)
        ) == 1, candidate
    create_moderator(admin, app, username=ADMIN_USERNAME.upper())
    assert _count(app, "SELECT COUNT(*) FROM admin_users") == 2


def test_creation_validates_identifiers_and_passwords(app, admin):
    for username, password in (
        ("ab", MODERATOR_PASSWORD),
        ("x" * 65, MODERATOR_PASSWORD),
        ("   ", MODERATOR_PASSWORD),
        ("modo espace", MODERATOR_PASSWORD),
        ("ok-ident", "court"),
    ):
        create_moderator(admin, app, username=username, password=password)
    assert _count(app, "SELECT COUNT(*) FROM admin_users") == 1
    create_moderator(admin, app, confirmation="autre-mot-de-passe-42")
    assert _count(app, "SELECT COUNT(*) FROM admin_users") == 1


def test_role_and_principal_fields_cannot_be_spoofed(app, admin):
    response = create_moderator(
        admin,
        app,
        username="modo-spoof",
        role="admin",
        id="1",
        is_active="0",
        account_id="1",
    )
    assert response.status_code == 302
    row = _row(app, "SELECT id, role, is_active FROM admin_users WHERE username = 'modo-spoof'")
    assert row is not None
    assert int(row[0]) != 1
    assert row[1] == "moderator"
    assert row[2] == 1


def test_account_mutations_require_csrf_and_origin(app, admin):
    assert admin.post(
        "/admin/accounts/create",
        data={
            "username": "sans-csrf",
            "password": MODERATOR_PASSWORD,
            "confirmation": MODERATOR_PASSWORD,
        },
    ).status_code == 403
    csrf = session_csrf(admin, app)
    response = admin.post(
        "/admin/accounts/create",
        data={
            "_csrf": csrf,
            "username": "origine-etrangere",
            "password": MODERATOR_PASSWORD,
            "confirmation": MODERATOR_PASSWORD,
        },
        headers={"Origin": "https://attaquant.example"},
    )
    assert response.status_code == 403
    assert _count(app, "SELECT COUNT(*) FROM admin_users") == 1


def test_unknown_account_is_a_404(app, admin):
    csrf = session_csrf(admin, app)
    for action in ("deactivate", "reactivate", "delete"):
        response = admin.post(f"/admin/accounts/999/{action}", data={"_csrf": csrf})
        assert response.status_code == 404, action


# --- Compte principal intouchable ----------------------------------------------


def test_principal_account_cannot_be_deactivated_deleted_or_reset(app, admin):
    csrf = session_csrf(admin, app)
    before = _row(app, "SELECT username, password_hash, role, is_active FROM admin_users WHERE id = 1")
    for action, extra in (
        ("deactivate", {}),
        ("delete", {"confirm_delete": "1"}),
    ):
        response = admin.post(f"/admin/accounts/1/{action}", data={"_csrf": csrf, **extra})
        assert response.status_code == 403, action
    response = admin.post(
        "/admin/accounts/reset-password",
        data={
            "_csrf": csrf,
            "account_id": "1",
            "new_password": "autre-mot-de-passe-42",
            "confirmation": "autre-mot-de-passe-42",
        },
    )
    assert response.status_code == 403
    after = _row(app, "SELECT username, password_hash, role, is_active FROM admin_users WHERE id = 1")
    assert before == after


def test_no_second_principal_can_be_created(app, admin):
    response = create_moderator(admin, app, username="faux-principal", role="admin")
    assert response.status_code == 302
    assert _count(app, "SELECT COUNT(*) FROM admin_users WHERE role = 'admin'") == 1


# --- Désactivation / réactivation / suppression ---------------------------------


def test_deactivation_revokes_session_and_blocks_login(app, admin):
    create_moderator(admin, app)
    client = moderator_client(app)
    assert client.get("/admin/").status_code == 200
    target = moderator_id(app)

    csrf = session_csrf(admin, app)
    response = admin.post(f"/admin/accounts/{target}/deactivate", data={"_csrf": csrf})
    assert response.status_code == 302
    assert _row(app, "SELECT is_active FROM admin_users WHERE id = ?", (target,))[0] == 0
    # session existante révoquée immédiatement
    assert client.get("/admin/").status_code == 302
    assert _count(app, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", (target,)) == 0
    # connexion refusée, aucune session créée
    fresh = app.test_client()
    response = login(fresh, app, username=MODERATOR_USERNAME, password=MODERATOR_PASSWORD)
    assert response.status_code == 200
    assert fresh.get("/admin/").status_code == 302
    assert _count(app, "SELECT COUNT(*) FROM sessions") == 1  # la session admin seule

    # réactivation : connexion possible à nouveau
    admin.post(f"/admin/accounts/{target}/reactivate", data={"_csrf": csrf})
    assert _row(app, "SELECT is_active FROM admin_users WHERE id = ?", (target,))[0] == 1
    recreated = app.test_client()
    assert login(recreated, app, username=MODERATOR_USERNAME, password=MODERATOR_PASSWORD).status_code == 302
    assert recreated.get("/admin/").status_code == 200


def test_delete_requires_confirmation_and_revokes_everything(app, admin):
    create_moderator(admin, app)
    client = moderator_client(app)
    target = moderator_id(app)
    csrf = session_csrf(admin, app)

    admin.post(f"/admin/accounts/{target}/delete", data={"_csrf": csrf})
    assert _count(app, "SELECT COUNT(*) FROM admin_users WHERE id = ?", (target,)) == 1

    response = admin.post(
        f"/admin/accounts/{target}/delete", data={"_csrf": csrf, "confirm_delete": "1"}
    )
    assert response.status_code == 302
    assert _count(app, "SELECT COUNT(*) FROM admin_users WHERE id = ?", (target,)) == 0
    assert _count(app, "SELECT COUNT(*) FROM sessions WHERE user_id = ?", (target,)) == 0
    assert client.get("/admin/").status_code == 302

    # recréation du même identifiant : l'ancien jeton reste refusé
    create_moderator(admin, app)
    new_target = moderator_id(app)
    assert new_target != target
    assert client.get("/admin/").status_code == 302
    fresh = app.test_client()
    assert login(fresh, app, username=MODERATOR_USERNAME, password=MODERATOR_PASSWORD).status_code == 302


def test_reset_password_revokes_target_sessions_only(app, admin):
    create_moderator(admin, app)
    client = moderator_client(app)
    target = moderator_id(app)
    csrf = session_csrf(admin, app)

    response = admin.post(
        f"/admin/accounts/{target}/reset-password",
        data={
            "_csrf": csrf,
            "new_password": NEW_MODERATOR_PASSWORD,
            "confirmation": NEW_MODERATOR_PASSWORD,
        },
    )
    assert response.status_code == 404  # route par identifiant inexistante : endpoint global
    response = admin.post(
        "/admin/accounts/reset-password",
        data={
            "_csrf": csrf,
            "account_id": str(target),
            "new_password": NEW_MODERATOR_PASSWORD,
            "confirmation": NEW_MODERATOR_PASSWORD,
        },
    )
    assert response.status_code == 302
    assert client.get("/admin/").status_code == 302  # sessions du compte révoquées
    assert admin.get("/admin/").status_code == 200  # session du principal intacte
    assert login(
        app.test_client(), app, username=MODERATOR_USERNAME, password=NEW_MODERATOR_PASSWORD
    ).status_code == 302
    assert login(
        app.test_client(), app, username=MODERATOR_USERNAME, password=MODERATOR_PASSWORD
    ).status_code == 200


# --- Matrice d'accès -----------------------------------------------------------


def test_anonymous_is_redirected_on_every_admin_surface(app, client):
    setup_admin(client, app)
    csrf = session_csrf(client, app)
    client.post("/admin/logout", data={"_csrf": csrf})
    for path in (
        "/admin/",
        "/admin/apps",
        "/admin/apps/new",
        "/admin/categories",
        "/admin/settings",
        "/admin/accounts",
        "/admin/certificates",
        "/admin/security",
        "/admin/security/vulnerabilities",
    ):
        response = client.get(path)
        assert response.status_code == 302, path
        assert "/admin/login" in response.headers.get("Location", ""), path


def test_moderator_can_manage_the_catalog(app, admin):
    create_moderator(admin, app)
    client = moderator_client(app)
    for path in ("/admin/", "/admin/apps", "/admin/apps/new", "/admin/categories", "/admin/settings"):
        assert client.get(path).status_code == 200, path

    csrf = session_csrf(client, app)
    response = client.post(
        "/admin/categories/create", data={"_csrf": csrf, "name": "Catégorie Modérateur"}
    )
    assert response.status_code == 302
    row = _row(app, "SELECT id FROM categories WHERE name = 'Catégorie Modérateur'")
    assert row is not None
    category_id = int(row[0])

    csrf = session_csrf(client, app)
    response = client.post(
        "/admin/apps/new",
        data={
            "_csrf": csrf,
            "name": "App Modérateur",
            "slug": "app-moderateur",
            "url": "https://modo.valdev.me",
            "description": "Créée par un modérateur.",
            "category_id": str(category_id),
            "status": "production",
        },
    )
    assert response.status_code == 302
    app_row = _row(app, "SELECT id, enabled FROM apps WHERE slug = 'app-moderateur'")
    assert app_row is not None
    app_id = int(app_row[0])

    csrf = session_csrf(client, app)
    assert client.post(f"/admin/apps/{app_id}/toggle", data={"_csrf": csrf}).status_code == 302
    assert _row(app, "SELECT enabled FROM apps WHERE id = ?", (app_id,))[0] == 0
    assert client.post(
        f"/admin/apps/{app_id}/delete", data={"_csrf": csrf, "confirm_delete": "1"}
    ).status_code == 302
    assert _count(app, "SELECT COUNT(*) FROM apps WHERE id = ?", (app_id,)) == 0


def test_moderator_is_refused_on_every_sensitive_surface(app, admin):
    create_moderator(admin, app)
    client = moderator_client(app)
    for path in (
        "/admin/accounts",
        "/admin/certificates",
        "/admin/security",
        "/admin/security/vulnerabilities",
    ):
        assert client.get(path).status_code == 403, path

    csrf = session_csrf(client, app)
    # POST forgés : refusés avant tout traitement métier
    with_password = {
        "username": "intrusion",
        "password": MODERATOR_PASSWORD,
        "confirmation": MODERATOR_PASSWORD,
    }
    for path, data in (
        ("/admin/accounts/create", with_password),
        ("/admin/accounts/1/deactivate", {}),
        ("/admin/settings/preferences", {"open_links_new_tab": "0"}),
        ("/admin/security/sync", {}),
        ("/admin/security/settings", {}),
        ("/admin/security/secret/delete", {"name": "smtp-password", "confirm_delete": "1"}),
        ("/admin/security/test-email", {}),
        ("/admin/certificates/validate", {}),
        ("/admin/certificates/validate-pkcs12", {}),
        ("/admin/certificates/activate", {"ticket": "x"}),
    ):
        response = client.post(path, data={"_csrf": csrf, **data})
        assert response.status_code == 403, path
    assert _count(app, "SELECT COUNT(*) FROM admin_users") == 2  # aucune création


def test_navigation_and_dashboard_do_not_leak_sensitive_configuration(app, admin):
    create_moderator(admin, app)
    client = moderator_client(app)
    dashboard = client.get("/admin/").get_data(as_text=True)
    assert "Certificat HTTPS" not in dashboard
    assert 'href="/admin/security"' not in dashboard
    assert 'href="/admin/certificates"' not in dashboard
    assert 'href="/admin/accounts"' not in dashboard
    assert MODERATOR_USERNAME in dashboard  # identité affichée

    settings_page = client.get("/admin/settings").get_data(as_text=True)
    assert "Préférences du portail" not in settings_page
    assert MODERATOR_USERNAME in settings_page

    # l'administrateur principal conserve la navigation complète
    principal_dashboard = admin.get("/admin/").get_data(as_text=True)
    for link in ('href="/admin/security"', 'href="/admin/certificates"', 'href="/admin/accounts"'):
        assert link in principal_dashboard


def test_accounts_page_never_renders_password_hashes(app, admin):
    create_moderator(admin, app)
    page = admin.get("/admin/accounts").get_data(as_text=True)
    assert MODERATOR_USERNAME in page
    connection = _db(app)
    try:
        hashes = [row[0] for row in connection.execute("SELECT password_hash FROM admin_users")]
    finally:
        connection.close()
    for value in hashes:
        assert value not in page
        assert value.split("$")[-1] not in page  # ni le digest seul


# --- Mot de passe personnel ----------------------------------------------------


def test_self_password_change_invalidates_only_own_sessions(app, admin):
    create_moderator(admin, app)
    client = moderator_client(app)
    csrf = session_csrf(client, app)

    response = client.post(
        "/admin/settings/password",
        data={
            "_csrf": csrf,
            "current_password": "mauvais-mot-de-passe",
            "new_password": NEW_MODERATOR_PASSWORD,
            "confirmation": NEW_MODERATOR_PASSWORD,
        },
        follow_redirects=True,
    )
    assert "Mot de passe actuel incorrect" in response.get_data(as_text=True)
    assert client.get("/admin/").status_code == 200

    response = client.post(
        "/admin/settings/password",
        data={
            "_csrf": csrf,
            "current_password": MODERATOR_PASSWORD,
            "new_password": NEW_MODERATOR_PASSWORD,
            "confirmation": NEW_MODERATOR_PASSWORD,
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/login")
    assert client.get("/admin/").status_code == 302  # sa session est révoquée
    assert admin.get("/admin/").status_code == 200  # le principal reste connecté
    assert login(
        app.test_client(), app, username=MODERATOR_USERNAME, password=NEW_MODERATOR_PASSWORD
    ).status_code == 302
    assert login(
        app.test_client(), app, username=MODERATOR_USERNAME, password=MODERATOR_PASSWORD
    ).status_code == 200


def test_moderator_login_is_rate_limited(app, admin):
    create_moderator(admin, app)
    client = app.test_client()
    for _ in range(5):
        login(client, app, username=MODERATOR_USERNAME, password="mauvais-mot-de-passe")
    response = login(client, app, username=MODERATOR_USERNAME, password=MODERATOR_PASSWORD)
    assert response.status_code == 429


# --- Configuration initiale préservée -------------------------------------------


def test_setup_creates_the_single_principal(app, client):
    response = setup_admin(client, app)
    assert response.status_code == 302
    row = _row(app, "SELECT id, role, is_active FROM admin_users")
    assert row == (1, "admin", 1)
    assert client.get("/admin/accounts").status_code == 200
