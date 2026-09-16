"""Authentification : configuration initiale, login, verrouillage, sessions, CSRF."""

from __future__ import annotations

import sqlite3

from conftest import (
    ADMIN_PASSWORD,
    ADMIN_USERNAME,
    login,
    session_csrf,
    session_token,
    setup_admin,
)


def _db(app):
    return sqlite3.connect(app.config["DB_PATH"])


def test_setup_creates_account_and_session(app, client):
    response = setup_admin(client, app)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/")
    cookie = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    connection = _db(app)
    row = connection.execute("SELECT username, password_hash FROM admin_users").fetchone()
    connection.close()
    assert row[0] == ADMIN_USERNAME
    assert row[1].startswith("scrypt$")
    assert ADMIN_PASSWORD not in row[1]


def test_session_stored_hashed(app, client):
    setup_admin(client, app)
    token = session_token(client)
    assert token
    connection = _db(app)
    stored = connection.execute("SELECT token_hash FROM sessions").fetchall()
    connection.close()
    assert len(stored) == 1
    assert token not in {row[0] for row in stored}


def test_setup_is_single_use(app, client):
    setup_admin(client, app)
    page = client.get("/admin/setup")
    assert page.status_code == 302 and page.headers["Location"].endswith("/admin/login")
    connection = _db(app)
    count = connection.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]
    connection.close()
    assert count == 1


def test_setup_rejects_short_password(app, client):
    client.get("/admin/setup")
    with client.session_transaction() as flask_session:
        preauth = flask_session.get("preauth_csrf")
    response = client.post(
        "/admin/setup",
        data={"username": "admin", "password": "court", "confirmation": "court", "_csrf": preauth},
    )
    assert response.status_code == 200
    assert "au moins" in response.get_data(as_text=True)
    connection = _db(app)
    count = connection.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]
    connection.close()
    assert count == 0


def test_setup_requires_csrf(app, client):
    client.get("/admin/setup")
    response = client.post(
        "/admin/setup",
        data={"username": "admin", "password": ADMIN_PASSWORD, "confirmation": ADMIN_PASSWORD},
    )
    assert response.status_code == 403


def test_login_success_and_logout(app, client):
    setup_admin(client, app)
    csrf = session_csrf(client, app)
    assert client.post("/admin/logout", data={"_csrf": csrf}).status_code == 302
    assert client.get("/admin/").status_code == 302  # session détruite
    response = login(client, app)
    assert response.status_code == 302 and response.headers["Location"].endswith("/admin/")
    assert client.get("/admin/").status_code == 200


def test_login_wrong_password(app, client):
    setup_admin(client, app)
    csrf = session_csrf(client, app)
    client.post("/admin/logout", data={"_csrf": csrf})
    response = login(client, app, password="mauvais-mot-de-passe")
    assert response.status_code == 200
    assert "Identifiants invalides" in response.get_data(as_text=True)
    assert client.get("/admin/").status_code == 302


def test_lockout_after_five_failures(app, client):
    setup_admin(client, app)
    csrf = session_csrf(client, app)
    client.post("/admin/logout", data={"_csrf": csrf})
    for _ in range(5):
        login(client, app, password="mauvais-mot-de-passe")
    response = login(client, app, password="mauvais-mot-de-passe")
    assert response.status_code == 429
    assert "Trop de tentatives" in response.get_data(as_text=True)
    # même le bon mot de passe est refusé pendant le verrouillage
    response = login(client, app)
    assert response.status_code == 429


def test_failures_cleared_after_success(app, client):
    setup_admin(client, app)
    csrf = session_csrf(client, app)
    client.post("/admin/logout", data={"_csrf": csrf})
    login(client, app, password="mauvais-1")
    login(client, app, password="mauvais-2")
    assert login(client, app).status_code == 302
    connection = _db(app)
    attempts = connection.execute("SELECT COUNT(*) FROM login_attempts").fetchone()[0]
    connection.close()
    assert attempts == 0


def test_admin_requires_session(app, client):
    setup_admin(client, app)
    csrf = session_csrf(client, app)
    client.post("/admin/logout", data={"_csrf": csrf})
    for path in ("/admin/", "/admin/apps", "/admin/settings", "/admin/certificates"):
        response = client.get(path)
        assert response.status_code == 302
        assert "/admin/login" in response.headers["Location"]


def test_session_expiry(app, client):
    setup_admin(client, app)
    connection = _db(app)
    connection.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00Z'")
    connection.commit()
    connection.close()
    assert client.get("/admin/").status_code == 302
    connection = _db(app)
    remaining = connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
    connection.close()
    assert remaining == 0  # session expirée purgée


def test_csrf_required_for_mutations(app, admin):
    response = admin.post("/admin/settings/preferences", data={"open_links_new_tab": "0"})
    assert response.status_code == 403


def test_origin_mismatch_rejected(app, admin):
    csrf = session_csrf(admin, app)
    response = admin.post(
        "/admin/settings/preferences",
        data={"_csrf": csrf, "open_links_new_tab": "0"},
        headers={"Origin": "https://attaquant.example"},
    )
    assert response.status_code == 403


def test_password_change_invalidates_sessions(app, client):
    setup_admin(client, app)
    csrf = session_csrf(client, app)
    response = client.post(
        "/admin/settings/password",
        data={
            "_csrf": csrf,
            "current_password": ADMIN_PASSWORD,
            "new_password": "nouveau-mot-de-passe-42",
            "confirmation": "nouveau-mot-de-passe-42",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/login")
    assert client.get("/admin/").status_code == 302  # session invalidée
    assert login(client, app, password="nouveau-mot-de-passe-42").status_code == 302
    assert login(client, app, password=ADMIN_PASSWORD).status_code == 200  # ancien refusé


def test_password_change_wrong_current(app, client):
    setup_admin(client, app)
    csrf = session_csrf(client, app)
    response = client.post(
        "/admin/settings/password",
        data={
            "_csrf": csrf,
            "current_password": "mauvais",
            "new_password": "nouveau-mot-de-passe-42",
            "confirmation": "nouveau-mot-de-passe-42",
        },
        follow_redirects=True,
    )
    assert "Mot de passe actuel incorrect" in response.get_data(as_text=True)
    assert client.get("/admin/").status_code == 200  # toujours connecté
