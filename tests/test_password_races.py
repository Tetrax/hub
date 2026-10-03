"""Régressions V1.7 : autorité du changement personnel face aux révocations.

Deux ordres déterministes : révocation après chargement de la session mais avant
la mutation ; mutation déjà verrouillée puis révocation. Données jetables, aucune
attente temporelle utilisée pour décider qui a gagné la course.
"""
from concurrent.futures import ThreadPoolExecutor
import sqlite3
from threading import Event

from flask import request
import pytest

from app import auth, db, manage
from conftest import login, session_csrf
from test_accounts import (
    MODERATOR_PASSWORD, MODERATOR_USERNAME,
    create_moderator, moderator_client, moderator_id,
)

SELF_PASSWORD = "changement-personnel-test-123"
RESET_PASSWORD = "reset-principal-test-456"


def change_password(client, csrf):
    return client.post("/admin/settings/password", data={
        "_csrf": csrf, "current_password": MODERATOR_PASSWORD,
        "new_password": SELF_PASSWORD, "confirmation": SELF_PASSWORD,
    })


def revoke(app, admin, target, csrf, action):
    if action == "reset":
        response = admin.post("/admin/accounts/reset-password", data={
            "_csrf": csrf, "account_id": str(target),
            "new_password": RESET_PASSWORD, "confirmation": RESET_PASSWORD,
        })
        assert response.status_code == 302
    elif action == "invalidate-sessions":
        with app.app_context():
            assert manage._invalidate_sessions() == 0
    else:
        first_action = action.split("-")[0]
        response = admin.post(f"/admin/accounts/{target}/{first_action}", data={
            "_csrf": csrf, "confirm_delete": "1",
        })
        assert response.status_code == 302
        if action == "deactivate-reactivate":
            assert admin.post(f"/admin/accounts/{target}/reactivate", data={
                "_csrf": csrf,
            }).status_code == 302
        elif action == "delete-recreate":
            assert create_moderator(admin, app).status_code == 302
            assert moderator_id(app) != target


def assert_writer_locked(app):
    contender = sqlite3.connect(app.config["DB_PATH"], timeout=0)
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            contender.execute("BEGIN IMMEDIATE")
    finally:
        contender.close()


def assert_result(app, admin, moderator, observer, target, action, *, changed):
    with db.connect(app.config["DB_PATH"]) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id = ?", (target,),
        ).fetchone()[0] == 0
        if action.startswith("delete"):
            assert auth.get_account(connection, target) is None
        else:
            assert auth.verify_user_password(connection, target, SELF_PASSWORD) is changed
            if action == "reset":
                assert auth.verify_user_password(connection, target, RESET_PASSWORD)
            elif not changed:
                assert auth.verify_user_password(connection, target, MODERATOR_PASSWORD)
    assert moderator.get("/admin/").status_code == 302
    assert observer.get("/admin/").status_code == 302
    expected = 302 if action == "invalidate-sessions" else 200
    assert admin.get("/admin/accounts").status_code == expected
    if action == "reset":
        # La récupération du compte par le principal reste autoritative.
        assert login(app.test_client(), app, username=MODERATOR_USERNAME,
                     password=RESET_PASSWORD).status_code == 302
        assert login(app.test_client(), app, username=MODERATOR_USERNAME,
                     password=SELF_PASSWORD).status_code == 200
    elif action == "delete-recreate":
        moderator_client(app)  # le compte neuf fonctionne sans réutiliser l'identité


@pytest.mark.parametrize("action", [
    "reset", "deactivate", "deactivate-reactivate", "delete", "delete-recreate",
    "invalidate-sessions",
])
def test_revocation_completed_after_cached_session_prevents_change(app, admin, monkeypatch, action):
    assert create_moderator(admin, app).status_code == 302
    moderator, observer = moderator_client(app), moderator_client(app)
    target = moderator_id(app)
    csrf, principal_csrf = session_csrf(moderator, app), session_csrf(admin, app)
    loaded, resume = Event(), Event()
    original = auth.require_session

    def pause_after_session_load():
        session_row = original()
        if request.path == "/admin/settings/password":
            loaded.set()
            assert resume.wait(10), "coordination de la requête interrompue"
        return session_row

    monkeypatch.setattr(auth, "require_session", pause_after_session_load)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(change_password, moderator, csrf)
        try:
            assert loaded.wait(10)
            revoke(app, admin, target, principal_csrf, action)
        finally:
            resume.set()
        response = future.result(timeout=10)
    assert response.status_code == 302
    assert_result(app, admin, moderator, observer, target, action, changed=False)


@pytest.mark.parametrize("action", ["reset", "deactivate", "delete", "invalidate-sessions"])
def test_change_holds_writer_lock_until_commit_then_revocation_wins(app, admin, monkeypatch, action):
    assert create_moderator(admin, app).status_code == 302
    moderator, observer = moderator_client(app), moderator_client(app)
    target = moderator_id(app)
    csrf, principal_csrf = session_csrf(moderator, app), session_csrf(admin, app)
    verified, resume, revoking = Event(), Event(), Event()
    original_verify, original_update = auth.verify_user_password, auth.update_password

    def pause_after_password_check(connection, user_id, password):
        result = original_verify(connection, user_id, password)
        if not verified.is_set():
            assert result
            verified.set()
            assert resume.wait(10), "coordination de la vérification interrompue"
        return result

    def update_under_lock(connection, user_id, password):
        # Le verrou ne doit pas être relâché entre vérification et écriture.
        if password == SELF_PASSWORD:
            assert_writer_locked(app)
        return original_update(connection, user_id, password)

    def concurrent_revocation():
        revoking.set()
        revoke(app, admin, target, principal_csrf, action)

    monkeypatch.setattr(auth, "verify_user_password", pause_after_password_check)
    monkeypatch.setattr(auth, "update_password", update_under_lock)
    with ThreadPoolExecutor(max_workers=2) as pool:
        change = pool.submit(change_password, moderator, csrf)
        try:
            assert verified.wait(10)
            # Preuve effective SQLite, pas une assertion fondée sur un sleep.
            assert_writer_locked(app)
            revocation = pool.submit(concurrent_revocation)
            assert revoking.wait(10)
        finally:
            resume.set()
        assert change.result(timeout=10).status_code == 302
        revocation.result(timeout=10)
    monkeypatch.undo()
    assert_result(app, admin, moderator, observer, target, action,
                  changed=action in ("deactivate", "invalidate-sessions"))


@pytest.mark.parametrize("mutation", ["inactive", "expired", "identity", "password", "logout"])
def test_live_authority_is_rechecked_not_only_cached_session(app, admin, monkeypatch, mutation):
    assert create_moderator(admin, app).status_code == 302
    moderator = moderator_client(app)
    target, csrf = moderator_id(app), session_csrf(moderator, app)
    original = auth.require_session

    def alter_after_load():
        session_row = original()
        # Injection par une autre connexion après le contrôle du décorateur.
        # Ne jamais fournir les identifiants de session par le formulaire.
        with db.connect(app.config["DB_PATH"]) as connection:
            if mutation == "inactive":
                connection.execute("UPDATE admin_users SET is_active = 0 WHERE id = ?", (target,))
            elif mutation == "expired":
                connection.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00Z' WHERE user_id = ?", (target,))
            elif mutation == "identity":
                connection.execute("UPDATE sessions SET user_id = 1 WHERE user_id = ?", (target,))
            elif mutation == "password":
                connection.execute("UPDATE admin_users SET password_hash = ? WHERE id = ?",
                                   (auth.hash_password(RESET_PASSWORD), target))
            else:
                auth.destroy_session(connection, session_row["token"])
        return session_row

    monkeypatch.setattr(auth, "require_session", alter_after_load)
    assert change_password(moderator, csrf).status_code == 302
    with db.connect(app.config["DB_PATH"]) as connection:
        assert not auth.verify_user_password(connection, target, SELF_PASSWORD)
        expected = RESET_PASSWORD if mutation == "password" else MODERATOR_PASSWORD
        assert auth.verify_user_password(connection, target, expected)


@pytest.mark.parametrize("failure", ["wrong-current", "same-password", "exception"])
def test_failed_change_releases_transaction_without_mutation(app, admin, monkeypatch, failure):
    assert create_moderator(admin, app).status_code == 302
    moderator = moderator_client(app)
    with moderator:
        moderator.get("/admin/")
        session_row = auth.require_session()
        connection = auth.db_connection()
        current = "incorrect-test-password" if failure == "wrong-current" else MODERATOR_PASSWORD
        new_password = MODERATOR_PASSWORD if failure == "same-password" else SELF_PASSWORD
        if failure == "exception":
            def fail_update(connection, user_id, password):
                connection.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
                raise RuntimeError("erreur simulée")

            monkeypatch.setattr(auth, "update_password", fail_update)
            with pytest.raises(RuntimeError, match="erreur simulée"):
                auth.change_own_password(connection, session_row, current, new_password)
        else:
            assert auth.change_own_password(connection, session_row, current, new_password)
        assert not connection.in_transaction
        assert auth.verify_user_password(connection, session_row["user_id"], MODERATOR_PASSWORD)
    assert moderator.get("/admin/").status_code == 200
