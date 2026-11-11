"""Durcissement de l'authentification (scan de sécurité de novembre 2026).

- le verrouillage ne doit plus permettre à un tiers de bloquer l'administrateur
  depuis n'importe quelle adresse (verrou par couple identifiant + IP) ;
- une IP qui essaie beaucoup d'identifiants reste freinée ;
- une attaque répartie sur un compte reste bornée (seuil global élevé) ;
- les essais simultanés ne dépassent jamais le seuil ;
- `reset-admin` lève les verrous ;
- la première configuration exige un jeton de premier démarrage.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
from datetime import timedelta

import pytest

from app import auth, db, manage, secretstore

from conftest import ADMIN_PASSWORD, ADMIN_USERNAME, session_csrf, setup_admin


def _login_from(app, ip: str, username: str = ADMIN_USERNAME, password: str = ADMIN_PASSWORD):
    """Connexion depuis une IP cliente donnée (vue derrière le proxy de confiance)."""
    client = app.test_client()
    headers = {"X-Forwarded-For": ip}
    client.get("/admin/login", headers=headers)
    with client.session_transaction() as flask_session:
        preauth = flask_session.get("preauth_csrf")
    return client.post(
        "/admin/login",
        data={"username": username, "password": password, "_csrf": preauth},
        headers=headers,
    )


@pytest.fixture()
def configured(app, client):
    setup_admin(client, app)
    client.post("/admin/logout", data={"_csrf": session_csrf(client, app)})
    return app


# --- Verrouillage -------------------------------------------------------------


def test_an_attacker_cannot_lock_the_admin_out_from_another_address(configured):
    attacker = "203.0.113.9"
    for _ in range(auth.LOCK_THRESHOLD):
        _login_from(configured, attacker, password="mauvais-mot-de-passe")
    assert _login_from(configured, attacker, password="mauvais-mot-de-passe").status_code == 429
    # L'attaquant ne se bloque que lui-même : le bon mot de passe passe ailleurs.
    response = _login_from(configured, "198.51.100.7")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/admin/")


def test_the_locked_address_is_refused_even_with_the_right_password(configured):
    attacker = "203.0.113.10"
    for _ in range(auth.LOCK_THRESHOLD):
        _login_from(configured, attacker, password="mauvais-mot-de-passe")
    assert _login_from(configured, attacker).status_code == 429


def test_one_address_spraying_usernames_is_throttled(configured):
    sprayer = "203.0.113.11"
    for index in range(auth.IP_LOCK_THRESHOLD):
        _login_from(configured, sprayer, username=f"compte-{index}", password="mauvais")
    response = _login_from(configured, sprayer, username="encore-un-autre", password="mauvais")
    assert response.status_code == 429


def test_distributed_attempts_on_one_account_stay_bounded(configured, monkeypatch):
    # Garde-fou contre une attaque répartie sur de nombreuses adresses : seuil
    # élevé (abaissé ici pour garder le test rapide).
    monkeypatch.setattr(auth, "USER_LOCK_THRESHOLD", 6)
    for index in range(6):
        _login_from(configured, f"192.0.2.{index + 1}", password="mauvais")
    assert _login_from(configured, "192.0.2.200").status_code == 429


def test_failure_counters_expire_after_the_window(configured, monkeypatch):
    connection = db.connect(configured.config["DB_PATH"])
    start = db.utc_now()
    try:
        monkeypatch.setattr(auth.db, "utc_now", lambda: start)
        for _ in range(auth.LOCK_THRESHOLD - 1):
            auth.register_failure(connection, ADMIN_USERNAME, "203.0.113.12")
        later = start + timedelta(seconds=auth.FAILURE_WINDOW_SECONDS + 1)
        monkeypatch.setattr(auth.db, "utc_now", lambda: later)
        monkeypatch.setattr(auth.db, "now_iso", lambda: later.strftime("%Y-%m-%dT%H:%M:%SZ"))
        auth.register_failure(connection, ADMIN_USERNAME, "203.0.113.12")
        # Les échecs anciens sont sortis de la fenêtre : pas de verrou.
        assert auth.lock_remaining(connection, ADMIN_USERNAME, "203.0.113.12") == 0
    finally:
        connection.close()


def test_simultaneous_failures_never_exceed_the_threshold(configured, monkeypatch):
    # Chaque essai doit consulter et incrémenter le compteur de façon atomique :
    # des requêtes parallèles ne peuvent pas toutes passer le contrôle avant
    # que le premier échec soit enregistré.
    calls = []
    real_authenticate = auth.authenticate

    def slow_authenticate(connection, username, password):
        calls.append(username)
        threading.Event().wait(0.05)
        return real_authenticate(connection, username, password)

    monkeypatch.setattr(auth, "authenticate", slow_authenticate)
    workers = 10
    barrier = threading.Barrier(workers)
    statuses = []

    def attempt():
        client = configured.test_client()
        headers = {"X-Forwarded-For": "203.0.113.13"}
        client.get("/admin/login", headers=headers)
        with client.session_transaction() as flask_session:
            preauth = flask_session.get("preauth_csrf")
        barrier.wait()
        response = client.post(
            "/admin/login",
            data={"username": ADMIN_USERNAME, "password": "mauvais", "_csrf": preauth},
            headers=headers,
        )
        statuses.append(response.status_code)

    threads = [threading.Thread(target=attempt) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert len(statuses) == workers
    assert len(calls) <= auth.LOCK_THRESHOLD
    assert statuses.count(429) >= workers - auth.LOCK_THRESHOLD


def test_reset_admin_lifts_login_locks(tmp_path, monkeypatch):
    data = tmp_path / "cli-data"
    data.mkdir()
    monkeypatch.setenv("HUB_DATA_DIR", str(data))
    assert manage.main(["seed"]) == 0
    connection = db.connect(data / "hub.sqlite")
    try:
        assert auth.create_admin(connection, "admin", "MotDePasse-Admin-1")
        for _ in range(auth.LOCK_THRESHOLD):
            auth.register_failure(connection, "admin", "203.0.113.14")
        assert auth.lock_remaining(connection, "admin", "203.0.113.14") > 0
    finally:
        connection.close()

    answers = iter(["Nouveau-MotDePasse-Solide-1", "Nouveau-MotDePasse-Solide-1"])
    monkeypatch.setattr(manage.getpass, "getpass", lambda *_: next(answers))
    assert manage.main(["reset-admin"]) == 0

    connection = db.connect(data / "hub.sqlite")
    try:
        assert auth.lock_remaining(connection, "admin", "203.0.113.14") == 0
    finally:
        connection.close()


# --- Jeton de premier démarrage ----------------------------------------------


def _setup_post(app, client, **fields):
    client.get("/admin/setup")
    with client.session_transaction() as flask_session:
        preauth = flask_session.get("preauth_csrf")
    data = {
        "username": ADMIN_USERNAME,
        "password": ADMIN_PASSWORD,
        "confirmation": ADMIN_PASSWORD,
        "_csrf": preauth,
    }
    data.update(fields)
    return client.post("/admin/setup", data=data)


def _admin_count(app) -> int:
    connection = sqlite3.connect(app.config["DB_PATH"])
    try:
        return connection.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]
    finally:
        connection.close()


def test_setup_without_the_first_run_token_is_refused(app, client):
    response = _setup_post(app, client)
    assert response.status_code == 403
    assert _admin_count(app) == 0


@pytest.mark.parametrize("token", ["mauvais-jeton", "\xe9t\xe9", ""])
def test_setup_with_a_wrong_token_is_refused(app, client, token):
    response = _setup_post(app, client, setup_token=token)
    assert response.status_code == 403
    assert "Jeton de premier démarrage" in response.get_data(as_text=True)
    assert _admin_count(app) == 0


def test_setup_with_the_token_creates_the_admin_and_burns_the_token(app, client):
    token = auth.ensure_setup_token(app.config["DATA_DIR"])
    response = _setup_post(app, client, setup_token=token)
    assert response.status_code == 302
    assert _admin_count(app) == 1
    assert secretstore.read_secret(app.config["DATA_DIR"], secretstore.SETUP_TOKEN) == ""


def test_setup_token_is_generated_at_startup_and_private(app):
    path = secretstore.secret_path(app.config["DATA_DIR"], secretstore.SETUP_TOKEN)
    assert path.is_file()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    token = secretstore.read_secret(app.config["DATA_DIR"], secretstore.SETUP_TOKEN)
    assert len(token) >= 32
    # Stable entre deux appels (plusieurs workers lisent le même jeton).
    assert auth.ensure_setup_token(app.config["DATA_DIR"]) == token


def test_setup_token_is_not_an_administrable_secret():
    # Le jeton de premier démarrage n'est ni affiché ni supprimable depuis la
    # section Sécurité (liste des secrets administrables inchangée).
    assert secretstore.SETUP_TOKEN not in secretstore.SECRET_NAMES


def test_setup_token_cli_prints_the_token_then_refuses_once_configured(tmp_path, monkeypatch, capsys):
    data = tmp_path / "cli-data"
    data.mkdir()
    monkeypatch.setenv("HUB_DATA_DIR", str(data))
    assert manage.main(["setup-token"]) == 0
    printed = capsys.readouterr().out.strip().splitlines()[-1]
    assert printed == secretstore.read_secret(data, secretstore.SETUP_TOKEN)

    connection = db.connect(data / "hub.sqlite")
    try:
        assert auth.create_admin(connection, "admin", "MotDePasse-Admin-1")
    finally:
        connection.close()
    assert manage.main(["setup-token"]) == 1
    assert "existe déjà" in capsys.readouterr().out
