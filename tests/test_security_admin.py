"""Section Sécurité de l'administration : accès, CSRF, secrets, pages, actions.

Rien de Trivy n'est public ; la configuration fonctionnelle vit dans l'admin et
les secrets (jeton GitHub, mot de passe SMTP) ne sont jamais rendus au navigateur.
"""

from __future__ import annotations

from conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login, session_csrf, setup_admin
from app import db, trivy_email, trivy_github, trivy_monitor
from test_trivy_monitor import BASELINE, capture_emails, enable, payload, state_of, use_github

SECRET_TOKEN = "jeton-github-secret-a-ne-jamais-rendre"
SECRET_SMTP = "mot-de-passe-smtp-secret-a-ne-jamais-rendre"


def admin_client(app):
    client = app.test_client()
    setup_admin(client, app)
    login(client, app)
    return client


def test_the_security_section_is_admin_only(app):
    anonymous = app.test_client()
    response = anonymous.get("/admin/security", follow_redirects=False)
    assert response.status_code == 302 and "/admin/login" in response.headers["Location"]
    response = anonymous.post("/admin/security/sync", follow_redirects=False)
    assert response.status_code == 302


def test_a_post_without_csrf_is_refused(app):
    client = admin_client(app)
    response = client.post("/admin/security/sync", data={})
    assert response.status_code == 403


def test_a_foreign_origin_is_refused(app):
    client = admin_client(app)
    response = client.post(
        "/admin/security/sync",
        data={"_csrf": session_csrf(client, app)},
        headers={"Origin": "https://attaquant.example"},
    )
    assert response.status_code == 403


def test_the_dashboard_shows_the_state_and_the_configuration(app, monkeypatch):
    client = admin_client(app)
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)
    app.config["GITHUB_TOKEN"] = SECRET_TOKEN
    app.config["SMTP_PASSWORD"] = SECRET_SMTP

    body = client.get("/admin/security").get_data(as_text=True)
    assert "État de l'image" in body
    assert "1" in body and "CRITICAL" in body  # compteurs
    assert "Voir les vulnérabilités" in body
    assert "Baseline initialisée" in body  # historique
    assert "À jour" in body
    assert SECRET_TOKEN not in body and SECRET_SMTP not in body
    assert "fourni au déploiement" in body


def test_the_findings_page_lists_the_actionable_vulnerabilities(app, monkeypatch):
    client = admin_client(app)
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    result = trivy_monitor.sync(app)
    assert result.ok, result.message

    body = client.get("/admin/security/vulnerabilities").get_data(as_text=True)
    assert "CVE-2026-0001" in body and "perl-base" in body and "gzip" in body
    # CRITICAL avant HIGH
    assert body.index("CVE-2026-0003") < body.index("CVE-2026-0001")


def test_the_settings_are_saved_and_validated(app):
    client = admin_client(app)
    csrf = session_csrf(client, app)
    bad = client.post(
        "/admin/security/settings",
        data={"_csrf": csrf, "recipients": "pas-un-email", "smtp_port": "587",
              "smtp_timeout": "15", "smtp_security": "starttls"},
        follow_redirects=True,
    )
    assert "Destinataire invalide" in bad.get_data(as_text=True)

    good = client.post(
        "/admin/security/settings",
        data={"_csrf": csrf, "severity_critical": "1", "severity_high": "1",
              "recipients": "equipe@valdev.me", "smtp_host": "smtp.valdev.me",
              "smtp_port": "587", "smtp_security": "starttls",
              "smtp_from": "sns-hub@valdev.me", "smtp_timeout": "15"},
        follow_redirects=True,
    )
    assert "Configuration de la surveillance enregistrée" in good.get_data(as_text=True)
    connection = db.connect(app.config["DB_PATH"])
    settings = trivy_monitor.load_settings(connection)
    connection.close()
    assert settings.recipients == ("equipe@valdev.me",)
    assert settings.smtp_host == "smtp.valdev.me"


def test_enabling_monitoring_without_a_token_is_refused_cleanly(app):
    client = admin_client(app)
    app.config["GITHUB_TOKEN"] = ""
    response = client.post(
        "/admin/security/settings",
        data={"_csrf": session_csrf(client, app), "sync_enabled": "1",
              "smtp_port": "587", "smtp_timeout": "15", "smtp_security": "starttls"},
        follow_redirects=True,
    )
    assert "jeton GitHub" in response.get_data(as_text=True)
    connection = db.connect(app.config["DB_PATH"])
    settings = trivy_monitor.load_settings(connection)
    connection.close()
    assert settings.sync_enabled is False, "l'activation est refusée, pas enregistrée à moitié"


def test_the_manual_sync_button_runs_the_engine(app, monkeypatch):
    client = admin_client(app)
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    response = client.post(
        "/admin/security/sync",
        data={"_csrf": session_csrf(client, app)},
        follow_redirects=True,
    )
    assert "Baseline initialisée" in response.get_data(as_text=True)
    assert state_of(app) is not None


def test_the_sync_button_reports_a_github_failure_cleanly(app, monkeypatch):
    client = admin_client(app)
    enable(app)

    def _boom(_token):
        raise trivy_github.GitHubError("GitHub inaccessible (URLError).")

    monkeypatch.setattr(trivy_github, "latest_successful_run", _boom)
    response = client.post(
        "/admin/security/sync",
        data={"_csrf": session_csrf(client, app)},
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    assert "GitHub inaccessible" in body
    assert "Traceback" not in body and "URLError" in body


def test_the_test_email_button_uses_the_saved_configuration(app, monkeypatch):
    client = admin_client(app)
    calls: list[str] = []

    def _fake_send(_app):
        calls.append("test")
        return True, "Email envoyé."

    monkeypatch.setattr(trivy_email, "send_test_email", _fake_send)
    response = client.post(
        "/admin/security/test-email",
        data={"_csrf": session_csrf(client, app)},
        follow_redirects=True,
    )
    assert calls == ["test"]
    assert "Envoi réussi" in response.get_data(as_text=True)


def test_the_retry_button_reports_nothing_to_retry(app):
    client = admin_client(app)
    enable(app)
    response = client.post(
        "/admin/security/retry-notification",
        data={"_csrf": session_csrf(client, app)},
        follow_redirects=True,
    )
    assert "Aucun envoi en échec" in response.get_data(as_text=True)


def test_the_public_landing_page_has_no_security_data(app, monkeypatch):
    client = admin_client(app)
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)

    landing = app.test_client().get("/").get_data(as_text=True)
    assert "CVE-2026-0001" not in landing
    assert "Sécurité de l'image" not in landing
    assert "/admin/security" not in landing


def test_no_secret_appears_in_any_admin_response(app):
    client = admin_client(app)
    app.config["GITHUB_TOKEN"] = SECRET_TOKEN
    app.config["SMTP_PASSWORD"] = SECRET_SMTP
    pages = [
        client.get("/admin/security"),
        client.get("/admin/security/vulnerabilities"),
        client.get("/admin/settings"),
        client.get("/admin/"),
    ]
    for page in pages:
        body = page.get_data(as_text=True)
        assert SECRET_TOKEN not in body
        assert SECRET_SMTP not in body
