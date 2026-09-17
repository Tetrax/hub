"""Section Sécurité de l'administration : accès, CSRF, secrets, pages, actions.

Rien de Trivy n'est public ; la configuration fonctionnelle vit dans l'admin et
les secrets (jeton GitHub, mot de passe SMTP) ne sont jamais rendus au navigateur.
"""

from __future__ import annotations

from conftest import ADMIN_PASSWORD, ADMIN_USERNAME, login, session_csrf, setup_admin
from app import db, graphmail, secretstore, trivy_email, trivy_github, trivy_monitor
from test_trivy_monitor import BASELINE, capture_emails, enable, payload, state_of, use_github

SECRET_TOKEN = "jeton-github-secret-a-ne-jamais-rendre"
SECRET_SMTP = "mot-de-passe-smtp-secret-a-ne-jamais-rendre"
SECRET_M365 = "secret-client-m365-a-ne-jamais-rendre"
M365_FORM = {
    "m365_tenant_id": "contoso.onmicrosoft.com",
    "m365_client_id": "11111111-2222-3333-4444-555555555555",
    "m365_mailbox": "hub@example.com",
    "m365_display_name": "SNS Hub",
}
SMTP_FORM = {
    "smtp_host": "smtp.valdev.me", "smtp_port": "587", "smtp_security": "starttls",
    "smtp_username": "", "smtp_from": "sns-hub@valdev.me", "smtp_display_name": "",
    "smtp_timeout": "15",
}


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
    assert "Fourni au déploiement" in body


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
    app.config["MICROSOFT_CLIENT_SECRET"] = SECRET_M365
    secretstore.write_secret(app.config["DATA_DIR"], secretstore.SMTP_PASSWORD, SECRET_SMTP)
    secretstore.write_secret(
        app.config["DATA_DIR"], secretstore.MICROSOFT365_CLIENT_SECRET, SECRET_M365
    )
    secretstore.write_secret(app.config["DATA_DIR"], secretstore.GITHUB_TOKEN, SECRET_TOKEN)
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
        assert SECRET_M365 not in body


# --- Transport email (V1.6.1) --------------------------------------------------------


def test_the_transport_selection_and_the_m365_settings_are_saved(app):
    client = admin_client(app)
    response = client.post(
        "/admin/security/settings",
        data={
            "_csrf": session_csrf(client, app),
            "severity_critical": "1", "severity_high": "1",
            "recipients": "equipe@valdev.me",
            "email_transport": "microsoft365",
            **M365_FORM, **SMTP_FORM,
        },
        follow_redirects=True,
    )
    assert "Configuration de la surveillance enregistrée" in response.get_data(as_text=True)
    settings, _secrets = trivy_email.load_email_state(app)
    assert settings.email_transport == "microsoft365"
    assert settings.m365_mailbox == "hub@example.com"


def test_an_invalid_m365_setting_is_refused_with_a_clear_message(app):
    client = admin_client(app)
    response = client.post(
        "/admin/security/settings",
        data={
            "_csrf": session_csrf(client, app),
            "email_transport": "microsoft365",
            "m365_client_id": "pas-un-guid",
            **SMTP_FORM,
        },
        follow_redirects=True,
    )
    assert "Client ID Microsoft 365 invalide" in response.get_data(as_text=True)


def test_a_submitted_secret_is_stored_and_never_rendered(app):
    client = admin_client(app)
    response = client.post(
        "/admin/security/settings",
        data={
            "_csrf": session_csrf(client, app),
            "severity_critical": "1", "severity_high": "1",
            "recipients": "equipe@valdev.me",
            "smtp_password_new": SECRET_SMTP,
            **SMTP_FORM,
        },
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    assert "Configuré (administration)" in body
    assert SECRET_SMTP not in body
    assert (
        secretstore.read_secret(app.config["DATA_DIR"], secretstore.SMTP_PASSWORD) == SECRET_SMTP
    )
    # Toute lecture ultérieure reste muette : provenance seulement.
    body = client.get("/admin/security").get_data(as_text=True)
    assert SECRET_SMTP not in body
    assert "Configuré (administration)" in body


def test_an_empty_secret_field_keeps_the_existing_secret(app):
    client = admin_client(app)
    data = {
        "_csrf": session_csrf(client, app),
        "severity_critical": "1", "severity_high": "1",
        "recipients": "equipe@valdev.me",
        **SMTP_FORM,
    }
    client.post(
        "/admin/security/settings",
        data={**data, "smtp_password_new": SECRET_SMTP},
        follow_redirects=True,
    )
    client.post(
        "/admin/security/settings",
        data={**data, "smtp_password_new": ""},
        follow_redirects=True,
    )
    assert (
        secretstore.read_secret(app.config["DATA_DIR"], secretstore.SMTP_PASSWORD) == SECRET_SMTP
    )


def test_a_secret_is_replaced_only_when_explicitly_provided(app):
    client = admin_client(app)
    data = {
        "_csrf": session_csrf(client, app),
        "severity_critical": "1", "severity_high": "1",
        "recipients": "equipe@valdev.me",
        **SMTP_FORM,
    }
    client.post(
        "/admin/security/settings", data={**data, "smtp_password_new": "premier-secret"},
        follow_redirects=True,
    )
    client.post(
        "/admin/security/settings", data={**data, "smtp_password_new": "second-secret"},
        follow_redirects=True,
    )
    assert (
        secretstore.read_secret(app.config["DATA_DIR"], secretstore.SMTP_PASSWORD)
        == "second-secret"
    )


def test_a_secret_can_be_deleted_with_an_explicit_confirmation(app):
    client = admin_client(app)
    secretstore.write_secret(app.config["DATA_DIR"], secretstore.SMTP_PASSWORD, SECRET_SMTP)
    response = client.post(
        "/admin/security/secret/delete",
        data={
            "_csrf": session_csrf(client, app),
            "name": secretstore.SMTP_PASSWORD,
            "confirm_delete": "1",
        },
        follow_redirects=True,
    )
    assert "Secret supprimé." in response.get_data(as_text=True)
    assert secretstore.read_secret(app.config["DATA_DIR"], secretstore.SMTP_PASSWORD) == ""
    assert "Non configuré" in response.get_data(as_text=True)


def test_deleting_a_secret_requires_csrf_and_the_confirmation_field(app):
    client = admin_client(app)
    secretstore.write_secret(app.config["DATA_DIR"], secretstore.SMTP_PASSWORD, SECRET_SMTP)
    without_csrf = client.post(
        "/admin/security/secret/delete",
        data={"name": secretstore.SMTP_PASSWORD, "confirm_delete": "1"},
    )
    assert without_csrf.status_code == 403
    without_confirmation = client.post(
        "/admin/security/secret/delete",
        data={"_csrf": session_csrf(client, app), "name": secretstore.SMTP_PASSWORD},
    )
    assert without_confirmation.status_code == 403
    unknown_name = client.post(
        "/admin/security/secret/delete",
        data={
            "_csrf": session_csrf(client, app),
            "name": "secret-inconnu",
            "confirm_delete": "1",
        },
    )
    assert unknown_name.status_code == 403
    assert (
        secretstore.read_secret(app.config["DATA_DIR"], secretstore.SMTP_PASSWORD) == SECRET_SMTP
    ), "aucune suppression ne doit avoir eu lieu"


def test_the_environment_secret_is_shown_as_provenance_only(app):
    client = admin_client(app)
    app.config["SMTP_PASSWORD"] = SECRET_SMTP
    body = client.get("/admin/security").get_data(as_text=True)
    assert "Fourni au déploiement" in body
    assert "variable d&#39;environnement" in body  # libellé échappé, jamais la valeur
    assert SECRET_SMTP not in body
    assert "Supprimer le secret" not in body, "pas de suppression d'un secret de déploiement"


def test_deleting_the_administrative_secret_reveals_the_environment_fallback(app):
    client = admin_client(app)
    app.config["SMTP_PASSWORD"] = SECRET_SMTP
    secretstore.write_secret(app.config["DATA_DIR"], secretstore.SMTP_PASSWORD, "administre")
    response = client.post(
        "/admin/security/secret/delete",
        data={
            "_csrf": session_csrf(client, app),
            "name": secretstore.SMTP_PASSWORD,
            "confirm_delete": "1",
        },
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    assert "redevient actif" in body
    assert "Fourni au déploiement" in body


def test_enabling_notifications_without_the_m365_secret_is_refused(app):
    client = admin_client(app)
    response = client.post(
        "/admin/security/settings",
        data={
            "_csrf": session_csrf(client, app),
            "notifications_enabled": "1",
            "severity_critical": "1", "severity_high": "1",
            "recipients": "equipe@valdev.me",
            "email_transport": "microsoft365",
            **M365_FORM, **SMTP_FORM,
        },
        follow_redirects=True,
    )
    assert "secret client Microsoft 365" in response.get_data(as_text=True)
    settings, _secrets = trivy_email.load_email_state(app)
    assert settings.notifications_enabled is False


def test_the_incomplete_transport_notice_is_shown(app):
    client = admin_client(app)
    connection = db.connect(app.config["DB_PATH"])
    trivy_monitor.save_settings(
        connection,
        {
            "security.notifications_enabled": "1",
            "security.recipients": "equipe@valdev.me",
            "security.email_transport": "microsoft365",
            "security.m365_tenant_id": "contoso.onmicrosoft.com",
            "security.m365_client_id": "11111111-2222-3333-4444-555555555555",
            "security.m365_mailbox": "hub@example.com",
        },
    )
    connection.close()
    body = client.get("/admin/security").get_data(as_text=True)
    assert "transport email incomplet" in body
    assert "Microsoft 365" in body
    assert "Incomplet" in body


def test_the_test_email_button_uses_the_microsoft365_transport(app, monkeypatch):
    from test_graph_email import FakeOpener, FakeResponse, token_response

    client = admin_client(app)
    client.post(
        "/admin/security/settings",
        data={
            "_csrf": session_csrf(client, app),
            "severity_critical": "1", "severity_high": "1",
            "recipients": "equipe@valdev.me",
            "email_transport": "microsoft365",
            "m365_client_secret_new": SECRET_M365,
            **M365_FORM, **SMTP_FORM,
        },
        follow_redirects=True,
    )
    fake = FakeOpener(token_response(), FakeResponse(202, b""))
    monkeypatch.setattr(graphmail, "_urlopen", fake)
    response = client.post(
        "/admin/security/test-email",
        data={"_csrf": session_csrf(client, app)},
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    assert "Envoi réussi" in body
    assert "Microsoft Graph" in body
    assert SECRET_M365 not in body


# --- Jeton GitHub administrable (V1.6.2) ----------------------------------------------


def test_the_github_token_can_be_stored_from_the_admin(app):
    client = admin_client(app)
    response = client.post(
        "/admin/security/settings",
        data={
            "_csrf": session_csrf(client, app),
            "github_token_new": SECRET_TOKEN,
            "smtp_port": "587", "smtp_timeout": "15", "smtp_security": "starttls",
        },
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    assert "Configuré (administration)" in body
    assert SECRET_TOKEN not in body
    assert (
        secretstore.read_secret(app.config["DATA_DIR"], secretstore.GITHUB_TOKEN) == SECRET_TOKEN
    )


def test_enabling_monitoring_with_a_stored_token_needs_no_deployment_variable(app):
    client = admin_client(app)
    app.config["GITHUB_TOKEN"] = ""
    response = client.post(
        "/admin/security/settings",
        data={
            "_csrf": session_csrf(client, app),
            "sync_enabled": "1",
            "github_token_new": SECRET_TOKEN,
            "smtp_port": "587", "smtp_timeout": "15", "smtp_security": "starttls",
        },
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    assert "Configuration de la surveillance enregistrée" in body
    assert "aucun jeton GitHub" not in body
    settings, _secrets = trivy_email.load_email_state(app)
    assert settings.sync_enabled is True


def test_enabling_monitoring_without_any_token_is_still_refused(app):
    client = admin_client(app)
    app.config["GITHUB_TOKEN"] = ""
    response = client.post(
        "/admin/security/settings",
        data={
            "_csrf": session_csrf(client, app),
            "sync_enabled": "1",
            "smtp_port": "587", "smtp_timeout": "15", "smtp_security": "starttls",
        },
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    assert "aucun jeton GitHub" in body
    settings, _secrets = trivy_email.load_email_state(app)
    assert settings.sync_enabled is False


def test_an_empty_token_field_keeps_the_stored_token(app):
    client = admin_client(app)
    secretstore.write_secret(app.config["DATA_DIR"], secretstore.GITHUB_TOKEN, SECRET_TOKEN)
    client.post(
        "/admin/security/settings",
        data={
            "_csrf": session_csrf(client, app),
            "github_token_new": "",
            "smtp_port": "587", "smtp_timeout": "15", "smtp_security": "starttls",
        },
        follow_redirects=True,
    )
    assert (
        secretstore.read_secret(app.config["DATA_DIR"], secretstore.GITHUB_TOKEN) == SECRET_TOKEN
    )


def test_deleting_the_github_token_reveals_the_environment_fallback(app):
    client = admin_client(app)
    app.config["GITHUB_TOKEN"] = SECRET_TOKEN
    secretstore.write_secret(app.config["DATA_DIR"], secretstore.GITHUB_TOKEN, "administre")
    response = client.post(
        "/admin/security/secret/delete",
        data={
            "_csrf": session_csrf(client, app),
            "name": secretstore.GITHUB_TOKEN,
            "confirm_delete": "1",
        },
        follow_redirects=True,
    )
    body = response.get_data(as_text=True)
    assert "redevient actif" in body
    assert "Fourni au déploiement" in body
    assert secretstore.read_secret(app.config["DATA_DIR"], secretstore.GITHUB_TOKEN) == ""


def test_the_sync_uses_the_administrative_github_token(app, monkeypatch):
    from app import trivy_github

    enable(app)  # réglages activés (validation passée avec un jeton)
    app.config["GITHUB_TOKEN"] = ""  # aucun jeton d'environnement
    secretstore.write_secret(app.config["DATA_DIR"], secretstore.GITHUB_TOKEN, SECRET_TOKEN)
    seen: list[str] = []

    def _record(token):
        seen.append(token)
        raise trivy_github.GitHubError("GitHub inaccessible (arrêt du test).")

    monkeypatch.setattr(trivy_github, "latest_successful_run", _record)
    result = trivy_monitor.sync(app)
    assert not result.ok and "GitHub inaccessible" in result.message
    assert seen == [SECRET_TOKEN]


def test_the_sync_falls_back_to_the_deployment_token(app, monkeypatch):
    from app import trivy_github

    enable(app)  # app.config["GITHUB_TOKEN"] = « jeton-de-test »
    seen: list[str] = []

    def _record(token):
        seen.append(token)
        raise trivy_github.GitHubError("GitHub inaccessible (arrêt du test).")

    monkeypatch.setattr(trivy_github, "latest_successful_run", _record)
    result = trivy_monitor.sync(app)
    assert not result.ok and "GitHub inaccessible" in result.message
    assert seen == ["jeton-de-test"]
