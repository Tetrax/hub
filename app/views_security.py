"""Administration — Sécurité de l'image (surveillance Trivy, V1.6.2).

Section strictement administrateur : état du dernier scan, liste des
vulnérabilités actionnables, configuration des alertes, du **transport email**
(SMTP ou Microsoft 365) et du **jeton GitHub** de la surveillance,
synchronisation manuelle et test d'envoi. Rien n'est exposé publiquement (voir
D22) et aucun secret n'est jamais rendu au navigateur : l'état des secrets se
limite à une provenance (« configuré (administration) », « fourni au
déploiement », « non configuré ») — jamais la valeur.
"""

from __future__ import annotations

import json

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for

from . import auth, secretstore, trivy_email, trivy_monitor
from .views_admin import _require_csrf, render_admin

bp = Blueprint("security", __name__, url_prefix="/admin/security")

FRESHNESS_LABELS = {
    "never": "Aucun rapport",
    "fresh": "À jour",
    "stale": "Rapport ancien",
}
SYNC_STATUS_LABELS = {
    "never": "Jamais synchronisé",
    "ok": "Synchronisation réussie",
    "error": "Échec de synchronisation",
    "ignored": "Rapport refusé",
}
NOTIFICATION_LABELS = {
    "": "—",
    "sent": "Envoyé",
    "failed": "Échec d'envoi",
    "none": "Non notifié",
}
SECRET_SOURCE_LABELS = {
    "": "Non configuré",
    secretstore.SOURCE_ADMIN: "Configuré (administration)",
    secretstore.SOURCE_ENV: "Fourni au déploiement (variable d'environnement)",
}


def _context(app):
    connection = auth.db_connection()
    settings = trivy_monitor.load_settings(connection)
    state = trivy_monitor.load_state(connection)
    return connection, settings, state


def _secrets(app) -> trivy_email.EmailSecrets:
    return trivy_email.load_email_state(app)[1]


@bp.get("")
@auth.admin_required
def dashboard():
    session_row = auth.require_session()
    connection, settings, state = _context(current_app)
    findings = list((state or {}).get("findings") or [])
    secrets = _secrets(current_app)
    github_token, github_token_source = trivy_monitor.effective_github_token(current_app)
    transport_complete = settings.transport_complete(
        smtp_password_present=secrets.smtp_present, m365_secret_present=secrets.m365_present
    )
    return render_admin(
        "admin/security.html",
        session_row,
        active_page="security",
        settings=settings,
        state=state,
        freshness=trivy_monitor.freshness(state),
        freshness_labels=FRESHNESS_LABELS,
        sync_status_labels=SYNC_STATUS_LABELS,
        notification_labels=NOTIFICATION_LABELS,
        secret_source_labels=SECRET_SOURCE_LABELS,
        next_sync=trivy_monitor.next_sync_at(state),
        findings_count=len(findings),
        events=trivy_monitor.recent_events(connection),
        github_token_set=bool(github_token),
        github_token_source=github_token_source,
        secrets=secrets,
        secret_names={
            "smtp": secretstore.SMTP_PASSWORD,
            "m365": secretstore.MICROSOFT365_CLIENT_SECRET,
            "github": secretstore.GITHUB_TOKEN,
        },
        transport_complete=transport_complete,
        transport_label=trivy_email.transport_label(settings),
        sync_interval_minutes=trivy_monitor.SYNC_INTERVAL_SECONDS // 60,
        stale_hours=trivy_monitor.STALE_SECONDS // 3600,
        events_display_limit=trivy_monitor.MAX_EVENTS_DISPLAY,
    )


@bp.get("/vulnerabilities")
@auth.admin_required
def vulnerabilities():
    session_row = auth.require_session()
    _connection, _settings, state = _context(current_app)
    findings = []
    if state:
        findings = [json.loads(json.dumps(item)) for item in state.get("findings") or []]
        findings.sort(key=lambda item: (0 if item.get("severity") == "critical" else 1,
                                        str(item.get("package") or ""), str(item.get("cve") or "")))
    return render_admin(
        "admin/security_findings.html",
        session_row,
        active_page="security",
        state=state,
        findings=findings,
        freshness=trivy_monitor.freshness(state),
        freshness_labels=FRESHNESS_LABELS,
    )


@bp.post("/sync")
@auth.admin_required
def sync_now():
    session_row = auth.require_session()
    _require_csrf(session_row)
    result = trivy_monitor.sync(current_app, manual=True)
    current_app.logger.info("Sécurité : synchronisation manuelle (%s)", "ok" if result.ok else "refusée")
    flash(result.message, "success" if result.ok else "error")
    return redirect(url_for("security.dashboard"))


@bp.post("/settings")
@auth.admin_required
def settings_save():
    session_row = auth.require_session()
    _require_csrf(session_row)
    connection = auth.db_connection()
    secrets = _secrets(current_app)
    github_token, _source = trivy_monitor.effective_github_token(current_app)
    # Un champ secret vide conserve le secret existant ; un champ rempli le remplace.
    new_smtp_password = request.form.get("smtp_password_new") or ""
    new_m365_secret = request.form.get("m365_client_secret_new") or ""
    new_github_token = request.form.get("github_token_new") or ""
    values, errors = trivy_monitor.validate_settings(
        request.form,
        github_token_present=bool(new_github_token) or bool(github_token),
        smtp_password_present=bool(new_smtp_password) or secrets.smtp_present,
        m365_secret_present=bool(new_m365_secret) or secrets.m365_present,
    )
    if errors:
        for message in errors:
            flash(message, "error")
        return redirect(url_for("security.dashboard"))
    # Les secrets d'abord : si le stockage refuse, rien n'est enregistré. Les
    # valeurs sont toutes validées avant toute écriture (jamais d'état partiel).
    data_dir = current_app.config["DATA_DIR"]
    replacements = (
        (secretstore.SMTP_PASSWORD, new_smtp_password, "Mot de passe SMTP"),
        (secretstore.MICROSOFT365_CLIENT_SECRET, new_m365_secret, "Secret client Microsoft 365"),
        (secretstore.GITHUB_TOKEN, new_github_token, "Jeton GitHub"),
    )
    try:
        for _name, value, _label in replacements:
            if value:
                secretstore.validate_secret(value)
    except secretstore.SecretValidationError:
        flash("Secret invalide (vide ou trop long).", "error")
        return redirect(url_for("security.dashboard"))
    for name, value, _label in replacements:
        if not value:
            continue
        try:
            secretstore.write_secret(data_dir, name, value)
        except OSError:
            current_app.logger.error("Sécurité : stockage des secrets indisponible (%s)", name)
            flash("Stockage des secrets indisponible : secret non enregistré.", "error")
            return redirect(url_for("security.dashboard"))
    trivy_monitor.save_settings(connection, values)
    if new_smtp_password or new_m365_secret or new_github_token:
        current_app.logger.info("Sécurité : secret remplacé depuis l'administration")
    current_app.logger.info("Sécurité : configuration des alertes enregistrée")
    flash("Configuration de la surveillance enregistrée.", "success")
    return redirect(url_for("security.dashboard"))


@bp.post("/secret/delete")
@auth.admin_required
def secret_delete():
    session_row = auth.require_session()
    _require_csrf(session_row)
    name = (request.form.get("name") or "").strip()
    if name not in secretstore.SECRET_NAMES or request.form.get("confirm_delete") != "1":
        abort(403)
    data_dir = current_app.config["DATA_DIR"]
    removed = secretstore.delete_secret(data_dir, name)
    current_app.logger.info("Sécurité : secret supprimé (%s : %s)", name, "oui" if removed else "absent")
    if not removed:
        flash("Aucun secret enregistré à supprimer.", "error")
        return redirect(url_for("security.dashboard"))
    environments = {
        secretstore.SMTP_PASSWORD: current_app.config.get("SMTP_PASSWORD") or "",
        secretstore.MICROSOFT365_CLIENT_SECRET: current_app.config.get("MICROSOFT_CLIENT_SECRET") or "",
        secretstore.GITHUB_TOKEN: current_app.config.get("GITHUB_TOKEN") or "",
    }
    if secretstore.status(data_dir, name, environments.get(name, "")):
        flash(
            "Secret supprimé — le secret fourni au déploiement (variable "
            "d'environnement) redevient actif.",
            "success",
        )
    else:
        flash("Secret supprimé.", "success")
    return redirect(url_for("security.dashboard"))


@bp.post("/test-email")
@auth.admin_required
def test_email():
    session_row = auth.require_session()
    _require_csrf(session_row)
    ok, detail = trivy_email.send_test_email(current_app)
    if ok:
        settings, _secrets = trivy_email.load_email_state(current_app)
        destinations = ", ".join(settings.recipients)
        flash(f"Envoi réussi — {detail} Destinataires : {destinations}.", "success")
    else:
        flash(f"Test d'envoi : {detail}", "error")
    return redirect(url_for("security.dashboard"))


@bp.post("/retry-notification")
@auth.admin_required
def retry_notification():
    session_row = auth.require_session()
    _require_csrf(session_row)
    result = trivy_monitor.retry_failed_notification(current_app)
    flash(result.message, "success" if result.ok else "error")
    return redirect(url_for("security.dashboard"))
