"""Administration — Sécurité de l'image (surveillance Trivy, V1.6).

Section strictement administrateur : état du dernier scan, liste des
vulnérabilités actionnables, configuration des alertes, synchronisation manuelle
et test d'envoi. Rien n'est exposé publiquement (voir D22) et aucun secret n'est
jamais rendu au navigateur : l'état des jetons se limite à « fourni / absent ».
"""

from __future__ import annotations

import json

from flask import Blueprint, current_app, flash, redirect, render_template, request, url_for

from . import auth, trivy_email, trivy_monitor
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


def _context(app):
    connection = auth.db_connection()
    settings = trivy_monitor.load_settings(connection)
    state = trivy_monitor.load_state(connection)
    return connection, settings, state


@bp.get("")
@auth.admin_required
def dashboard():
    session_row = auth.require_session()
    connection, settings, state = _context(current_app)
    findings = list((state or {}).get("findings") or [])
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
        next_sync=trivy_monitor.next_sync_at(state),
        findings_count=len(findings),
        events=trivy_monitor.recent_events(connection),
        github_token_set=bool((current_app.config.get("GITHUB_TOKEN") or "").strip()),
        smtp_password_set=bool((current_app.config.get("SMTP_PASSWORD") or "").strip()),
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
    token_present = bool((current_app.config.get("GITHUB_TOKEN") or "").strip())
    password_present = bool((current_app.config.get("SMTP_PASSWORD") or "").strip())
    values, errors = trivy_monitor.validate_settings(
        request.form, github_token_present=token_present, smtp_password_present=password_present
    )
    if errors:
        for message in errors:
            flash(message, "error")
        return redirect(url_for("security.dashboard"))
    trivy_monitor.save_settings(connection, values)
    current_app.logger.info("Sécurité : configuration des alertes enregistrée")
    flash("Configuration de la surveillance enregistrée.", "success")
    return redirect(url_for("security.dashboard"))


@bp.post("/test-email")
@auth.admin_required
def test_email():
    session_row = auth.require_session()
    _require_csrf(session_row)
    ok, detail = trivy_email.send_test_email(current_app)
    if ok:
        connection = auth.db_connection()
        settings = trivy_monitor.load_settings(connection)
        destinations = ", ".join(settings.recipients)
        flash(f"Envoi réussi ({detail}) — destinataires : {destinations}.", "success")
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

