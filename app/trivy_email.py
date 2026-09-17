"""Emails de changement de sécurité : composition SNS + transport SMTP.

Un email par synchronisation au **maximum**, et uniquement si un changement
pertinent existe (voir `app/trivy_monitor.py`). L'envoi ne lève jamais : toutes les
pannes (configuration incomplète, DNS, connexion, STARTTLS, authentification,
timeout, message invalide) sont converties en résultat exploitable, journalisées
sans le mot de passe, et n'affectent ni la baseline ni le reste de l'application.

Transport retenu (V1.6, D22) : **SMTP standard** (implicite TLS, STARTTLS ou sans
chiffrement explicitement autorisé), la primitive éprouvée de FortiUpgrade. Le mot
de passe vient du déploiement (`HUB_SMTP_PASSWORD`), jamais de la base, jamais d'une
réponse HTTP, jamais d'un log. Microsoft 365 / Graph est documenté comme évolution
ultérieure : l'intégrer doublerait le chantier pour un besoin non démontré.

Le rendu utilise la direction artistique SNS en HTML simple (tables, styles en
ligne) : lisible dans Outlook, sans CSS exotique. Toute valeur dynamique est
échappée ; un lien CVE n'est rendu que si l'URL a été validée (HTTPS) à
l'ingestion, re-vérifiée ici.
"""

from __future__ import annotations

import html
import smtplib
import ssl
import urllib.parse
from email.message import EmailMessage

from . import trivy_monitor

SEVERITY_LABELS = {"critical": "CRITICAL", "high": "HIGH"}
KIND_LABELS = {
    "new": "Nouveaux",
    "resolved": "Non détectées dans la nouvelle image",
    "severity_up": "Aggravations",
    "severity_down": "Atténuations",
}


def _safe_url(value: str) -> str:
    """URL cliquable uniquement si https simple (défense en profondeur, jamais un href brut)."""
    if not value or len(value) > 500:
        return ""
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        return ""
    if any(character in value for character in ("\n", "\r", "\t", "<", ">", '"', "'")):
        return ""
    return value


def _counts(events: list[dict]) -> dict:
    counts = {
        "new_critical": 0,
        "new_high": 0,
        "resolved": 0,
        "severity": 0,
    }
    for event in events:
        kind = event.get("kind")
        severity = event.get("severity") or ""
        if kind == "new":
            if severity == "critical":
                counts["new_critical"] += 1
            elif severity == "high":
                counts["new_high"] += 1
        elif kind == "resolved":
            counts["resolved"] += 1
        elif kind in ("severity_up", "severity_down"):
            counts["severity"] += 1
    return counts


def compose_subject(events: list[dict]) -> str:
    total = len(events)
    suffix = "changement détecté" if total == 1 else "changements détectés"
    return f"[SNS Hub] Sécurité de l'image — {total} {suffix}"


def _severity_cell(event: dict) -> str:
    severity = (event.get("severity") or "").upper()
    previous = event.get("detail", {}).get("previous_severity")
    if previous:
        return f"{previous.upper()} → {severity}"
    return severity or "—"


def compose_bodies(events: list[dict], scan, *, base_url: str, run_url: str = "") -> tuple[str, str]:
    """Corps texte et HTML du mail de changement (une synchronisation = un email)."""
    counts = _counts(events)
    commit = (scan.commit or "")[:12] or "inconnu"
    scan_at = scan.scanned_at or "inconnu"
    safe_run_url = _safe_url(run_url)

    summary_lines: list[str] = []
    if counts["new_critical"] or counts["new_high"]:
        parts = []
        if counts["new_critical"]:
            parts.append(f"{counts['new_critical']} CRITICAL")
        if counts["new_high"]:
            parts.append(f"{counts['new_high']} HIGH")
        summary_lines.append("Nouveaux : " + ", ".join(parts))
    if counts["resolved"]:
        summary_lines.append(f"Non détectées dans la nouvelle image : {counts['resolved']}")
    if counts["severity"]:
        summary_lines.append(f"Changements de sévérité : {counts['severity']}")

    rows = []
    for event in events:
        detail = event.get("detail") or {}
        rows.append(
            {
                "severity": _severity_cell(event),
                "kind": KIND_LABELS.get(event.get("kind", ""), event.get("kind", "")),
                "cve": str(detail.get("cve") or ""),
                "package": str(detail.get("package") or ""),
                "installed": str(detail.get("installed_version") or "—"),
                "fixed": str(detail.get("fixed_version") or "—"),
                "url": _safe_url(str(detail.get("advisory_url") or "")),
            }
        )

    text_lines = ["SNS Hub — Sécurité de l'image", "", "Résumé :"]
    text_lines.extend(f"- {line}" for line in summary_lines)
    text_lines.extend(["", "Détail :"])
    for row in rows:
        cve = f"{row['cve']} ({row['url']})" if row["url"] else row["cve"]
        text_lines.append(
            f"- [{row['severity']}] {cve} — {row['package']} — "
            f"installé {row['installed']}, correctif {row['fixed']} ({row['kind']})"
        )
    text_lines.extend(["", f"Commit : {commit}", f"Date du scan : {scan_at}"])
    if safe_run_url:
        text_lines.append(f"Run GitHub : {safe_run_url}")
    if base_url:
        text_lines.extend(["", f"Voir dans SNS Hub : {base_url}/admin/security"])
    text = "\n".join(text_lines) + "\n"

    def cell(value: str) -> str:
        return html.escape(value, quote=True)

    html_rows = []
    for row in rows:
        cve_html = cell(row["cve"])
        if row["url"]:
            cve_html = (
                f'<a href="{cell(row["url"])}" style="color:#B23A6B;text-decoration:none;">'
                f"{cve_html}</a>"
            )
        severity_color = "#B3202B" if "CRITICAL" in row["severity"] else "#8A5A00"
        html_rows.append(
            "<tr>"
            f'<td style="padding:8px 10px;border-bottom:1px solid #E3E3E6;color:{severity_color};'
            f'font-weight:600;white-space:nowrap;">{cell(row["severity"])}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #E3E3E6;">{cve_html}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #E3E3E6;font-family:Consolas,'
            f'monospace;font-size:13px;">{cell(row["package"])}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #E3E3E6;font-family:Consolas,'
            f'monospace;font-size:13px;">{cell(row["installed"])}</td>'
            f'<td style="padding:8px 10px;border-bottom:1px solid #E3E3E6;font-family:Consolas,'
            f'monospace;font-size:13px;">{cell(row["fixed"])}</td>'
            "</tr>"
        )
    summary_html = "".join(
        f'<li style="margin:2px 0;color:#141417;">{cell(line)}</li>' for line in summary_lines
    )
    cta = ""
    if base_url:
        cta = (
            '<tr><td style="padding:0 28px 24px;">'
            f'<a href="{cell(base_url)}/admin/security" style="display:inline-block;'
            "padding:10px 18px;border-radius:999px;background:#F4A8C9;color:#0B0B0D;"
            'text-decoration:none;font-weight:600;">Voir dans SNS Hub</a></td></tr>'
        )
    html_body = (
        '<html><body style="margin:0;padding:0;background:#ECECEE;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="background:#ECECEE;padding:24px 12px;"><tr><td align="center">'
        '<table role="presentation" width="640" cellpadding="0" cellspacing="0" '
        'style="max-width:640px;width:100%;background:#FFFFFF;border-radius:14px;'
        'overflow:hidden;font-family:Segoe UI,Arial,sans-serif;">'
        '<tr><td style="background:#0B0B0D;padding:20px 28px;">'
        '<span style="color:#F4A8C9;font-size:20px;font-weight:700;">SNS</span>'
        '<span style="color:#ECECEE;font-size:15px;">&nbsp;| Sécurité de l\'image</span>'
        "</td></tr>"
        '<tr><td style="padding:22px 28px 6px;">'
        f'<p style="margin:0 0 10px;color:#141417;font-size:15px;">{len(events)} '
        f"changement{'s' if len(events) > 1 else ''} détecté"
        f"{'s' if len(events) > 1 else ''} sur l'image SNS Hub.</p>"
        f'<ul style="margin:0 0 14px;padding-left:18px;font-size:14px;">{summary_html}</ul>'
        "</td></tr>"
        '<tr><td style="padding:0 28px;">'
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        'style="border-collapse:collapse;font-size:13px;">'
        '<tr><th align="left" style="padding:8px 10px;border-bottom:2px solid #141417;'
        'color:#5A5A61;font-size:12px;letter-spacing:0.05em;text-transform:uppercase;">'
        "Sévérité</th>"
        '<th align="left" style="padding:8px 10px;border-bottom:2px solid #141417;color:#5A5A61;'
        'font-size:12px;letter-spacing:0.05em;text-transform:uppercase;">CVE</th>'
        '<th align="left" style="padding:8px 10px;border-bottom:2px solid #141417;color:#5A5A61;'
        'font-size:12px;letter-spacing:0.05em;text-transform:uppercase;">Package</th>'
        '<th align="left" style="padding:8px 10px;border-bottom:2px solid #141417;color:#5A5A61;'
        'font-size:12px;letter-spacing:0.05em;text-transform:uppercase;">Installé</th>'
        '<th align="left" style="padding:8px 10px;border-bottom:2px solid #141417;color:#5A5A61;'
        'font-size:12px;letter-spacing:0.05em;text-transform:uppercase;">Correctif</th></tr>'
        + "".join(html_rows)
        + "</table></td></tr>"
        '<tr><td style="padding:18px 28px 4px;color:#5A5A61;font-size:13px;">'
        f"Commit : {cell(commit)}<br>Date du scan : {cell(scan_at)}"
        + (
            f'<br>Run GitHub : <a href="{cell(safe_run_url)}" '
            'style="color:#B23A6B;text-decoration:none;">voir le run</a>'
            if safe_run_url
            else ""
        )
        + "</td></tr>"
        + cta
        + '<tr><td style="background:#141417;padding:14px 28px;color:#9A9AA1;font-size:12px;">'
        "SNS Hub — surveillance de l'image, alimentée par le scan Trivy de la CI. "
        "Un email uniquement lorsqu'un changement est détecté."
        "</td></tr>"
        "</table></td></tr></table></body></html>"
    )
    return text, html_body


def _smtp_send(settings: trivy_monitor.SecuritySettings, password: str, message: EmailMessage) -> tuple[bool, str]:
    """Envoi SMTP : ne lève jamais, ne journalise jamais le mot de passe."""
    security = settings.smtp_security
    stage = "connexion"
    try:
        if security == "ssl":
            client = smtplib.SMTP_SSL(
                settings.smtp_host,
                settings.smtp_port,
                timeout=settings.smtp_timeout,
                context=ssl.create_default_context(),
            )
        else:
            client = smtplib.SMTP(
                settings.smtp_host, settings.smtp_port, timeout=settings.smtp_timeout
            )
        with client:
            if security == "starttls":
                stage = "starttls"
                client.starttls(context=ssl.create_default_context())
            if settings.smtp_username:
                stage = "authentification"
                client.login(settings.smtp_username, password)
            stage = "envoi"
            client.send_message(message)
        return True, "Email envoyé."
    except smtplib.SMTPAuthenticationError:
        return False, "Authentification SMTP refusée."
    except smtplib.SMTPSenderRefused:
        return False, "Expéditeur refusé par le serveur SMTP."
    except smtplib.SMTPRecipientsRefused:
        return False, "Destinataire refusé par le serveur SMTP."
    except (smtplib.SMTPException, ConnectionError, TimeoutError, ssl.SSLError, OSError) as error:
        return False, f"Échec SMTP ({stage}) : {type(error).__name__}."
    except (ValueError, TypeError, AttributeError):
        return False, "Message email invalide."


def _build_message(
    settings: trivy_monitor.SecuritySettings, subject: str, text: str, html_body: str
) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = settings.smtp_from
    message["To"] = ", ".join(settings.recipients)
    message.set_content(text)
    message.add_alternative(html_body, subtype="html")
    return message


def _base_url(app) -> str:
    """URL publique du Hub (CTA), dérivée du hostname configuré si disponible."""
    hostname = (app.config.get("TLS_HOSTNAME") or "").strip()
    return f"https://{hostname}" if hostname else ""


def send_delta_email(app, events: list[dict], scan) -> tuple[bool, str]:
    """Compose et envoie l'email de changement. Retourne (ok, message nettoyé)."""
    try:
        from . import db

        connection = db.connect(app.config["DB_PATH"])
        try:
            settings = trivy_monitor.load_settings(connection)
            state = trivy_monitor.load_state(connection) or {}
        finally:
            connection.close()
    except OSError:
        return False, "Base de données illisible (configuration email indisponible)."
    password = (app.config.get("SMTP_PASSWORD") or "").strip()
    if not settings.notifications_enabled:
        return False, "Notifications désactivées."
    if not settings.smtp_complete(password_present=bool(password)):
        return False, "Configuration SMTP incomplète ou invalide."
    subject = compose_subject(events)
    try:
        text, html_body = compose_bodies(
            events, scan, base_url=_base_url(app), run_url=str(state.get("run_url") or "")
        )
        message = _build_message(settings, subject, text, html_body)
    except (ValueError, TypeError, AttributeError):
        return False, "Message email invalide."
    return _smtp_send(settings, password, message)


def send_test_email(app) -> tuple[bool, str]:
    """Test d'envoi depuis l'admin : utilise exactement la configuration sauvegardée."""
    try:
        from . import db

        connection = db.connect(app.config["DB_PATH"])
        try:
            settings = trivy_monitor.load_settings(connection)
        finally:
            connection.close()
    except OSError:
        return False, "Base de données illisible (configuration email indisponible)."
    password = (app.config.get("SMTP_PASSWORD") or "").strip()
    if not settings.smtp_complete(password_present=bool(password)):
        return False, "Configuration SMTP incomplète (serveur, expéditeur, destinataires)."
    base_url = _base_url(app)
    from .trivy import Scan

    scan = Scan(image="", commit="", scanned_at="", findings=())
    events = [
        {
            "kind": "new",
            "severity": "high",
            "summary": "Test d'envoi",
            "detail": {
                "cve": "CVE-0000-0000",
                "package": "exemple",
                "installed_version": "1.0",
                "fixed_version": "1.1",
                "advisory_url": "",
            },
        }
    ]
    try:
        text, html_body = compose_bodies(events, scan, base_url=base_url)
        message = _build_message(settings, "[SNS Hub] Test de notification sécurité", text, html_body)
    except (ValueError, TypeError, AttributeError):
        return False, "Message email invalide."
    return _smtp_send(settings, password, message)
