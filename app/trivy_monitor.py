"""Surveillance Trivy de Hub : configuration, état, baseline, delta, synchronisation.

Hub est un **consumer** : il télécharge l'artefact `trivy-report` produit par la CI
(voir `app/trivy_github.py`), le valide (`app/trivy.py`), le publie de façon
atomique dans son propre état (SQLite, la persistance existante) et n'émet que les
**changements pertinents**.

Règles exactes appliquées ici :

- **Identité d'un finding** : CVE + paquet, jamais la version installée. Une image
  reconstruite ne fait donc pas réapparaître les mêmes CVE comme « nouvelles ».
- **Première ingestion** : baseline initiale silencieuse (aucun événement, aucun
  email) — les findings déjà présents au moment de l'activation ne sont pas une
  alerte.
- **Delta** (à partir de la seconde baseline) : apparition, disparition (dit
  « vulnérabilité non détectée dans la nouvelle image », jamais « corrigée » sans
  preuve), et changement de sévérité (aggravation ou atténuation).
- **Rafraîchissement silencieux** : un changement de version installée, de version
  corrigée ou de titre met l'état à jour sans créer d'événement ni d'email.
- **Idempotence** : même run ou même rapport (SHA-256) → aucune écriture, aucun
  événement, aucun email.
- **Rapport non plus récent** : un run ou un scan plus ancien que l'état courant est
  refusé ; la baseline n'est jamais remplacée par accident.
- **Publication atomique** : un téléchargement, une validation ou un parse qui
  échoue conserve intégralement le dernier état valide — jamais de fausse
  « résolution » quand GitHub est simplement indisponible.
- **Un email au maximum par synchronisation**, et uniquement si un événement
  notifiable existe et que les notifications sont activées. Un échec SMTP ne
  revient pas sur la baseline (sinon la même CVE serait « nouvelle » à chaque
  synchronisation) : l'événement est marqué en échec, visible dans l'admin, et
  peut être renvoyé.

La feature est **désactivée par défaut** ; l'activation depuis l'admin exige un
jeton GitHub en lecture seule (`HUB_GITHUB_TOKEN`) et, pour les emails, un
transport email complet — SMTP **ou** Microsoft 365 — configurable dans la
webapp (V1.6.1, D23). Les secrets (mot de passe SMTP, secret client Microsoft
365, jeton GitHub) vivent dans des fichiers dédiés du répertoire de données (voir
`app/secretstore.py`) ; les variables d'environnement ne servent que de
bootstrap.
"""

from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import db, trivy
from .trivy import Finding, ReportError, Scan

SYNC_INTERVAL_SECONDS = 3600
STALE_SECONDS = 48 * 3600
MANUAL_SYNC_MIN_INTERVAL_SECONDS = 60
MAX_EVENTS_DISPLAY = 20
LOCK_FILENAME = "trivy-sync.lock"
MAX_RECIPIENTS = 10
MAX_DISPLAY_NAME = 80

# Transports email (D23) : un seul actif à la fois, persisté en base.
TRANSPORT_SMTP = "smtp"
TRANSPORT_MICROSOFT365 = "microsoft365"
EMAIL_TRANSPORTS = (TRANSPORT_SMTP, TRANSPORT_MICROSOFT365)
M365_DEFAULT_DISPLAY_NAME = "SNS Hub"

SETTING_KEYS = (
    "security.sync_enabled",
    "security.notifications_enabled",
    "security.notify_new",
    "security.notify_resolved",
    "security.notify_severity",
    "security.severity_critical",
    "security.severity_high",
    "security.recipients",
    "security.email_transport",
    "security.smtp_host",
    "security.smtp_port",
    "security.smtp_security",
    "security.smtp_username",
    "security.smtp_from",
    "security.smtp_display_name",
    "security.smtp_timeout",
    "security.m365_tenant_id",
    "security.m365_client_id",
    "security.m365_mailbox",
    "security.m365_display_name",
)

DEFAULT_VALUES = {
    "security.sync_enabled": "0",
    "security.notifications_enabled": "0",
    "security.notify_new": "1",
    "security.notify_resolved": "1",
    "security.notify_severity": "1",
    "security.severity_critical": "1",
    "security.severity_high": "1",
    "security.recipients": "",
    "security.email_transport": TRANSPORT_SMTP,
    "security.smtp_host": "",
    "security.smtp_port": "587",
    "security.smtp_security": "starttls",
    "security.smtp_username": "",
    "security.smtp_from": "",
    "security.smtp_display_name": "",
    "security.smtp_timeout": "15",
    "security.m365_tenant_id": "",
    "security.m365_client_id": "",
    "security.m365_mailbox": "",
    "security.m365_display_name": M365_DEFAULT_DISPLAY_NAME,
}

_EMAIL_RE = re.compile(r"^[^@\s,;<>]{1,64}@[^@\s,;<>]{1,190}\.[A-Za-z]{2,24}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,253})$")
_GUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
_TENANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")

EVENT_LABELS = {
    "baseline": "Baseline initialisée",
    "new": "Nouveau finding",
    "resolved": "Vulnérabilité non détectée",
    "severity_up": "Aggravation de sévérité",
    "severity_down": "Atténuation de sévérité",
}


# --- Configuration fonctionnelle -------------------------------------------------


@dataclass(frozen=True)
class SecuritySettings:
    sync_enabled: bool = False
    notifications_enabled: bool = False
    notify_new: bool = True
    notify_resolved: bool = True
    notify_severity: bool = True
    severities: tuple[str, ...] = trivy.ALLOWED_SEVERITIES
    recipients: tuple[str, ...] = ()
    email_transport: str = TRANSPORT_SMTP
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"
    smtp_username: str = ""
    smtp_from: str = ""
    smtp_display_name: str = ""
    smtp_timeout: int = 15
    m365_tenant_id: str = ""
    m365_client_id: str = ""
    m365_mailbox: str = ""
    m365_display_name: str = M365_DEFAULT_DISPLAY_NAME

    def smtp_complete(self, *, password_present: bool) -> bool:
        """Configuration SMTP exploitable : hôte, port, expéditeur, destinataires."""
        if not (self.smtp_host and self.smtp_from and self.recipients):
            return False
        if self.smtp_username and not password_present:
            return False
        return True

    def m365_complete(self, *, secret_present: bool) -> bool:
        """Configuration Microsoft 365 exploitable : identité, boîte, secret, destinataires."""
        if not (self.m365_tenant_id and self.m365_client_id and self.m365_mailbox):
            return False
        if not secret_present or not self.recipients:
            return False
        return True

    def transport_complete(
        self, *, smtp_password_present: bool, m365_secret_present: bool
    ) -> bool:
        """Le transport **sélectionné** est-il exploitable ? (l'autre n'entre pas en jeu)"""
        if self.email_transport == TRANSPORT_MICROSOFT365:
            return self.m365_complete(secret_present=m365_secret_present)
        if self.email_transport == TRANSPORT_SMTP:
            return self.smtp_complete(password_present=smtp_password_present)
        return False

    def notifies(self, kind: str, severity: str) -> bool:
        """Un événement est notifiable selon son type et sa sévérité effective."""
        if not self.notifications_enabled:
            return False
        if severity and severity not in self.severities:
            return False
        if kind == "new":
            return self.notify_new
        if kind == "resolved":
            return self.notify_resolved
        if kind in ("severity_up", "severity_down"):
            return self.notify_severity
        # `baseline` n'est jamais notifiée (première activation silencieuse).
        return False


def _as_bool(value: str) -> bool:
    return value == "1"


def load_settings(connection) -> SecuritySettings:
    values = {
        key: db.get_setting(connection, key, DEFAULT_VALUES.get(key, "")) for key in SETTING_KEYS
    }
    recipients = tuple(
        chunk
        for chunk in (line.strip() for line in re.split(r"[\n,;]+", values["security.recipients"]))
        if chunk
    )
    severities = tuple(
        severity
        for severity, key in (("critical", "security.severity_critical"), ("high", "security.severity_high"))
        if _as_bool(values[key])
    )
    try:
        port = int(values["security.smtp_port"])
    except ValueError:
        port = 587
    try:
        timeout = int(values["security.smtp_timeout"])
    except ValueError:
        timeout = 15
    return SecuritySettings(
        sync_enabled=_as_bool(values["security.sync_enabled"]),
        notifications_enabled=_as_bool(values["security.notifications_enabled"]),
        notify_new=_as_bool(values["security.notify_new"]),
        notify_resolved=_as_bool(values["security.notify_resolved"]),
        notify_severity=_as_bool(values["security.notify_severity"]),
        severities=severities,
        recipients=recipients,
        email_transport=values["security.email_transport"].strip().lower(),
        smtp_host=values["security.smtp_host"].strip(),
        smtp_port=port,
        smtp_security=values["security.smtp_security"].strip().lower(),
        smtp_username=values["security.smtp_username"].strip(),
        smtp_from=values["security.smtp_from"].strip(),
        smtp_display_name=values["security.smtp_display_name"].strip(),
        smtp_timeout=timeout,
        m365_tenant_id=values["security.m365_tenant_id"].strip(),
        m365_client_id=values["security.m365_client_id"].strip(),
        m365_mailbox=values["security.m365_mailbox"].strip(),
        m365_display_name=values["security.m365_display_name"].strip()
        or M365_DEFAULT_DISPLAY_NAME,
    )


def _clean_display_name(value: str) -> str:
    return " ".join((value or "").split())


def validate_settings(
    form,
    *,
    github_token_present: bool,
    smtp_password_present: bool,
    m365_secret_present: bool = False,
) -> tuple[dict, list[str]]:
    """Valide le formulaire admin ; retourne (valeurs, erreurs). Aucun secret ici."""
    errors: list[str] = []
    flags = {
        "security.sync_enabled": form.get("sync_enabled") == "1",
        "security.notifications_enabled": form.get("notifications_enabled") == "1",
        "security.notify_new": form.get("notify_new") == "1",
        "security.notify_resolved": form.get("notify_resolved") == "1",
        "security.notify_severity": form.get("notify_severity") == "1",
        "security.severity_critical": form.get("severity_critical") == "1",
        "security.severity_high": form.get("severity_high") == "1",
    }
    if flags["security.sync_enabled"] and not github_token_present:
        errors.append(
            "Surveillance impossible : aucun jeton GitHub (lecture seule, portée "
            "Actions: Read) n'est configuré — le saisir dans cette page, ou fournir "
            "HUB_GITHUB_TOKEN au déploiement."
        )

    transport = (form.get("email_transport") or TRANSPORT_SMTP).strip().lower()
    if transport not in EMAIL_TRANSPORTS:
        errors.append("Transport email invalide (smtp ou microsoft365).")
        transport = TRANSPORT_SMTP

    raw_recipients = (form.get("recipients") or "").replace("\r", "\n")
    recipients = [
        chunk.strip()
        for chunk in re.split(r"[\n,;]+", raw_recipients)
        if chunk.strip()
    ]
    if len(recipients) > MAX_RECIPIENTS:
        errors.append(f"Destinataires : {MAX_RECIPIENTS} au maximum.")
    for address in recipients:
        if not _EMAIL_RE.fullmatch(address):
            errors.append(f"Destinataire invalide : {address[:80]}.")
            break

    host = (form.get("smtp_host") or "").strip()
    if host and not _HOST_RE.fullmatch(host):
        errors.append("Serveur SMTP invalide (nom d'hôte ou adresse sans espace ni schéma).")
    raw_port = (form.get("smtp_port") or "").strip()
    port = 587
    if raw_port:
        try:
            port = int(raw_port)
        except ValueError:
            errors.append("Port SMTP invalide.")
        else:
            if not 1 <= port <= 65535:
                errors.append("Port SMTP hors plage (1-65535).")
    security = (form.get("smtp_security") or "starttls").strip().lower()
    if security not in ("starttls", "ssl", "none"):
        errors.append("Sécurité SMTP invalide (starttls, ssl ou none).")
    username = (form.get("smtp_username") or "").strip()
    if len(username) > 255:
        errors.append("Identifiant SMTP trop long.")
    from_address = (form.get("smtp_from") or "").strip()
    if from_address and not _EMAIL_RE.fullmatch(from_address):
        errors.append("Expéditeur invalide.")
    smtp_display_name = _clean_display_name(form.get("smtp_display_name") or "")
    if len(smtp_display_name) > MAX_DISPLAY_NAME:
        errors.append(f"Nom d'affichage SMTP : {MAX_DISPLAY_NAME} caractères au maximum.")
    raw_timeout = (form.get("smtp_timeout") or "").strip()
    timeout = 15
    if raw_timeout:
        try:
            timeout = int(raw_timeout)
        except ValueError:
            errors.append("Délai SMTP invalide.")
        else:
            if not 5 <= timeout <= 60:
                errors.append("Délai SMTP hors plage (5-60 secondes).")

    tenant_id = (form.get("m365_tenant_id") or "").strip()
    if tenant_id and not _TENANT_RE.fullmatch(tenant_id):
        errors.append("Tenant ID Microsoft 365 invalide (identifiant ou domaine, sans espace).")
    client_id = (form.get("m365_client_id") or "").strip()
    if client_id and not _GUID_RE.fullmatch(client_id):
        errors.append("Client ID Microsoft 365 invalide (GUID attendu).")
    mailbox = (form.get("m365_mailbox") or "").strip()
    if mailbox and not (_EMAIL_RE.fullmatch(mailbox) or _GUID_RE.fullmatch(mailbox)):
        errors.append("Boîte Microsoft 365 invalide (adresse email attendue).")
    m365_display_name = _clean_display_name(form.get("m365_display_name") or "")
    if len(m365_display_name) > MAX_DISPLAY_NAME:
        errors.append(
            f"Nom d'affichage Microsoft 365 : {MAX_DISPLAY_NAME} caractères au maximum."
        )
    m365_display_name = m365_display_name or M365_DEFAULT_DISPLAY_NAME

    if flags["security.notifications_enabled"]:
        if not recipients:
            errors.append("Notifications activées sans destinataire.")
        if not (flags["security.severity_critical"] or flags["security.severity_high"]):
            errors.append("Notifications activées sans aucune sévérité suivie.")
        if transport == TRANSPORT_SMTP:
            if not host:
                errors.append("Notifications activées sans serveur SMTP.")
            if not from_address:
                errors.append("Notifications activées sans expéditeur.")
            if username and not smtp_password_present:
                errors.append(
                    "Notifications activées avec un identifiant SMTP, mais aucun mot de passe "
                    "SMTP n'est configuré (le saisir dans cette page, ou fournir "
                    "HUB_SMTP_PASSWORD au déploiement)."
                )
        else:
            if not tenant_id:
                errors.append("Notifications activées sans Tenant ID Microsoft 365.")
            if not client_id:
                errors.append("Notifications activées sans Client ID Microsoft 365.")
            if not mailbox:
                errors.append("Notifications activées sans boîte Microsoft 365.")
            if not m365_secret_present:
                errors.append(
                    "Notifications activées sans secret client Microsoft 365 (le saisir dans "
                    "cette page, ou fournir HUB_MICROSOFT_CLIENT_SECRET au déploiement)."
                )

    values = {
        "security.sync_enabled": "1" if flags["security.sync_enabled"] else "0",
        "security.notifications_enabled": "1" if flags["security.notifications_enabled"] else "0",
        "security.notify_new": "1" if flags["security.notify_new"] else "0",
        "security.notify_resolved": "1" if flags["security.notify_resolved"] else "0",
        "security.notify_severity": "1" if flags["security.notify_severity"] else "0",
        "security.severity_critical": "1" if flags["security.severity_critical"] else "0",
        "security.severity_high": "1" if flags["security.severity_high"] else "0",
        "security.recipients": "\n".join(recipients),
        "security.email_transport": transport,
        "security.smtp_host": host,
        "security.smtp_port": str(port),
        "security.smtp_security": security,
        "security.smtp_username": username,
        "security.smtp_from": from_address,
        "security.smtp_display_name": smtp_display_name,
        "security.smtp_timeout": str(timeout),
        "security.m365_tenant_id": tenant_id,
        "security.m365_client_id": client_id,
        "security.m365_mailbox": mailbox,
        "security.m365_display_name": m365_display_name,
    }
    return values, errors


def save_settings(connection, values: dict) -> None:
    for key, value in values.items():
        db.set_setting(connection, key, value)
    connection.commit()


# --- État persistant -------------------------------------------------------------


def load_state(connection) -> dict | None:
    row = connection.execute("SELECT * FROM security_state WHERE id = 1").fetchone()
    if row is None:
        return None
    state = dict(row)
    findings: list[dict] = []
    try:
        parsed = json.loads(state.get("findings_json") or "[]")
        if isinstance(parsed, list):
            findings = [item for item in parsed if isinstance(item, dict)]
    except ValueError:
        findings = []
    state["findings"] = findings
    return state


def state_findings(state: dict | None) -> dict[str, Finding]:
    if not state:
        return {}
    return {
        Finding.from_state(item).key: Finding.from_state(item)
        for item in state.get("findings") or []
    }


def freshness(state: dict | None, *, now: str | None = None) -> str:
    """`never`, `fresh` ou `stale` (seuil 48 h : le scan CI est quotidien)."""
    if not state:
        return "never"
    reference = state.get("scan_at") or state.get("fetched_at")
    if not isinstance(reference, str) or not reference:
        return "never"
    try:
        scanned = db.parse_iso(reference)
    except ValueError:
        return "stale"
    current = db.parse_iso(now) if now else db.utc_now()
    return "stale" if (current - scanned).total_seconds() > STALE_SECONDS else "fresh"


def next_sync_at(state: dict | None, *, now: dt.datetime | None = None) -> str | None:
    """Horodatage indicatif de la prochaine synchronisation planifiée."""
    reference = None
    if state and state.get("last_attempt_at"):
        reference = state.get("last_attempt_at")
    if not reference:
        return None
    try:
        moment = db.parse_iso(reference)
    except ValueError:
        return None
    upcoming = (now or db.utc_now()) + dt.timedelta(seconds=SYNC_INTERVAL_SECONDS)
    base = moment + dt.timedelta(seconds=SYNC_INTERVAL_SECONDS)
    return max(base, upcoming).strftime("%Y-%m-%dT%H:%M:%SZ")


def recent_events(connection, limit: int = MAX_EVENTS_DISPLAY) -> list[dict]:
    rows = connection.execute(
        "SELECT * FROM security_events ORDER BY id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [dict(row) for row in rows]


# --- Delta et événements ---------------------------------------------------------


@dataclass
class Delta:
    new: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)
    severity_up: list[tuple[Finding, Finding]] = field(default_factory=list)
    severity_down: list[tuple[Finding, Finding]] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.new or self.resolved or self.severity_up or self.severity_down)


def compute_delta(previous: dict[str, Finding], current: dict[str, Finding]) -> Delta:
    """Différence entre deux images : apparitions, disparitions, sévérités modifiées.

    Un changement de version installée, de version corrigée ou de titre n'est PAS un
    événement : c'est un rafraîchissement de contenu, mis à jour dans l'état sans
    bruit.
    """
    delta = Delta()
    for key, finding in current.items():
        before = previous.get(key)
        if before is None:
            delta.new.append(finding)
        elif trivy.SEVERITY_RANK[finding.severity] < trivy.SEVERITY_RANK[before.severity]:
            delta.severity_up.append((before, finding))
        elif trivy.SEVERITY_RANK[finding.severity] > trivy.SEVERITY_RANK[before.severity]:
            delta.severity_down.append((before, finding))
    for key, finding in previous.items():
        if key not in current:
            delta.resolved.append(finding)
    order = lambda item: (trivy.SEVERITY_RANK[item.severity], item.package, item.cve)  # noqa: E731
    delta.new.sort(key=order)
    delta.resolved.sort(key=order)
    delta.severity_up.sort(key=lambda pair: order(pair[1]))
    delta.severity_down.sort(key=lambda pair: order(pair[1]))
    return delta


def _event(kind: str, severity: str, summary: str, finding: dict) -> dict:
    return {
        "kind": kind,
        "severity": severity,
        "summary": summary,
        "detail": finding,
    }


def events_from_delta(delta: Delta) -> list[dict]:
    """Événements (historique complet) dérivés d'un delta, dans l'ordre de présentation.

    Les plus actionnables d'abord (apparitions), puis les changements de sévérité,
    puis les disparitions — c'est aussi l'ordre des lignes de l'email.
    """
    events: list[dict] = []
    for finding in delta.new:
        events.append(
            _event(
                "new",
                finding.severity,
                f"Apparition — {finding.cve} ({finding.package}, {finding.severity.upper()})",
                finding.to_state(),
            )
        )
    for before, after in delta.severity_up:
        events.append(
            _event(
                "severity_up",
                after.severity,
                f"Aggravation — {after.cve} ({after.package}) : "
                f"{before.severity.upper()} → {after.severity.upper()}",
                {**after.to_state(), "previous_severity": before.severity},
            )
        )
    for before, after in delta.severity_down:
        events.append(
            _event(
                "severity_down",
                after.severity,
                f"Atténuation — {after.cve} ({after.package}) : "
                f"{before.severity.upper()} → {after.severity.upper()}",
                {**after.to_state(), "previous_severity": before.severity},
            )
        )
    for finding in delta.resolved:
        events.append(
            _event(
                "resolved",
                finding.severity,
                f"Vulnérabilité non détectée dans la nouvelle image — "
                f"{finding.cve} ({finding.package}, {finding.severity.upper()})",
                finding.to_state(),
            )
        )
    return events


def notifiable_events(events: list[dict], settings: SecuritySettings) -> list[dict]:
    """Sous-ensemble des événements qui déclenchent un email (au plus un par sync)."""
    return [event for event in events if settings.notifies(event["kind"], event["severity"])]


# --- Verrou inter-process --------------------------------------------------------


class SyncBusy(RuntimeError):
    """Une autre synchronisation est déjà en cours (verrou détenu ailleurs)."""


def lock_path(data_dir: Path | str) -> Path:
    return Path(data_dir) / LOCK_FILENAME


@contextmanager
def sync_lock(data_dir: Path | str):
    """Verrou exclusif inter-process (flock) : une seule synchronisation à la fois.

    Robuste aux redémarrages (le noyau libère le verrou à la mort du processus) et
    compatible avec plusieurs workers gunicorn comme avec un rechargement SIGHUP.
    """
    path = lock_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = path.open("a+")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise SyncBusy("Synchronisation déjà en cours.") from error
        try:
            yield
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()


# --- Synchronisation -------------------------------------------------------------


@dataclass
class SyncResult:
    ok: bool
    message: str
    changed: bool = False
    events: list[dict] = field(default_factory=list)
    notified: int = 0


def _record_attempt(connection, *, status: str, error: str = "") -> None:
    """Curseur d'activité : n'existe que si un état existe déjà (sinon rien à dater)."""
    connection.execute(
        "UPDATE security_state SET last_attempt_at = ?, last_sync_status = ?, "
        "last_sync_error = ? WHERE id = 1",
        (db.now_iso(), status, error[:500]),
    )
    connection.commit()


def _publish(connection, scan: Scan, provenance: dict, *, first: bool) -> list[dict]:
    """Transaction unique : nouvel état + événements dérivés. Retourne les événements."""
    now = db.now_iso()
    previous = state_findings(load_state(connection)) if not first else {}
    if first:
        events = [
            {
                "kind": "baseline",
                "severity": "",
                "summary": f"Baseline initialisée — {scan.counts()['critical']} CRITICAL / "
                f"{scan.counts()['high']} HIGH",
                "detail": {},
            }
        ]
    else:
        events = events_from_delta(compute_delta(previous, scan.by_key()))

    with connection:
        for event in events:
            connection.execute(
                "INSERT INTO security_events (created_at, kind, severity, summary, detail_json, "
                "commit_sha, run_id, notification_status) VALUES (?, ?, ?, ?, ?, ?, ?, 'none')",
                (
                    now,
                    event["kind"],
                    event["severity"],
                    event["summary"],
                    json.dumps(event["detail"], ensure_ascii=False),
                    scan.commit,
                    provenance["run_id"],
                ),
            )
        connection.execute(
            """
            INSERT INTO security_state (
                id, image, commit_sha, run_id, run_url, run_started_at, scan_at, fetched_at,
                report_sha256, findings_json, critical_count, high_count,
                last_attempt_at, last_sync_at, last_sync_status, last_sync_error
            ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ok', '')
            ON CONFLICT(id) DO UPDATE SET
                image = excluded.image,
                commit_sha = excluded.commit_sha,
                run_id = excluded.run_id,
                run_url = excluded.run_url,
                run_started_at = excluded.run_started_at,
                scan_at = excluded.scan_at,
                fetched_at = excluded.fetched_at,
                report_sha256 = excluded.report_sha256,
                findings_json = excluded.findings_json,
                critical_count = excluded.critical_count,
                high_count = excluded.high_count,
                last_attempt_at = excluded.last_attempt_at,
                last_sync_at = excluded.last_sync_at,
                last_sync_status = 'ok',
                last_sync_error = ''
            """,
            (
                scan.image,
                scan.commit,
                provenance["run_id"],
                provenance["run_url"],
                provenance["run_started_at"],
                scan.scanned_at,
                now,
                provenance["sha256"],
                json.dumps([finding.to_state() for finding in scan.findings], ensure_ascii=False),
                scan.counts()["critical"],
                scan.counts()["high"],
                now,
                now,
            ),
        )
    return events


def effective_github_token(app) -> tuple[str, str]:
    """Jeton GitHub effectif et provenance (administration prioritaire, env en bootstrap)."""
    from . import secretstore

    return secretstore.effective_secret(
        app.config["DATA_DIR"],
        secretstore.GITHUB_TOKEN,
        app.config.get("GITHUB_TOKEN") or "",
    )


def sync(app, *, manual: bool = False) -> SyncResult:
    """Une synchronisation complète : téléchargement, validation, publication, email.

    Ne lève jamais : toute panne (réseau, jeton, artefact, rapport, SMTP) est
    convertie en résultat exploitable et en erreur propre dans l'admin, en
    conservant le dernier état valide.
    """
    from . import trivy_github

    connection = db.connect(app.config["DB_PATH"])
    try:
        settings = load_settings(connection)
        if not settings.sync_enabled:
            return SyncResult(
                ok=False,
                message="Surveillance désactivée : activez-la dans la configuration ci-dessous.",
            )
        token, _source = effective_github_token(app)
        if not token:
            return SyncResult(
                ok=False,
                message=(
                    "Aucun jeton GitHub configuré (lecture seule) : le saisir dans "
                    "l'administration, ou fournir HUB_GITHUB_TOKEN au déploiement."
                ),
            )
        try:
            with sync_lock(app.config["DATA_DIR"]):
                return _sync_locked(app, connection, settings, token, manual=manual)
        except SyncBusy as error:
            return SyncResult(ok=False, message=str(error))
    finally:
        connection.close()


def _sync_locked(app, connection, settings: SecuritySettings, token: str, *, manual: bool) -> SyncResult:
    from . import trivy_email, trivy_github

    now = db.now_iso()
    state = load_state(connection)
    if manual and state and state.get("last_manual_sync_at"):
        try:
            elapsed = (db.utc_now() - db.parse_iso(state["last_manual_sync_at"])).total_seconds()
        except ValueError:
            elapsed = MANUAL_SYNC_MIN_INTERVAL_SECONDS
        if elapsed < MANUAL_SYNC_MIN_INTERVAL_SECONDS:
            return SyncResult(
                ok=False,
                message=(
                    "Synchronisation manuelle déjà effectuée il y a moins d'une minute : "
                    "patientez un instant."
                ),
            )

    try:
        run = trivy_github.latest_successful_run(token)
        artifact_id = trivy_github.find_artifact(run.run_id, token)
        raw = trivy_github.extract_report(trivy_github.download_artifact(artifact_id, token))
    except trivy_github.GitHubError as error:
        _record_attempt(connection, status="error", error=str(error))
        return SyncResult(ok=False, message=str(error))

    try:
        scan = trivy.parse_report(raw, commit=run.commit)
    except ReportError as error:
        _record_attempt(connection, status="error", error=str(error))
        return SyncResult(ok=False, message=str(error))

    checksum = hashlib.sha256(raw).hexdigest()
    if state and state.get("report_sha256") == checksum:
        return SyncResult(ok=True, changed=False, message="Rapport déjà à jour (aucune écriture).")
    if state and state.get("run_id") == run.run_id:
        return SyncResult(ok=True, changed=False, message="Run déjà ingéré (aucune écriture).")
    if state and state.get("run_started_at") and run.started_at < state["run_started_at"]:
        message = (
            "Rapport refusé : le run GitHub est plus ancien que l'état courant "
            f"({run.started_at} < {state['run_started_at']}) — la baseline est conservée."
        )
        _record_attempt(connection, status="ignored", error=message)
        return SyncResult(ok=False, message=message)
    if state and state.get("scan_at") and scan.scanned_at < state["scan_at"]:
        message = (
            "Rapport refusé : le scan est plus ancien que l'état courant "
            f"({scan.scanned_at} < {state['scan_at']}) — la baseline est conservée."
        )
        _record_attempt(connection, status="ignored", error=message)
        return SyncResult(ok=False, message=message)

    first = state is None
    provenance = {
        "run_id": run.run_id,
        "run_url": run.run_url,
        "run_started_at": run.started_at,
        "sha256": checksum,
    }
    if manual and state is not None:
        # Horodatage posé avant l'écriture du nouvel état : une synchronisation
        # manuelle réussie, en échec ou sans changement est également limitée.
        connection.execute(
            "UPDATE security_state SET last_manual_sync_at = ? WHERE id = 1", (now,)
        )
        connection.commit()
    events = _publish(connection, scan, provenance, first=first)
    if manual and first:
        # Premier rapport : l'état vient d'être créé, on horodate la synchronisation
        # manuelle pour que la limite s'applique dès la suivante.
        connection.execute(
            "UPDATE security_state SET last_manual_sync_at = ? WHERE id = 1", (now,)
        )
        connection.commit()

    if first:
        return SyncResult(
            ok=True,
            changed=True,
            message=(
                f"Baseline initialisée — {scan.counts()['critical']} CRITICAL / "
                f"{scan.counts()['high']} HIGH (aucun email)."
            ),
            events=[],
        )

    deliverable = notifiable_events(events, settings)
    if not deliverable:
        return SyncResult(
            ok=True,
            changed=True,
            message="Rapport ingéré : aucun changement pertinent à notifier."
            if events
            else "Rapport ingéré : aucun changement (aucun email).",
        )

    ok, detail = trivy_email.send_delta_email(app, deliverable, scan)
    mark_last_events_status(
        connection, len(events), status="sent" if ok else "failed", error="" if ok else detail
    )
    return SyncResult(
        ok=True,
        changed=True,
        message=(
            f"{len(deliverable)} changement(s) notifié(s) par email."
            if ok
            else f"Changement(s) détecté(s), mais l'email a échoué : {detail}"
        ),
        events=deliverable,
        notified=len(deliverable) if ok else 0,
    )


def mark_last_events_status(connection, count: int, *, status: str, error: str = "") -> None:
    """Marque les `count` derniers événements (le lot qui vient d'être publié)."""
    if count <= 0:
        return
    rows = connection.execute(
        "SELECT id FROM security_events ORDER BY id DESC LIMIT ?", (count,)
    ).fetchall()
    ids = [row["id"] for row in rows]
    now = db.now_iso()
    with connection:
        connection.execute(
            f"UPDATE security_events SET notification_status = ?, notification_error = ?, "
            f"notified_at = ? WHERE id IN ({','.join('?' for _ in ids)})",
            (status, error[:500], now if status == "sent" else None, *ids),
        )
        if status == "sent":
            connection.execute(
                "UPDATE security_state SET last_notification_at = ?, "
                "last_notification_status = 'sent', last_notification_error = '' WHERE id = 1",
                (now,),
            )
        elif status == "failed":
            connection.execute(
                "UPDATE security_state SET last_notification_at = ?, "
                "last_notification_status = 'failed', last_notification_error = ? WHERE id = 1",
                (now, error[:500]),
            )


def retry_failed_notification(app) -> SyncResult:
    """Renvoie le dernier lot d'événements dont la notification a échoué."""
    from . import trivy_email

    connection = db.connect(app.config["DB_PATH"])
    try:
        settings = load_settings(connection)
        if not settings.notifications_enabled:
            return SyncResult(ok=False, message="Notifications désactivées.")
        rows = connection.execute(
            "SELECT * FROM security_events WHERE notification_status = 'failed' ORDER BY id"
        ).fetchall()
        if not rows:
            return SyncResult(ok=False, message="Aucun envoi en échec à réessayer.")
        events = [
            {
                "id": row["id"],
                "kind": row["kind"],
                "severity": row["severity"],
                "summary": row["summary"],
                "detail": json.loads(row["detail_json"] or "{}"),
            }
            for row in rows
        ]
        state = load_state(connection)
        scan = Scan(
            image=state.get("image", "") if state else "",
            commit=state.get("commit_sha", "") if state else "",
            scanned_at=state.get("scan_at", "") if state else "",
            findings=(),
        )
        ok, detail = trivy_email.send_delta_email(app, events, scan)
        ids = [row["id"] for row in rows]
        now = db.now_iso()
        with connection:
            connection.execute(
                f"UPDATE security_events SET notification_status = ?, notification_error = ?, "
                f"notified_at = ? WHERE id IN ({','.join('?' for _ in ids)})",
                ("sent" if ok else "failed", "" if ok else detail[:500], now if ok else None, *ids),
            )
            connection.execute(
                "UPDATE security_state SET last_notification_at = ?, last_notification_status = ?, "
                "last_notification_error = ? WHERE id = 1",
                (now, "sent" if ok else "failed", "" if ok else detail[:500]),
            )
        return SyncResult(
            ok=ok,
            message="Email renvoyé." if ok else f"Échec du renvoi : {detail}",
        )
    finally:
        connection.close()
