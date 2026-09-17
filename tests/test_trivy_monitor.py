"""Moteur de surveillance Trivy : baseline, delta, idempotence, pannes, concurrence.

Le client GitHub et l'envoi email sont remplacés par des doubles : ces tests
portent sur les règles de l'ingestion (D22), pas sur le réseau.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

from app import db, trivy_email, trivy_github, trivy_monitor

COMMIT_A = "a" * 40
COMMIT_B = "b" * 40
RUN_A = "1001"
RUN_B = "1002"


def _finding(cve: str, package: str, severity: str, installed: str = "1.0", fixed: str = "1.1") -> dict:
    return {
        "VulnerabilityID": cve,
        "PkgName": package,
        "Severity": severity,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
    }


def payload(findings: list[dict], *, created: str = "2026-09-17T05:24:00Z") -> dict:
    return {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "ArtifactName": "hub:ci-scan",
        "CreatedAt": created,
        "Results": [
            # Copie défensive : un test qui altère un payload ne doit jamais polluer
            # les constantes partagées entre tests.
            {"Class": "os-pkgs", "Type": "debian", "Vulnerabilities": [dict(item) for item in findings]},
            {"Class": "lang-pkgs", "Type": "python-pkg", "Vulnerabilities": 0},
        ],
    }


def use_github(monkeypatch, report: dict, *, run_id: str = RUN_A, commit: str = COMMIT_A,
               started: str = "2026-09-17T05:23:00Z", delay: float = 0.0) -> bytes:
    raw = json.dumps(report).encode()

    def _run(_token):
        if delay:
            time.sleep(delay)
        return trivy_github.RunInfo(
            run_id=run_id,
            commit=commit,
            run_url=f"https://github.com/Tetrax/hub/actions/runs/{run_id}",
            started_at=started,
        )

    monkeypatch.setattr(trivy_github, "latest_successful_run", _run)
    monkeypatch.setattr(trivy_github, "find_artifact", lambda _run_id, _token: 99)
    monkeypatch.setattr(trivy_github, "download_artifact", lambda _artifact_id, _token: b"zip")
    monkeypatch.setattr(trivy_github, "extract_report", lambda _payload: raw)
    return raw


def capture_emails(monkeypatch, *, ok: bool = True, detail: str = "Email envoyé.") -> list[dict]:
    calls: list[dict] = []

    def _send(app, events, scan):
        calls.append({"events": events, "scan": scan})
        return ok, detail

    monkeypatch.setattr(trivy_email, "send_delta_email", _send)
    return calls


def enable(app, *, notifications: bool = True, token: str = "jeton-de-test", severities=("critical", "high"), **overrides):
    app.config["GITHUB_TOKEN"] = token
    connection = db.connect(app.config["DB_PATH"])
    form = {
        "sync_enabled": "1",
        "notifications_enabled": "1" if notifications else "0",
        "notify_new": "1",
        "notify_resolved": "1",
        "notify_severity": "1",
        "severity_critical": "1" if "critical" in severities else "0",
        "severity_high": "1" if "high" in severities else "0",
        "recipients": "sns@valdev.me",
        "smtp_host": "smtp.valdev.me",
        "smtp_port": "587",
        "smtp_security": "starttls",
        "smtp_username": "",
        "smtp_from": "sns-hub@valdev.me",
        "smtp_timeout": "15",
    }
    form.update(overrides)
    values, errors = trivy_monitor.validate_settings(
        form, github_token_present=bool(token), smtp_password_present=False
    )
    assert not errors, errors
    trivy_monitor.save_settings(connection, values)
    connection.close()


def state_of(app) -> dict:
    connection = db.connect(app.config["DB_PATH"])
    try:
        return trivy_monitor.load_state(connection)
    finally:
        connection.close()


def events_of(app) -> list[dict]:
    connection = db.connect(app.config["DB_PATH"])
    try:
        return trivy_monitor.recent_events(connection, limit=100)
    finally:
        connection.close()


def kinds_of(app) -> list[str]:
    return [event["kind"] for event in reversed(events_of(app))]


BASELINE = [
    _finding("CVE-2026-0001", "gzip", "high"),
    _finding("CVE-2026-0002", "libsqlite3-0", "high"),
    _finding("CVE-2026-0003", "perl-base", "critical"),
]


# --- Configuration ---------------------------------------------------------------


def test_settings_round_trip(app):
    enable(app, recipients="a@valdev.me\nb@valdev.me")
    connection = db.connect(app.config["DB_PATH"])
    settings = trivy_monitor.load_settings(connection)
    connection.close()
    assert settings.sync_enabled and settings.notifications_enabled
    assert settings.recipients == ("a@valdev.me", "b@valdev.me")
    assert settings.severities == ("critical", "high")


@pytest.mark.parametrize(
    ("form", "needle"),
    [
        ({"recipients": "pas-un-email"}, "Destinataire invalide"),
        ({"smtp_port": "70000"}, "Port SMTP hors plage"),
        ({"smtp_port": "abc"}, "Port SMTP invalide"),
        ({"smtp_security": "magique"}, "Sécurité SMTP invalide"),
        ({"smtp_from": "invalide"}, "Expéditeur invalide"),
        ({"smtp_timeout": "3"}, "Délai SMTP hors plage"),
        ({"smtp_host": "smtp avec espaces"}, "Serveur SMTP invalide"),
    ],
)
def test_settings_validation_refuses_bad_values(app, form, needle):
    base = {
        "sync_enabled": "1", "notifications_enabled": "0", "notify_new": "1",
        "notify_resolved": "1", "notify_severity": "1", "severity_critical": "1",
        "severity_high": "1", "recipients": "sns@valdev.me", "smtp_host": "smtp.valdev.me",
        "smtp_port": "587", "smtp_security": "starttls", "smtp_username": "",
        "smtp_from": "sns-hub@valdev.me", "smtp_timeout": "15",
    }
    base.update(form)
    _values, errors = trivy_monitor.validate_settings(
        base, github_token_present=True, smtp_password_present=False
    )
    assert any(needle in message for message in errors), errors


def test_enabling_monitoring_without_a_github_token_is_refused():
    base = {
        "sync_enabled": "1", "notifications_enabled": "0", "notify_new": "1",
        "notify_resolved": "1", "notify_severity": "1", "severity_critical": "1",
        "severity_high": "1", "recipients": "", "smtp_host": "", "smtp_port": "587",
        "smtp_security": "starttls", "smtp_username": "", "smtp_from": "", "smtp_timeout": "15",
    }
    _values, errors = trivy_monitor.validate_settings(
        base, github_token_present=False, smtp_password_present=False
    )
    assert any("jeton GitHub" in message for message in errors)


@pytest.mark.parametrize(
    ("overrides", "needle"),
    [
        ({"recipients": ""}, "sans destinataire"),
        ({"smtp_host": ""}, "sans serveur SMTP"),
        ({"smtp_from": ""}, "sans expéditeur"),
        ({"severity_critical": "0", "severity_high": "0"}, "sans aucune sévérité suivie"),
    ],
)
def test_enabling_notifications_requires_a_complete_configuration(overrides, needle):
    base = {
        "sync_enabled": "1", "notifications_enabled": "1", "notify_new": "1",
        "notify_resolved": "1", "notify_severity": "1", "severity_critical": "1",
        "severity_high": "1", "recipients": "sns@valdev.me", "smtp_host": "smtp.valdev.me",
        "smtp_port": "587", "smtp_security": "starttls", "smtp_username": "",
        "smtp_from": "sns-hub@valdev.me", "smtp_timeout": "15",
    }
    base.update(overrides)
    _values, errors = trivy_monitor.validate_settings(
        base, github_token_present=True, smtp_password_present=False
    )
    assert any(needle in message for message in errors), errors


def test_an_smtp_identifier_requires_a_password():
    base = {
        "sync_enabled": "1", "notifications_enabled": "1", "notify_new": "1",
        "notify_resolved": "1", "notify_severity": "1", "severity_critical": "1",
        "severity_high": "1", "recipients": "sns@valdev.me", "smtp_host": "smtp.valdev.me",
        "smtp_port": "587", "smtp_security": "starttls", "smtp_username": "hub",
        "smtp_from": "sns-hub@valdev.me", "smtp_timeout": "15",
    }
    _values, errors = trivy_monitor.validate_settings(
        base, github_token_present=True, smtp_password_present=False
    )
    assert any("HUB_SMTP_PASSWORD" in message for message in errors)


# --- Baseline et delta ------------------------------------------------------------


def test_first_sync_creates_a_silent_baseline(app, monkeypatch):
    enable(app)
    emails = capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    result = trivy_monitor.sync(app)
    assert result.ok and result.changed
    assert "Baseline initialisée — 1 CRITICAL / 2 HIGH" in result.message
    assert kinds_of(app) == ["baseline"]
    assert emails == []
    state = state_of(app)
    assert state["critical_count"] == 1 and state["high_count"] == 2
    assert trivy_monitor.freshness(state) == "fresh"


def test_the_mission_delta_scenario_produces_one_email(app, monkeypatch):
    enable(app)
    emails = capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)

    second = [
        _finding("CVE-2026-0001", "gzip", "critical"),  # HIGH → CRITICAL
        _finding("CVE-2026-0003", "perl-base", "critical"),  # inchangé
        _finding("CVE-2026-0004", "libpcre2-8-0", "high"),  # nouveau
    ]
    use_github(
        monkeypatch,
        payload(second, created="2026-09-18T05:24:00Z"),
        run_id=RUN_B,
        commit=COMMIT_B,
        started="2026-09-18T05:23:00Z",
    )
    result = trivy_monitor.sync(app)

    assert result.ok and result.changed
    kind_order = kinds_of(app)
    assert kind_order == ["baseline", "new", "severity_up", "resolved"]
    assert len(emails) == 1, "un seul email par synchronisation"
    summaries = [event["summary"] for event in emails[0]["events"]]
    assert any("HIGH → CRITICAL" in text for text in summaries)
    assert any("Apparition" in text for text in summaries)
    assert any("non détectée" in text for text in summaries), summaries
    assert "3 changement(s) notifié(s)" in result.message


def test_installed_or_fixed_version_changes_are_silent(app, monkeypatch):
    enable(app)
    emails = capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)

    refreshed = [
        _finding("CVE-2026-0001", "gzip", "high", installed="1.13-2", fixed="1.13-2+deb13u1"),
        _finding("CVE-2026-0002", "libsqlite3-0", "high", installed="3.46.1-8"),
        _finding("CVE-2026-0003", "perl-base", "critical", fixed="5.40.1-7"),
    ]
    use_github(
        monkeypatch,
        payload(refreshed, created="2026-09-18T05:24:00Z"),
        run_id=RUN_B,
        commit=COMMIT_B,
        started="2026-09-18T05:23:00Z",
    )
    result = trivy_monitor.sync(app)
    assert result.changed
    assert kinds_of(app) == ["baseline"], "aucun événement pour un rafraîchissement de contenu"
    assert emails == []
    state = state_of(app)
    gzip = next(item for item in state["findings"] if item["package"] == "gzip")
    assert gzip["installed_version"] == "1.13-2"
    assert state["critical_count"] == 1


def test_an_identical_report_is_a_strict_no_op(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)
    before = state_of(app)

    result = trivy_monitor.sync(app)
    assert result.ok and not result.changed
    assert "déjà à jour" in result.message
    assert state_of(app)["fetched_at"] == before["fetched_at"]
    assert len(events_of(app)) == 1


def test_the_same_run_is_not_ingested_twice(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    raw = payload(BASELINE)
    use_github(monkeypatch, raw)
    trivy_monitor.sync(app)
    # Même run, contenu différent (situation anormale) : le run est refusé avant tout.
    connection = db.connect(app.config["DB_PATH"])
    connection.execute("UPDATE security_state SET report_sha256 = 'autre' WHERE id = 1")
    connection.commit()
    connection.close()
    use_github(monkeypatch, payload(BASELINE + [_finding("CVE-2026-0009", "x", "high")]))
    result = trivy_monitor.sync(app)
    assert not result.changed and "déjà ingéré" in result.message
    assert state_of(app)["report_sha256"] == "autre"


def test_an_older_run_is_refused_and_the_baseline_kept(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)
    before = state_of(app)

    use_github(
        monkeypatch,
        payload([_finding("CVE-2026-0009", "x", "high")]),
        run_id="999",
        commit=COMMIT_B,
        started="2026-09-01T05:23:00Z",
    )
    result = trivy_monitor.sync(app)
    assert not result.ok and "plus ancien" in result.message
    assert state_of(app)["report_sha256"] == before["report_sha256"]
    assert kinds_of(app) == ["baseline"]
    assert state_of(app)["last_sync_status"] == "ignored"


def test_a_report_with_an_older_scan_date_is_refused(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)
    before = state_of(app)
    use_github(
        monkeypatch,
        payload([_finding("CVE-2026-0009", "x", "high")], created="2026-08-01T00:00:00Z"),
        run_id=RUN_B,
        commit=COMMIT_B,
        started="2026-09-18T05:23:00Z",
    )
    result = trivy_monitor.sync(app)
    assert not result.ok and "scan est plus ancien" in result.message
    assert state_of(app)["report_sha256"] == before["report_sha256"]


# --- Pannes -----------------------------------------------------------------------


def test_a_github_failure_keeps_the_previous_state(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)
    before = state_of(app)

    def _boom(_token):
        raise trivy_github.GitHubError("GitHub inaccessible (URLError).")

    monkeypatch.setattr(trivy_github, "latest_successful_run", _boom)
    result = trivy_monitor.sync(app)
    assert not result.ok and "inaccessible" in result.message
    after = state_of(app)
    assert after["report_sha256"] == before["report_sha256"]
    assert after["last_sync_status"] == "error"
    assert "inaccessible" in after["last_sync_error"]
    assert kinds_of(app) == ["baseline"], "aucune fausse résolution"


def test_an_invalid_report_is_refused_entirely(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)
    before = state_of(app)

    broken = payload(BASELINE)
    broken["Results"][0]["Vulnerabilities"][0]["Severity"] = "medium"
    use_github(monkeypatch, broken, run_id=RUN_B, commit=COMMIT_B, started="2026-09-18T05:23:00Z")
    result = trivy_monitor.sync(app)
    assert not result.ok and "refusé" in result.message
    assert state_of(app)["report_sha256"] == before["report_sha256"]
    assert kinds_of(app) == ["baseline"]


def test_disabled_monitoring_or_missing_token_refuses_cleanly(app, monkeypatch):
    emails = capture_emails(monkeypatch)
    result = trivy_monitor.sync(app)
    assert not result.ok and "désactivée" in result.message

    enable(app)
    app.config["GITHUB_TOKEN"] = ""
    result = trivy_monitor.sync(app)
    assert not result.ok and "Jeton GitHub" in result.message
    assert emails == []


def test_a_smtp_failure_does_not_roll_back_the_baseline(app, monkeypatch):
    enable(app)
    calls = capture_emails(monkeypatch, ok=False, detail="Échec SMTP (envoi) : SMTPServerDisconnected.")
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)

    second = BASELINE + [_finding("CVE-2026-0004", "libpcre2-8-0", "high")]
    use_github(monkeypatch, payload(second, created="2026-09-18T05:24:00Z"), run_id=RUN_B,
               commit=COMMIT_B, started="2026-09-18T05:23:00Z")
    result = trivy_monitor.sync(app)
    assert result.ok, "la synchronisation reste réussie même si l'email échoue"
    assert "email a échoué" in result.message
    state = state_of(app)
    assert state["last_notification_status"] == "failed"
    assert "SMTPServerDisconnected" in state["last_notification_error"]
    failed = [event for event in events_of(app) if event["notification_status"] == "failed"]
    assert len(failed) == 1

    # La CVE déjà connue n'est PAS re-notifiée à la synchronisation suivante.
    third = second + [_finding("CVE-2026-0005", "zlib", "high")]
    use_github(monkeypatch, payload(third, created="2026-09-19T05:24:00Z"), run_id="1003",
               commit="c" * 40, started="2026-09-19T05:23:00Z")
    trivy_monitor.sync(app)
    assert calls[-1]["events"][0]["detail"]["cve"] == "CVE-2026-0005"


def test_a_failed_notification_can_be_retried(app, monkeypatch):
    enable(app)
    calls = capture_emails(monkeypatch, ok=False, detail="Échec SMTP (connexion) : ConnectionRefusedError.")
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)
    second = BASELINE + [_finding("CVE-2026-0004", "libpcre2-8-0", "high")]
    use_github(monkeypatch, payload(second, created="2026-09-18T05:24:00Z"), run_id=RUN_B,
               commit=COMMIT_B, started="2026-09-18T05:23:00Z")
    trivy_monitor.sync(app)

    capture_emails(monkeypatch, ok=True)
    result = trivy_monitor.retry_failed_notification(app)
    assert result.ok
    failed = [event for event in events_of(app) if event["notification_status"] == "failed"]
    assert failed == []
    assert state_of(app)["last_notification_status"] == "sent"


def test_a_retry_without_failure_is_refused_cleanly(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    result = trivy_monitor.retry_failed_notification(app)
    assert not result.ok and "Aucun envoi en échec" in result.message


# --- Filtres de notification ------------------------------------------------------


def test_a_severity_outside_the_followed_set_is_not_notified(app, monkeypatch):
    enable(app, severities=("critical",))
    emails = capture_emails(monkeypatch)
    use_github(monkeypatch, payload([_finding("CVE-2026-0001", "gzip", "high")]))
    trivy_monitor.sync(app)

    second = [
        _finding("CVE-2026-0001", "gzip", "high"),
        _finding("CVE-2026-0002", "perl-base", "critical"),
    ]
    use_github(monkeypatch, payload(second, created="2026-09-18T05:24:00Z"), run_id=RUN_B,
               commit=COMMIT_B, started="2026-09-18T05:23:00Z")
    result = trivy_monitor.sync(app)
    assert result.changed
    assert kinds_of(app) == ["baseline", "new"], "l'événement HIGH est enregistré..."
    new_event = [event for event in events_of(app) if event["kind"] == "new"][0]
    assert new_event["severity"] == "critical"
    assert len(emails) == 1
    assert [event["detail"]["cve"] for event in emails[0]["events"]] == ["CVE-2026-0002"]


def test_notification_types_are_switchable(app, monkeypatch):
    enable(app, notify_new="0", notify_resolved="0")
    emails = capture_emails(monkeypatch)
    use_github(monkeypatch, payload([_finding("CVE-2026-0001", "gzip", "high")]))
    trivy_monitor.sync(app)
    second = [_finding("CVE-2026-0002", "perl-base", "critical")]
    use_github(monkeypatch, payload(second, created="2026-09-18T05:24:00Z"), run_id=RUN_B,
               commit=COMMIT_B, started="2026-09-18T05:23:00Z")
    result = trivy_monitor.sync(app)
    assert result.changed and emails == []
    assert kinds_of(app) == ["baseline", "new", "resolved"]

    # Réactivation des nouveaux uniquement : l'événement suivant repart par email.
    enable(app, notify_new="1", notify_resolved="0")
    third = second + [_finding("CVE-2026-0003", "zlib", "high")]
    use_github(monkeypatch, payload(third, created="2026-09-19T05:24:00Z"), run_id="1003",
               commit="c" * 40, started="2026-09-19T05:23:00Z")
    trivy_monitor.sync(app)
    assert len(emails) == 1
    assert [event["kind"] for event in emails[0]["events"]] == ["new"]


def test_notifications_disabled_still_updates_the_state(app, monkeypatch):
    enable(app, notifications=False)
    emails = capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)
    second = BASELINE + [_finding("CVE-2026-0004", "libpcre2-8-0", "high")]
    use_github(monkeypatch, payload(second, created="2026-09-18T05:24:00Z"), run_id=RUN_B,
               commit=COMMIT_B, started="2026-09-18T05:23:00Z")
    result = trivy_monitor.sync(app)
    assert result.changed and emails == []
    assert [event["notification_status"] for event in events_of(app)][0] == "none"


# --- Concurrence et cadence -------------------------------------------------------


def test_the_lock_serialises_concurrent_syncs(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE), delay=0.3)
    results: list = []

    def _run():
        results.append(trivy_monitor.sync(app))

    threads = [threading.Thread(target=_run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(kinds_of(app)) == 1, "une seule baseline, aucun doublon"
    busy = [result for result in results if "déjà en cours" in result.message]
    succeeded = [result for result in results if result.changed]
    assert len(succeeded) == 1
    assert len(busy) == 1


def test_a_held_lock_refuses_a_sync(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    with trivy_monitor.sync_lock(app.config["DATA_DIR"]):
        result = trivy_monitor.sync(app)
    assert not result.ok and "déjà en cours" in result.message


def test_manual_syncs_are_rate_limited(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    first = trivy_monitor.sync(app, manual=True)
    assert first.ok
    second = trivy_monitor.sync(app, manual=True)
    assert not second.ok and "moins d'une minute" in second.message


def test_freshness_and_next_sync(app, monkeypatch):
    assert trivy_monitor.freshness(None) == "never"
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_monitor.sync(app)
    state = state_of(app)
    assert trivy_monitor.freshness(state) == "fresh"
    stale = dict(state, scan_at="2026-09-01T00:00:00Z")
    assert trivy_monitor.freshness(stale) == "stale"
    assert trivy_monitor.next_sync_at(state) is not None
