"""Planification Trivy : un seul travail, cadence maîtrisée, désactivation propre."""

from __future__ import annotations

import json

from app import db, trivy_email, trivy_github, trivy_monitor, trivy_scheduler
from test_trivy_monitor import (  # helpers partagés
    BASELINE,
    capture_emails,
    enable,
    kinds_of,
    payload,
    state_of,
    use_github,
)


def test_nothing_happens_when_monitoring_is_disabled(app, monkeypatch):
    monkeypatch.setattr(
        trivy_github, "latest_successful_run", lambda _token: (_ for _ in ()).throw(AssertionError("ne doit pas être appelé"))
    )
    assert trivy_scheduler.run_due_sync(app) is False
    assert state_of(app) is None


def test_a_due_sync_runs_then_waits_for_the_interval(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_scheduler._last_scheduler_sync.clear()
    assert trivy_scheduler.run_due_sync(app) is True
    assert kinds_of(app) == ["baseline"]
    # Deuxième appel immédiat : curseur mémoire, aucun nouvel appel réseau.
    assert trivy_scheduler.run_due_sync(app) is False


def test_the_persisted_last_attempt_throttles_after_a_restart(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_scheduler._last_scheduler_sync.clear()
    assert trivy_scheduler.run_due_sync(app) is True
    # « Redémarrage » : curseur mémoire perdu, l'état persisté prend le relais.
    trivy_scheduler._last_scheduler_sync.clear()
    assert trivy_scheduler.run_due_sync(app) is False


def test_an_old_attempt_makes_the_sync_due_again(app, monkeypatch):
    enable(app)
    capture_emails(monkeypatch)
    use_github(monkeypatch, payload(BASELINE))
    trivy_scheduler._last_scheduler_sync.clear()
    trivy_scheduler.run_due_sync(app)
    connection = db.connect(app.config["DB_PATH"])
    connection.execute(
        "UPDATE security_state SET last_attempt_at = '2026-09-01T00:00:00Z' WHERE id = 1"
    )
    connection.commit()
    connection.close()
    trivy_scheduler._last_scheduler_sync.clear()
    assert trivy_scheduler.run_due_sync(app) is True


def test_the_scheduler_thread_is_not_started_when_disabled(app):
    assert app.config["TRIVY_SCHEDULER_ENABLED"] is False
    assert trivy_scheduler.start_scheduler(app) is None


def test_the_scheduler_thread_starts_when_explicitly_enabled(app):
    app.config["TRIVY_SCHEDULER_ENABLED"] = True
    app.config["TESTING"] = False
    thread = trivy_scheduler.start_scheduler(app)
    assert thread is not None and thread.daemon
    # Le thread attend le délai de démarrage : il ne doit rien synchroniser tout de suite.
    assert thread.is_alive()
