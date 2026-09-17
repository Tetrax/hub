"""Planification de la synchronisation Trivy : un travail unique, sans second conteneur.

Le standalone Hub est volontairement **un seul conteneur** : pas de service
`scheduler` séparé, pas de Celery/Redis/cron système. La synchronisation est portée
par un thread d'arrière-plan démarré dans chaque worker gunicorn, et l'unicité est
garantie par un **verrou fichier inter-process** (`flock`, voir
`trivy_monitor.sync_lock`) : quel que soit le nombre de workers, une seule
synchronisation s'exécute à la fois. Le verrou est libéré par le noyau à la mort du
processus — compatible redémarrage et rechargement Gunicorn (`SIGHUP` lors d'un
changement de certificat) : les anciens workers meurent, les nouveaux reprennent la
boucle.

Cadence : le scan CI est quotidien, la synchronisation interroge GitHub **une fois
par heure** au maximum (jamais toutes les 5 minutes). Un curseur en mémoire évite
les appels répétés quand rien n'a changé (aucune écriture inutile en base), et le
dernier essai persisté (`security_state.last_attempt_at`) sert de référence après un
redémarrage.
"""

from __future__ import annotations

import threading
import time

from . import db, trivy_monitor

POLL_SECONDS = 300
STARTUP_DELAY_SECONDS = 20
SYNC_INTERVAL_SECONDS = trivy_monitor.SYNC_INTERVAL_SECONDS

_last_scheduler_sync: dict[str, float] = {}


def _due(app, state: dict | None) -> bool:
    """Vrai si le délai est écoulé (curseur mémoire, puis dernier essai persisté)."""
    key = str(app.config.get("DB_PATH", ""))
    stamp = _last_scheduler_sync.get(key)
    if stamp is not None and (time.monotonic() - stamp) < SYNC_INTERVAL_SECONDS:
        return False
    if state and state.get("last_attempt_at"):
        try:
            elapsed = (db.utc_now() - db.parse_iso(state["last_attempt_at"])).total_seconds()
        except ValueError:
            return True
        if elapsed < SYNC_INTERVAL_SECONDS:
            return False
    return True


def run_due_sync(app) -> bool:
    """Une itération : synchronise si la surveillance est active et le délai écoulé.

    Retourne vrai quand une synchronisation a réellement été tentée.
    """
    connection = db.connect(app.config["DB_PATH"])
    try:
        settings = trivy_monitor.load_settings(connection)
        if not settings.sync_enabled:
            return False
        state = trivy_monitor.load_state(connection)
    finally:
        connection.close()
    if not _due(app, state):
        return False

    result = trivy_monitor.sync(app)
    _last_scheduler_sync[str(app.config.get("DB_PATH", ""))] = time.monotonic()
    if result.changed:
        app.logger.info("Surveillance Trivy : %s", result.message)
    elif result.ok:
        app.logger.debug("Surveillance Trivy : %s", result.message)
    else:
        app.logger.warning("Surveillance Trivy : %s", result.message)
    return True


def _loop(app) -> None:
    time.sleep(STARTUP_DELAY_SECONDS)
    while True:
        try:
            run_due_sync(app)
        except Exception:  # pragma: no cover - garde-fou : la boucle ne doit jamais mourir
            app.logger.exception("Surveillance Trivy : erreur inattendue du planificateur")
        time.sleep(POLL_SECONDS)


def start_scheduler(app):
    """Démarre la boucle d'arrière-plan (désactivable par `TRIVY_SCHEDULER_ENABLED`)."""
    if not app.config.get("TRIVY_SCHEDULER_ENABLED", True):
        return None
    if app.config.get("TESTING"):
        return None
    thread = threading.Thread(target=_loop, args=(app,), name="trivy-scheduler", daemon=True)
    thread.start()
    return thread
