"""Configuration gunicorn — un seul serveur, deux usages.

- **VPS / proxy externe** (défaut) : HTTP sur `HUB_BIND` (8000), TLS terminé par
  Nginx ou l'équipement amont ; les en-têtes `X-Forwarded-*` ne sont PAS réécrits
  par gunicorn, l'application applique elle-même sa frontière de confiance
  (`HUB_TRUSTED_PROXY_CIDRS`) sur l'adresse réellement observée.
- **Standalone** (`HUB_TLS_CERT`/`HUB_TLS_KEY` définis) : le Hub termine lui-même
  TLS sur `HUB_TLS_BIND_PORT` (8443 publié en 443). Le contexte SSL est construit
  par les workers : un `SIGHUP` du maître (envoyé par l'activation d'un
  certificat, `app/certlocal.py`) les redémarre gracieusement et le nouveau
  certificat est présenté — sans redémarrer le conteneur.
"""

import os

certfile = (os.environ.get("HUB_TLS_CERT") or "").strip() or None
keyfile = (os.environ.get("HUB_TLS_KEY") or "").strip() or None

bind = os.environ.get("HUB_BIND") or (
    f"0.0.0.0:{os.environ.get('HUB_TLS_BIND_PORT', '8443')}" if certfile else "0.0.0.0:8000"
)

# Deux workers suffisent très largement pour un catalogue ; threads pour I/O.
workers = 2
threads = 4

forwarded_allow_ips = ""

timeout = 30
graceful_timeout = 30
keepalive = 5

accesslog = "-"
errorlog = "-"
loglevel = "info"

# PID du maître : l'application le lit pour envoyer SIGHUP lors d'une activation de
# certificat (chemin en /tmp, seul répertoire inscriptible du conteneur en lecture seule).
pidfile = os.environ.get("HUB_GUNICORN_PIDFILE", "/tmp/gunicorn.pid")

# gunicorn 26 ouvre par défaut une socket de contrôle interactive
# ($XDG_RUNTIME_DIR ou $HOME/.gunicorn/) : inutile ici, et en lecture seule elle
# échoue au démarrage (« Control server error: Read-only file system »). Désactivée.
control_socket_disable = True
