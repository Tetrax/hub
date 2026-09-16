"""Configuration gunicorn — servie derrière Nginx (proxy inverse local)."""

bind = "0.0.0.0:8000"

# Deux workers suffisent très largement pour un catalogue ; threads pour I/O.
workers = 2
threads = 4

# Les en-têtes X-Forwarded-* ne sont PAS réécrits par gunicorn :
# l'application applique elle-même sa frontière de confiance proxy
# (HUB_TRUSTED_PROXY_CIDRS) sur l'adresse réellement observée.
forwarded_allow_ips = ""

timeout = 30
graceful_timeout = 30
keepalive = 5

accesslog = "-"
errorlog = "-"
loglevel = "info"
