#!/bin/sh
# SNS Hub — entrypoint du conteneur.
#
# Deux usages, un seul script :
#
#   1. VPS / derrière un proxy (défaut, aucune variable TLS) : ne fait rien,
#      exécute simplement la commande (gunicorn en HTTP sur 8000).
#
#   2. Standalone (HUB_TLS_CERT / HUB_TLS_KEY définis) : le conteneur termine
#      lui-même TLS. Avant de lancer le serveur — gunicorn refuse de démarrer
#      sans paire lisible — un certificat temporaire AUTO-SIGNÉ est créé pour
#      HUB_HOSTNAME s'il n'existe pas encore de paire définitive. Il est stocké
#      dans le volume hub_certs (il survit aux redémarrages), il est annoncé
#      comme temporaire dans l'interface, et la première activation d'un vrai
#      certificat le remplace automatiquement.
#
# Le script ne fait rien d'autre : pas d'orchestration, pas de surveillance, pas
# de privilèges particuliers (le conteneur tourne en utilisateur applicatif).
set -eu

if [ -n "${HUB_TLS_CERT:-}" ]; then
	: "${HUB_TLS_HOSTNAME:=${HUB_HOSTNAME:-}}"
	if [ -z "$HUB_TLS_HOSTNAME" ]; then
		echo "[hub] HUB_HOSTNAME (ou HUB_TLS_HOSTNAME) est requis pour servir HTTPS." >&2
		exit 64
	fi
	export HUB_TLS_HOSTNAME

	# Le volume doit être inscriptible par l'utilisateur applicatif : un volume
	# nommé est initialisé depuis l'image avec les bons droits, aucun chown hôte
	# n'est nécessaire. Sans droits d'écriture, le message est explicite.
	CERTS_DIR="${HUB_CERTS_DIR:-$(dirname "$HUB_TLS_CERT")}"
	if [ ! -w "$CERTS_DIR" ]; then
		echo "[hub] volume de certificats ($CERTS_DIR) non inscriptible :" \
			"vérifier le volume hub_certs." >&2
		exit 73
	fi

	python -m app.certlocal bootstrap || {
		echo "[hub] amorçage TLS impossible ; arrêt." >&2
		exit 70
	}
fi

exec "$@"
