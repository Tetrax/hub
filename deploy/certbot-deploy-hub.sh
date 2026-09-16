#!/bin/sh
# Hook certbot (déploiement) pour le renouvellement Let's Encrypt de Hub.
#
# Nginx sert /var/lib/hub/certificates/active, pas la lignée Certbot : ce hook
# réinstalle la paire renouvelée par le mécanisme autoritatif du helper
# (validation complète, bascule atomique, nginx -t, reload, vérification du
# certificat servi, rollback en cas d'échec).
#
# Le service certbot tient déjà le verrou infra partagé (certbot.service) ;
# ne pas le reprendre ici.
#
# Installation : /etc/letsencrypt/renewal-hooks/deploy/hub (root, 0755).

set -eu
[ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/hub.valdev.me ] || exit 0
set -a
. /etc/hub-cert-helper.env
set +a
exec /usr/bin/python3 /opt/hub-cert-helper/scripts/hub_cert_helper.py renew
