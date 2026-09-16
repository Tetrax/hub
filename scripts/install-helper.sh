#!/usr/bin/env bash
# Installe (idempotent) le helper certificat root de SNS Hub.
# À exécuter en root : sudo scripts/install-helper.sh
#
# Installe : /opt/hub-cert-helper, /var/lib/hub/certificates, le service systemd,
# /etc/hub-cert-helper.env (depuis l'exemple si absent) et le hook certbot.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

if [ "$(id -u)" -ne 0 ]; then
  echo "À exécuter en root (sudo scripts/install-helper.sh)." >&2
  exit 1
fi

install -d -m 0755 /opt/hub-cert-helper/scripts
install -m 0644 "$REPO/helper/hub_certctl.py" /opt/hub-cert-helper/scripts/
install -m 0644 "$REPO/helper/hub_cert_lock.py" /opt/hub-cert-helper/scripts/
install -m 0644 "$REPO/helper/hub_cert_helper.py" /opt/hub-cert-helper/scripts/
install -m 0644 "$REPO/app/hub_cert_protocol.py" /opt/hub-cert-helper/scripts/
install -d -m 0755 /var/lib/hub/certificates

if [ ! -f /etc/hub-cert-helper.env ]; then
  install -m 0600 "$REPO/deploy/hub-cert-helper.env.example" /etc/hub-cert-helper.env
  echo "Créé /etc/hub-cert-helper.env depuis l'exemple (vérifier HUB_TLS_HOSTNAME)."
fi

install -m 0644 "$REPO/deploy/hub-cert-helper.service" /etc/systemd/system/hub-cert-helper.service
systemctl daemon-reload
systemctl enable --now hub-cert-helper.service
sleep 1

if ! systemctl is-active --quiet hub-cert-helper.service; then
  echo "Le service hub-cert-helper n'est pas actif :" >&2
  systemctl status hub-cert-helper.service --no-pager >&2 || true
  exit 1
fi

install -m 0755 "$REPO/deploy/certbot-deploy-hub.sh" /etc/letsencrypt/renewal-hooks/deploy/hub
echo "Hook certbot installé : /etc/letsencrypt/renewal-hooks/deploy/hub"

HUB_CERT_HELPER_SOCKET="$(grep -oP '^HUB_CERT_HELPER_SOCKET=\K.*' /etc/hub-cert-helper.env || echo /run/hub-cert-helper/helper.sock)"
if HUB_CERT_HELPER_SOCKET="$HUB_CERT_HELPER_SOCKET" \
     /usr/bin/python3 /opt/hub-cert-helper/scripts/hub_cert_helper.py ping; then
  echo "Helper opérationnel (socket $HUB_CERT_HELPER_SOCKET)."
else
  echo "Le helper ne répond pas au ping." >&2
  exit 1
fi
