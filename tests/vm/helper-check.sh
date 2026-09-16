#!/usr/bin/env bash
# V1.3 — helper certificat : Nginx réellement optionnel (§34).
#
# Lance une instance ISOLÉE du helper (socket et répertoires dans /tmp, binaires
# Nginx/systemctl factices absents). La production n'est pas touchée :
# /run/hub-cert-helper et /var/lib/hub ne sont jamais utilisés.
#
# Usage : sudo bash tests/vm/helper-check.sh
set -uo pipefail
cd "$(dirname "$0")/../.."
REPO="$PWD"
ROOT="${HELPER_CHECK_ROOT:-/tmp/hub-helper-check}"
HOSTNAME_TEST="hub.interne.example"

PASS=0; FAIL=0
check() { local label="$1"; shift; if "$@" >/dev/null 2>&1; then printf '  [OK]   %s\n' "$label"; PASS=$((PASS+1)); else printf '  [FAIL] %s\n' "$label"; FAIL=$((FAIL+1)); fi; }
ok()   { printf '  [OK]   %s\n' "$1"; PASS=$((PASS+1)); }
ko()   { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
info() { printf '  [INFO] %s\n' "$1"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "À exécuter en root : sudo bash tests/vm/helper-check.sh" >&2
  exit 1
fi

rm -rf "$ROOT"; mkdir -p "$ROOT/fake-bin"
info "bac à sable : $ROOT (binaires Nginx/systemctl volontairement absents)"

# Paire de test (auto-signée) pour le domaine interne simulé.
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -keyout "$ROOT/key.pem" -out "$ROOT/cert.pem" \
  -subj "/CN=$HOSTNAME_TEST" -addext "subjectAltName=DNS:$HOSTNAME_TEST" >/dev/null 2>&1
check "paire de test générée" test -s "$ROOT/cert.pem"

helper_env() { # helper_env <reload> <répertoire> <commande...>
  local reload="$1"; shift
  local dir="$1"; shift
  env HUB_TLS_HOSTNAME="$HOSTNAME_TEST" \
      HUB_CERT_OUTPUT_DIR="$dir/active" \
      HUB_CERT_STAGING_DIR="$dir/staging" \
      HUB_CERT_HELPER_SOCKET="$dir/helper.sock" \
      HUB_PUID=1000 HUB_PGID=1000 \
      HUB_CERT_RELOAD_NGINX="$reload" \
      HUB_NGINX_BIN=/nonexistent/nginx HUB_SYSTEMCTL=/nonexistent/systemctl \
      python3 "$REPO/helper/hub_cert_helper.py" "$@"
}

helper_socket_env() { # client lié à une socket précise (mêmes variables requises)
  local dir="$1"; shift
  env HUB_TLS_HOSTNAME="$HOSTNAME_TEST" \
      HUB_CERT_OUTPUT_DIR="$dir/active" \
      HUB_CERT_STAGING_DIR="$dir/staging" \
      HUB_CERT_HELPER_SOCKET="$dir/helper.sock" \
      HUB_PUID=1000 HUB_PGID=1000 \
      HUB_CERT_RELOAD_NGINX=0 \
      python3 "$REPO/helper/hub_cert_helper.py" "$@"
}

echo "### A. Mode sans Nginx (HUB_CERT_RELOAD_NGINX=0)"
mkdir -p "$ROOT/sans-nginx"
install_out="$(helper_env 0 "$ROOT/sans-nginx" install --cert "$ROOT/cert.pem" --key "$ROOT/key.pem" 2>&1)"
rc=$?
if [ "$rc" -eq 0 ]; then
  ok "install (validation + activation) réussit SANS Nginx ni systemctl"
else
  ko "install échoue sans Nginx : $install_out"
fi
if [ -L "$ROOT/sans-nginx/active" ] || [ -d "$ROOT/sans-nginx/active" ]; then
  ok "paire activée (lien/génération en place)"
else
  ko "aucune activation constatée dans $ROOT/sans-nginx"
fi
status_out="$(helper_env 0 "$ROOT/sans-nginx" status 2>&1)"
if printf '%s' "$status_out" | grep -q "$HOSTNAME_TEST"; then
  ok "status décrit la paire active"
else
  ko "status inattendu : $status_out"
fi

echo "### B. Mode Nginx (HUB_CERT_RELOAD_NGINX=1) avec Nginx absent"
mkdir -p "$ROOT/avec-nginx"
helper_env 0 "$ROOT/avec-nginx" install --cert "$ROOT/cert.pem" --key "$ROOT/key.pem" >/dev/null 2>&1
BEFORE="$(readlink -f "$ROOT/avec-nginx/active" 2>/dev/null || echo none)"
reload_out="$(helper_env 1 "$ROOT/avec-nginx" install --cert "$ROOT/cert.pem" --key "$ROOT/key.pem" 2>&1)"
rc=$?
AFTER="$(readlink -f "$ROOT/avec-nginx/active" 2>/dev/null || echo none)"
if [ "$rc" -ne 0 ] && printf '%s' "$reload_out" | grep -qi "nginx"; then
  ok "activation refusée proprement (Nginx requis en mode reload=1)"
else
  ko "échec attendu non observé (rc=$rc) : $reload_out"
fi
if [ "$BEFORE" = "$AFTER" ]; then
  ok "aucune bascule : la paire active reste celle d'avant l'échec"
else
  ko "la paire active a changé malgré l'échec ($BEFORE → $AFTER)"
fi

echo "### C. Socket Unix + SO_PEERCRED (mode service)"
mkdir -p "$ROOT/service"
helper_env 0 "$ROOT/service" serve >"$ROOT/service.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 20); do [ -S "$ROOT/service/helper.sock" ] && break; sleep 0.5; done
check "socket créée" test -S "$ROOT/service/helper.sock"
helper_socket_env "$ROOT/service" ping >/dev/null 2>&1 \
  && ok "ping via la socket (processus root autorisé par SO_PEERCRED)" \
  || ko "ping via la socket"
sock_status="$(helper_socket_env "$ROOT/service" status 2>&1)"
printf '%s' "$sock_status" | grep -q "$HOSTNAME_TEST" \
  && ok "status via la socket (helper sans Nginx opérationnel)" \
  || ko "status via la socket : $sock_status"
kill "$SERVER_PID" 2>/dev/null
wait "$SERVER_PID" 2>/dev/null

echo "### D. Durcissement du service systemd"
if command -v systemd-analyze >/dev/null 2>&1; then
  verify="$(systemd-analyze verify "$REPO/deploy/hub-cert-helper.service" 2>&1 || true)"
  if printf '%s' "$verify" | grep -qi "nginx.service.*not found\|requires.*nginx"; then
    ko "dépendance Nginx encore détectée : $verify"
  else
    ok "unité systemd valide sans dépendance Nginx absolue"
  fi
  printf '%s' "$verify" | grep -qi "Requires=nginx" && ko "Requires=nginx encore présent" || ok "Requires=nginx absent"
else
  info "systemd-analyze indisponible : vérification statique ignorée"
fi
grep -q "Requires=nginx.service" "$REPO/deploy/hub-cert-helper.service" \
  && ko "Requires=nginx.service encore dans le fichier" || ok "fichier d'unité sans Requires=nginx.service"

echo
echo "==================================================="
printf 'Helper certificat : %d réussites, %d échecs\n' "$PASS" "$FAIL"
echo "==================================================="
[ "$FAIL" -eq 0 ]
