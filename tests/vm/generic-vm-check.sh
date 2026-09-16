#!/usr/bin/env bash
# V1.3 — recette « nouvelle VM » isolée.
#
# Simule une VM Linux vierge : Docker + Compose uniquement, AUCUN Nginx,
# AUCUN Certbot, AUCUN helper certificat, AUCUNE surcharge VPS.
# Le stack tourne dans un projet Compose séparé (hub-vmcheck) sur un port
# dédié : la production du VPS n'est ni touchée ni arrêtée.
#
# Couvre :
#   §30 application complète sans helper/Nginx (landing, admin, CRUD, uploads,
#       catégories, paramètres, thème, healthcheck, page certificats propre) ;
#   §31 en-têtes de proxy : trusted (cookie Secure, HSTS, Host) vs non trusted ;
#   §32 UID/GID : défaut, ownership incorrect (erreur claire), UID/GID alternatif ;
#   §33 réseau Docker : plus de sous-réseau imposé, aucun conflit.
#
# Usage : bash tests/vm/generic-vm-check.sh [--keep]
set -uo pipefail
cd "$(dirname "$0")/../.."
REPO="$PWD"

PROJECT=hub-vmcheck
PORT="${VM_CHECK_PORT:-13807}"
ROOT="${VM_CHECK_ROOT:-/tmp/hub-vmcheck}"
KEEP="${1:-}"

PASS=0; FAIL=0
check() { # check "libellé" "commande de test"
  local label="$1"; shift
  if "$@" >/dev/null 2>&1; then printf '  [OK]   %s\n' "$label"; PASS=$((PASS+1));
  else printf '  [FAIL] %s\n' "$label"; FAIL=$((FAIL+1)); fi
}
check_eq() { # check_eq "libellé" attendu obtenu
  if [ "$2" = "$3" ]; then printf '  [OK]   %s (%s)\n' "$1" "$3"; PASS=$((PASS+1));
  else printf '  [FAIL] %s — attendu « %s », obtenu « %s »\n' "$1" "$2" "$3"; FAIL=$((FAIL+1)); fi
}
check_contains() { # check_contains "libellé" fichier/chaîne valeur
  if printf '%s' "$3" | grep -qF -- "$2"; then printf '  [OK]   %s\n' "$1"; PASS=$((PASS+1));
  else printf '  [FAIL] %s — « %s » absent\n' "$1" "$2"; FAIL=$((FAIL+1)); fi
}
compose() { docker compose -p "$PROJECT" -f compose.yaml "$@" >/dev/null 2>&1; }
compose_env() { # compose_env VAR=VAL ... -- args
  local envs=()
  while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done
  shift || true
  env "${envs[@]}" docker compose -p "$PROJECT" -f compose.yaml "$@"
}

cleanup() {
  docker compose -p "$PROJECT" -f compose.yaml down --remove-orphans >/dev/null 2>&1 || true
  if [ "$KEEP" != "--keep" ]; then sudo rm -rf "$ROOT" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

echo "### Phase 0 — préparation de la « VM » ($ROOT)"
sudo rm -rf "$ROOT"; mkdir -p "$ROOT"; cd "$REPO"

DATA="$ROOT/data"
DATA_ALT="$ROOT/data-alt"
DATA_BAD="$ROOT/data-bad"
NOHELPER="$ROOT/no-helper"; mkdir -p "$NOHELPER"
# Préparation documentée du répertoire de données (propriétaire = UID applicatif).
sudo install -d -o 1000 -g 1000 -m 0755 "$DATA" "$DATA/uploads"
check "répertoire de données préparé (propriétaire 1000:1000)" test "$(stat -c %u "$DATA")" = 1000

BASE_ENV=(
  "HUB_IMAGE_TAG=vmcheck"
  "HUB_GIT_SHA=vmcheck"
  "HUB_CONTAINER_NAME=$PROJECT-web"
  "HUB_PORT=$PORT"
  "HUB_BIND_IP=127.0.0.1"
  "HUB_DATA_PATH=$DATA"
  "HUB_CERT_HELPER_DIR=$NOHELPER"
  "HUB_TLS_HOSTNAME="
  "HUB_TRUSTED_PROXY_CIDRS="
)

echo "### Phase 1 — Compose générique (sans surcharge VPS)"
RENDER="$(env "${BASE_ENV[@]}" docker compose -p "$PROJECT" -f compose.yaml config 2>&1)"
check "compose générique valide" test "$(env "${BASE_ENV[@]}" docker compose -p "$PROJECT" -f compose.yaml config >/dev/null 2>&1; echo $?)" = 0
if printf '%s' "$RENDER" | grep -q "subnet: 172.31.244"; then
  printf '  [FAIL] sous-réseau VPS présent dans le rendu générique\n'; FAIL=$((FAIL+1))
else
  printf '  [OK]   aucun sous-réseau VPS dans le rendu générique\n'; PASS=$((PASS+1))
fi

echo "### Phase 2 — build + démarrage sans Nginx / Certbot / helper"
env "${BASE_ENV[@]}" docker compose -p "$PROJECT" -f compose.yaml up -d --build >/tmp/hub-vmcheck-up.log 2>&1
UP_RC=$?
check_eq "docker compose up -d --build" "0" "$UP_RC"
if [ "$UP_RC" != "0" ]; then tail -20 /tmp/hub-vmcheck-up.log; ls; exit 1; fi

for _ in $(seq 1 40); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$PROJECT-web" 2>/dev/null)" = "healthy" ] && break
  sleep 2
done
check_eq "conteneur healthy (sans helper)" "healthy" "$(docker inspect -f '{{.State.Health.Status}}' "$PROJECT-web" 2>/dev/null)"

BASE_URL="http://127.0.0.1:$PORT"
CURL=(curl -sS --max-time 10)
JAR="$ROOT/cookies.txt"

check_eq "healthz = 200" "200" "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE_URL/healthz")"
HZ="$("${CURL[@]}" "$BASE_URL/healthz")"
EXPECTED_VERSION=$(grep -m1 '^__version__' app/__init__.py | cut -d'"' -f2)
check_contains "healthz : version $EXPECTED_VERSION" "$EXPECTED_VERSION" "$HZ"
LANDING="$("${CURL[@]}" "$BASE_URL/")"
check_eq "landing = 200" "200" "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE_URL/")"
check_contains "landing : contenu rendu" "SNS" "$LANDING"
check_contains "landing : données de thème" "data-theme" "$LANDING"

# Première configuration (compte local de cette instance jetable).
"${CURL[@]}" -c "$JAR" -L "$BASE_URL/admin/setup" -o "$ROOT/setup.html"
TOKEN="$(grep -oP 'name="_csrf" value="\K[^"]+' "$ROOT/setup.html" | head -1)"
"${CURL[@]}" -b "$JAR" -c "$JAR" -o /dev/null -w '' \
  -d "_csrf=$TOKEN" -d "username=vmcheck" -d "password=MotDePasseVmCheck2026" -d "confirmation=MotDePasseVmCheck2026" \
  "$BASE_URL/admin/setup"
check_eq "admin : tableau de bord accessible" "200" "$("${CURL[@]}" -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE_URL/admin/")"

for path in /admin/apps /admin/categories /admin/settings /admin/certificates; do
  check_eq "admin $path = 200" "200" "$("${CURL[@]}" -b "$JAR" -o /dev/null -w '%{http_code}' "$BASE_URL$path")"
done

CERT_PAGE="$("${CURL[@]}" -b "$JAR" "$BASE_URL/admin/certificates")"
check_contains "page certificats : indisponibilité signalée" "indisponible" "$CERT_PAGE"
check_contains "page certificats : méthode PKCS#12 proposée" "method-pkcs12" "$CERT_PAGE"

# CRUD : nouvelle catégorie (création rapide — formulaire, comme le JS), puis application + capture.
PAGE_APPS="$("${CURL[@]}" -b "$JAR" "$BASE_URL/admin/apps/new")"
TOKEN="$(printf '%s' "$PAGE_APPS" | grep -oP 'name="_csrf" value="\K[^"]+' | head -1)"
check "jeton CSRF récupéré depuis le formulaire" test -n "$TOKEN"
QC="$("${CURL[@]}" -b "$JAR" -H 'Accept: application/json' \
      --data-urlencode "_csrf=$TOKEN" --data-urlencode "name=VM Check" \
      "$BASE_URL/admin/categories/quick-create")"
CAT_ID="$(printf '%s' "$QC" | .venv/bin/python -c 'import json,sys; d=json.load(sys.stdin); print(d.get("category",{}).get("id",""))' 2>/dev/null)"
check_contains "création rapide de catégorie (JSON)" "\"name\"" "$QC"
check "identifiant de catégorie exploitable" test -n "$CAT_ID"

.venv/bin/python - "$ROOT/shot.png" <<'PY'
import sys
from PIL import Image
Image.new("RGB", (320, 180), (244, 168, 201)).save(sys.argv[1])
PY
CREATE_RC="$("${CURL[@]}" -b "$JAR" -o "$ROOT/create.html" -w '%{http_code}' \
  -F "_csrf=$TOKEN" -F "name=Application de test VM" -F "slug=app-test-vm" \
  -F "description=Créée par la recette de portabilité." -F "url=https://interne.example/app" \
  -F "category_id=$CAT_ID" -F "status=production" -F "image=@$ROOT/shot.png;type=image/png" \
  "$BASE_URL/admin/apps/new")"
check_eq "création d'application + capture (multipart)" "302" "$CREATE_RC"

LANDING2="$("${CURL[@]}" "$BASE_URL/")"
check_contains "landing : application publiée visible" "Application de test VM" "$LANDING2"
IMG="$(printf '%s' "$LANDING2" | grep -oP '/img/\K[a-f0-9-]+\.(png|webp|jpg)' | head -1)"
check_eq "capture servie = 200" "200" "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE_URL/img/$IMG")"
check "capture persistée sur le disque hôte" test -n "$(ls -A "$DATA/uploads" 2>/dev/null)"
check "base SQLite créée sur l'hôte" test -f "$DATA/hub.sqlite"
check "clé de session créée (0600)" test "$(stat -c %a "$DATA/.secret_key")" = "600"

SETTINGS_RC="$("${CURL[@]}" -b "$JAR" -o "$ROOT/settings.html" -w '%{http_code}' "$BASE_URL/admin/settings")"
check_eq "paramètres : page rendue" "200" "$SETTINGS_RC"

echo "### Phase 3 — réseau Docker"
NET_SUBNET="$(docker network inspect "${PROJECT}_default" -f '{{(index .IPAM.Config 0).Subnet}}' 2>/dev/null)"
printf '  [INFO] sous-réseau attribué automatiquement : %s\n' "${NET_SUBNET:-inconnu}"
if [ "${NET_SUBNET:-}" = "172.31.244.0/24" ]; then
  printf '  [FAIL] conflit : Docker a repris le sous-réseau du VPS\n'; FAIL=$((FAIL+1))
else
  printf '  [OK]   sous-réseau distinct du VPS (aucun conflit)\n'; PASS=$((PASS+1))
fi

echo "### Phase 4 — UID/GID"
# (a) ownership incorrect : reproduit l'erreur la plus fréquente d'une VM vierge.
sudo install -d -o 0 -g 0 -m 0755 "$DATA_BAD"
env "${BASE_ENV[@]/HUB_DATA_PATH=$DATA/HUB_DATA_PATH=$DATA_BAD}" \
  docker compose -p "$PROJECT" -f compose.yaml up -d >/dev/null 2>&1
BAD_LOGS=""
for _ in $(seq 1 20); do
  BAD_LOGS="$(docker logs "$PROJECT-web" 2>&1 | tail -40)"
  printf '%s' "$BAD_LOGS" | grep -q "non inscriptible" && break
  sleep 3
done
if printf '%s' "$BAD_LOGS" | grep -q "non inscriptible"; then
  printf '  [OK]   ownership incorrect → erreur explicite dans les journaux\n'; PASS=$((PASS+1))
else
  printf '  [FAIL] ownership incorrect → message attendu absent :\n%s\n' "$BAD_LOGS"; FAIL=$((FAIL+1))
fi
if printf '%s' "$BAD_LOGS" | grep -q "prepare-data-dir.sh"; then
  printf '  [OK]   le message indique la commande de correction\n'; PASS=$((PASS+1))
else
  printf '  [FAIL] le message ne guide pas vers la correction\n'; FAIL=$((FAIL+1))
fi
BAD_STATE="$(docker inspect -f '{{.State.Health.Status}}' "$PROJECT-web" 2>/dev/null)"
if [ "$BAD_STATE" != "healthy" ]; then
  printf '  [OK]   conteneur jamais healthy avec un data dir inaccessible (%s)\n' "$BAD_STATE"
  PASS=$((PASS+1))
else
  printf '  [FAIL] conteneur healthy avec un data dir inaccessible\n'; FAIL=$((FAIL+1))
fi
# (b) UID/GID alternatif (1301:1301) : la portabilité ne dépend pas de l'UID 1000.
sudo install -d -o 1301 -g 1301 -m 0755 "$DATA_ALT" "$DATA_ALT/uploads"
env "HUB_IMAGE_TAG=vmcheck" "HUB_GIT_SHA=vmcheck" "HUB_CONTAINER_NAME=$PROJECT-web" \
    "HUB_PORT=$PORT" "HUB_BIND_IP=127.0.0.1" "HUB_DATA_PATH=$DATA_ALT" \
    "HUB_CERT_HELPER_DIR=$NOHELPER" "HUB_UID=1301" "HUB_GID=1301" \
  docker compose -p "$PROJECT" -f compose.yaml up -d >/dev/null 2>&1
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$PROJECT-web" 2>/dev/null)" = "healthy" ] && break
  sleep 2
done
check_eq "UID/GID alternatif 1301:1301 → healthy" "healthy" \
  "$(docker inspect -f '{{.State.Health.Status}}' "$PROJECT-web" 2>/dev/null)"
check_eq "UID/GID alternatif : propriétaire écrit sur l'hôte" "1301" \
  "$(stat -c %u "$DATA_ALT/.secret_key" 2>/dev/null)"
# Retour à la configuration nominale (données 1000:1000).
env "${BASE_ENV[@]}" docker compose -p "$PROJECT" -f compose.yaml up -d >/dev/null 2>&1
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$PROJECT-web" 2>/dev/null)" = "healthy" ] && break
  sleep 2
done

echo "### Phase 5 — en-têtes de proxy (§31)"
GW="$(docker network inspect "${PROJECT}_default" -f '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null)"
printf '  [INFO] gateway du réseau (source des requêtes depuis l’hôte) : %s\n' "${GW:-inconnu}"

# 5a. proxy NON déclaré de confiance : les en-têtes forgés sont ignorés.
"${CURL[@]}" -D "$ROOT/h-untrusted.txt" -o /dev/null -H 'X-Forwarded-Proto: https' \
  -H 'X-Forwarded-For: 203.0.113.9' "$BASE_URL/healthz"
if grep -qi "strict-transport-security" "$ROOT/h-untrusted.txt"; then
  printf '  [FAIL] HSTS émis sans proxy de confiance (en-tête forgé accepté)\n'; FAIL=$((FAIL+1))
else
  printf '  [OK]   en-tête X-Forwarded-Proto ignoré sans proxy de confiance (pas de HSTS)\n'; PASS=$((PASS+1))
fi
"${CURL[@]}" -D "$ROOT/login-untrusted.txt" -o /dev/null \
  -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-For: 203.0.113.9' "$BASE_URL/admin/login"
UT_COOKIE="$(grep -i '^set-cookie' "$ROOT/login-untrusted.txt" || true)"
if [ -n "$UT_COOKIE" ] && ! printf '%s' "$UT_COOKIE" | grep -qi "secure"; then
  printf '  [OK]   cookie de session émis SANS Secure (HTTPS non prouvé)\n'; PASS=$((PASS+1))
else
  printf '  [FAIL] cookie inattendu sans proxy de confiance : %s\n' "${UT_COOKIE:-aucun cookie émis}"; FAIL=$((FAIL+1))
fi
# Origine refusée : POST CSRF depuis une origine étrangère.
CROSS="$("${CURL[@]}" -b "$JAR" -o /dev/null -w '%{http_code}' -H "Origin: https://attaquant.example" \
  -F "_csrf=$TOKEN" -F "name=Pirate" -F "url=https://attaquant.example" -F "category_id=$CAT_ID" \
  -F "status=production" "$BASE_URL/admin/apps/new")"
check_eq "origine étrangère refusée (CSRF/Origin)" "403" "$CROSS"

# 5b. proxy DÉCLARÉ de confiance : HTTPS détecté (cookie Secure + HSTS),
#     et l'origine attendue est bien calculée depuis Host + X-Forwarded-Proto.
env "HUB_IMAGE_TAG=vmcheck" "HUB_GIT_SHA=vmcheck" "HUB_CONTAINER_NAME=$PROJECT-web" \
    "HUB_PORT=$PORT" "HUB_BIND_IP=127.0.0.1" "HUB_DATA_PATH=$DATA" \
    "HUB_CERT_HELPER_DIR=$NOHELPER" "HUB_TRUSTED_PROXY_CIDRS=${GW}/32" \
  docker compose -p "$PROJECT" -f compose.yaml up -d >/dev/null 2>&1
for _ in $(seq 1 30); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$PROJECT-web" 2>/dev/null)" = "healthy" ] && break
  sleep 2
done
"${CURL[@]}" -D "$ROOT/h-trusted.txt" -o /dev/null -H 'X-Forwarded-Proto: https' "$BASE_URL/healthz"
if grep -qi "^strict-transport-security" "$ROOT/h-trusted.txt"; then
  printf '  [OK]   HSTS présent derrière proxy de confiance\n'; PASS=$((PASS+1))
else
  printf '  [FAIL] HSTS absent derrière proxy de confiance\n'; FAIL=$((FAIL+1))
fi
"${CURL[@]}" -c "$ROOT/cookies-trusted.txt" -D "$ROOT/login-trusted.txt" -o /dev/null \
  -H 'X-Forwarded-Proto: https' "$BASE_URL/admin/login"
if grep -i '^set-cookie' "$ROOT/login-trusted.txt" | grep -qi "secure"; then
  printf '  [OK]   cookie de session Secure derrière proxy de confiance\n'; PASS=$((PASS+1))
else
  printf '  [FAIL] cookie Secure absent derrière proxy de confiance : %s\n' \
    "$(grep -i '^set-cookie' "$ROOT/login-trusted.txt" || echo 'aucun cookie émis')"; FAIL=$((FAIL+1))
fi
# Host + proto du proxy : l'origine attendue devient https://hub.intra.example,
# donc un POST portant cette origine est accepté (au lieu d'un 403).
PROXY_POST="$("${CURL[@]}" -b "$JAR" -o /dev/null -w '%{http_code}' \
  -H 'X-Forwarded-Proto: https' -H 'Host: hub.intra.example' \
  -H 'Origin: https://hub.intra.example' \
  -F "_csrf=$TOKEN" -F "name=Depuis proxy entreprise" -F "slug=depuis-proxy" \
  -F "url=https://interne.example/proxy" -F "category_id=$CAT_ID" -F "status=production" \
  "$BASE_URL/admin/apps/new")"
check_eq "Host + proto du proxy honorés (origine HTTPS acceptée)" "302" "$PROXY_POST"
LANDING_PROXY="$("${CURL[@]}" -H 'X-Forwarded-Proto: https' -H 'Host: hub.intra.example' "$BASE_URL/")"
check_contains "landing servie derrière proxy (Host interne)" "SNS" "$LANDING_PROXY"
# Connexion réelle derrière le proxy : le cookie applicatif doit être Secure+HttpOnly.
LOGIN_PAGE="$("${CURL[@]}" -c "$ROOT/jar-proxy.txt" -H 'X-Forwarded-Proto: https' "$BASE_URL/admin/login")"
PTOKEN="$(printf '%s' "$LOGIN_PAGE" | grep -oP 'name="_csrf" value="\K[^"]+' | head -1)"
"${CURL[@]}" -b "$ROOT/jar-proxy.txt" -c "$ROOT/jar-proxy.txt" -D "$ROOT/login-ok.txt" -o /dev/null \
  -H 'X-Forwarded-Proto: https' --data-urlencode "_csrf=$PTOKEN" \
  --data-urlencode "username=vmcheck" --data-urlencode "password=MotDePasseVmCheck2026" \
  "$BASE_URL/admin/login"
SESSION_COOKIE="$(grep -i '^set-cookie: hub_session' "$ROOT/login-ok.txt" || true)"
if printf '%s' "$SESSION_COOKIE" | grep -qi "secure" && printf '%s' "$SESSION_COOKIE" | grep -qi "httponly"; then
  printf '  [OK]   cookie applicatif Secure + HttpOnly derrière proxy de confiance\n'; PASS=$((PASS+1))
else
  printf '  [FAIL] cookie applicatif inattendu : %s\n' "${SESSION_COOKIE:-aucun}"; FAIL=$((FAIL+1))
fi

echo "### Phase 6 — nettoyage"
docker compose -p "$PROJECT" -f compose.yaml down --remove-orphans >/dev/null 2>&1
check_eq "production intacte (hub-web healthy)" "healthy" \
  "$(docker inspect -f '{{.State.Health.Status}}' hub-web 2>/dev/null)"
printf '  [INFO] conteneur de production : %s (image %s)\n' \
  "$(docker inspect -f '{{.State.Health.Status}} restarts={{.RestartCount}}' hub-web 2>/dev/null)" \
  "$(docker inspect -f '{{.Config.Image}}' hub-web 2>/dev/null)"

echo
echo "==================================================="
printf 'Recette VM générique : %d réussites, %d échecs\n' "$PASS" "$FAIL"
echo "==================================================="
[ "$FAIL" -eq 0 ]
