#!/usr/bin/env bash
# V1.4 — recette « déploiement STANDALONE » isolée (HTTPS direct, un seul conteneur).
#
# Simule ce que fait Portainer : un seul fichier Compose
# (`compose.standalone.yaml`), un nom de domaine, un port — et rien d'autre.
# AUCUN Nginx, AUCUN Caddy, AUCUN Certbot, AUCUN helper root, AUCUN socket
# Docker, AUCUNE commande à lancer sur la machine (ni mkdir, ni chown, ni
# /etc/hosts).
#
# Le stack tourne dans un projet Compose séparé (hub-standalone-check) sur un
# port dédié : une production présente sur la même machine n'est pas touchée.
#
# Couvre : bootstrap TLS, création du compte, import PKCS#12, activation et
# certificat RÉELLEMENT servi (sans redémarrage du conteneur), persistance
# (restart + redéploiement), refus d'un certificat hors domaine, isolation et
# privilèges. Avec STANDALONE_CHECK_BROWSER=1, la recette navigateur réelle est
# rejouée contre ce déploiement.
#
# Usage : bash tests/vm/standalone-check.sh [--keep]
set -uo pipefail
cd "$(dirname "$0")/../.."
REPO="$PWD"

PROJECT="${STANDALONE_CHECK_PROJECT:-hub-standalone-check}"
HOSTNAME_TEST="${STANDALONE_CHECK_HOSTNAME:-hub.standalone.test}"
HTTPS_PORT="${STANDALONE_CHECK_HTTPS_PORT:-18443}"
KEEP="${1:-}"

WORK="${STANDALONE_CHECK_WORK:-/tmp/hub-standalone-check}"
CERTS="$WORK/pki"
ADMIN_PASSWORD="RecetteStandalone-V14!"
IMAGE_TAG="standalone-check"

PASS=0; FAIL=0
ok()   { printf '  [OK]   %s\n' "$1"; PASS=$((PASS+1)); }
ko()   { printf '  [FAIL] %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if eval "$2" >/dev/null 2>&1; then ok "$1"; else ko "$1"; fi; }
check_eq() { if [ "$2" = "$3" ]; then ok "$1"; else ko "$1 — attendu « $2 », obtenu « $3 »"; fi; }

BASE_URL="https://${HOSTNAME_TEST}:${HTTPS_PORT}"
RESOLVE="--resolve ${HOSTNAME_TEST}:${HTTPS_PORT}:127.0.0.1"
COOKIES="$WORK/cookies.txt"

compose() {
  HUB_HOSTNAME="$HOSTNAME_TEST" HUB_HTTPS_PORT="$HTTPS_PORT" \
  HUB_IMAGE_TAG="$IMAGE_TAG" HUB_GIT_SHA="$IMAGE_TAG" \
  docker compose -p "$PROJECT" -f compose.standalone.yaml "$@"
}
web_container() {
  docker ps -aqf "label=com.docker.compose.project=${PROJECT}" \
    -f "label=com.docker.compose.service=web" | head -1
}
served_fingerprint() {
  echo | openssl s_client -connect "127.0.0.1:${HTTPS_PORT}" -servername "$HOSTNAME_TEST" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2
}

echo "### Phase 0 — prérequis et bac à sable"
missing=0
for tool in docker openssl curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "  outil manquant : $tool"; missing=1; }
done
docker compose version >/dev/null 2>&1 || { echo "  docker compose indisponible"; missing=1; }
[ "$missing" = "0" ] || { echo "Prérequis non satisfaits."; exit 1; }
mkdir -p "$WORK"
compose down -v --remove-orphans >/dev/null 2>&1 || true
busy=$(docker ps --format '{{.Names}}\t{{.Ports}}' | grep -E ":${HTTPS_PORT}->" || true)
if [ -n "$busy" ]; then
  echo "  port déjà utilisé par un conteneur étranger :"; printf '    %s\n' "$busy"
  echo "  → STANDALONE_CHECK_HTTPS_PORT=18444 bash tests/vm/standalone-check.sh"
  exit 1
fi
echo "  projet $PROJECT · domaine $HOSTNAME_TEST · port $HTTPS_PORT · volumes vierges"

echo
echo "### Phase 1 — image (un seul service, aucun second conteneur)"
docker build -q -t "hub:${IMAGE_TAG}" --build-arg HUB_GIT_SHA="$IMAGE_TAG" . >/dev/null 2>&1
check "image applicative construite" "docker image inspect hub:${IMAGE_TAG}"
check "openssl embarqué (validation partagée avec le VPS)" \
  "docker run --rm --entrypoint sh hub:${IMAGE_TAG} -c 'command -v openssl'"
check "module partagé hub_certctl embarqué" \
  "docker run --rm --entrypoint sh hub:${IMAGE_TAG} -c 'python -c \"import hub_certctl\"'"
check "aucun second Dockerfile livré" "[ \"\$(ls Dockerfile* | wc -l)\" = \"1\" ]"
check "aucun composant proxy dans le dépôt" "[ ! -d deploy/standalone ]"
check "entrypoint d'amorçage présent dans l'image" \
  "docker run --rm --entrypoint sh hub:${IMAGE_TAG} -c 'test -x /opt/hub/app/standalone/entrypoint.sh'"

echo
echo "### Phase 2 — démarrage (aucun prérequis hôte, volumes créés automatiquement)"
compose up -d >/dev/null 2>&1
sleep 12
check_eq "conteneur healthy" "healthy" "$(docker inspect -f '{{.State.Health.Status}}' "$(web_container)" 2>/dev/null)"
check_eq "aucun redémarrage" "0" "$(docker inspect -f '{{.RestartCount}}' "$(web_container)" 2>/dev/null)"
check_eq "un seul conteneur pour la stack" "1" "$(docker ps -aqf "label=com.docker.compose.project=${PROJECT}" | wc -l)"

echo
echo "### Phase 3 — certificat temporaire de bootstrap, HTTPS immédiat"
BOOT_FP="$(served_fingerprint)"
BOOT_ISSUER=$(echo | openssl s_client -connect "127.0.0.1:${HTTPS_PORT}" -servername "$HOSTNAME_TEST" 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null)
check "certificat de bootstrap servi (auto-signé)" "[ -n \"$BOOT_FP\" ]"
check "le certificat couvre le domaine demandé" \
  "echo | openssl s_client -connect 127.0.0.1:${HTTPS_PORT} -servername $HOSTNAME_TEST 2>/dev/null | openssl x509 -noout -checkhost $HOSTNAME_TEST"
check "landing joignable en HTTPS" "curl -k -s $RESOLVE -o /dev/null -w '%{http_code}' $BASE_URL | grep -q 200"
check "HSTS posé (TLS terminé par le Hub lui-même)" \
  "curl -k -sI $RESOLVE $BASE_URL | grep -qi 'strict-transport-security'"
check "marqueur de bootstrap présent dans le volume" \
  "docker exec $(web_container) test -f /certs/.bootstrap"
check "aucun ACME ni requête sortante dans les journaux" \
  "! docker logs $(web_container) 2>&1 | grep -qiE 'acme|letsencrypt'"

echo
echo "### Phase 4 — administration : compte et état du certificat"
CSRF=$(curl -k -s -c "$COOKIES" $RESOLVE "$BASE_URL/admin/setup" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | cut -d'"' -f4)
curl -k -s -b "$COOKIES" -c "$COOKIES" $RESOLVE -X POST "$BASE_URL/admin/setup" \
  --data-urlencode "_csrf=$CSRF" --data-urlencode "username=admin" \
  --data-urlencode "password=$ADMIN_PASSWORD" --data-urlencode "confirmation=$ADMIN_PASSWORD" >/dev/null
PAGE=$(curl -k -s -b "$COOKIES" -c "$COOKIES" $RESOLVE "$BASE_URL/admin/certificates")
check "page Certificats accessible" \
  "curl -k -s -b $COOKIES $RESOLVE -o /dev/null -w '%{http_code}' $BASE_URL/admin/certificates | grep -q 200"
printf '%s' "$PAGE" | grep -q "bootstrap" && ok "certificat temporaire annoncé" || ko "certificat temporaire annoncé"
printf '%s' "$PAGE" | grep -q "PKCS#12" && ok "import PKCS#12 proposé" || ko "import PKCS#12 proposé"
printf '%s' "$PAGE" | grep -q "HTTPS servi par le Hub" && ok "backend local annoncé" || ko "backend local annoncé"
# Connexion « comme un navigateur » (en-têtes Origin/Referer) : le contrôle
# d'origine doit accepter un port HTTPS non standard.
LOGIN_JAR="$WORK/cookies-login.txt"
LOGIN_CSRF=$(curl -k -s -c "$LOGIN_JAR" $RESOLVE "$BASE_URL/admin/login" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | cut -d'"' -f4)
LOGIN_CODE=$(curl -k -s -o /dev/null -w '%{http_code}' -b "$LOGIN_JAR" -c "$LOGIN_JAR" $RESOLVE \
  -X POST "$BASE_URL/admin/login" -H "Origin: $BASE_URL" -H "Referer: $BASE_URL/admin/login" \
  --data-urlencode "_csrf=$LOGIN_CSRF" --data-urlencode "username=admin" --data-urlencode "password=$ADMIN_PASSWORD")
check_eq "connexion navigateur acceptée (contrôle d'origine, port non standard)" "302" "$LOGIN_CODE"

echo
echo "### Phase 5 — PKI de recette (racine → intermédiaire → serveur) et PKCS#12"
mkdir -p "$CERTS"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout "$CERTS/root.key" -out "$CERTS/root.crt" \
  -subj "/CN=Root recette V1.4" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$CERTS/int.key" -out "$CERTS/int.csr" \
  -subj "/CN=Intermediaire recette V1.4" >/dev/null 2>&1
printf 'basicConstraints=CA:TRUE\nkeyUsage=keyCertSign\n' >"$CERTS/int.ext"
openssl x509 -req -in "$CERTS/int.csr" -CA "$CERTS/root.crt" -CAkey "$CERTS/root.key" -CAcreateserial \
  -days 25 -out "$CERTS/int.crt" -extfile "$CERTS/int.ext" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$CERTS/server.key" -out "$CERTS/server.csr" \
  -subj "/CN=$HOSTNAME_TEST" >/dev/null 2>&1
printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:FALSE\n' "$HOSTNAME_TEST" >"$CERTS/server.ext"
openssl x509 -req -in "$CERTS/server.csr" -CA "$CERTS/int.crt" -CAkey "$CERTS/int.key" -CAcreateserial \
  -days 20 -out "$CERTS/server.crt" -extfile "$CERTS/server.ext" >/dev/null 2>&1
openssl pkcs12 -export -out "$CERTS/hub.p12" -inkey "$CERTS/server.key" -in "$CERTS/server.crt" \
  -certfile "$CERTS/int.crt" -passout pass:RecetteV14 -name hub >/dev/null 2>&1
openssl pkcs12 -export -out "$CERTS/hub-nopass.p12" -inkey "$CERTS/server.key" -in "$CERTS/server.crt" \
  -certfile "$CERTS/int.crt" -passout pass: -name hub >/dev/null 2>&1
TARGET_FP=$(openssl x509 -in "$CERTS/server.crt" -noout -fingerprint -sha256 | cut -d= -f2)
check "PKCS#12 avec mot de passe généré" "[ -s $CERTS/hub.p12 ]"
check "PKCS#12 sans mot de passe généré" "[ -s $CERTS/hub-nopass.p12 ]"
check "paire PEM équivalente disponible" "[ -s $CERTS/server.crt ] && [ -s $CERTS/server.key ]"

echo
echo "### Phase 6 — import → activation → certificat RÉELLEMENT servi (sans redémarrage)"
CSRF=$(curl -k -s -b "$COOKIES" -c "$COOKIES" $RESOLVE "$BASE_URL/admin/certificates" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | cut -d'"' -f4)
VALIDATED=$(curl -k -s -b "$COOKIES" -c "$COOKIES" $RESOLVE -X POST "$BASE_URL/admin/certificates/validate-pkcs12" \
  -F "_csrf=$CSRF" -F "bundle=@$CERTS/hub.p12" -F "password=RecetteV14")
printf '%s' "$VALIDATED" | grep -q "prête à être activée" && ok "validation PKCS#12 acceptée" || ko "validation PKCS#12 acceptée"
TICKET=$(printf '%s' "$VALIDATED" | grep -o 'name="ticket" value="[^"]*"' | head -1 | cut -d'"' -f4)
CSRF2=$(printf '%s' "$VALIDATED" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | cut -d'"' -f4)
curl -k -s -o /dev/null -b "$COOKIES" -c "$COOKIES" $RESOLVE -X POST "$BASE_URL/admin/certificates/activate" \
  --data-urlencode "_csrf=$CSRF2" --data-urlencode "ticket=$TICKET"
AFTER=$(curl -k -s -b "$COOKIES" -c "$COOKIES" $RESOLVE "$BASE_URL/admin/certificates")
printf '%s' "$AFTER" | grep -q "Certificat activé" && ok "activation acceptée" || ko "activation acceptée"
sleep 2
SERVED_FP="$(served_fingerprint)"
check_eq "le serveur présente le certificat installé (empreinte)" "$TARGET_FP" "$SERVED_FP"
check "le certificat de bootstrap n'est plus servi" "[ \"$SERVED_FP\" != \"$BOOT_FP\" ]"
check_eq "aucun redémarrage du conteneur (rechargement par SIGHUP)" "0" \
  "$(docker inspect -f '{{.RestartCount}}' "$(web_container)" 2>/dev/null)"
check "chaîne servie complète (feuille + intermédiaire)" \
  "[ \"\$(echo | openssl s_client -connect 127.0.0.1:${HTTPS_PORT} -servername $HOSTNAME_TEST -showcerts 2>/dev/null | grep -c 'BEGIN CERTIFICATE')\" = \"2\" ]"
check "marqueur de bootstrap retiré" "! docker exec $(web_container) test -f /certs/.bootstrap"
check "landing toujours joignable après activation" \
  "curl -k -s $RESOLVE -o /dev/null -w '%{http_code}' $BASE_URL | grep -q 200"
check "interface : paire gérée confirmée" \
  "curl -k -s -b $COOKIES $RESOLVE $BASE_URL/admin/certificates | grep -q 'correspond à la paire gérée'"

echo
echo "### Phase 7 — persistance : redémarrage puis redéploiement (volumes conservés)"
compose down >/dev/null 2>&1
compose up -d >/dev/null 2>&1
sleep 12
check_eq "certificat conservé après restart" "$TARGET_FP" "$(served_fingerprint)"
check "aucune régénération du bootstrap" "! docker exec $(web_container) test -f /certs/.bootstrap"
compose up -d >/dev/null 2>&1   # redéploiement de la stack (même image, volumes conservés)
sleep 8
check_eq "certificat conservé après redéploiement" "$TARGET_FP" "$(served_fingerprint)"
check "données applicatives conservées (session admin valide)" \
  "curl -k -s -b $COOKIES $RESOLVE -o /dev/null -w '%{http_code}' $BASE_URL/admin/certificates | grep -q 200"

echo
echo "### Phase 8 — certificats refusés (aucune bascule)"
openssl req -newkey rsa:2048 -nodes -keyout "$CERTS/other.key" -out "$CERTS/other.csr" \
  -subj "/CN=autre.test" >/dev/null 2>&1
printf 'subjectAltName=DNS:autre.test\n' >"$CERTS/other.ext"
openssl x509 -req -in "$CERTS/other.csr" -CA "$CERTS/root.crt" -CAkey "$CERTS/root.key" -CAcreateserial \
  -days 20 -out "$CERTS/other.crt" -extfile "$CERTS/other.ext" >/dev/null 2>&1
openssl pkcs12 -export -out "$CERTS/other.p12" -inkey "$CERTS/other.key" -in "$CERTS/other.crt" \
  -passout pass:RecetteV14 -name other >/dev/null 2>&1
CSRF3=$(curl -k -s -b "$COOKIES" -c "$COOKIES" $RESOLVE "$BASE_URL/admin/certificates" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | cut -d'"' -f4)
curl -k -s -o /dev/null -b "$COOKIES" -c "$COOKIES" $RESOLVE -X POST "$BASE_URL/admin/certificates/validate-pkcs12" \
  -F "_csrf=$CSRF3" -F "bundle=@$CERTS/other.p12" -F "password=RecetteV14"
REJECTED=$(curl -k -s -b "$COOKIES" -c "$COOKIES" $RESOLVE "$BASE_URL/admin/certificates")
printf '%s' "$REJECTED" | grep -q "prête à être activée" && ko "certificat hors domaine refusé" || ok "certificat hors domaine refusé"
printf '%s' "$REJECTED" | grep -q "$HOSTNAME_TEST" && ok "message d'erreur explicite (nom attendu)" || ko "message d'erreur explicite (nom attendu)"
CSRF4=$(curl -k -s -b "$COOKIES" -c "$COOKIES" $RESOLVE "$BASE_URL/admin/certificates" | grep -o 'name="_csrf" value="[^"]*"' | head -1 | cut -d'"' -f4)
curl -k -s -o /dev/null -b "$COOKIES" -c "$COOKIES" $RESOLVE -X POST "$BASE_URL/admin/certificates/validate-pkcs12" \
  -F "_csrf=$CSRF4" -F "bundle=@$CERTS/hub.p12" -F "password=MauvaisMotDePasse"
WRONGPASS=$(curl -k -s -b "$COOKIES" -c "$COOKIES" $RESOLVE "$BASE_URL/admin/certificates")
printf '%s' "$WRONGPASS" | grep -qi "mot de passe" && ok "mauvais mot de passe refusé (message clair)" || ko "mauvais mot de passe refusé"
check_eq "certificat servi inchangé après les refus" "$TARGET_FP" "$(served_fingerprint)"

echo
echo "### Phase 9 — isolation, privilèges et absence de proxy"
WEB_ID="$(web_container)"
check_eq "seul HTTPS est publié sur l'hôte" "1" "$(docker inspect -f '{{len .HostConfig.PortBindings}}' "$WEB_ID")"
check "capabilities retirées" "docker inspect $WEB_ID -f '{{.HostConfig.CapDrop}}' | grep -qi ALL"
check "conteneur en lecture seule" "docker inspect $WEB_ID -f '{{.HostConfig.ReadonlyRootfs}}' | grep -q true"
check "aucun socket Docker monté" \
  "! docker inspect $WEB_ID -f '{{range .Mounts}}{{.Source}} {{end}}' | grep -q docker.sock"
check "volumes Docker nommés uniquement (aucun chemin hôte)" \
  "docker inspect $WEB_ID -f '{{range .Mounts}}{{.Type}} {{end}}' | grep -qv bind"
check "clé privée : permissions minimales" \
  "docker exec $WEB_ID sh -c 'stat -c %a /certs/active/privkey.pem | grep -qx 600'"
check "aucun log d'erreur applicatif (socket de contrôle gunicorn)" \
  "! docker logs $WEB_ID 2>&1 | grep -q 'Control server error'"

echo
echo "### Phase 9bis — recette navigateur réelle (optionnelle : STANDALONE_CHECK_BROWSER=1)"
if [ "${STANDALONE_CHECK_BROWSER:-0}" = "1" ]; then
  compose exec -T web python -m app.manage seed >/dev/null 2>&1 \
    && ok "catalogue amorcé (seeds/catalog.json)" || ko "catalogue amorcé"
  rm -rf "$WORK/shots"
  run_acceptance() {
    HUB_BASE_URL="$BASE_URL" \
      HUB_HOST_RESOLVER="MAP ${HOSTNAME_TEST} 127.0.0.1" \
      HUB_SKIP_CERT=1 HUB_SCOPE=full HUB_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
      HUB_SHOTS_DIR="$WORK/shots" \
      .venv/bin/python tests/browser/acceptance.py >"$WORK/acceptance.log" 2>&1
  }
  # La recette navigateur peut dépasser le délai de 30 s d'une navigation quand la
  # machine est chargée (construction d'image, conteneurs) : une seconde tentative,
  # sur un serveur déjà vérifié par les 15 phases précédentes.
  if run_acceptance || { sleep 10; printf '  [INFO] seconde tentative de la recette navigateur\n'; run_acceptance; }; then
    ok "recette navigateur ($(grep -c '\[PASS\]' "$WORK/acceptance.log") contrôles réussis)"
  else
    ko "recette navigateur — voir $WORK/acceptance.log"
    grep -E '\[FAIL\]|TimeoutError' "$WORK/acceptance.log" | head -5
  fi
else
  printf '  [INFO] ignorée (activer avec STANDALONE_CHECK_BROWSER=1)\n'
fi

echo
echo "### Phase 9ter — rattachement à un réseau Docker existant + IPv4 statique"
EXT_NET="${STANDALONE_CHECK_NETWORK:-hub-standalone-ext}"
EXT_PROJECT="${PROJECT}-net"
EXT_PORT=$((HTTPS_PORT + 1))
docker network rm "$EXT_NET" >/dev/null 2>&1 || true
# Sous-réseau de recette : le premier libre parmi des candidats hors des pools
# par défaut de Docker (une autre pile peut occuper le premier essayé).
EXT_SUBNET=""; EXT_IP=""; EXT_ERR=""
for candidate in "${STANDALONE_CHECK_SUBNET:-}" 10.99.11.0/24 10.99.12.0/24 10.99.13.0/24; do
  [ -n "$candidate" ] || continue
  if EXT_ERR=$(docker network create --subnet "$candidate" "$EXT_NET" 2>&1); then
    EXT_SUBNET="$candidate"
    EXT_IP="${STANDALONE_CHECK_IP:-${candidate%.0/24}.12}"
    break
  fi
done
if [ -n "$EXT_SUBNET" ]; then
  ok "réseau de recette créé ($EXT_NET, $EXT_SUBNET)"
else
  ko "création du réseau de recette — ${EXT_ERR:-échec inconnu}"
fi

ext_compose() { # ext_compose [IP=...] sous-commande...
  HUB_HOSTNAME="$HOSTNAME_TEST" HUB_HTTPS_PORT="$EXT_PORT" HUB_IMAGE_TAG="$IMAGE_TAG" \
  HUB_GIT_SHA="$IMAGE_TAG" HUB_DOCKER_NETWORK="$EXT_NET" HUB_DOCKER_NETWORK_EXTERNAL=true \
  HUB_IPV4_ADDRESS="${EXT_IP_FORCE:-$EXT_IP}" \
  docker compose -p "$EXT_PROJECT" -f compose.standalone.yaml "$@"
}
ext_container() {
  docker ps -aqf "label=com.docker.compose.project=${EXT_PROJECT}" \
    -f "label=com.docker.compose.service=web" | head -1
}

# 1) réseau externe + IPv4 statique
ext_compose up -d >/dev/null 2>&1 && ok "déploiement sur réseau existant avec IPv4 statique" \
  || ko "déploiement sur réseau existant avec IPv4 statique"
sleep 10
EC="$(ext_container)"
check_eq "conteneur attaché au réseau existant" "$EXT_NET" \
  "$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$EC" 2>/dev/null)"
check_eq "IPv4 statique réellement portée" "$EXT_IP" \
  "$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$EC" 2>/dev/null)"
check_eq "healthcheck vert (HTTPS direct, IP statique)" "healthy" \
  "$(docker inspect -f '{{.State.Health.Status}}' "$EC" 2>/dev/null)"
ext_compose down -v >/dev/null 2>&1
check "réseau externe préservé après down" "docker network inspect '$EXT_NET' >/dev/null 2>&1"

# 2) réseau externe SANS IPv4 statique → Docker attribue l'adresse
EXT_IP_FORCE="" ext_compose up -d >/dev/null 2>&1 \
  && ok "déploiement sur réseau existant sans IPv4 statique" \
  || ko "déploiement sur réseau existant sans IPv4 statique"
sleep 10
EC="$(ext_container)"
AUTO_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$EC" 2>/dev/null)"
check "adresse attribuée automatiquement par Docker" "[ -n '$AUTO_IP' ]"
check_eq "réseau cible toujours respecté" "$EXT_NET" \
  "$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$EC" 2>/dev/null)"
ext_compose down -v >/dev/null 2>&1

# 3) déploiement standard (aucune variable réseau) : inchangé
SC="$(web_container)"
check_eq "standard : réseau du projet (comportement historique)" "${PROJECT}_default" \
  "$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' "$SC" 2>/dev/null)"
check "standard : adresse attribuée par Docker" \
  "[ -n \"$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$SC" 2>/dev/null)\" ]"
check_eq "standard : certificat servi inchangé par ce déploiement" "$SERVED_FP" "$(served_fingerprint)"
docker network rm "$EXT_NET" >/dev/null 2>&1 || true

echo
echo "### Phase 10 — nettoyage"
if [ "$KEEP" = "--keep" ]; then
  echo "  --keep : stack conservée (projet $PROJECT, port $HTTPS_PORT)"
else
  compose down -v --remove-orphans >/dev/null 2>&1
  docker image rm -f "hub:${IMAGE_TAG}" >/dev/null 2>&1 || true
fi
if docker inspect hub-web >/dev/null 2>&1; then
  check_eq "production intacte (hub-web healthy)" "healthy" \
    "$(docker inspect -f '{{.State.Health.Status}}' hub-web 2>/dev/null)"
fi

echo
echo "==================================================="
printf 'Recette standalone : %d réussites, %d échecs\n' "$PASS" "$FAIL"
echo "==================================================="
[ "$FAIL" -eq 0 ]
