#!/usr/bin/env bash
# Prépare le répertoire de données avant le premier démarrage (évite l'erreur
# la plus fréquente : un bind mount créé par Docker en root:root, alors que le
# conteneur tourne en HUB_UID:HUB_GID et ne peut pas écrire dedans).
#
# Usage : sudo scripts/prepare-data-dir.sh
# Lit HUB_UID / HUB_GID / HUB_DATA_PATH depuis l'environnement, sinon depuis .env.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

env_value() {
  [ -f "$REPO/.env" ] || return 0
  grep -E "^$1=" "$REPO/.env" | tail -n 1 | cut -d= -f2- || true
}

UID_VALUE="${HUB_UID:-$(env_value HUB_UID)}"; UID_VALUE="${UID_VALUE:-1000}"
GID_VALUE="${HUB_GID:-$(env_value HUB_GID)}"; GID_VALUE="${GID_VALUE:-1000}"
DATA_PATH="${HUB_DATA_PATH:-$(env_value HUB_DATA_PATH)}"; DATA_PATH="${DATA_PATH:-./runtime/data}"

case "$DATA_PATH" in
  /*) TARGET="$DATA_PATH" ;;
  *) TARGET="$REPO/${DATA_PATH#./}" ;;
esac

if [ "$(id -u)" -ne 0 ]; then
  echo "Réexécuter avec sudo : sudo scripts/prepare-data-dir.sh" >&2
  exit 1
fi

install -d -o "$UID_VALUE" -g "$GID_VALUE" -m 0755 "$TARGET" "$TARGET/uploads"
chown -R "$UID_VALUE:$GID_VALUE" "$TARGET"
echo "Répertoire de données prêt : $TARGET (propriétaire $UID_VALUE:$GID_VALUE)"
