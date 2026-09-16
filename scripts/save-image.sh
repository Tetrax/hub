#!/usr/bin/env bash
# Exporte l'image SNS Hub vers une archive, pour un déploiement hors ligne.
# Usage : scripts/save-image.sh [tag] [archive]
#   tag     : défaut = SHA du commit courant (image construite par scripts/build.sh)
#   archive : défaut = hub-<tag>.tar.gz
set -euo pipefail
cd "$(dirname "$0")/.."

TAG="${1:-$(git rev-parse HEAD)}"
OUT="${2:-hub-$TAG.tar.gz}"

if ! docker image inspect "hub:$TAG" >/dev/null 2>&1; then
  echo "Image hub:$TAG absente : lancer d'abord scripts/build.sh $TAG" >&2
  exit 1
fi

echo "Export de hub:$TAG vers $OUT ..."
docker save "hub:$TAG" | gzip -1 > "$OUT"
chmod 600 "$OUT"
echo "OK : $OUT ($(du -h "$OUT" | cut -f1))"
echo "Sur la machine cible : git clone <dépôt> && scripts/load-image.sh $OUT"
