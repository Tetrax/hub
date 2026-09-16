#!/usr/bin/env bash
# Importe une image SNS Hub exportée par scripts/save-image.sh (machine hors ligne).
# Usage : scripts/load-image.sh <archive.tar.gz>
set -euo pipefail
cd "$(dirname "$0")/.."

ARCHIVE="${1:-}"
if [ -z "$ARCHIVE" ] || [ ! -f "$ARCHIVE" ]; then
  echo "Usage : scripts/load-image.sh <archive.tar.gz>" >&2
  exit 1
fi

echo "Chargement de $ARCHIVE ..."
gunzip -c "$ARCHIVE" | docker load

cat <<'EOF'
Image chargée. Déploiement sans reconstruction :
  HUB_IMAGE_TAG=<tag affiché ci-dessus> docker compose up -d --no-build
(ou renseigner HUB_IMAGE_TAG dans .env, puis docker compose up -d --no-build)
EOF
