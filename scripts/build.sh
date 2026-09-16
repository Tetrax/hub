#!/usr/bin/env bash
# Construit l'image Docker de SNS Hub, taguée avec le SHA Git (traçabilité
# Git SHA -> image -> conteneur). Usage : scripts/build.sh [tag]
set -euo pipefail
cd "$(dirname "$0")/.."

SHA="$(git rev-parse HEAD)"
TAG="${1:-$SHA}"
CREATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "Image hub:$TAG (commit $SHA, construit $CREATED)"
docker build \
  --build-arg "HUB_GIT_SHA=$SHA" \
  --label "org.opencontainers.image.title=SNS Hub" \
  --label "org.opencontainers.image.source=https://github.com/Tetrax/hub" \
  --label "org.opencontainers.image.revision=$SHA" \
  --label "org.opencontainers.image.created=$CREATED" \
  --tag "hub:$TAG" \
  --tag "hub:previous" \
  --file Dockerfile \
  .
echo "OK : image hub:$TAG (et hub:previous)"
