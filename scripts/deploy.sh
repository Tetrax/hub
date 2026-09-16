#!/usr/bin/env bash
# Déploie le commit courant (HEAD) sur la production locale, puis vérifie.
#
#  - refuse un working tree non propre ;
#  - exige que HEAD soit présent sur origin/main (sauf ALLOW_UNPUSHED=1) ;
#  - construit l'image taguée SHA, démarre le Compose canonique, attend le
#    healthcheck et affiche l'état.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain)" ]; then
  echo "Working tree non propre : committer avant de déployer." >&2
  exit 1
fi

SHA="$(git rev-parse HEAD)"
if [ "${ALLOW_UNPUSHED:-0}" != "1" ]; then
  git fetch --quiet origin main || true
  if ! git merge-base --is-ancestor "$SHA" origin/main 2>/dev/null; then
    echo "Le commit $SHA n'est pas sur origin/main : pousser d'abord (ou ALLOW_UNPUSHED=1)." >&2
    exit 1
  fi
fi

./scripts/build.sh "$SHA"

export HUB_IMAGE_TAG="$SHA"
export HUB_GIT_SHA="$SHA"
docker compose up -d --no-build
docker compose ps

status="unknown"
for _ in $(seq 1 30); do
  status="$(docker inspect -f '{{.State.Health.Status}}' hub-web 2>/dev/null || echo unknown)"
  [ "$status" = "healthy" ] && break
  sleep 2
done
echo "hub-web : $status"

if [ "$status" != "healthy" ]; then
  echo "Le conteneur n'est pas healthy — logs récents :" >&2
  docker compose logs --tail 40 web >&2 || true
  exit 1
fi

echo "Déploiement terminé : commit $SHA"
docker inspect hub-web --format 'image={{.Config.Image}} commit={{index .Config.Labels "org.opencontainers.image.revision"}}'
