#!/usr/bin/env bash
# Sauvegarde SNS Hub : base SQLite (copie cohérente), uploads, clé de session,
# et certificats gérés (nécessite sudo pour /var/lib/hub).
#
# Destination par défaut : /home/tetrax/backups/hub (surchargeable HUB_BACKUP_DIR).
# Conserve les N dernières archives (HUB_BACKUP_KEEP, défaut 10).
set -euo pipefail
cd "$(dirname "$0")/.."

# Les certificats (/var/lib/hub) et la clé de session (0600) exigent root :
# la sauvegarde complète s'exécute sous sudo (réélévation automatique).
if [ "$(id -u)" -ne 0 ]; then
  if sudo -n true 2>/dev/null; then
    exec sudo HUB_BACKUP_DIR="${HUB_BACKUP_DIR:-}" HUB_BACKUP_KEEP="${HUB_BACKUP_KEEP:-}" "$0" "$@"
  fi
  echo "Sauvegarde complète requise : relancer avec sudo scripts/backup.sh" >&2
  exit 1
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="${HUB_BACKUP_DIR:-/home/tetrax/backups/hub}"
KEEP="${HUB_BACKUP_KEEP:-10}"
mkdir -p "$DEST"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

DB="$PWD/runtime/data/hub.sqlite"
if [ -f "$DB" ]; then
  python3 - "$DB" "$TMP/hub.sqlite" <<'PY'
import sqlite3, sys
source = sqlite3.connect(sys.argv[1])
target = sqlite3.connect(sys.argv[2])
with target:
    source.backup(target)
print(f"Base sauvegardée : {sys.argv[2]}")
PY
else
  echo "Aucune base trouvée ($DB) — sauvegarde sans base." >&2
fi

mkdir -p "$TMP/uploads"
if [ -d runtime/data/uploads ]; then
  cp -a runtime/data/uploads/. "$TMP/uploads/" 2>/dev/null || true
fi
if [ -f runtime/data/.secret_key ]; then
  cp -a runtime/data/.secret_key "$TMP/secret_key"
fi
cat > "$TMP/MANIFEST.txt" <<EOF
SNS Hub — sauvegarde $STAMP
- hub.sqlite : base applicative (applications, sessions, compte admin)
- uploads/   : screenshots du catalogue
- secret_key : clé de signature des sessions (sensible)
- certificats : archive séparée hub-certificates-$STAMP.tar.gz (clé privée, root)
Restauration : voir docs/operations.md
EOF

ARCHIVE="$DEST/hub-backup-$STAMP.tar.gz"
tar -czf "$ARCHIVE" -C "$TMP" .
chmod 600 "$ARCHIVE"

if [ "$(id -u)" -eq 0 ]; then
  CERT_ARCHIVE="$DEST/hub-certificates-$STAMP.tar.gz"
  if tar -czf "$CERT_ARCHIVE" -C /var/lib/hub certificates 2>/dev/null; then
    chmod 600 "$CERT_ARCHIVE"
    echo "Certificats : $CERT_ARCHIVE"
  fi
else
  echo "root requis pour les certificats." >&2
fi

echo "Sauvegarde : $ARCHIVE"
ls -1t "$DEST"/hub-backup-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
  rm -f "$old" && echo "Ancienne sauvegarde supprimée : $old"
done
