#!/usr/bin/env bash
# Sauvegarde SNS Hub : base SQLite (copie cohérente), uploads, clé de session,
# et certificats gérés (nécessite sudo pour /var/lib/hub).
#
# Destination : HUB_BACKUP_DIR (environnement, sinon valeur lue dans `.env`,
# sinon ./backups/hub). Nombre d'archives conservées : HUB_BACKUP_KEEP (défaut 10).
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

# Valeur d'une clé simple dans .env (fichier d'installation, jamais versionné).
env_value() {
  [ -f "$REPO/.env" ] || return 0
  grep -E "^$1=" "$REPO/.env" | tail -n 1 | cut -d= -f2- || true
}

DEST="${HUB_BACKUP_DIR:-$(env_value HUB_BACKUP_DIR)}"
DEST="${DEST:-$REPO/backups/hub}"
KEEP="${HUB_BACKUP_KEEP:-$(env_value HUB_BACKUP_KEEP)}"
KEEP="${KEEP:-10}"
DATA_PATH="${HUB_DATA_PATH:-$(env_value HUB_DATA_PATH)}"
case "$DATA_PATH" in
  "") DATA_DIR="$REPO/runtime/data" ;;
  /*) DATA_DIR="$DATA_PATH" ;;
  *) DATA_DIR="$REPO/${DATA_PATH#./}" ;;
esac

# Les certificats (/var/lib/hub) et la clé de session (0600) exigent root :
# la sauvegarde complète s'exécute sous sudo (réélévation automatique).
if [ "$(id -u)" -ne 0 ]; then
  if sudo -n true 2>/dev/null; then
    exec sudo HUB_BACKUP_DIR="$DEST" HUB_BACKUP_KEEP="$KEEP" "$0" "$@"
  fi
  echo "Sauvegarde complète requise : relancer avec sudo scripts/backup.sh" >&2
  exit 1
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$DEST"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

DB="$DATA_DIR/hub.sqlite"
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
if [ -d "$DATA_DIR/uploads" ]; then
  cp -a "$DATA_DIR/uploads/." "$TMP/uploads/" 2>/dev/null || true
fi
if [ -f "$DATA_DIR/.secret_key" ]; then
  cp -a "$DATA_DIR/.secret_key" "$TMP/secret_key"
fi
# Secrets email administrables (V1.6.1) : mot de passe SMTP et secret client
# Microsoft 365 saisis dans l'administration — sensibles, comme la clé de session.
mkdir -p "$TMP/secrets"
if [ -d "$DATA_DIR/secrets" ]; then
  cp -a "$DATA_DIR/secrets/." "$TMP/secrets/" 2>/dev/null || true
fi
chmod 700 "$TMP/secrets"
cat > "$TMP/MANIFEST.txt" <<EOF
SNS Hub — sauvegarde $STAMP
- hub.sqlite : base applicative (applications, catégories, sessions, compte admin)
- uploads/   : screenshots du catalogue
- secret_key : clé de signature des sessions (sensible)
- secrets/   : secrets email administrés — mot de passe SMTP, secret client
               Microsoft 365 (sensibles ; l'archive est en 0600)
- certificats : archive séparée hub-certificates-$STAMP.tar.gz (clé privée, root)
Restauration : voir docs/operations.md (§ Sauvegarde et restauration)
EOF

ARCHIVE="$DEST/hub-backup-$STAMP.tar.gz"
tar -czf "$ARCHIVE" -C "$TMP" .
chmod 600 "$ARCHIVE"

CERT_ARCHIVE="$DEST/hub-certificates-$STAMP.tar.gz"
if tar -czf "$CERT_ARCHIVE" -C /var/lib/hub certificates 2>/dev/null; then
  chmod 600 "$CERT_ARCHIVE"
  echo "Certificats : $CERT_ARCHIVE"
else
  echo "Certificats non sauvegardés (/var/lib/hub/certificates absent)." >&2
  rm -f "$CERT_ARCHIVE"
fi

echo "Sauvegarde : $ARCHIVE"
ls -1t "$DEST"/hub-backup-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
  rm -f "$old" && echo "Ancienne sauvegarde supprimée : $old"
done
