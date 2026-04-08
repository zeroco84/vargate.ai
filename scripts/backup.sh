#!/usr/bin/env bash
# Nightly backup of Vargate audit database to Hetzner Storage Box.
# Run via cron on the host (not inside Docker).
#
# Prerequisites:
#   - SSH key configured for Hetzner Storage Box
#   - STORAGE_BOX_USER and STORAGE_BOX_HOST set in /etc/vargate/backup.env
#
set -euo pipefail

source /etc/vargate/backup.env 2>/dev/null || true

BACKUP_DIR="/var/lib/docker/volumes/vargate-proxy_backup-data/_data"
STORAGE_BOX_USER="${STORAGE_BOX_USER:-}"
STORAGE_BOX_HOST="${STORAGE_BOX_HOST:-}"
STORAGE_BOX_PATH="${STORAGE_BOX_PATH:-./backups/vargate}"
RETENTION_DAYS=30

# Step 1: Trigger a fresh backup via the gateway API
echo "[BACKUP] Triggering SQLite backup..."
curl -sf http://127.0.0.1:8000/backup/trigger \
  -H "Authorization: Bearer ${ADMIN_TOKEN:-}" \
  -X POST || echo "[BACKUP] Warning: API trigger failed, using latest file"

# Step 2: Find the latest backup file
LATEST=$(ls -t "$BACKUP_DIR"/audit-*.db 2>/dev/null | head -1)
if [ -z "$LATEST" ]; then
  echo "[BACKUP] ERROR: No backup files found in $BACKUP_DIR"
  exit 1
fi

echo "[BACKUP] Latest backup: $LATEST ($(stat -c%s "$LATEST") bytes)"

# Step 3: Upload to Storage Box (if configured)
if [ -n "$STORAGE_BOX_USER" ] && [ -n "$STORAGE_BOX_HOST" ]; then
  echo "[BACKUP] Uploading to Hetzner Storage Box..."
  scp -o StrictHostKeyChecking=accept-new \
    "$LATEST" \
    "${STORAGE_BOX_USER}@${STORAGE_BOX_HOST}:${STORAGE_BOX_PATH}/$(basename "$LATEST")"
  echo "[BACKUP] Upload complete."

  # Step 4: Prune remote backups older than retention
  echo "[BACKUP] Pruning remote backups older than ${RETENTION_DAYS} days..."
  ssh "${STORAGE_BOX_USER}@${STORAGE_BOX_HOST}" \
    "find ${STORAGE_BOX_PATH} -name 'audit-*.db' -mtime +${RETENTION_DAYS} -delete" \
    2>/dev/null || echo "[BACKUP] Warning: Remote pruning skipped (limited shell)"
else
  echo "[BACKUP] Storage Box not configured, local backup only."
fi

echo "[BACKUP] Done."
