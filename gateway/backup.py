"""
Vargate SQLite Backup

Uses the SQLite .backup() API to create safe, consistent backups of the
audit database while it is in use. Backups are stored in /backup/ with
timestamped filenames and a configurable retention policy.
"""

import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = os.getenv("DB_PATH", "/data/audit.db")
BACKUP_DIR = os.getenv("BACKUP_DIR", "/backup")
BACKUP_RETENTION = int(os.getenv("BACKUP_RETENTION_COUNT", "7"))


def backup_database(db_path: str = DB_PATH, backup_dir: str = BACKUP_DIR) -> dict:
    """
    Create a consistent backup of the SQLite database using the .backup() API.
    Returns metadata about the backup (path, size, duration).
    """
    Path(backup_dir).mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = os.path.join(backup_dir, f"audit-{timestamp}.db")

    start = time.monotonic()

    source = sqlite3.connect(db_path)
    try:
        dest = sqlite3.connect(backup_path)
        try:
            source.backup(dest)
        finally:
            dest.close()
    finally:
        source.close()

    elapsed_ms = int((time.monotonic() - start) * 1000)
    size_bytes = os.path.getsize(backup_path)

    # Prune old backups beyond retention count
    _prune_backups(backup_dir)

    print(
        f"[BACKUP] Created {backup_path} ({size_bytes} bytes, {elapsed_ms}ms)",
        flush=True,
    )

    return {
        "path": backup_path,
        "size_bytes": size_bytes,
        "duration_ms": elapsed_ms,
        "timestamp": timestamp,
    }


def _prune_backups(backup_dir: str):
    """Remove oldest backups beyond BACKUP_RETENTION count."""
    backups = sorted(
        [f for f in os.listdir(backup_dir) if f.startswith("audit-") and f.endswith(".db")],
        reverse=True,
    )
    for old in backups[BACKUP_RETENTION:]:
        path = os.path.join(backup_dir, old)
        os.remove(path)
        print(f"[BACKUP] Pruned old backup: {old}", flush=True)
