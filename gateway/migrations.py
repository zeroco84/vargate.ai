"""
Database schema migration versioning (Audit Item 15).

Simple ordered migration system for SQLite. Each migration is a
(version, description, callable) tuple. Migrations run in order,
skipping any already applied. No rollback support — forward-only.
"""

import sqlite3
from datetime import datetime, timezone


def _init_schema_version(conn: sqlite3.Connection):
    """Create the schema_version table if it doesn't exist."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version     INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at  TEXT NOT NULL
        )
    """)
    conn.commit()


def _get_current_version(conn: sqlite3.Connection) -> int:
    """Get the highest applied migration version, or 0 if none."""
    try:
        row = conn.execute(
            "SELECT MAX(version) as v FROM schema_version"
        ).fetchone()
        return row["v"] or 0 if row else 0
    except sqlite3.OperationalError:
        return 0


def _migration_2_sprint5_columns(conn: sqlite3.Connection):
    """Add Sprint 5 columns (anchor_chain on tenants, merkle_anchor_log columns)."""
    for sql in [
        "ALTER TABLE tenants ADD COLUMN anchor_chain TEXT DEFAULT 'polygon'",
        "ALTER TABLE merkle_anchor_log ADD COLUMN prev_merkle_root TEXT",
        "ALTER TABLE merkle_anchor_log ADD COLUMN root_chain_hash TEXT",
        "ALTER TABLE merkle_anchor_log ADD COLUMN anchor_chain TEXT DEFAULT 'sepolia'",
    ]:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass  # Column already exists


def _migration_3_audit_columns(conn: sqlite3.Connection):
    """Add audit_log columns from sessions 2-8."""
    for sql in [
        "ALTER TABLE audit_log ADD COLUMN evaluation_pass INTEGER DEFAULT 1",
        "ALTER TABLE audit_log ADD COLUMN anomaly_score_at_eval REAL DEFAULT 0.0",
        "ALTER TABLE audit_log ADD COLUMN opa_input TEXT",
        "ALTER TABLE audit_log ADD COLUMN contains_pii INTEGER DEFAULT 0",
        "ALTER TABLE audit_log ADD COLUMN pii_subject_id TEXT",
        "ALTER TABLE audit_log ADD COLUMN pii_fields TEXT",
        "ALTER TABLE audit_log ADD COLUMN erasure_status TEXT DEFAULT 'active'",
        "ALTER TABLE audit_log ADD COLUMN execution_mode TEXT DEFAULT 'agent_direct'",
        "ALTER TABLE audit_log ADD COLUMN execution_result TEXT",
        "ALTER TABLE audit_log ADD COLUMN execution_latency_ms INTEGER",
        "ALTER TABLE audit_log ADD COLUMN credential_accessed TEXT",
        "ALTER TABLE audit_log ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'vargate-internal'",
    ]:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass


def _migration_4_anchor_log_columns(conn: sqlite3.Connection):
    """Add Merkle columns to legacy anchor_log."""
    for sql in [
        "ALTER TABLE anchor_log ADD COLUMN merkle_root TEXT",
        "ALTER TABLE anchor_log ADD COLUMN from_record INTEGER",
        "ALTER TABLE anchor_log ADD COLUMN to_record INTEGER",
    ]:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass


# Ordered list of migrations. Version 1 is the baseline (all existing tables).
# Each entry: (version, description, migration_fn)
MIGRATIONS = [
    (1, "Baseline schema — all existing tables", lambda conn: None),
    (2, "Sprint 5: anchor_chain, merkle_anchor_log columns", _migration_2_sprint5_columns),
    (3, "Sessions 2-8: audit_log additional columns", _migration_3_audit_columns),
    (4, "Merkle columns on legacy anchor_log", _migration_4_anchor_log_columns),
]


def run_migrations(conn: sqlite3.Connection):
    """Run any unapplied migrations in order."""
    _init_schema_version(conn)
    current = _get_current_version(conn)

    applied = 0
    for version, description, migrate_fn in MIGRATIONS:
        if version <= current:
            continue

        print(f"[MIGRATION] Applying v{version}: {description}", flush=True)
        migrate_fn(conn)

        conn.execute(
            "INSERT INTO schema_version (version, description, applied_at) VALUES (?, ?, ?)",
            (version, description, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        applied += 1

    if applied:
        print(f"[MIGRATION] Applied {applied} migration(s). Current version: {MIGRATIONS[-1][0]}", flush=True)
    else:
        print(f"[MIGRATION] Schema up to date (v{current}).", flush=True)
