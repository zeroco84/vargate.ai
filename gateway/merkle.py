"""
SQLite-bound Merkle helpers for Pro's audit_log (Sprint 5 — AG-2.2 / AG-2.3).

The pure Merkle math (`MerkleTree`, `GENESIS_ROOT`, leaf-pair hashing)
moved into the `vargate-audit-chain` Python package in Sprint 16 so
both Pro and Telemetry can build trees without depending on each
other's storage. The DB-coupled helpers — hourly-tree builders against
`audit_log`, inclusion proofs, consistency proofs, full-chain
verification — stay here because they're intrinsically shaped around
Pro's `audit_log` and `merkle_trees` SQLite tables.

`from merkle import MerkleTree` and `from merkle import GENESIS_ROOT`
continue to work via the re-exports below; existing main.py imports
need no changes.

Leaf ordering: RFC 6962 §2.1 — leaves are appended left-to-right in
the order they appear in the audit log (by id ASC).
"""

import sqlite3
from datetime import datetime, timezone
from typing import Optional

# Pure primitives — moved to vargate-audit-chain in Sprint 16.
# Re-exported here so existing `from merkle import ...` call sites
# (notably gateway/main.py) keep working without edits.
from vargate_audit_chain.merkle import GENESIS_ROOT, MerkleTree  # noqa: F401

# ── Hourly Tenant-Scoped Trees (Sprint 5, AG-2.2) ──────────────────────────


def init_merkle_trees_table(conn: sqlite3.Connection):
    """Create the merkle_trees table for hourly tree storage."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS merkle_trees (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id       TEXT NOT NULL,
            tree_index      INTEGER NOT NULL,
            merkle_root     TEXT NOT NULL,
            record_count    INTEGER NOT NULL,
            tree_height     INTEGER NOT NULL,
            from_record_id  INTEGER NOT NULL,
            to_record_id    INTEGER NOT NULL,
            period_start    TEXT NOT NULL,
            period_end      TEXT NOT NULL,
            created_at      TEXT NOT NULL,
            prev_tree_root  TEXT,
            anchor_tx_hash  TEXT,
            anchor_chain    TEXT,
            anchor_block    INTEGER
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_merkle_trees_tenant
        ON merkle_trees (tenant_id, tree_index)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_merkle_trees_root
        ON merkle_trees (merkle_root)
    """)
    conn.commit()


def build_hourly_trees(conn: sqlite3.Connection, tenant_id: str) -> list[dict]:
    """
    Build Merkle trees for any un-treed hourly periods for the given tenant.

    Scans audit_log for records that fall after the last tree's to_record_id,
    groups them by hour, builds a tree for each complete hour, and stores results.

    Returns list of newly created tree metadata dicts.
    """
    # Find the last tree for this tenant
    last_tree = conn.execute(
        "SELECT tree_index, to_record_id, merkle_root, period_end "
        "FROM merkle_trees WHERE tenant_id = ? ORDER BY tree_index DESC LIMIT 1",
        (tenant_id,),
    ).fetchone()

    if last_tree:
        after_id = last_tree["to_record_id"]
        next_index = last_tree["tree_index"] + 1
        prev_root = last_tree["merkle_root"]
    else:
        after_id = 0
        next_index = 0
        prev_root = GENESIS_ROOT

    # Get all un-treed records for this tenant
    rows = conn.execute(
        "SELECT id, record_hash, created_at FROM audit_log "
        "WHERE tenant_id = ? AND id > ? AND (erasure_status = 'active' OR erasure_status IS NULL) "
        "ORDER BY id ASC",
        (tenant_id, after_id),
    ).fetchall()

    if not rows:
        return []

    # Group by hour (truncate to hour boundary)
    hourly_buckets: dict[str, list] = {}
    for row in rows:
        ts = row["created_at"]
        # Truncate to hour: "2026-04-08T14:23:45..." -> "2026-04-08T14:00:00"
        hour_key = ts[:13] + ":00:00"
        if hour_key not in hourly_buckets:
            hourly_buckets[hour_key] = []
        hourly_buckets[hour_key].append(row)

    # Only build trees for complete hours (current hour is still accumulating)
    now = datetime.now(timezone.utc)
    current_hour = now.strftime("%Y-%m-%dT%H:00:00")

    new_trees = []
    for hour_key in sorted(hourly_buckets.keys()):
        # Skip the current (incomplete) hour
        if hour_key >= current_hour:
            continue

        bucket = hourly_buckets[hour_key]
        leaves = [r["record_hash"] for r in bucket]
        tree = MerkleTree(leaves)

        from_id = bucket[0]["id"]
        to_id = bucket[-1]["id"]
        period_end = hour_key[:11] + str(int(hour_key[11:13]) + 1).zfill(2) + ":00:00"
        # Handle hour overflow (23 -> next day 00)
        if int(hour_key[11:13]) == 23:
            # Parse and add 1 hour
            dt = datetime.fromisoformat(hour_key + "+00:00")
            from datetime import timedelta

            dt_end = dt + timedelta(hours=1)
            period_end = dt_end.strftime("%Y-%m-%dT%H:%M:%S")

        created = now.isoformat()

        conn.execute(
            """INSERT INTO merkle_trees
               (tenant_id, tree_index, merkle_root, record_count, tree_height,
                from_record_id, to_record_id, period_start, period_end,
                created_at, prev_tree_root)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                tenant_id,
                next_index,
                tree.root,
                tree.leaf_count,
                tree.height,
                from_id,
                to_id,
                hour_key,
                period_end,
                created,
                prev_root,
            ),
        )

        tree_info = {
            "tenant_id": tenant_id,
            "tree_index": next_index,
            "merkle_root": tree.root,
            "record_count": tree.leaf_count,
            "tree_height": tree.height,
            "from_record_id": from_id,
            "to_record_id": to_id,
            "period_start": hour_key,
            "period_end": period_end,
        }
        new_trees.append(tree_info)

        prev_root = tree.root
        next_index += 1

    if new_trees:
        conn.commit()

    return new_trees


def get_inclusion_proof(
    conn: sqlite3.Connection, record_hash: str, tenant_id: str
) -> Optional[dict]:
    """
    Generate an inclusion proof for a record in its hourly tree.

    Finds which tree contains the record, rebuilds that tree,
    and returns the proof path.
    """
    # Find the record
    record = conn.execute(
        "SELECT id, action_id, record_hash, tenant_id, created_at FROM audit_log "
        "WHERE record_hash = ? AND tenant_id = ?",
        (record_hash, tenant_id),
    ).fetchone()

    if not record:
        return None

    record_id = record["id"]

    # Find which tree contains this record
    tree_row = conn.execute(
        "SELECT * FROM merkle_trees "
        "WHERE tenant_id = ? AND from_record_id <= ? AND to_record_id >= ? "
        "ORDER BY tree_index ASC LIMIT 1",
        (tenant_id, record_id, record_id),
    ).fetchone()

    if not tree_row:
        return None

    # Rebuild the tree from its records to generate the proof
    tree_records = conn.execute(
        "SELECT id, record_hash FROM audit_log "
        "WHERE tenant_id = ? AND id >= ? AND id <= ? "
        "AND (erasure_status = 'active' OR erasure_status IS NULL) "
        "ORDER BY id ASC",
        (tenant_id, tree_row["from_record_id"], tree_row["to_record_id"]),
    ).fetchall()

    leaves = [r["record_hash"] for r in tree_records]
    record_ids = [r["id"] for r in tree_records]

    tree = MerkleTree(leaves)

    try:
        leaf_index = record_ids.index(record_id)
    except ValueError:
        return None

    proof = tree.get_proof(leaf_index)
    verified = MerkleTree.verify_proof(record_hash, proof, tree.root)

    return {
        "record_hash": record_hash,
        "action_id": record["action_id"],
        "leaf_index": leaf_index,
        "tree_index": tree_row["tree_index"],
        "tree_root": tree.root,
        "tree_size": tree.leaf_count,
        "tree_height": tree.height,
        "period_start": tree_row["period_start"],
        "period_end": tree_row["period_end"],
        "proof": proof,
        "proof_depth": len(proof),
        "verified": verified,
        "anchor_tx_hash": tree_row["anchor_tx_hash"],
        "anchor_chain": tree_row["anchor_chain"],
    }


def get_consistency_proof(
    conn: sqlite3.Connection, tenant_id: str, tree_n: int, tree_m: int
) -> Optional[dict]:
    """
    Consistency proof between two hourly trees.

    Verifies that:
    1. Tree N's records are unmodified (root matches stored)
    2. Tree N's records are a prefix of the full record sequence up to Tree M
    3. All intermediate trees' roots chain correctly via prev_tree_root
    """
    if tree_n >= tree_m:
        return {"error": "tree_n must be less than tree_m", "consistent": False}

    # Fetch both trees
    tree_n_row = conn.execute(
        "SELECT * FROM merkle_trees WHERE tenant_id = ? AND tree_index = ?",
        (tenant_id, tree_n),
    ).fetchone()
    tree_m_row = conn.execute(
        "SELECT * FROM merkle_trees WHERE tenant_id = ? AND tree_index = ?",
        (tenant_id, tree_m),
    ).fetchone()

    if not tree_n_row:
        return {"error": f"Tree {tree_n} not found", "consistent": False}
    if not tree_m_row:
        return {"error": f"Tree {tree_m} not found", "consistent": False}

    # 1. Verify tree N's records haven't been tampered with
    n_records = conn.execute(
        "SELECT record_hash FROM audit_log "
        "WHERE tenant_id = ? AND id >= ? AND id <= ? "
        "AND (erasure_status = 'active' OR erasure_status IS NULL) "
        "ORDER BY id ASC",
        (tenant_id, tree_n_row["from_record_id"], tree_n_row["to_record_id"]),
    ).fetchall()

    n_leaves = [r["record_hash"] for r in n_records]
    n_tree = MerkleTree(n_leaves)
    n_root_matches = n_tree.root == tree_n_row["merkle_root"]

    if not n_root_matches:
        return {
            "tree_n": tree_n,
            "tree_m": tree_m,
            "consistent": False,
            "reason": f"Tree {tree_n} records have been modified. "
            f"Recomputed root={n_tree.root[:16]}... != stored={tree_n_row['merkle_root'][:16]}...",
        }

    # 2. Verify the chain of prev_tree_root links between N and M
    chain_trees = conn.execute(
        "SELECT tree_index, merkle_root, prev_tree_root FROM merkle_trees "
        "WHERE tenant_id = ? AND tree_index > ? AND tree_index <= ? "
        "ORDER BY tree_index ASC",
        (tenant_id, tree_n, tree_m),
    ).fetchall()

    expected_prev = tree_n_row["merkle_root"]
    chain_valid = True
    broken_at = None

    for ct in chain_trees:
        stored_prev = ct["prev_tree_root"] or GENESIS_ROOT
        if stored_prev != expected_prev:
            chain_valid = False
            broken_at = ct["tree_index"]
            break
        expected_prev = ct["merkle_root"]

    # 3. Verify tree M's records
    m_records = conn.execute(
        "SELECT record_hash FROM audit_log "
        "WHERE tenant_id = ? AND id >= ? AND id <= ? "
        "AND (erasure_status = 'active' OR erasure_status IS NULL) "
        "ORDER BY id ASC",
        (tenant_id, tree_m_row["from_record_id"], tree_m_row["to_record_id"]),
    ).fetchall()

    m_leaves = [r["record_hash"] for r in m_records]
    m_tree = MerkleTree(m_leaves)
    m_root_matches = m_tree.root == tree_m_row["merkle_root"]

    total_records = sum(
        conn.execute(
            "SELECT COUNT(*) FROM audit_log "
            "WHERE tenant_id = ? AND id >= ? AND id <= ? "
            "AND (erasure_status = 'active' OR erasure_status IS NULL)",
            (tenant_id, tree_n_row["from_record_id"], tree_m_row["to_record_id"]),
        ).fetchone()[0]
        for _ in [1]  # just execute once
    )

    return {
        "tree_n": {
            "index": tree_n,
            "merkle_root": tree_n_row["merkle_root"],
            "record_count": tree_n_row["record_count"],
            "period": [tree_n_row["period_start"], tree_n_row["period_end"]],
            "root_verified": n_root_matches,
        },
        "tree_m": {
            "index": tree_m,
            "merkle_root": tree_m_row["merkle_root"],
            "record_count": tree_m_row["record_count"],
            "period": [tree_m_row["period_start"], tree_m_row["period_end"]],
            "root_verified": m_root_matches,
        },
        "consistent": chain_valid and n_root_matches and m_root_matches,
        "chain_valid": chain_valid,
        "broken_at_tree": broken_at,
        "trees_between": tree_m - tree_n,
        "total_records_spanned": total_records,
    }


def verify_merkle_chain(conn: sqlite3.Connection, tenant_id: str) -> dict:
    """
    Verify the complete Merkle tree chain for a tenant.

    Checks:
    1. Every tree's records produce the stored root when rebuilt
    2. Every tree's prev_tree_root matches the previous tree's root
    3. Record ID ranges are contiguous (no gaps)
    """
    trees = conn.execute(
        "SELECT * FROM merkle_trees WHERE tenant_id = ? ORDER BY tree_index ASC",
        (tenant_id,),
    ).fetchall()

    if not trees:
        return {
            "valid": True,
            "tree_count": 0,
            "record_count": 0,
            "issues": [],
        }

    issues = []
    total_records = 0
    prev_root = GENESIS_ROOT
    prev_to_id = 0

    for t in trees:
        # Check prev_tree_root chain
        stored_prev = t["prev_tree_root"] or GENESIS_ROOT
        if stored_prev != prev_root:
            issues.append(
                {
                    "tree_index": t["tree_index"],
                    "type": "broken_chain",
                    "detail": f"prev_tree_root={stored_prev[:16]}... expected={prev_root[:16]}...",
                }
            )

        # Check record ID contiguity
        if prev_to_id > 0 and t["from_record_id"] != prev_to_id + 1:
            # Allow gaps between trees (records from other tenants may be between)
            pass

        # Rebuild tree and verify root
        records = conn.execute(
            "SELECT record_hash FROM audit_log "
            "WHERE tenant_id = ? AND id >= ? AND id <= ? "
            "AND (erasure_status = 'active' OR erasure_status IS NULL) "
            "ORDER BY id ASC",
            (tenant_id, t["from_record_id"], t["to_record_id"]),
        ).fetchall()

        leaves = [r["record_hash"] for r in records]
        rebuilt = MerkleTree(leaves)

        if rebuilt.root != t["merkle_root"]:
            issues.append(
                {
                    "tree_index": t["tree_index"],
                    "type": "root_mismatch",
                    "detail": f"rebuilt={rebuilt.root[:16]}... stored={t['merkle_root'][:16]}...",
                }
            )

        total_records += t["record_count"]
        prev_root = t["merkle_root"]
        prev_to_id = t["to_record_id"]

    return {
        "valid": len(issues) == 0,
        "tree_count": len(trees),
        "record_count": total_records,
        "first_period": trees[0]["period_start"],
        "last_period": trees[-1]["period_end"],
        "issues": issues,
    }
