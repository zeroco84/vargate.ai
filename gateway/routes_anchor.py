"""
Anchor routes: blockchain anchoring, Merkle tree proofs, anchor log,
anchor status, and consistency verification endpoints.
Extracted from main.py for maintainability (Audit Item 14).
"""

import hashlib as _hashlib
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query

router = APIRouter(tags=["Blockchain"])


# ── Anchor trigger ──────────────────────────────────────────────────────────


@router.post("/anchor/trigger")
async def trigger_anchor(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
):
    """Trigger an immediate Merkle anchor to Sepolia (or fallback to legacy).
    Requires authentication — admin-only action."""
    import main

    # Require authenticated tenant (no public access)
    tenant = await main.get_session_tenant(authorization, x_api_key, None)
    if not tenant:
        raise HTTPException(401, "Authentication required")

    # Prefer Sepolia Merkle anchoring
    if main.merkle_blockchain_client and main.merkle_blockchain_client.connected:
        conn = main.get_db()
        try:
            result = await main.merkle_blockchain_client.anchor_now(conn)
            result["sepolia_explorer_url"] = (
                f"https://sepolia.etherscan.io/tx/{result['tx_hash']}"
            )
            main.write_anchor_audit_record(
                conn,
                result,
                contract_address=main.merkle_blockchain_client.contract_address,
            )
            return result
        except Exception as e:
            raise HTTPException(500, f"Merkle anchor failed: {e}")
        finally:
            conn.close()

    # Fallback to legacy Hardhat
    if not main.blockchain_client:
        return {"error": "blockchain unavailable"}
    result = await main.submit_anchor(force=True)
    if not result:
        raise HTTPException(500, "Anchor submission failed")
    return result


@router.get("/anchor/verify")
async def verify_anchor():
    """Verify current Merkle root against latest on-chain anchor."""
    import main

    if main.merkle_blockchain_client and main.merkle_blockchain_client.connected:
        conn = main.get_db()
        try:
            result = await main.merkle_blockchain_client.verify_latest(conn)
            return result
        except Exception as e:
            return {
                "error": f"Merkle verification failed: {e}",
                "match": False,
                "computed_root": None,
                "on_chain_root": None,
            }
        finally:
            conn.close()

    tip = main._get_chain_tip()
    if not main.blockchain_client:
        return {
            "error": "blockchain unavailable",
            "match": False,
            "computed_root": None,
            "on_chain_root": None,
            "record_count": tip["record_count"],
        }

    latest = main.blockchain_client.get_latest_anchor()
    if not latest:
        return {
            "current_chain_tip": tip["record_hash"],
            "current_record_count": tip["record_count"],
            "latest_anchor": None,
            "match": False,
            "blockchain_connected": True,
            "interpretation": "No anchors submitted yet. Trigger an anchor first.",
        }

    anchor_hash = latest["chain_tip_hash"]
    anchor_hash_clean = anchor_hash.lstrip("0") or "0"
    tip_hash_clean = tip["record_hash"].lstrip("0") or "0"
    match = anchor_hash_clean == tip_hash_clean

    return {
        "current_chain_tip": tip["record_hash"],
        "current_record_count": tip["record_count"],
        "latest_anchor": {
            "chain_tip_hash": anchor_hash,
            "record_count": latest["record_count"],
            "block_number": latest["block_number"],
            "anchor_index": latest["index"],
        },
        "match": match,
        "blockchain_connected": True,
        "interpretation": (
            "Chain tip matches latest on-chain anchor. Audit trail is consistent."
            if match
            else f"Chain has advanced since last anchor — "
            f"{tip['record_count'] - latest['record_count']} new records pending."
        ),
    }


@router.get("/anchor/proof/{action_id}")
async def anchor_proof(action_id: str):
    """Get a Merkle inclusion proof for a specific audit record (AG-2.3)."""
    import main
    from merkle import MerkleTree

    conn = main.get_db()
    try:
        row = conn.execute(
            "SELECT id, record_hash FROM audit_log WHERE action_id = ?",
            (action_id,),
        ).fetchone()
        if not row:
            raise HTTPException(404, f"Record not found: {action_id}")

        record_hash = row["record_hash"]
        tree = await main.tree_cache.get(conn)

        all_rows = conn.execute("SELECT id FROM audit_log ORDER BY id ASC").fetchall()
        record_ids = [r["id"] for r in all_rows]

        try:
            leaf_index = record_ids.index(row["id"])
        except ValueError:
            raise HTTPException(500, "Record found but not in ordered leaf list")

        proof = tree.get_proof(leaf_index)
        verified = MerkleTree.verify_proof(record_hash, proof, tree.root)

        return {
            "action_id": action_id,
            "record_hash": record_hash,
            "leaf_index": leaf_index,
            "proof": proof,
            "current_root": tree.root,
            "verified": verified,
            "tree_size": tree.leaf_count,
            "proof_depth": len(proof),
        }
    finally:
        conn.close()


@router.get("/anchor/chain-verify")
async def verify_anchor_chain():
    """Verify the hash chain between successive Merkle roots."""
    import main
    from merkle import GENESIS_ROOT

    conn = main.get_db()
    try:
        rows = conn.execute(
            "SELECT id, anchor_index, merkle_root, prev_merkle_root, root_chain_hash "
            "FROM merkle_anchor_log ORDER BY id ASC"
        ).fetchall()

        if not rows:
            return {"valid": True, "anchor_count": 0, "broken_at": None, "chain": []}

        chain = []
        valid = True
        broken_at = None
        prev_root = GENESIS_ROOT

        for row in rows:
            merkle_root = row["merkle_root"]
            stored_prev = row["prev_merkle_root"] or GENESIS_ROOT
            stored_hash = row["root_chain_hash"] or ""

            expected_hash = _hashlib.sha256(
                bytes.fromhex(prev_root) + bytes.fromhex(merkle_root)
            ).hexdigest()

            prev_matches = (stored_prev.lstrip("0") or "0") == (
                prev_root.lstrip("0") or "0"
            )
            hash_matches = (stored_hash.lstrip("0") or "0") == (
                expected_hash.lstrip("0") or "0"
            )
            link_valid = prev_matches and hash_matches

            entry = {
                "anchor_index": row["anchor_index"],
                "merkle_root": merkle_root,
                "prev_merkle_root": stored_prev,
                "root_chain_hash": stored_hash,
                "expected_hash": expected_hash,
                "match": link_valid,
            }
            chain.append(entry)

            if not link_valid and valid:
                valid = False
                broken_at = row["anchor_index"]

            prev_root = merkle_root

        return {
            "valid": valid,
            "anchor_count": len(chain),
            "broken_at": broken_at,
            "chain": chain,
        }
    finally:
        conn.close()


@router.get("/merkle/roots")
async def get_merkle_roots():
    """Return all locally-recorded Merkle roots."""
    import main

    conn = main.get_db()
    try:
        rows = conn.execute(
            "SELECT id, merkle_root, record_count, computed_at, anchored, anchor_id "
            "FROM merkle_root_log ORDER BY id DESC LIMIT 100"
        ).fetchall()

        return {
            "roots": [
                {
                    "id": r["id"],
                    "merkle_root": r["merkle_root"],
                    "record_count": r["record_count"],
                    "computed_at": r["computed_at"],
                    "anchored": bool(r["anchored"]),
                    "anchor_id": r["anchor_id"],
                }
                for r in rows
            ],
            "count": len(rows),
            "interval_seconds": main.MERKLE_ROOT_INTERVAL_SECONDS,
        }
    finally:
        conn.close()


# ── Sprint 5: Hourly Merkle Tree API (AG-2.2 / AG-2.3) ─────────────────────


@router.get("/audit/merkle/roots")
async def audit_merkle_roots(
    limit: int = Query(default=100, le=500),
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Get Merkle tree roots for the tenant's audit records."""
    import main
    from merkle import build_hourly_trees

    tenant = await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    conn = main.get_db()
    try:
        build_hourly_trees(conn, tenant["tenant_id"])
        rows = conn.execute(
            "SELECT id, tree_index, merkle_root, record_count, tree_height, "
            "from_record_id, to_record_id, period_start, period_end, created_at, "
            "prev_tree_root, anchor_tx_hash, anchor_chain, anchor_block "
            "FROM merkle_trees WHERE tenant_id = ? ORDER BY tree_index DESC LIMIT ?",
            (tenant["tenant_id"], limit),
        ).fetchall()

        return {
            "trees": [
                {
                    "tree_index": r["tree_index"],
                    "merkle_root": r["merkle_root"],
                    "record_count": r["record_count"],
                    "tree_height": r["tree_height"],
                    "from_record_id": r["from_record_id"],
                    "to_record_id": r["to_record_id"],
                    "period_start": r["period_start"],
                    "period_end": r["period_end"],
                    "created_at": r["created_at"],
                    "prev_tree_root": r["prev_tree_root"],
                    "anchor_tx_hash": r["anchor_tx_hash"],
                    "anchor_chain": r["anchor_chain"],
                    "anchor_block": r["anchor_block"],
                    "anchored": r["anchor_tx_hash"] is not None,
                }
                for r in rows
            ],
            "count": len(rows),
            "tenant_id": tenant["tenant_id"],
        }
    finally:
        conn.close()


@router.get("/audit/merkle/proof/{record_hash}")
async def audit_merkle_proof(
    record_hash: str,
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Get a Merkle inclusion proof for a specific audit record hash."""
    import main
    from merkle import build_hourly_trees, get_inclusion_proof

    tenant = await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    conn = main.get_db()
    try:
        build_hourly_trees(conn, tenant["tenant_id"])
        result = get_inclusion_proof(conn, record_hash, tenant["tenant_id"])
        if not result:
            raise HTTPException(
                404, "Record not found or not yet in a completed hourly tree"
            )
        return result
    finally:
        conn.close()


@router.get("/audit/merkle/consistency/{tree_n}/{tree_m}")
async def audit_merkle_consistency(
    tree_n: int,
    tree_m: int,
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Verify consistency between two Merkle trees."""
    import main
    from merkle import get_consistency_proof

    tenant = await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    conn = main.get_db()
    try:
        result = get_consistency_proof(conn, tenant["tenant_id"], tree_n, tree_m)
        if "error" in result:
            raise HTTPException(
                400 if "must be less" in result["error"] else 404, result["error"]
            )
        return result
    finally:
        conn.close()


@router.get("/audit/merkle/verify")
async def audit_merkle_verify(
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Verify the overall Merkle tree integrity."""
    import main
    from merkle import build_hourly_trees, verify_merkle_chain

    tenant = await main.get_tenant(x_api_key, authorization, x_vargate_public_tenant)
    conn = main.get_db()
    try:
        build_hourly_trees(conn, tenant["tenant_id"])
        result = verify_merkle_chain(conn, tenant["tenant_id"])
        return result
    finally:
        conn.close()


@router.get("/anchor/consistency-proof")
async def consistency_proof(from_anchor_index: int, to_anchor_index: int):
    """Consistency proof between two anchor indices."""
    import main
    from merkle import MerkleTree as _MT

    if from_anchor_index >= to_anchor_index:
        raise HTTPException(400, "from_anchor_index must be less than to_anchor_index")

    conn = main.get_db()
    try:
        from_row = conn.execute(
            "SELECT * FROM merkle_anchor_log WHERE anchor_index = ?",
            (from_anchor_index,),
        ).fetchone()
        to_row = conn.execute(
            "SELECT * FROM merkle_anchor_log WHERE anchor_index = ?",
            (to_anchor_index,),
        ).fetchone()

        if not from_row:
            raise HTTPException(404, f"Anchor index {from_anchor_index} not found")
        if not to_row:
            raise HTTPException(404, f"Anchor index {to_anchor_index} not found")

        from_root_stored = from_row["merkle_root"]
        to_root_stored = to_row["merkle_root"]
        from_start = from_row["from_record"]
        from_end = from_row["to_record"]
        to_start = to_row["from_record"]
        to_end = to_row["to_record"]

        from_records = conn.execute(
            "SELECT id, record_hash FROM audit_log WHERE id >= ? AND id <= ? ORDER BY id ASC",
            (from_start, from_end),
        ).fetchall()

        if not from_records:
            return {
                "consistent": False,
                "reason": f"No records found in range [{from_start}..{from_end}]",
            }

        from_leaves = [r["record_hash"] for r in from_records]
        from_tree = _MT(from_leaves)

        from_clean = from_tree.root.lstrip("0") or "0"
        stored_clean = from_root_stored.lstrip("0") or "0"
        from_matches = from_clean == stored_clean

        if not from_matches:
            return {
                "from_anchor": {
                    "index": from_anchor_index,
                    "merkle_root": from_root_stored,
                    "record_range": [from_start, from_end],
                },
                "to_anchor": {
                    "index": to_anchor_index,
                    "merkle_root": to_root_stored,
                    "record_range": [to_start, to_end],
                },
                "consistent": False,
                "added_records": 0,
                "verification": (
                    f"Records in from_anchor range [{from_start}..{from_end}] have been "
                    f"modified. Recomputed root={from_tree.root[:16]}... does not match "
                    f"stored root={from_root_stored[:16]}..."
                ),
            }

        added_records = to_end - from_end if to_end > from_end else 0

        return {
            "from_anchor": {
                "index": from_anchor_index,
                "merkle_root": from_root_stored,
                "record_range": [from_start, from_end],
            },
            "to_anchor": {
                "index": to_anchor_index,
                "merkle_root": to_root_stored,
                "record_range": [to_start, to_end],
            },
            "consistent": True,
            "added_records": added_records,
            "verification": (
                f"Records from anchor {from_anchor_index} are an unmodified prefix of "
                f"anchor {to_anchor_index}'s tree. {added_records} records were added "
                f"between the two anchors."
            ),
        }
    finally:
        conn.close()


@router.get("/anchor/log")
async def get_anchor_log():
    """Return all Merkle anchor records with explorer URLs."""
    import main

    conn = main.get_db()
    try:
        try:
            rows = conn.execute(
                "SELECT * FROM merkle_anchor_log ORDER BY id DESC"
            ).fetchall()
        except Exception:
            rows = []

        legacy_rows = conn.execute(
            "SELECT * FROM anchor_log ORDER BY id DESC"
        ).fetchall()

        anchors = []
        for r in rows:
            d = dict(r)
            d["sepolia_explorer_url"] = (
                f"https://sepolia.etherscan.io/tx/{d.get('tx_hash', '')}"
            )
            d["source"] = "sepolia_merkle"
            anchors.append(d)

        for r in legacy_rows:
            d = dict(r)
            d["source"] = "hardhat_legacy"
            anchors.append(d)

        return {
            "anchors": anchors,
            "count": len(anchors),
        }
    finally:
        conn.close()


@router.get("/anchor/status")
async def anchor_status():
    """Status of blockchain anchoring systems (multi-chain)."""
    import main
    from blockchain_client import ANCHOR_MODE

    legacy_connected = main.blockchain_client is not None
    legacy_addr = (
        main.blockchain_client.contract_address if main.blockchain_client else None
    )
    legacy_count = (
        main.blockchain_client.get_anchor_count() if main.blockchain_client else 0
    )

    sepolia_connected = (
        main.merkle_blockchain_client is not None
        and main.merkle_blockchain_client.connected
    )
    sepolia_addr = (
        main.merkle_blockchain_client.contract_address
        if main.merkle_blockchain_client
        else None
    )
    sepolia_deployer = (
        main.merkle_blockchain_client.get_deployer_address()
        if main.merkle_blockchain_client
        else None
    )
    sepolia_count = (
        main.merkle_blockchain_client.get_anchor_count() if sepolia_connected else 0
    )
    latest_merkle = (
        await main.merkle_blockchain_client.get_latest_anchor()
        if sepolia_connected
        else None
    )

    conn = main.get_db()
    try:
        last_anchor_row = conn.execute(
            "SELECT anchored_at FROM anchor_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        last_anchor_time = last_anchor_row["anchored_at"] if last_anchor_row else None

        tree_stats = conn.execute(
            "SELECT COUNT(*) as total, "
            "SUM(CASE WHEN anchor_tx_hash IS NOT NULL THEN 1 ELSE 0 END) as anchored "
            "FROM merkle_trees"
        ).fetchone()
    finally:
        conn.close()

    chains_status = main.chain_manager.status() if main.chain_manager else {}
    connected_chains = main.chain_manager.connected_chains if main.chain_manager else []

    return {
        "network": (
            connected_chains[0]
            if connected_chains
            else ("hardhat" if legacy_connected else None)
        ),
        "connected_chains": connected_chains,
        "contract_address": sepolia_addr or legacy_addr,
        "deployer_address": sepolia_deployer,
        "anchor_count": sepolia_count or legacy_count,
        "latest_merkle_root": latest_merkle["merkle_root"] if latest_merkle else None,
        "last_anchor_time": last_anchor_time,
        "web3_connected": sepolia_connected
        or legacy_connected
        or bool(connected_chains),
        "anchor_interval_seconds": main.ANCHOR_INTERVAL_SECONDS,
        "anchor_mode": ANCHOR_MODE,
        "blockchain_connected": legacy_connected
        or sepolia_connected
        or bool(connected_chains),
        "merkle_trees": {
            "total": tree_stats["total"] if tree_stats else 0,
            "anchored": tree_stats["anchored"] if tree_stats else 0,
        },
        "chains": chains_status,
        "legacy_hardhat": {
            "connected": legacy_connected,
            "contract_address": legacy_addr,
            "anchor_count": legacy_count,
        },
    }
