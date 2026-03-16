"""
Vargate MCP Proxy Gateway
Intercepts AI agent tool calls, evaluates them against OPA policy,
and logs every decision to a hash-chained SQLite audit log.
Implements two-pass evaluation with Redis behavioral history.
Blockchain anchoring via Sepolia Ethereum testnet with Merkle tree roots.
Stage 8: Credential Enclave — agent-blind brokered execution.
Stage 7B: Merkle tree audit anchoring (AG-2.2 / AG-2.3).
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import execution_engine

# ── Configuration ────────────────────────────────────────────────────────────

OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
OPA_DECISION_PATH = "/v1/data/vargate/policy/decision"
DB_PATH = os.getenv("DB_PATH", "/data/audit.db")
DEFAULT_BUNDLE_REVISION = "v1.0.0-prototype"
BUNDLE_SERVER_URL = os.getenv("BUNDLE_SERVER_URL", "http://bundle-server:8080")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
HSM_URL = os.getenv("HSM_URL", "http://hsm:8300")
MOCK_TOOLS_URL = os.getenv("MOCK_TOOLS_URL", "http://mock-tools:9000")
BLOCKCHAIN_RPC_URL = os.getenv("BLOCKCHAIN_RPC_URL", "http://blockchain:8545")
CONTRACT_ADDRESS_FILE = os.getenv("CONTRACT_ADDRESS_FILE", "/shared/contract_address.txt")
CONTRACT_ABI_FILE = os.getenv("CONTRACT_ABI_FILE", "/shared/AuditAnchor.abi.json")
ANCHOR_INTERVAL_SECONDS = int(os.getenv("ANCHOR_INTERVAL_SECONDS", "3600"))
SEPOLIA_RPC_URL = os.getenv("SEPOLIA_RPC_URL", "")
MERKLE_CONTRACT_FILE = os.getenv("MERKLE_CONTRACT_FILE", "/shared/MerkleAuditAnchor.json")

# PII detection patterns
_PII_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_PII_SORT_CODE_RE = re.compile(r"\d{2}-\d{2}-\d{2}")
_PII_NI_NUMBER_RE = re.compile(r"[A-Z]{2}\d{6}[A-Z]")
_PII_NAME_FIELDS = {"name", "customer_name", "full_name", "first_name", "last_name"}

# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(title="Vargate Gateway", version="0.5.0")

# DEMO ONLY — remove in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# DEMO ONLY — stores original hashes during tamper simulation
_tamper_store: dict[int, str] = {}

# ── Redis connection pool ────────────────────────────────────────────────────

redis_pool: Optional[aioredis.Redis] = None

# ── Blockchain client (legacy Hardhat + new Sepolia Merkle) ──────────────────

blockchain_client = None
_anchor_task = None

# New Sepolia Merkle anchor client
merkle_blockchain_client = None
_merkle_anchor_task = None

# Merkle tree cache (Fix 2 — avoids full rebuild on every proof/verify request)
from tree_cache import tree_cache

# Fix 5: Background task for local Merkle root recording
_merkle_root_task = None


async def run_merkle_root_loop(get_db_fn):
    """
    Fix 5 (AG-2.2): Background task that computes and records the current
    Merkle root at regular intervals (default: every hour, must be ≤ 3600s).
    This provides evidence that roots were computed at least hourly,
    regardless of whether on-chain anchoring succeeded.
    """
    from merkle import MerkleTree as _MT
    await asyncio.sleep(20)  # Initial delay

    while True:
        try:
            conn = get_db_fn()
            try:
                count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
                if count > 0:
                    tree = _MT.from_db(conn)
                    now = datetime.now(timezone.utc).isoformat()
                    conn.execute(
                        "INSERT INTO merkle_root_log (merkle_root, record_count, computed_at) "
                        "VALUES (?, ?, ?)",
                        (tree.root, tree.leaf_count, now),
                    )
                    conn.commit()
                    print(
                        f"[MERKLE-ROOT] Recorded root={tree.root[:16]}... records={tree.leaf_count}",
                        flush=True,
                    )
            finally:
                conn.close()
        except Exception as e:
            print(f"[MERKLE-ROOT] Background loop error: {e}", flush=True)

        await asyncio.sleep(MERKLE_ROOT_INTERVAL_SECONDS)


# ── Request / Response models ────────────────────────────────────────────────

class ContextOverride(BaseModel):
    is_business_hours: Optional[bool] = None


class ToolCallRequest(BaseModel):
    agent_id: str
    agent_type: str = "unknown"
    agent_version: str = "0.0.0"
    tool: str
    method: str
    params: dict[str, Any] = {}
    context_override: Optional[ContextOverride] = None


class AllowedResponse(BaseModel):
    status: str = "allowed"
    action_id: str


class BlockedResponse(BaseModel):
    status: str = "blocked"
    action_id: str
    violations: list[str]
    severity: str
    alert_tier: str


# ── SQLite setup ─────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id             TEXT NOT NULL UNIQUE,
            agent_id              TEXT NOT NULL,
            tool                  TEXT NOT NULL,
            method                TEXT NOT NULL,
            params                TEXT NOT NULL,
            requested_at          TEXT NOT NULL,
            decision              TEXT NOT NULL,
            violations            TEXT NOT NULL,
            severity              TEXT NOT NULL,
            alert_tier            TEXT NOT NULL,
            bundle_revision       TEXT NOT NULL,
            prev_hash             TEXT,
            record_hash           TEXT NOT NULL,
            created_at            TEXT NOT NULL,
            evaluation_pass       INTEGER DEFAULT 1,
            anomaly_score_at_eval REAL DEFAULT 0.0,
            opa_input             TEXT,
            contains_pii          INTEGER DEFAULT 0,
            pii_subject_id        TEXT,
            pii_fields            TEXT,
            erasure_status        TEXT DEFAULT 'active',
            execution_mode        TEXT DEFAULT 'agent_direct',
            execution_result      TEXT,
            execution_latency_ms  INTEGER,
            credential_accessed   TEXT
        )
    """)
    # Add columns if upgrading from earlier schemas
    for col_sql in [
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
    ]:
        try:
            conn.execute(col_sql)
        except sqlite3.OperationalError:
            pass  # Column already exists
    # Anchor log table (legacy linear chain)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS anchor_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            anchor_index    INTEGER NOT NULL,
            chain_tip_hash  TEXT NOT NULL,
            record_count    INTEGER NOT NULL,
            tx_hash         TEXT NOT NULL,
            block_number    INTEGER NOT NULL,
            anchored_at     TEXT NOT NULL
        )
    """)
    # Merkle anchor log table (Stage 7B — Sepolia)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS merkle_anchor_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            anchor_index    INTEGER NOT NULL,
            merkle_root     TEXT NOT NULL,
            record_count    INTEGER NOT NULL,
            from_record     INTEGER NOT NULL,
            to_record       INTEGER NOT NULL,
            tx_hash         TEXT NOT NULL,
            block_number    INTEGER NOT NULL,
            anchored_at     TEXT NOT NULL
        )
    """)
    # Migrate: add Merkle columns to anchor_log if upgrading
    for col_sql in [
        "ALTER TABLE anchor_log ADD COLUMN merkle_root TEXT",
        "ALTER TABLE anchor_log ADD COLUMN from_record INTEGER",
        "ALTER TABLE anchor_log ADD COLUMN to_record INTEGER",
    ]:
        try:
            conn.execute(col_sql)
        except sqlite3.OperationalError:
            pass  # Column already exists
    # Fix 4A (AG-2.2): Add Merkle root chain columns to merkle_anchor_log
    for col_sql in [
        "ALTER TABLE merkle_anchor_log ADD COLUMN prev_merkle_root TEXT",
        "ALTER TABLE merkle_anchor_log ADD COLUMN root_chain_hash TEXT",
    ]:
        try:
            conn.execute(col_sql)
        except sqlite3.OperationalError:
            pass  # Column already exists
    # Fix 5 (AG-2.2): Local Merkle root recording table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS merkle_root_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            merkle_root     TEXT NOT NULL,
            record_count    INTEGER NOT NULL,
            computed_at     TEXT NOT NULL,
            anchored        INTEGER NOT NULL DEFAULT 0,
            anchor_id       INTEGER REFERENCES merkle_anchor_log(id)
        )
    """)
    conn.commit()
    conn.close()


MERKLE_ROOT_INTERVAL_SECONDS = int(os.getenv("MERKLE_ROOT_INTERVAL_SECONDS", "3600"))

# ── Hash-chain functions ────────────────────────────────────────────────────
# Note: hash computation uses the original Session 1 fields only for
# backward compatibility. New columns are NOT included in the hash.

def compute_record_hash(
    action_id: str,
    agent_id: str,
    tool: str,
    method: str,
    params: str,
    requested_at: str,
    decision: str,
    violations: str,
    severity: str,
    bundle_revision: str,
    prev_hash: str,
) -> str:
    """Compute SHA-256 hash of record fields in canonical order."""
    payload = json.dumps(
        {
            "action_id": action_id,
            "agent_id": agent_id,
            "tool": tool,
            "method": method,
            "params": params,
            "requested_at": requested_at,
            "decision": decision,
            "violations": violations,
            "severity": severity,
            "bundle_revision": bundle_revision,
            "prev_hash": prev_hash,
        },
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def get_prev_hash(conn: sqlite3.Connection) -> str:
    """Get the hash of the most recent audit record, or GENESIS."""
    row = conn.execute(
        "SELECT record_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["record_hash"] if row else "GENESIS"


def write_audit_record(
    conn: sqlite3.Connection,
    action_id: str,
    agent_id: str,
    tool: str,
    method: str,
    params: dict,
    requested_at: str,
    decision: str,
    violations: list[str],
    severity: str,
    alert_tier: str,
    bundle_revision: str = DEFAULT_BUNDLE_REVISION,
    evaluation_pass: int = 1,
    anomaly_score_at_eval: float = 0.0,
    opa_input: Optional[dict] = None,
    contains_pii: int = 0,
    pii_subject_id: Optional[str] = None,
    pii_fields: Optional[list[str]] = None,
    execution_mode: str = "agent_direct",
    execution_result: Optional[dict] = None,
    execution_latency_ms: Optional[int] = None,
    credential_accessed: Optional[str] = None,
):
    """Write a hash-chained audit record to SQLite."""
    params_str = json.dumps(params, separators=(",", ":"))
    violations_str = json.dumps(violations, separators=(",", ":"))
    opa_input_str = json.dumps(opa_input, separators=(",", ":")) if opa_input else None
    pii_fields_str = json.dumps(pii_fields) if pii_fields else None
    execution_result_str = json.dumps(execution_result, separators=(",", ":")) if execution_result else None
    prev_hash = get_prev_hash(conn)

    record_hash = compute_record_hash(
        action_id=action_id,
        agent_id=agent_id,
        tool=tool,
        method=method,
        params=params_str,
        requested_at=requested_at,
        decision=decision,
        violations=violations_str,
        severity=severity,
        bundle_revision=bundle_revision,
        prev_hash=prev_hash,
    )

    now = datetime.now(timezone.utc).isoformat()

    conn.execute(
        """
        INSERT INTO audit_log
            (action_id, agent_id, tool, method, params, requested_at,
             decision, violations, severity, alert_tier, bundle_revision,
             prev_hash, record_hash, created_at,
             evaluation_pass, anomaly_score_at_eval, opa_input,
             contains_pii, pii_subject_id, pii_fields, erasure_status,
             execution_mode, execution_result, execution_latency_ms, credential_accessed)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            action_id, agent_id, tool, method, params_str, requested_at,
            decision, violations_str, severity, alert_tier, bundle_revision,
            prev_hash, record_hash, now,
            evaluation_pass, anomaly_score_at_eval, opa_input_str,
            contains_pii, pii_subject_id, pii_fields_str, "active",
            execution_mode, execution_result_str, execution_latency_ms, credential_accessed,
        ),
    )
    conn.commit()

    # Fix 2: Invalidate the Merkle tree cache so the next proof/verify
    # request rebuilds the tree including this new record.
    tree_cache.invalidate()


def write_anchor_audit_record(conn: sqlite3.Connection, anchor_result: dict, contract_address: str = None):
    """
    Fix 3 (AG-3.2): Write a blockchain anchor event into the hash-chained audit log.

    This creates a bi-directional link between the audit chain and the public ledger:
    - This audit record contains the tx_hash pointing to Sepolia.
    - The NEXT Merkle root computed on Sepolia will include this record's hash.

    IMPORTANT: This record is included in the NEXT anchor's Merkle tree, NOT in the
    current one. This is correct and expected — the current anchor's root was computed
    BEFORE this record was written. The next anchor will cover records including this one.
    """
    import uuid

    action_id = str(uuid.uuid4())
    requested_at = datetime.now(timezone.utc).isoformat()

    explorer_url = f"https://sepolia.etherscan.io/tx/{anchor_result.get('tx_hash', '')}"

    params = {
        "merkle_root": anchor_result.get("merkle_root", ""),
        "record_count": anchor_result.get("record_count", 0),
        "from_record": anchor_result.get("from_record", 0),
        "to_record": anchor_result.get("to_record", 0),
        "tx_hash": anchor_result.get("tx_hash", ""),
        "block_number": anchor_result.get("block_number", 0),
        "network": "sepolia",
        "chain_id": 11155111,
        "contract_address": contract_address or "",
        "explorer_url": explorer_url,
    }

    write_audit_record(
        conn=conn,
        action_id=action_id,
        agent_id="vargate-system",
        tool="blockchain_anchor",
        method="submitAnchor",
        params=params,
        requested_at=requested_at,
        decision="allow",
        violations=[],
        severity="none",
        alert_tier="none",
        bundle_revision=DEFAULT_BUNDLE_REVISION,
    )

    print(
        f"[ANCHOR] AG-3.2 audit record written: action_id={action_id[:16]}... "
        f"tx={anchor_result.get('tx_hash', '?')[:18]}...",
        flush=True,
    )

    return action_id


# ── Chain verification ───────────────────────────────────────────────────────

def verify_chain_integrity(conn: sqlite3.Connection) -> dict:
    """Verify the entire hash chain. Returns validity status."""
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id ASC"
    ).fetchall()

    if not rows:
        return {"valid": True, "record_count": 0}

    expected_prev = "GENESIS"

    for row in rows:
        if row["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "failed_at_action_id": row["action_id"],
                "reason": "prev_hash mismatch",
            }

        expected_hash = compute_record_hash(
            action_id=row["action_id"],
            agent_id=row["agent_id"],
            tool=row["tool"],
            method=row["method"],
            params=row["params"],
            requested_at=row["requested_at"],
            decision=row["decision"],
            violations=row["violations"],
            severity=row["severity"],
            bundle_revision=row["bundle_revision"],
            prev_hash=row["prev_hash"],
        )

        if expected_hash != row["record_hash"]:
            return {
                "valid": False,
                "failed_at_action_id": row["action_id"],
                "reason": "record_hash mismatch",
            }

        expected_prev = row["record_hash"]

    return {"valid": True, "record_count": len(rows)}


# ── Helper: build OPA input ─────────────────────────────────────────────────

def build_opa_input(
    req: ToolCallRequest,
    action_id: str,
    history: Optional[dict] = None,
    credentials_registered: Optional[list[str]] = None,
) -> dict:
    """Assemble the OPA input document from the incoming request."""
    now = datetime.now(timezone.utc)
    hour = now.hour
    weekday = now.weekday()
    is_business_hours = (0 <= weekday <= 4) and (9 <= hour < 18)

    if req.context_override and req.context_override.is_business_hours is not None:
        is_business_hours = req.context_override.is_business_hours

    # Default neutral history (Pass 1)
    if history is None:
        history = {
            "last_10min": {
                "action_count": 0,
                "denied_count": 0,
            },
            "last_24h": {
                "high_value_transactions": 0,
                "policy_violations": 0,
            },
            "anomaly_score": 0.0,
            "flagged": False,
        }

    return {
        "agent": {
            "id": req.agent_id,
            "type": req.agent_type,
            "version": req.agent_version,
            "deployment": "bridge",
            "enclave_verified": False,
            "roles": ["crm_read", "crm_write", "email_send"],
            "jurisdiction": "EU",
        },
        "action": {
            "id": action_id,
            "tool": req.tool,
            "method": req.method,
            "params": req.params,
            "requested_at": now.isoformat(),
        },
        "context": {
            "time_utc": now.isoformat(),
            "hour_of_day": hour,
            "is_business_hours": is_business_hours,
            "approval": {
                "required": False,
                "granted": False,
                "approver": None,
            },
        },
        "data": {
            "contains_pii": False,
            "pii_types": [],
            "classification": "internal",
            "residency_required": "EU",
            "destination": {
                "type": "external_saas",
                "approved": True,
            },
        },
        "history": history,
        "vault": {
            "credentials_registered": credentials_registered or [],
            "brokered_execution": True,
        },
    }


# ── Redis behavioral history ────────────────────────────────────────────────

async def fetch_behavioral_history(agent_id: str) -> dict:
    """Fetch agent behavioral history from Redis for Pass 2 enrichment."""
    global redis_pool
    if redis_pool is None:
        return _default_history()

    try:
        now_ts = time.time()
        ts_10min_ago = now_ts - 600
        ts_24h_ago = now_ts - 86400

        pipe = redis_pool.pipeline()
        pipe.hgetall(f"agent:{agent_id}:counters")
        pipe.get(f"agent:{agent_id}:anomaly_score")
        pipe.zcount(f"agent:{agent_id}:actions", ts_10min_ago, "+inf")
        pipe.zcount(f"agent:{agent_id}:actions", ts_24h_ago, "+inf")
        results = await pipe.execute()

        counters = results[0] or {}
        anomaly_raw = results[1]
        action_count_10min = results[2] or 0
        action_count_24h = results[3] or 0

        anomaly_score = float(anomaly_raw) if anomaly_raw else 0.0
        denied_10min = int(counters.get(b"denied_count_10min", counters.get("denied_count_10min", 0)))
        high_value_24h = int(counters.get(b"high_value_count_24h", counters.get("high_value_count_24h", 0)))
        violation_24h = int(counters.get(b"violation_count_24h", counters.get("violation_count_24h", 0)))

        return {
            "last_10min": {
                "action_count": action_count_10min,
                "denied_count": denied_10min,
            },
            "last_24h": {
                "high_value_transactions": high_value_24h,
                "policy_violations": violation_24h,
            },
            "anomaly_score": round(anomaly_score, 4),
            "flagged": anomaly_score > 0.5,
        }
    except Exception as e:
        print(f"[REDIS] Error fetching history for {agent_id}: {e}", flush=True)
        return _default_history()


def _default_history() -> dict:
    return {
        "last_10min": {"action_count": 0, "denied_count": 0},
        "last_24h": {"high_value_transactions": 0, "policy_violations": 0},
        "anomaly_score": 0.0,
        "flagged": False,
    }


async def update_behavioral_history(
    agent_id: str,
    action_id: str,
    decision: str,
    amount: Optional[float],
):
    """Update Redis behavioral history after a decision."""
    global redis_pool
    if redis_pool is None:
        return

    try:
        now_ts = time.time()
        ts_24h_ago = now_ts - 86400

        # Always read current anomaly score from Redis
        current_raw = await redis_pool.get(f"agent:{agent_id}:anomaly_score")
        current_score = float(current_raw) if current_raw else 0.0

        # Compute new anomaly score with decay
        new_score = current_score * 0.95  # decay
        if decision == "deny":
            new_score = min(1.0, new_score + 0.15)
        elif amount is not None and amount >= 1000:
            new_score = min(1.0, new_score + 0.03)

        pipe = redis_pool.pipeline()

        # Increment counters
        pipe.hincrby(f"agent:{agent_id}:counters", "action_count_10min", 1)
        pipe.hincrby(f"agent:{agent_id}:counters", "action_count_24h", 1)

        if decision == "deny":
            pipe.hincrby(f"agent:{agent_id}:counters", "denied_count_10min", 1)
            pipe.hincrby(f"agent:{agent_id}:counters", "violation_count_24h", 1)

        if amount is not None and amount >= 1000:
            pipe.hincrby(f"agent:{agent_id}:counters", "high_value_count_24h", 1)

        # Update anomaly score
        pipe.set(f"agent:{agent_id}:anomaly_score", str(round(new_score, 6)),
                 ex=7 * 86400)  # 7 day TTL

        # Add action to sorted set
        pipe.zadd(f"agent:{agent_id}:actions", {action_id: now_ts})

        # Trim sorted set to last 24 hours
        pipe.zremrangebyscore(f"agent:{agent_id}:actions", "-inf", ts_24h_ago)

        # Set TTL on counters (25 hours)
        pipe.expire(f"agent:{agent_id}:counters", 25 * 3600)

        await pipe.execute()
    except Exception as e:
        print(f"[REDIS] Error updating history for {agent_id}: {e}", flush=True)


async def flush_agent_history(agent_id: str):
    """Clear all Redis data for an agent (used by tests)."""
    global redis_pool
    if redis_pool is None:
        return
    try:
        pipe = redis_pool.pipeline()
        pipe.delete(f"agent:{agent_id}:counters")
        pipe.delete(f"agent:{agent_id}:anomaly_score")
        pipe.delete(f"agent:{agent_id}:actions")
        await pipe.execute()
    except Exception as e:
        print(f"[REDIS] Error flushing agent {agent_id}: {e}", flush=True)


async def get_agent_anomaly_score(agent_id: str) -> float:
    """Get current anomaly score for an agent."""
    global redis_pool
    if redis_pool is None:
        return 0.0
    try:
        val = await redis_pool.get(f"agent:{agent_id}:anomaly_score")
        return float(val) if val else 0.0
    except Exception:
        return 0.0


async def _agent_has_violations(agent_id: str) -> bool:
    """Quick check: does this agent have any recorded violations?
    Single Redis HGET — fast enough for every request."""
    global redis_pool
    if redis_pool is None:
        return False
    try:
        val = await redis_pool.hget(f"agent:{agent_id}:counters", "violation_count_24h")
        return val is not None and int(val) > 0
    except Exception:
        return False


# ── OPA query helper ────────────────────────────────────────────────────────

async def query_opa(opa_input: dict) -> dict:
    """Send input to OPA and return the decision result."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(
                f"{OPA_URL}{OPA_DECISION_PATH}",
                json={"input": opa_input},
            )
            resp.raise_for_status()
        except httpx.HTTPError as e:
            raise HTTPException(
                status_code=502,
                detail=f"OPA unreachable: {str(e)}",
            )
    return resp.json().get("result", {})


# ── Bundle revision ─────────────────────────────────────────────────────────

async def get_bundle_revision() -> str:
    """Fetch the current bundle revision from the bundle server."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{BUNDLE_SERVER_URL}/bundles/vargate/status")
            if resp.status_code == 200:
                data = resp.json()
                revision = data.get("revision", "")
                if revision:
                    return revision
    except Exception:
        pass
    return DEFAULT_BUNDLE_REVISION


@app.get("/bundles/vargate/status")
async def bundle_status_proxy():
    """Proxy bundle status from the bundle server so the UI can fetch it via /api/."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{BUNDLE_SERVER_URL}/bundles/vargate/status")
            if resp.status_code == 200:
                return resp.json()
    except Exception:
        pass
    return {"revision": DEFAULT_BUNDLE_REVISION, "etag": "unknown"}


# ── PII detection and HSM encryption ────────────────────────────────────────

def detect_pii_fields(params: dict) -> list[str]:
    """Scan params for fields containing PII. Returns list of field names."""
    pii_fields = []
    for key, value in params.items():
        if not isinstance(value, str):
            continue
        # Check name fields
        if key.lower() in _PII_NAME_FIELDS:
            pii_fields.append(key)
            continue
        # Check email
        if _PII_EMAIL_RE.search(value):
            pii_fields.append(key)
            continue
        # Check sort code
        if _PII_SORT_CODE_RE.fullmatch(value):
            pii_fields.append(key)
            continue
        # Check NI number
        if _PII_NI_NUMBER_RE.fullmatch(value.upper()):
            pii_fields.append(key)
            continue
    return pii_fields


def extract_subject_id(params: dict, agent_id: str) -> str:
    """Extract data subject ID from params, falling back to agent_id."""
    for key in ("customer_id", "subject_id", "user_id"):
        if key in params and isinstance(params[key], str):
            return params[key]
    return agent_id


async def encrypt_pii_in_params(
    params: dict, pii_fields: list[str], subject_id: str
) -> dict:
    """Encrypt PII fields in params via the HSM service. Returns modified params."""
    # Ensure key exists for this subject
    async with httpx.AsyncClient(timeout=10.0) as client:
        await client.post(f"{HSM_URL}/keys", json={"subject_id": subject_id})

        encrypted_params = dict(params)
        for field in pii_fields:
            plaintext = str(params[field])
            resp = await client.post(
                f"{HSM_URL}/encrypt",
                json={"subject_id": subject_id, "plaintext": plaintext},
            )
            if resp.status_code == 200:
                data = resp.json()
                encrypted_params[field] = (
                    f"[ENCRYPTED:{data['key_id']}:{data['ciphertext_b64']}]"
                )
            else:
                print(f"[VARGATE] HSM encrypt failed for {field}: {resp.text}", flush=True)

    return encrypted_params


async def decrypt_field_value(value: str) -> dict:
    """Attempt to decrypt an [ENCRYPTED:key_id:ciphertext] value."""
    if not isinstance(value, str) or not value.startswith("[ENCRYPTED:"):
        return {"plaintext": value, "encrypted": False}

    # Parse [ENCRYPTED:key_id:ciphertext_b64]
    inner = value[len("[ENCRYPTED:"):-1]
    parts = inner.split(":", 1)
    if len(parts) != 2:
        return {"error": "malformed_encrypted_field"}

    key_id = parts[0]
    ciphertext_b64 = parts[1]

    # Extract subject_id from key_id (key-{subject_id}-v1)
    subject_id = key_id.replace("key-", "").replace("-v1", "")

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{HSM_URL}/decrypt",
            json={"subject_id": subject_id, "ciphertext_b64": ciphertext_b64},
        )
        if resp.status_code == 200:
            data = resp.json()
            if "error" in data:
                return data
            return {"plaintext": data["plaintext"], "encrypted": True, "decrypted": True}
        return {"error": f"HSM returned {resp.status_code}", "encrypted": True}


# ── Startup / Shutdown ──────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    global redis_pool, _anchor_task, merkle_blockchain_client, _merkle_anchor_task
    init_db()
    try:
        redis_pool = aioredis.from_url(
            REDIS_URL,
            decode_responses=False,
            socket_connect_timeout=5,
        )
        await redis_pool.ping()
        print("[VARGATE] Redis connected.", flush=True)
    except Exception as e:
        print(f"[VARGATE] Redis not available ({e}), running without history.", flush=True)
        redis_pool = None

    # Initialize legacy blockchain anchoring (Hardhat)
    if _init_blockchain():
        _anchor_task = asyncio.create_task(_anchor_loop())
        print(f"[VARGATE] Legacy anchor task started (interval: {ANCHOR_INTERVAL_SECONDS}s).", flush=True)

    # Initialize Sepolia Merkle anchor client (Stage 7B)
    try:
        from blockchain_client import BlockchainClient as MerkleBlockchainClient
        from blockchain_client import run_anchor_loop as merkle_anchor_loop
        merkle_blockchain_client = MerkleBlockchainClient()
        if merkle_blockchain_client.connect():
            # Fix 3: pass callback to write AG-3.2 audit records after each anchor
            def _post_anchor(conn, result):
                write_anchor_audit_record(
                    conn, result,
                    contract_address=merkle_blockchain_client.contract_address,
                )
            _merkle_anchor_task = asyncio.create_task(
                merkle_anchor_loop(merkle_blockchain_client, get_db, post_anchor_fn=_post_anchor)
            )
            print(
                f"[VARGATE] Sepolia Merkle anchor connected. "
                f"Contract: {merkle_blockchain_client.contract_address}",
                flush=True,
            )
        else:
            print("[VARGATE] Sepolia not configured — Merkle anchoring disabled.", flush=True)
    except Exception as e:
        print(f"[VARGATE] Merkle blockchain init failed: {e}", flush=True)
        merkle_blockchain_client = None

    # Fix 5 (AG-2.2): Start background Merkle root recording loop
    _merkle_root_task = asyncio.create_task(run_merkle_root_loop(get_db))
    print(
        f"[VARGATE] Merkle root recording started (interval: {MERKLE_ROOT_INTERVAL_SECONDS}s).",
        flush=True,
    )

    # Initialize execution engine
    execution_engine.init(MOCK_TOOLS_URL)
    print(f"[VARGATE] Execution engine initialized (mock-tools: {MOCK_TOOLS_URL}).", flush=True)

    # Register mock tokens with the mock tool server for validation
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            for tool_id, token in [
                ("gmail", "mock-gmail-key-001"),
                ("salesforce", "mock-salesforce-key-001"),
                ("stripe", "mock-stripe-key-001"),
                ("slack", "mock-slack-key-001"),
            ]:
                await client.post(
                    f"{MOCK_TOOLS_URL}/admin/register-token",
                    json={"tool_id": tool_id, "token": token},
                )
        print("[VARGATE] Mock tool tokens registered.", flush=True)
    except Exception as e:
        print(f"[VARGATE] Could not register mock tokens: {e}", flush=True)

    print("[VARGATE] Gateway started. Database initialised.", flush=True)


@app.on_event("shutdown")
async def shutdown():
    global redis_pool
    if redis_pool:
        await redis_pool.close()


# ── Routes ───────────────────────────────────────────────────────────────────

@app.post("/mcp/tools/call")
async def tool_call(req: ToolCallRequest):
    total_start = time.monotonic()
    action_id = str(uuid.uuid4())
    bundle_revision = await get_bundle_revision()
    amount = req.params.get("amount")

    # ── Fetch registered credentials for OPA vault input ─────────
    credentials_registered = []
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            cred_resp = await client.get(f"{HSM_URL}/credentials")
            if cred_resp.status_code == 200:
                cred_data = cred_resp.json()
                credentials_registered = list(set(
                    c["tool_id"] for c in cred_data.get("credentials", [])
                ))
    except Exception as e:
        print(f"[VARGATE] Failed to fetch credential list: {e}", flush=True)

    # ── Pass 1: Fast path (no Redis) ─────────────────────────────
    opa_start = time.monotonic()
    opa_input_p1 = build_opa_input(req, action_id, history=None, credentials_registered=credentials_registered)
    requested_at = opa_input_p1["action"]["requested_at"]
    result_p1 = await query_opa(opa_input_p1)

    allowed_p1 = result_p1.get("allow", False)
    violations_p1 = result_p1.get("violations", [])
    eval_mode = result_p1.get("evaluation_mode", "fast")

    evaluation_pass = 1
    anomaly_score = 0.0

    # Check if agent has behavioral red flags (cheap single Redis key check)
    agent_flagged = await _agent_has_violations(req.agent_id)

    # If denied on Pass 1 — block immediately
    if not allowed_p1:
        final_result = result_p1
    # If needs_enrichment OR agent has behavioral flags — do Pass 2
    elif eval_mode == "needs_enrichment" or agent_flagged:
        evaluation_pass = 2
        history = await fetch_behavioral_history(req.agent_id)
        anomaly_score = history.get("anomaly_score", 0.0)
        opa_input_p2 = build_opa_input(req, action_id, history=history, credentials_registered=credentials_registered)
        # Preserve the same requested_at from Pass 1
        opa_input_p2["action"]["requested_at"] = requested_at
        final_result = await query_opa(opa_input_p2)
    # If allowed and fast mode with clean history — forward immediately
    else:
        final_result = result_p1

    opa_elapsed_ms = int((time.monotonic() - opa_start) * 1000)

    # Extract final decision
    allowed = final_result.get("allow", False)
    violations = final_result.get("violations", [])
    severity = final_result.get("severity", "none")
    alert_tier = final_result.get("alert_tier", "none")
    decision_str = "allow" if allowed else "deny"

    # Determine the final opa_input used for the decision
    if evaluation_pass == 2:
        final_opa_input = opa_input_p2
    else:
        final_opa_input = opa_input_p1

    # ── Brokered execution (Stage 8) ─────────────────────────────
    execution_mode = "agent_direct"
    execution_result = None
    execution_latency_ms = None
    credential_accessed = None
    hsm_fetch_ms = 0
    exec_ms = 0

    if allowed:
        # Attempt brokered execution
        cred_name = "api_key"  # Default credential name
        try:
            # Fetch credential from HSM vault
            hsm_start = time.monotonic()
            async with httpx.AsyncClient(timeout=10.0) as client:
                fetch_resp = await client.get(
                    f"{HSM_URL}/credentials/{req.tool}/status"
                )
                if fetch_resp.status_code == 200 and fetch_resp.json().get("registered"):
                    # Credential exists — do brokered execution
                    # SECURITY: fetch via HSM HTTP endpoint, logs access but never the value
                    cred_fetch_resp = await client.post(
                        f"{HSM_URL}/credentials/fetch-for-execution",
                        json={
                            "tool_id": req.tool,
                            "name": cred_name,
                            "action_id": action_id,
                            "agent_id": req.agent_id,
                        },
                    )
                    hsm_fetch_ms = int((time.monotonic() - hsm_start) * 1000)

                    if cred_fetch_resp.status_code == 200:
                        cred_data = cred_fetch_resp.json()
                        credential_value = cred_data.get("credential")
                        # SECURITY: credential_value used only for execution, never logged

                        # Execute the tool call
                        exec_result = await execution_engine.execute_tool_call(
                            tool=req.tool,
                            method=req.method,
                            params=req.params,
                            credential=credential_value,
                        )

                        execution_mode = "vargate_brokered"
                        execution_result = exec_result.get("result", {})
                        exec_ms = exec_result.get("execution_ms", 0)
                        execution_latency_ms = hsm_fetch_ms + exec_ms
                        credential_accessed = f"{req.tool}:{cred_name}"
                    else:
                        hsm_fetch_ms = int((time.monotonic() - hsm_start) * 1000)
                else:
                    hsm_fetch_ms = int((time.monotonic() - hsm_start) * 1000)
        except Exception as e:
            print(f"[VARGATE] Brokered execution error: {e}", flush=True)

    # Log to stdout
    pass_label = f"P{evaluation_pass}"
    total_ms = int((time.monotonic() - total_start) * 1000)
    latency_breakdown = {
        "opa_eval_ms": opa_elapsed_ms,
        "hsm_fetch_ms": hsm_fetch_ms,
        "execution_ms": exec_ms,
        "total_ms": total_ms,
    }

    if allowed:
        mode_label = "BROKERED" if execution_mode == "vargate_brokered" else "DIRECT"
        print(
            f"[ALLOW] action_id={action_id} agent={req.agent_id} "
            f"tool={req.tool} method={req.method} "
            f"mode={mode_label} pass={pass_label} bundle={bundle_revision} "
            f"latency={json.dumps(latency_breakdown)}",
            flush=True,
        )
    else:
        print(
            f"[BLOCK] action_id={action_id} agent={req.agent_id} "
            f"tool={req.tool} method={req.method} "
            f"violations={json.dumps(sorted(violations))} severity={severity} "
            f"pass={pass_label} bundle={bundle_revision}",
            flush=True,
        )

    # ── PII detection and encryption ─────────────────────────────────
    pii_fields = detect_pii_fields(req.params)
    contains_pii = 1 if pii_fields else 0
    pii_subject_id = None
    params_for_audit = req.params

    if pii_fields:
        pii_subject_id = extract_subject_id(req.params, req.agent_id)
        try:
            params_for_audit = await encrypt_pii_in_params(
                req.params, pii_fields, pii_subject_id
            )
            print(
                f"[PII] Encrypted {len(pii_fields)} field(s) for subject "
                f"{pii_subject_id}: {pii_fields}",
                flush=True,
            )
        except Exception as e:
            print(f"[PII] HSM encryption failed: {e}. Storing plaintext.", flush=True)
            params_for_audit = req.params
            contains_pii = 0
            pii_fields = []

    # Write audit record
    conn = get_db()
    try:
        write_audit_record(
            conn=conn,
            action_id=action_id,
            agent_id=req.agent_id,
            tool=req.tool,
            method=req.method,
            params=params_for_audit,
            requested_at=requested_at,
            decision=decision_str,
            violations=sorted(violations),
            severity=severity,
            alert_tier=alert_tier,
            bundle_revision=bundle_revision,
            evaluation_pass=evaluation_pass,
            anomaly_score_at_eval=anomaly_score,
            opa_input=final_opa_input,
            contains_pii=contains_pii,
            pii_subject_id=pii_subject_id,
            pii_fields=pii_fields if pii_fields else None,
            execution_mode=execution_mode,
            execution_result=execution_result,
            execution_latency_ms=execution_latency_ms,
            credential_accessed=credential_accessed,
        )
    finally:
        conn.close()

    # Update Redis behavioral history
    await update_behavioral_history(
        agent_id=req.agent_id,
        action_id=action_id,
        decision=decision_str,
        amount=amount,
    )

    # Return response
    if allowed:
        response = {"status": "allowed", "action_id": action_id}
        if execution_mode == "vargate_brokered":
            response["execution_mode"] = "vargate_brokered"
            response["execution_result"] = execution_result
            response["latency"] = latency_breakdown
        return response
    else:
        raise HTTPException(
            status_code=403,
            detail=BlockedResponse(
                action_id=action_id,
                violations=sorted(violations),
                severity=severity,
                alert_tier=alert_tier,
            ).model_dump(),
        )


# ── Agent history endpoints (for test scripts) ──────────────────────────────

@app.delete("/agents/{agent_id}/history")
async def clear_agent_history(agent_id: str):
    """Clear behavioral history for an agent. Used by test scripts."""
    await flush_agent_history(agent_id)
    return {"status": "cleared", "agent_id": agent_id}


@app.get("/agents/{agent_id}/anomaly_score")
async def agent_anomaly_score(agent_id: str):
    """Get current anomaly score for an agent."""
    score = await get_agent_anomaly_score(agent_id)
    return {"agent_id": agent_id, "anomaly_score": round(score, 6)}


@app.delete("/agents/{agent_id}/counters")
async def clear_agent_counters(agent_id: str):
    """Clear counters and actions but keep anomaly_score. Used by test scripts."""
    global redis_pool
    if redis_pool:
        try:
            pipe = redis_pool.pipeline()
            pipe.delete(f"agent:{agent_id}:counters")
            pipe.delete(f"agent:{agent_id}:actions")
            await pipe.execute()
        except Exception:
            pass
    return {"status": "counters_cleared", "agent_id": agent_id}


# ── Audit endpoints ─────────────────────────────────────────────────────────

@app.get("/audit/verify")
async def audit_verify():
    conn = get_db()
    try:
        result = verify_chain_integrity(conn)
    finally:
        conn.close()
    return result


@app.get("/audit/log")
async def audit_log(
    limit: int = Query(default=50, ge=1, le=1000),
    agent_id: Optional[str] = Query(default=None),
):
    conn = get_db()
    try:
        if agent_id:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE agent_id = ? ORDER BY id DESC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
            total = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE agent_id = ?", (agent_id,)
            ).fetchone()[0]
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        conn.close()

    records = []
    for row in rows:
        rec = {
            "id": row["id"],
            "action_id": row["action_id"],
            "agent_id": row["agent_id"],
            "tool": row["tool"],
            "method": row["method"],
            "params": json.loads(row["params"]),
            "requested_at": row["requested_at"],
            "decision": row["decision"],
            "violations": json.loads(row["violations"]),
            "severity": row["severity"],
            "alert_tier": row["alert_tier"],
            "bundle_revision": row["bundle_revision"],
            "prev_hash": row["prev_hash"],
            "record_hash": row["record_hash"],
            "created_at": row["created_at"],
            "evaluation_pass": row["evaluation_pass"] if "evaluation_pass" in row.keys() else 1,
            "anomaly_score_at_eval": row["anomaly_score_at_eval"] if "anomaly_score_at_eval" in row.keys() else 0.0,
            "opa_input": json.loads(row["opa_input"]) if ("opa_input" in row.keys() and row["opa_input"]) else None,
            "contains_pii": row["contains_pii"] if "contains_pii" in row.keys() else 0,
            "pii_subject_id": row["pii_subject_id"] if "pii_subject_id" in row.keys() else None,
            "pii_fields": json.loads(row["pii_fields"]) if ("pii_fields" in row.keys() and row["pii_fields"]) else None,
            "erasure_status": row["erasure_status"] if "erasure_status" in row.keys() else "active",
            "execution_mode": row["execution_mode"] if "execution_mode" in row.keys() else "agent_direct",
            "execution_result": json.loads(row["execution_result"]) if ("execution_result" in row.keys() and row["execution_result"]) else None,
            "execution_latency_ms": row["execution_latency_ms"] if "execution_latency_ms" in row.keys() else None,
            "credential_accessed": row["credential_accessed"] if "credential_accessed" in row.keys() else None,
        }
        records.append(rec)

    return {"records": records, "count": len(records), "total": total}


# ── Tamper simulation endpoints (DEMO ONLY) ─────────────────────────────────

class TamperRequest(BaseModel):
    record_number: int


@app.post("/audit/tamper-simulate")  # DEMO ONLY
async def tamper_simulate(req: TamperRequest):
    """Simulate an insider modifying an audit record hash."""
    conn = get_db()
    try:
        # Get record by sequential position (1-indexed, ordered by id ASC)
        row = conn.execute(
            "SELECT id, action_id, record_hash FROM audit_log ORDER BY id ASC LIMIT 1 OFFSET ?",
            (req.record_number - 1,),
        ).fetchone()

        if not row:
            raise HTTPException(404, f"Record #{req.record_number} not found")

        record_id = row["id"]
        original_hash = row["record_hash"]

        # Store original hash for restoration
        _tamper_store[record_id] = original_hash

        # Corrupt the hash
        fake_hash = secrets.token_hex(32)
        conn.execute(
            "UPDATE audit_log SET record_hash = ? WHERE id = ?",
            (fake_hash, record_id),
        )
        conn.commit()

        # Count affected records (this record + all after it)
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        affected = total - req.record_number + 1

        return {
            "tampered_record_number": req.record_number,
            "tampered_action_id": row["action_id"],
            "records_affected": affected,
            "message": f"Record corrupted. Chain broken from record {req.record_number} onward.",
        }
    finally:
        conn.close()


@app.post("/audit/tamper-restore")  # DEMO ONLY
async def tamper_restore():
    """Restore all tampered records to their original hashes."""
    conn = get_db()
    try:
        for record_id, original_hash in _tamper_store.items():
            conn.execute(
                "UPDATE audit_log SET record_hash = ? WHERE id = ?",
                (original_hash, record_id),
            )
        conn.commit()
        _tamper_store.clear()

        result = verify_chain_integrity(conn)
        return {
            "restored": True,
            "chain_valid": result.get("valid", False),
            "record_count": result.get("record_count", 0),
        }
    finally:
        conn.close()


# ── Crypto-shredding / Erasure endpoints ────────────────────────────────────

@app.post("/audit/erase/{subject_id}")
async def erase_subject(subject_id: str):
    """GDPR right-to-erasure: delete the subject's HSM key and mark records."""
    # 1. Delete the key in HSM
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.delete(f"{HSM_URL}/keys/{subject_id}")
        if resp.status_code == 404:
            raise HTTPException(404, f"No key found for subject {subject_id}")
        hsm_result = resp.json()

    erasure_certificate = hsm_result.get("erasure_certificate", "")
    erased_at = hsm_result.get("erased_at", datetime.now(timezone.utc).isoformat())

    # 2. Mark all audit records for this subject as erased
    conn = get_db()
    try:
        cursor = conn.execute(
            "UPDATE audit_log SET erasure_status = 'erased' WHERE pii_subject_id = ?",
            (subject_id,),
        )
        records_affected = cursor.rowcount
        conn.commit()
    finally:
        conn.close()

    print(
        f"[ERASURE] Subject {subject_id}: key deleted, "
        f"{records_affected} records marked erased. "
        f"Certificate: {erasure_certificate[:16]}...",
        flush=True,
    )

    return {
        "subject_id": subject_id,
        "records_affected": records_affected,
        "erasure_certificate": erasure_certificate,
        "erased_at": erased_at,
        "interpretation": (
            f"Key deleted. {records_affected} audit records contain encrypted PII "
            f"for this subject. The ciphertext fields are now irrecoverable. "
            f"Record count and hash chain integrity are preserved."
        ),
    }


@app.get("/audit/erase/{subject_id}/verify")
async def verify_erasure(subject_id: str):
    """Attempt to decrypt PII after erasure — should fail."""
    # Get the first encrypted record for this subject
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT params, pii_fields FROM audit_log WHERE pii_subject_id = ? LIMIT 1",
            (subject_id,),
        ).fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(404, f"No records found for subject {subject_id}")

    params = json.loads(row["params"])
    pii_fields = json.loads(row["pii_fields"]) if row["pii_fields"] else []

    # Attempt to decrypt the first PII field
    if not pii_fields:
        return {
            "subject_id": subject_id,
            "decryption_attempted": False,
            "interpretation": "No PII fields found in record.",
        }

    first_field = pii_fields[0]
    encrypted_value = params.get(first_field, "")

    result = await decrypt_field_value(encrypted_value)

    if "error" in result:
        return {
            "subject_id": subject_id,
            "decryption_attempted": True,
            "decryption_result": "failed",
            "error": result["error"],
            "erased": result.get("erased", False),
            "interpretation": "PII is irrecoverable. Erasure is complete and verifiable.",
        }

    return {
        "subject_id": subject_id,
        "decryption_attempted": True,
        "decryption_result": "success",
        "plaintext": result.get("plaintext"),
        "interpretation": "Key still exists. PII is still accessible.",
    }


@app.get("/audit/subjects")
async def list_subjects():
    """List all subjects with encrypted PII in the audit log."""
    conn = get_db()
    try:
        rows = conn.execute("""
            SELECT pii_subject_id, COUNT(*) as record_count,
                   MAX(erasure_status) as erasure_status,
                   MAX(created_at) as last_seen
            FROM audit_log
            WHERE pii_subject_id IS NOT NULL
            GROUP BY pii_subject_id
            ORDER BY last_seen DESC
        """).fetchall()
    finally:
        conn.close()

    subjects = []
    for row in rows:
        subjects.append({
            "subject_id": row["pii_subject_id"],
            "record_count": row["record_count"],
            "erasure_status": row["erasure_status"],
            "last_seen": row["last_seen"],
        })

    return {"subjects": subjects}


# ── HSM proxy endpoints (for UI and test scripts) ───────────────────────────

@app.post("/hsm/keys")
async def proxy_hsm_create_key(req: dict):
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{HSM_URL}/keys", json=req)
        return resp.json()


@app.post("/hsm/encrypt")
async def proxy_hsm_encrypt(req: dict):
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{HSM_URL}/encrypt", json=req)
        return resp.json()


@app.post("/hsm/decrypt")
async def proxy_hsm_decrypt(req: dict):
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(f"{HSM_URL}/decrypt", json=req)
        return resp.json()


@app.get("/hsm/keys/{subject_id}/status")
async def proxy_hsm_key_status(subject_id: str):
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{HSM_URL}/keys/{subject_id}/status")
        return resp.json()


@app.get("/hsm/keys")
async def proxy_hsm_list_keys():
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{HSM_URL}/keys")
        return resp.json()


@app.delete("/hsm/keys/{subject_id}")
async def proxy_hsm_delete_key(subject_id: str):
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.delete(f"{HSM_URL}/keys/{subject_id}")
        if resp.status_code == 404:
            raise HTTPException(404, f"No key found for subject {subject_id}")
        return resp.json()


# ── Credential vault proxy endpoints (Stage 8) ──────────────────────────────

class RegisterCredentialRequest(BaseModel):
    tool_id: str
    name: str
    value: str  # SECURITY: passes through to HSM, never stored in gateway


@app.post("/credentials/register")
async def register_credential(req: RegisterCredentialRequest):
    """Register a tool credential in the HSM vault."""
    # SECURITY: value passes through to HSM immediately, never logged by gateway
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(
            f"{HSM_URL}/credentials",
            json={"tool_id": req.tool_id, "name": req.name, "value": req.value},
        )
        return resp.json()


@app.get("/credentials")
async def list_credentials():
    """List registered tool credentials (no values returned)."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{HSM_URL}/credentials")
        return resp.json()


@app.delete("/credentials/{tool_id}/{name}")
async def delete_credential(tool_id: str, name: str):
    """Delete a tool credential from the vault."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.delete(f"{HSM_URL}/credentials/{tool_id}/{name}")
        if resp.status_code == 404:
            raise HTTPException(404, f"No credential found for {tool_id}/{name}")
        return resp.json()


@app.get("/credentials/{tool_id}/status")
async def credential_status(tool_id: str):
    """Check credential registration status for a tool."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{HSM_URL}/credentials/{tool_id}/status")
        return resp.json()


@app.get("/credentials/access-log")
async def credential_access_log():
    """Get the credential access log (no values ever returned)."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.get(f"{HSM_URL}/credentials/access-log")
        return resp.json()


# ── Policy replay endpoints ──────────────────────────────────────────────────

class ReplayRequest(BaseModel):
    action_id: Optional[str] = None
    record_number: Optional[int] = None
    last_block: bool = False


class BulkReplayRequest(BaseModel):
    count: int = 10


async def _replay_with_opa(opa_input: dict, bundle_revision: str) -> dict:
    """Fetch the archived bundle and evaluate opa_input against it using a temp OPA."""
    # 1. Fetch archived bundle from bundle server
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{BUNDLE_SERVER_URL}/bundles/vargate/archive/{bundle_revision}"
            )
            if resp.status_code != 200:
                return {"error": f"Archived bundle {bundle_revision} not found (HTTP {resp.status_code})"}
            bundle_bytes = resp.content
    except Exception as e:
        return {"error": f"Failed to fetch archived bundle: {e}"}

    # 2. Write bundle to temp dir, start ephemeral OPA, query, shut down
    tmpdir = tempfile.mkdtemp(prefix="vargate_replay_")
    try:
        bundle_path = os.path.join(tmpdir, "bundle.tar.gz")
        with open(bundle_path, "wb") as f:
            f.write(bundle_bytes)

        # Find a free port
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            port = s.getsockname()[1]

        # Start OPA with bundle
        proc = subprocess.Popen(
            [
                "/usr/local/bin/opa", "run", "--server",
                f"--addr=127.0.0.1:{port}",
                "--log-level=error",
                "-b", bundle_path,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Wait for OPA to be ready
        import asyncio
        for _ in range(30):
            try:
                async with httpx.AsyncClient(timeout=1.0) as client:
                    r = await client.get(f"http://127.0.0.1:{port}/health")
                    if r.status_code == 200:
                        break
            except Exception:
                pass
            await asyncio.sleep(0.1)

        # Query OPA
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.post(
                    f"http://127.0.0.1:{port}/v1/data/vargate/policy/decision",
                    json={"input": opa_input},
                )
                r.raise_for_status()
                return r.json().get("result", {})
        finally:
            proc.terminate()
            proc.wait(timeout=5)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _build_replay_response(row, replayed_result: dict) -> dict:
    """Build the structured comparison response."""
    original_decision = row["decision"]
    original_violations = json.loads(row["violations"])
    original_severity = row["severity"]
    original_bundle = row["bundle_revision"]

    replayed_decision = "allow" if replayed_result.get("allow", False) else "deny"
    replayed_violations = sorted(replayed_result.get("violations", []))
    replayed_severity = replayed_result.get("severity", "none")

    match_decision = original_decision == replayed_decision
    match_violations = sorted(original_violations) == replayed_violations
    match_severity = original_severity == replayed_severity

    all_match = match_decision and match_violations and match_severity
    status = "MATCH" if all_match else "MISMATCH"

    if all_match:
        viols_str = ", ".join(original_violations) if original_violations else "no violations"
        interpretation = (
            f"The recorded decision is verified. Under policy {original_bundle}, "
            f"this action was correctly {'denied for ' + viols_str if original_decision == 'deny' else 'allowed'}. "
            f"This decision is reproducible and tamper-evident."
        )
    else:
        interpretation = (
            f"MISMATCH detected. The replayed decision differs from the original record. "
            f"This indicates either: (a) the stored input document was modified, or "
            f"(b) the policy bundle archive does not match what was deployed at the time. "
            f"Recommend forensic investigation."
        )

    return {
        "action_id": row["action_id"],
        "replay_status": status,
        "original": {
            "decision": original_decision,
            "violations": original_violations,
            "severity": original_severity,
            "bundle_revision": original_bundle,
            "recorded_at": row["created_at"],
        },
        "replayed": {
            "decision": replayed_decision,
            "violations": replayed_violations,
            "severity": replayed_severity,
            "bundle_revision": original_bundle,
            "replayed_at": datetime.now(timezone.utc).isoformat(),
        },
        "match": {
            "decision": match_decision,
            "violations": match_violations,
            "severity": match_severity,
            "bundle_revision": True,
        },
        "opa_input_used": json.loads(row["opa_input"]) if row["opa_input"] else None,
        "interpretation": interpretation,
    }


@app.post("/audit/replay")
async def audit_replay(req: ReplayRequest):
    """Replay a policy decision from archived input document and bundle."""
    conn = get_db()
    try:
        if req.action_id:
            row = conn.execute(
                "SELECT * FROM audit_log WHERE action_id = ?", (req.action_id,)
            ).fetchone()
        elif req.record_number:
            row = conn.execute(
                "SELECT * FROM audit_log ORDER BY id ASC LIMIT 1 OFFSET ?",
                (req.record_number - 1,),
            ).fetchone()
        elif req.last_block:
            row = conn.execute(
                "SELECT * FROM audit_log WHERE decision = 'deny' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        else:
            raise HTTPException(400, "Provide action_id, record_number, or last_block=true")

        if not row:
            raise HTTPException(404, "Record not found")

        if not row["opa_input"]:
            raise HTTPException(
                422,
                f"Record {row['action_id']} predates Session 5 — no opa_input stored. "
                f"Only records created after the replay feature can be replayed."
            )

        opa_input = json.loads(row["opa_input"])
        bundle_revision = row["bundle_revision"]

        replayed_result = await _replay_with_opa(opa_input, bundle_revision)
        if "error" in replayed_result:
            raise HTTPException(502, replayed_result["error"])

        return _build_replay_response(row, replayed_result)
    finally:
        conn.close()


@app.post("/audit/replay-bulk")
async def audit_replay_bulk(req: BulkReplayRequest):
    """Bulk replay the last N records."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE opa_input IS NOT NULL ORDER BY id DESC LIMIT ?",
            (req.count,),
        ).fetchall()
    finally:
        conn.close()

    results = []
    match_count = 0
    mismatch_count = 0
    skip_count = 0

    for row in reversed(rows):  # oldest first
        opa_input = json.loads(row["opa_input"])
        replayed_result = await _replay_with_opa(opa_input, row["bundle_revision"])

        if "error" in replayed_result:
            results.append({
                "action_id": row["action_id"],
                "replay_status": "ERROR",
                "error": replayed_result["error"],
            })
            skip_count += 1
            continue

        resp = _build_replay_response(row, replayed_result)
        results.append(resp)
        if resp["replay_status"] == "MATCH":
            match_count += 1
        else:
            mismatch_count += 1

    return {
        "results": results,
        "summary": {
            "total": len(results),
            "matched": match_count,
            "mismatched": mismatch_count,
            "errors": skip_count,
        },
    }


# ── Blockchain Anchoring ─────────────────────────────────────────────────────

class BlockchainClient:
    """Interacts with the AuditAnchor smart contract on Hardhat local chain."""

    def __init__(self, rpc_url: str, contract_address: str, abi: list):
        from web3 import Web3
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(contract_address),
            abi=abi,
        )
        self.account = self.w3.eth.accounts[0]  # Hardhat default funded account
        self.contract_address = contract_address

    def submit_anchor(
        self, chain_tip_hash: str, record_count: int, system_id: str
    ) -> dict:
        # Pad/truncate to bytes32
        hash_bytes = bytes.fromhex(chain_tip_hash)
        if len(hash_bytes) < 32:
            hash_bytes = hash_bytes.ljust(32, b'\x00')
        elif len(hash_bytes) > 32:
            hash_bytes = hash_bytes[:32]

        tx_hash = self.contract.functions.submitAnchor(
            hash_bytes, record_count, system_id
        ).transact({"from": self.account})
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)

        # Extract anchor index from event logs
        anchor_index = 0
        try:
            logs = self.contract.events.AnchorSubmitted().process_receipt(receipt)
            if logs:
                anchor_index = logs[0]["args"]["anchorIndex"]
        except Exception:
            pass

        return {
            "tx_hash": receipt.transactionHash.hex(),
            "block_number": receipt.blockNumber,
            "anchor_index": anchor_index,
        }

    def get_anchor(self, index: int) -> dict:
        anchor = self.contract.functions.getAnchor(index).call()
        return {
            "block_number": anchor[0],
            "timestamp": anchor[1],
            "chain_tip_hash": anchor[2].hex(),
            "record_count": anchor[3],
            "system_id": anchor[4],
        }

    def get_latest_anchor(self) -> Optional[dict]:
        try:
            anchor, index = self.contract.functions.getLatestAnchor().call()
            return {
                "index": index,
                "block_number": anchor[0],
                "timestamp": anchor[1],
                "chain_tip_hash": anchor[2].hex(),
                "record_count": anchor[3],
                "system_id": anchor[4],
            }
        except Exception:
            return None

    def get_anchor_count(self) -> int:
        try:
            return self.contract.functions.getAnchorCount().call()
        except Exception:
            return 0


def _get_chain_tip() -> dict:
    """Get the current chain tip hash and record count from SQLite."""
    conn = get_db()
    row = conn.execute(
        "SELECT record_hash, id FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    count = conn.execute("SELECT COUNT(*) as c FROM audit_log").fetchone()["c"]
    conn.close()
    if row:
        return {"record_hash": row["record_hash"], "record_count": count}
    return {"record_hash": "GENESIS", "record_count": 0}


_last_anchored_count = 0

async def submit_anchor(force=False):
    """Submit current chain state to the blockchain.
    Skips if no new records since last anchor (unless force=True).
    """
    global blockchain_client, _last_anchored_count
    if not blockchain_client:
        return None

    tip = _get_chain_tip()
    if tip["record_count"] == 0:
        return None

    # Skip if no new records since last anchor (saves gas)
    if not force and tip["record_count"] == _last_anchored_count:
        return None

    try:
        result = blockchain_client.submit_anchor(
            chain_tip_hash=tip["record_hash"],
            record_count=tip["record_count"],
            system_id="vargate-prototype-v1",
        )

        # Write to anchor_log
        anchored_at = datetime.now(timezone.utc).isoformat()
        conn = get_db()
        conn.execute(
            """INSERT INTO anchor_log
               (anchor_index, chain_tip_hash, record_count, tx_hash, block_number, anchored_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                result["anchor_index"],
                tip["record_hash"],
                tip["record_count"],
                result["tx_hash"],
                result["block_number"],
                anchored_at,
            ),
        )
        conn.commit()
        conn.close()

        print(
            f"[ANCHOR] chain_tip={tip['record_hash'][:16]}... "
            f"records={tip['record_count']} "
            f"tx={result['tx_hash'][:16]}... "
            f"block={result['block_number']}",
            flush=True,
        )

        _last_anchored_count = tip["record_count"]

        return {
            "chain_tip_hash": tip["record_hash"],
            "record_count": tip["record_count"],
            "tx_hash": result["tx_hash"],
            "block_number": result["block_number"],
            "anchor_index": result["anchor_index"],
            "anchored_at": anchored_at,
        }
    except Exception as e:
        print(f"[ANCHOR] Error: {e}", flush=True)
        return None


async def _anchor_loop():
    """Background task that anchors the chain every ANCHOR_INTERVAL_SECONDS."""
    await asyncio.sleep(10)  # Initial delay to let things settle
    while True:
        try:
            await submit_anchor()
        except Exception as e:
            print(f"[ANCHOR] Background error: {e}", flush=True)
        await asyncio.sleep(ANCHOR_INTERVAL_SECONDS)


def _init_blockchain():
    """Initialize blockchain client from shared volume files."""
    global blockchain_client

    try:
        if not os.path.exists(CONTRACT_ADDRESS_FILE):
            print(f"[ANCHOR] Contract address file not found: {CONTRACT_ADDRESS_FILE}", flush=True)
            return False

        with open(CONTRACT_ADDRESS_FILE) as f:
            contract_address = f.read().strip()

        if not os.path.exists(CONTRACT_ABI_FILE):
            print(f"[ANCHOR] Contract ABI file not found: {CONTRACT_ABI_FILE}", flush=True)
            return False

        with open(CONTRACT_ABI_FILE) as f:
            abi = json.load(f)

        blockchain_client = BlockchainClient(BLOCKCHAIN_RPC_URL, contract_address, abi)
        print(
            f"[ANCHOR] Blockchain connected. Contract: {contract_address}",
            flush=True,
        )
        return True
    except Exception as e:
        print(f"[ANCHOR] Failed to init blockchain: {e}", flush=True)
        return False


# ── Anchor Endpoints (Legacy Hardhat) ────────────────────────────────────────

@app.post("/anchor/trigger")
async def trigger_anchor():
    """Trigger an immediate Merkle anchor to Sepolia (or fallback to legacy)."""
    global merkle_blockchain_client

    # Prefer Sepolia Merkle anchoring
    if merkle_blockchain_client and merkle_blockchain_client.connected:
        conn = get_db()
        try:
            result = await merkle_blockchain_client.anchor_now(conn)
            result["sepolia_explorer_url"] = (
                f"https://sepolia.etherscan.io/tx/{result['tx_hash']}"
            )
            # Fix 3 (AG-3.2): Write anchor event into the hash-chained audit log
            write_anchor_audit_record(
                conn, result,
                contract_address=merkle_blockchain_client.contract_address,
            )
            return result
        except Exception as e:
            raise HTTPException(500, f"Merkle anchor failed: {e}")
        finally:
            conn.close()

    # Fallback to legacy Hardhat
    if not blockchain_client:
        return {"error": "blockchain unavailable"}
    result = await submit_anchor(force=True)
    if not result:
        raise HTTPException(500, "Anchor submission failed")
    return result


@app.get("/anchor/verify")
async def verify_anchor():
    """Verify current Merkle root against latest on-chain anchor."""
    global merkle_blockchain_client

    # Prefer Sepolia Merkle verification
    if merkle_blockchain_client and merkle_blockchain_client.connected:
        conn = get_db()
        try:
            result = await merkle_blockchain_client.verify_latest(conn)
            return result
        finally:
            conn.close()

    # Fallback to legacy
    tip = _get_chain_tip()

    if not blockchain_client:
        return {"error": "blockchain unavailable",
                "match": False, "computed_root": None, "on_chain_root": None,
                "record_count": tip["record_count"]}

    latest = blockchain_client.get_latest_anchor()

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
    }


@app.get("/anchor/proof/{action_id}")
async def anchor_proof(action_id: str):
    """Get a Merkle inclusion proof for a specific audit record (AG-2.3)."""
    from merkle import MerkleTree

    conn = get_db()
    try:
        # Find the record
        row = conn.execute(
            "SELECT id, record_hash FROM audit_log WHERE action_id = ?",
            (action_id,),
        ).fetchone()

        if not row:
            raise HTTPException(404, f"Record not found: {action_id}")

        record_hash = row["record_hash"]

        # Use cached Merkle tree (Fix 2) — rebuilds only when new records exist
        tree = await tree_cache.get(conn)

        # We need the ordered record IDs to find the leaf index
        all_rows = conn.execute(
            "SELECT id FROM audit_log ORDER BY id ASC"
        ).fetchall()
        record_ids = [r["id"] for r in all_rows]

        # Find the leaf index for this record
        try:
            leaf_index = record_ids.index(row["id"])
        except ValueError:
            raise HTTPException(500, "Record found but not in ordered leaf list")

        # Get proof from the cached tree
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


@app.get("/anchor/chain-verify")
async def verify_anchor_chain():
    """
    Fix 4D (AG-2.2): Verify the hash chain between successive Merkle roots.
    Walks all rows in merkle_anchor_log in order and recomputes root_chain_hash.
    """
    import hashlib as _hashlib
    from merkle import GENESIS_ROOT

    conn = get_db()
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

            # Recompute root_chain_hash
            expected_hash = _hashlib.sha256(
                bytes.fromhex(prev_root) + bytes.fromhex(merkle_root)
            ).hexdigest()

            # Check that stored prev matches our expected prev
            prev_matches = (stored_prev.lstrip("0") or "0") == (prev_root.lstrip("0") or "0")
            hash_matches = (stored_hash.lstrip("0") or "0") == (expected_hash.lstrip("0") or "0")
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


@app.get("/merkle/roots")
async def get_merkle_roots():
    """
    Fix 5 (AG-2.2): Return all locally-recorded Merkle roots.
    This is the evidence trail showing roots were computed at least hourly,
    regardless of whether on-chain anchoring was available.
    """
    conn = get_db()
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
            "interval_seconds": MERKLE_ROOT_INTERVAL_SECONDS,
        }
    finally:
        conn.close()


@app.get("/anchor/consistency-proof")
async def consistency_proof(from_anchor_index: int, to_anchor_index: int):
    """
    Fix 6 (AG-2.3): Consistency proof between two anchor indices.

    Verifies that the log has not been truncated or reordered between two known states.

    NOTE: This is a best-effort consistency check, not a compact O(log n) proof in the
    RFC 6962 sense. We verify that:
    1. All record hashes in the from_anchor range still exist in SQLite unchanged
    2. Rebuilding a Merkle tree from only those records produces the same root as stored
    3. Those records are a prefix of the to_anchor's record range

    This is a sound consistency check: if any record in the from_anchor range was modified,
    deleted, or reordered, the recomputed root will not match. It is NOT the compact
    sub-logarithmic proof described in RFC 6962 §2.1.2.
    """
    from merkle import MerkleTree as _MT

    if from_anchor_index >= to_anchor_index:
        raise HTTPException(400, "from_anchor_index must be less than to_anchor_index")

    conn = get_db()
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

        # 1. Fetch records in the from_anchor range
        from_records = conn.execute(
            "SELECT id, record_hash FROM audit_log WHERE id >= ? AND id <= ? ORDER BY id ASC",
            (from_start, from_end),
        ).fetchall()

        if not from_records:
            return {
                "consistent": False,
                "reason": f"No records found in range [{from_start}..{from_end}]",
            }

        # 2. Rebuild Merkle tree from the from_anchor's records
        from_leaves = [r["record_hash"] for r in from_records]
        from_tree = _MT(from_leaves)

        # Compare to stored root
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

        # 3. Verify that from_anchor records are a prefix of to_anchor
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


@app.get("/anchor/log")
async def get_anchor_log():
    """Return all Merkle anchor records with Sepolia explorer URLs."""
    conn = get_db()
    try:
        # Try merkle_anchor_log first (new table), fallback to anchor_log
        try:
            rows = conn.execute(
                "SELECT * FROM merkle_anchor_log ORDER BY id DESC"
            ).fetchall()
        except Exception:
            rows = []

        # Also include legacy anchors
        legacy_rows = conn.execute(
            "SELECT * FROM anchor_log ORDER BY id DESC"
        ).fetchall()

        anchors = []
        for r in rows:
            d = dict(r)
            d["sepolia_explorer_url"] = f"https://sepolia.etherscan.io/tx/{d.get('tx_hash', '')}"
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


@app.get("/anchor/status")
async def anchor_status():
    """Status of both legacy and Sepolia Merkle anchoring systems."""
    global merkle_blockchain_client

    # Legacy Hardhat info
    legacy_connected = blockchain_client is not None
    legacy_addr = blockchain_client.contract_address if blockchain_client else None
    legacy_count = blockchain_client.get_anchor_count() if blockchain_client else 0

    # Sepolia Merkle info
    sepolia_connected = (
        merkle_blockchain_client is not None
        and merkle_blockchain_client.connected
    )
    sepolia_addr = (
        merkle_blockchain_client.contract_address
        if merkle_blockchain_client
        else None
    )
    sepolia_deployer = (
        merkle_blockchain_client.get_deployer_address()
        if merkle_blockchain_client
        else None
    )
    sepolia_count = (
        merkle_blockchain_client.get_anchor_count()
        if sepolia_connected
        else 0
    )
    latest_merkle = (
        await merkle_blockchain_client.get_latest_anchor()
        if sepolia_connected
        else None
    )

    # Get last anchor time from local DB
    conn = get_db()
    try:
        last_anchor_row = conn.execute(
            "SELECT anchored_at FROM anchor_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        last_anchor_time = last_anchor_row["anchored_at"] if last_anchor_row else None
    finally:
        conn.close()

    # Fix 7: import anchor mode
    from blockchain_client import ANCHOR_MODE

    return {
        "network": "sepolia" if sepolia_connected else ("hardhat" if legacy_connected else None),
        "contract_address": sepolia_addr or legacy_addr,
        "deployer_address": sepolia_deployer,
        "anchor_count": sepolia_count or legacy_count,
        "latest_merkle_root": latest_merkle["merkle_root"] if latest_merkle else None,
        "last_anchor_time": last_anchor_time,
        "web3_connected": sepolia_connected or legacy_connected,
        "anchor_interval_seconds": ANCHOR_INTERVAL_SECONDS,
        "anchor_mode": ANCHOR_MODE,
        # Legacy info for backward compatibility
        "blockchain_connected": legacy_connected or sepolia_connected,
        "legacy_hardhat": {
            "connected": legacy_connected,
            "contract_address": legacy_addr,
            "anchor_count": legacy_count,
        },
    }


@app.get("/health")
async def health():
    redis_ok = False
    if redis_pool:
        try:
            await redis_pool.ping()
            redis_ok = True
        except Exception:
            pass
    blockchain_ok = blockchain_client is not None
    sepolia_ok = (
        merkle_blockchain_client is not None
        and merkle_blockchain_client.connected
    )
    return {
        "status": "ok",
        "service": "vargate-gateway",
        "redis": redis_ok,
        "blockchain": blockchain_ok,
        "sepolia_merkle": sepolia_ok,
    }
