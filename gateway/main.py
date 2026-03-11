"""
Vargate MCP Proxy Gateway
Intercepts AI agent tool calls, evaluates them against OPA policy,
and logs every decision to a hash-chained SQLite audit log.
Implements two-pass evaluation with Redis behavioral history.
"""

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

# ── Configuration ────────────────────────────────────────────────────────────

OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
OPA_DECISION_PATH = "/v1/data/vargate/policy/decision"
DB_PATH = os.getenv("DB_PATH", "/data/audit.db")
DEFAULT_BUNDLE_REVISION = "v1.0.0-prototype"
BUNDLE_SERVER_URL = os.getenv("BUNDLE_SERVER_URL", "http://bundle-server:8080")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
HSM_URL = os.getenv("HSM_URL", "http://hsm:8300")

# PII detection patterns
_PII_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_PII_SORT_CODE_RE = re.compile(r"\d{2}-\d{2}-\d{2}")
_PII_NI_NUMBER_RE = re.compile(r"[A-Z]{2}\d{6}[A-Z]")
_PII_NAME_FIELDS = {"name", "customer_name", "full_name", "first_name", "last_name"}

# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(title="Vargate Gateway", version="0.4.0")

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
            erasure_status        TEXT DEFAULT 'active'
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
    ]:
        try:
            conn.execute(col_sql)
        except sqlite3.OperationalError:
            pass  # Column already exists
    conn.commit()
    conn.close()


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
):
    """Write a hash-chained audit record to SQLite."""
    params_str = json.dumps(params, separators=(",", ":"))
    violations_str = json.dumps(violations, separators=(",", ":"))
    opa_input_str = json.dumps(opa_input, separators=(",", ":")) if opa_input else None
    pii_fields_str = json.dumps(pii_fields) if pii_fields else None
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
             contains_pii, pii_subject_id, pii_fields, erasure_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            action_id, agent_id, tool, method, params_str, requested_at,
            decision, violations_str, severity, alert_tier, bundle_revision,
            prev_hash, record_hash, now,
            evaluation_pass, anomaly_score_at_eval, opa_input_str,
            contains_pii, pii_subject_id, pii_fields_str, "active",
        ),
    )
    conn.commit()


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
    global redis_pool
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
    print("[VARGATE] Gateway started. Database initialised.", flush=True)


@app.on_event("shutdown")
async def shutdown():
    global redis_pool
    if redis_pool:
        await redis_pool.close()


# ── Routes ───────────────────────────────────────────────────────────────────

@app.post("/mcp/tools/call")
async def tool_call(req: ToolCallRequest):
    action_id = str(uuid.uuid4())
    bundle_revision = await get_bundle_revision()
    amount = req.params.get("amount")

    # ── Pass 1: Fast path (no Redis) ─────────────────────────────────
    opa_input_p1 = build_opa_input(req, action_id, history=None)
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
        opa_input_p2 = build_opa_input(req, action_id, history=history)
        # Preserve the same requested_at from Pass 1
        opa_input_p2["action"]["requested_at"] = requested_at
        final_result = await query_opa(opa_input_p2)
    # If allowed and fast mode with clean history — forward immediately
    else:
        final_result = result_p1

    # Extract final decision
    allowed = final_result.get("allow", False)
    violations = final_result.get("violations", [])
    severity = final_result.get("severity", "none")
    alert_tier = final_result.get("alert_tier", "none")
    decision_str = "allow" if allowed else "deny"

    # Log to stdout
    pass_label = f"P{evaluation_pass}"
    if allowed:
        print(
            f"[ALLOW] action_id={action_id} agent={req.agent_id} "
            f"tool={req.tool} method={req.method} "
            f"pass={pass_label} bundle={bundle_revision}",
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

    # Determine the final opa_input used for the decision
    if evaluation_pass == 2:
        final_opa_input = opa_input_p2
    else:
        final_opa_input = opa_input_p1

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
        return AllowedResponse(action_id=action_id)
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


@app.get("/health")
async def health():
    redis_ok = False
    if redis_pool:
        try:
            await redis_pool.ping()
            redis_ok = True
        except Exception:
            pass
    return {"status": "ok", "service": "vargate-gateway", "redis": redis_ok}
