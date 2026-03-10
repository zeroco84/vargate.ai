"""
Vargate MCP Proxy Gateway
Intercepts AI agent tool calls, evaluates them against OPA policy,
and logs every decision to a hash-chained SQLite audit log.
Implements two-pass evaluation with Redis behavioral history.
"""

import hashlib
import json
import os
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

# ── Configuration ────────────────────────────────────────────────────────────

OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
OPA_DECISION_PATH = "/v1/data/vargate/policy/decision"
DB_PATH = os.getenv("DB_PATH", "/data/audit.db")
DEFAULT_BUNDLE_REVISION = "v1.0.0-prototype"
BUNDLE_SERVER_URL = os.getenv("BUNDLE_SERVER_URL", "http://bundle-server:8080")
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(title="Vargate Gateway", version="0.3.0")

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
            anomaly_score_at_eval REAL DEFAULT 0.0
        )
    """)
    # Add columns if upgrading from Session 1/2 schema
    try:
        conn.execute("ALTER TABLE audit_log ADD COLUMN evaluation_pass INTEGER DEFAULT 1")
    except sqlite3.OperationalError:
        pass  # Column already exists
    try:
        conn.execute("ALTER TABLE audit_log ADD COLUMN anomaly_score_at_eval REAL DEFAULT 0.0")
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
):
    """Write a hash-chained audit record to SQLite."""
    params_str = json.dumps(params, separators=(",", ":"))
    violations_str = json.dumps(violations, separators=(",", ":"))
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
             evaluation_pass, anomaly_score_at_eval)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            action_id, agent_id, tool, method, params_str, requested_at,
            decision, violations_str, severity, alert_tier, bundle_revision,
            prev_hash, record_hash, now,
            evaluation_pass, anomaly_score_at_eval,
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

    # Write audit record
    conn = get_db()
    try:
        write_audit_record(
            conn=conn,
            action_id=action_id,
            agent_id=req.agent_id,
            tool=req.tool,
            method=req.method,
            params=req.params,
            requested_at=requested_at,
            decision=decision_str,
            violations=sorted(violations),
            severity=severity,
            alert_tier=alert_tier,
            bundle_revision=bundle_revision,
            evaluation_pass=evaluation_pass,
            anomaly_score_at_eval=anomaly_score,
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
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
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
        }
        records.append(rec)

    return {"records": records, "count": len(records)}


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
