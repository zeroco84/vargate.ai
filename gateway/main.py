"""
Vargate MCP Proxy Gateway
Intercepts AI agent tool calls, evaluates them against OPA policy,
and logs every decision to a hash-chained SQLite audit log.
"""

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

# ── Configuration ────────────────────────────────────────────────────────────

OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
OPA_DECISION_PATH = "/v1/data/vargate/policy/decision"
DB_PATH = os.getenv("DB_PATH", "/data/audit.db")
DEFAULT_BUNDLE_REVISION = "v1.0.0-prototype"

# ── FastAPI app ──────────────────────────────────────────────────────────────

app = FastAPI(title="Vargate Gateway", version="0.1.0")


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
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            action_id       TEXT NOT NULL UNIQUE,
            agent_id        TEXT NOT NULL,
            tool            TEXT NOT NULL,
            method          TEXT NOT NULL,
            params          TEXT NOT NULL,
            requested_at    TEXT NOT NULL,
            decision        TEXT NOT NULL,
            violations      TEXT NOT NULL,
            severity        TEXT NOT NULL,
            alert_tier      TEXT NOT NULL,
            bundle_revision TEXT NOT NULL,
            prev_hash       TEXT,
            record_hash     TEXT NOT NULL,
            created_at      TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# ── Hash-chain functions ────────────────────────────────────────────────────

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
             prev_hash, record_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            action_id, agent_id, tool, method, params_str, requested_at,
            decision, violations_str, severity, alert_tier, bundle_revision,
            prev_hash, record_hash, now,
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
        # Check prev_hash link
        if row["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "failed_at_action_id": row["action_id"],
                "reason": "prev_hash mismatch",
            }

        # Recompute and compare record hash
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

def build_opa_input(req: ToolCallRequest, action_id: str) -> dict:
    """Assemble the OPA input document from the incoming request."""
    now = datetime.now(timezone.utc)
    hour = now.hour
    weekday = now.weekday()  # 0=Monday ... 6=Sunday
    is_business_hours = (0 <= weekday <= 4) and (9 <= hour < 18)

    # Allow test/demo overrides for deterministic results
    if req.context_override and req.context_override.is_business_hours is not None:
        is_business_hours = req.context_override.is_business_hours

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
        "history": {
            "last_10min": {
                "action_count": 0,
                "denied_count": 0,
            },
            "anomaly_score": 0.05,
            "flagged": False,
        },
    }


# ── Startup ──────────────────────────────────────────────────────────────────

BUNDLE_SERVER_URL = os.getenv("BUNDLE_SERVER_URL", "http://bundle-server:8080")


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


@app.on_event("startup")
async def startup():
    init_db()
    print("[VARGATE] Gateway started. Database initialised.", flush=True)


# ── Routes ───────────────────────────────────────────────────────────────────

@app.post("/mcp/tools/call")
async def tool_call(req: ToolCallRequest):
    action_id = str(uuid.uuid4())
    opa_input = build_opa_input(req, action_id)
    requested_at = opa_input["action"]["requested_at"]

    # Fetch current bundle revision from OPA
    bundle_revision = await get_bundle_revision()

    # Query OPA
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            opa_resp = await client.post(
                f"{OPA_URL}{OPA_DECISION_PATH}",
                json={"input": opa_input},
            )
            opa_resp.raise_for_status()
        except httpx.HTTPError as e:
            raise HTTPException(
                status_code=502,
                detail=f"OPA unreachable: {str(e)}",
            )

    opa_result = opa_resp.json().get("result", {})
    allowed = opa_result.get("allow", False)
    violations = opa_result.get("violations", [])
    severity = opa_result.get("severity", "none")
    alert_tier = opa_result.get("alert_tier", "none")

    decision_str = "allow" if allowed else "deny"

    # Log to stdout
    if allowed:
        print(
            f"[ALLOW] action_id={action_id} agent={req.agent_id} "
            f"tool={req.tool} method={req.method} "
            f"bundle={bundle_revision}",
            flush=True,
        )
    else:
        print(
            f"[BLOCK] action_id={action_id} agent={req.agent_id} "
            f"tool={req.tool} method={req.method} "
            f"violations={json.dumps(sorted(violations))} severity={severity} "
            f"bundle={bundle_revision}",
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
        )
    finally:
        conn.close()

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


@app.get("/audit/verify")
async def audit_verify():
    conn = get_db()
    try:
        result = verify_chain_integrity(conn)
    finally:
        conn.close()
    return result


@app.get("/audit/log")
async def audit_log(limit: int = Query(default=50, ge=1, le=1000)):
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    finally:
        conn.close()

    records = []
    for row in rows:
        records.append({
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
        })

    return {"records": records, "count": len(records)}


@app.get("/health")
async def health():
    return {"status": "ok", "service": "vargate-gateway"}
