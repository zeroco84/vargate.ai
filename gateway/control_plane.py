"""
Vargate Control Plane — Managed Agent Session Governance (Sprint 11)

Entry point for managed agent session lifecycle: creation, configuration,
monitoring, and termination. Wraps the Anthropic managed agents API with
governance controls.

AGCS Controls: AG-1.6, AG-1.7, AG-1.8, AG-2.7, AG-2.9
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
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ── Configuration ──────────────────────────────────────────────────────────

ANTHROPIC_API_BASE = os.getenv("ANTHROPIC_API_BASE", "https://api.anthropic.com")
VARGATE_MCP_SERVER_URL = os.getenv(
    "VARGATE_MCP_SERVER_URL", "https://vargate.ai/api/mcp/server"
)
ANTHROPIC_API_VERSION = "2024-11-05"

# Default session limits (can be overridden per-tenant)
DEFAULT_MAX_CONCURRENT_SESSIONS = 10
DEFAULT_MAX_DAILY_SESSIONS = 50
DEFAULT_MAX_SESSION_HOURS = 8.0

router = APIRouter(prefix="/managed", tags=["Managed Agents"])


# ── Request / Response Models ──────────────────────────────────────────────


class AgentConfigCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    anthropic_model: str = Field(default="claude-sonnet-4-6")
    system_prompt: Optional[str] = None
    allowed_tools: Optional[list[str]] = None
    max_session_hours: Optional[float] = Field(default=None, ge=0.1, le=24.0)
    max_daily_sessions: Optional[int] = Field(default=None, ge=1, le=1000)
    require_human_approval: Optional[list[str]] = None  # Tool name patterns
    parent_agent_id: Optional[str] = None
    max_delegation_depth: int = Field(default=1, ge=1, le=5)
    governance_profile: Optional[dict] = None


class SessionCreate(BaseModel):
    agent_id: str = Field(..., description="Vargate agent config ID")
    user_message: Optional[str] = Field(
        default=None, description="Initial user message to start the session"
    )
    environment_id: Optional[str] = None
    metadata: Optional[dict] = None


class SessionInterrupt(BaseModel):
    reason: str = Field(..., min_length=1, max_length=1000)
    auto_triggered: bool = Field(default=False)


# ── System Prompt Governance Injection (Sprint 11.3) ───────────────────────

DEFAULT_GOVERNANCE_TEMPLATE = """
## Governance Context (injected by Vargate)

This agent session is governed by Vargate (vargate.ai). All tool calls
through the Vargate MCP server are subject to policy evaluation, audit
logging, and may require human approval.

When using governed tools:
- Provide complete context for why you are taking this action.
- If a tool call returns "pending_approval", inform the user and proceed
  with other work while awaiting approval.
- Never attempt to bypass governed tools by using built-in tools to
  achieve the same effect (e.g., using bash + curl instead of the
  governed API tool).
- All actions are logged and auditable.
""".strip()


def build_governance_prompt(
    tenant_name: str,
    agent_config: dict,
    custom_template: Optional[str] = None,
) -> str:
    """Build the governance injection prompt for a managed agent session."""
    template = custom_template or DEFAULT_GOVERNANCE_TEMPLATE

    # Append agent-specific constraints if configured
    extras = []

    allowed_tools = agent_config.get("allowed_tools")
    if allowed_tools:
        try:
            tools = json.loads(allowed_tools) if isinstance(allowed_tools, str) else allowed_tools
            extras.append(f"Allowed governed tools: {', '.join(tools)}")
        except (json.JSONDecodeError, TypeError):
            pass

    approval_rules = agent_config.get("require_human_approval")
    if approval_rules:
        try:
            rules = json.loads(approval_rules) if isinstance(approval_rules, str) else approval_rules
            extras.append(f"Tools requiring human approval: {', '.join(rules)}")
        except (json.JSONDecodeError, TypeError):
            pass

    max_hours = agent_config.get("max_session_hours")
    if max_hours:
        extras.append(f"Session time limit: {max_hours} hours")

    if extras:
        template += "\n\nSession-specific constraints:\n" + "\n".join(f"- {e}" for e in extras)

    template += f"\n\nOrganization: {tenant_name}"
    return template


def hash_prompt(prompt: str) -> str:
    """SHA-256 hash of the governance prompt for audit trail."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


# ── Auth / DB Helpers ──────────────────────────────────────────────────────


def _get_db():
    import main as gateway_main
    return gateway_main.get_db()


async def _get_tenant(
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> dict:
    import main as gateway_main
    return await gateway_main.get_tenant(x_api_key, authorization)


def _get_anthropic_key(tenant_id: str) -> Optional[str]:
    """Retrieve the tenant's Anthropic API key from HSM vault (sync for now)."""
    import main as gateway_main
    try:
        resp = httpx.get(
            f"{gateway_main.HSM_URL}/credentials/anthropic",
            headers={"X-Tenant-Id": tenant_id},
            timeout=5.0,
        )
        if resp.status_code == 200:
            return resp.json().get("value")
    except Exception:
        pass
    return None


# ── Session Limit Checks (AG-1.7) ─────────────────────────────────────────


def _check_session_limits(
    conn: sqlite3.Connection,
    tenant_id: str,
    agent_config: dict,
) -> Optional[str]:
    """
    Check session creation limits. Returns error message if exceeded, None if OK.

    Checks:
    - Max concurrent active sessions
    - Max daily sessions
    - Agent-specific max_daily_sessions
    """
    # Count active sessions for tenant
    active = conn.execute(
        "SELECT COUNT(*) FROM managed_sessions WHERE tenant_id = ? AND status = 'active'",
        (tenant_id,),
    ).fetchone()[0]

    if active >= DEFAULT_MAX_CONCURRENT_SESSIONS:
        return f"Max concurrent sessions exceeded ({active}/{DEFAULT_MAX_CONCURRENT_SESSIONS})"

    # Count sessions created today
    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0
    ).isoformat()
    daily = conn.execute(
        "SELECT COUNT(*) FROM managed_sessions WHERE tenant_id = ? AND created_at >= ?",
        (tenant_id, today_start),
    ).fetchone()[0]

    if daily >= DEFAULT_MAX_DAILY_SESSIONS:
        return f"Max daily sessions exceeded ({daily}/{DEFAULT_MAX_DAILY_SESSIONS})"

    # Agent-specific daily limit
    agent_max_daily = agent_config.get("max_daily_sessions")
    if agent_max_daily:
        agent_daily = conn.execute(
            "SELECT COUNT(*) FROM managed_sessions WHERE tenant_id = ? AND agent_id = ? AND created_at >= ?",
            (tenant_id, agent_config["id"], today_start),
        ).fetchone()[0]
        if agent_daily >= agent_max_daily:
            return f"Agent daily session limit exceeded ({agent_daily}/{agent_max_daily})"

    return None


# ── Agent Config Endpoints ─────────────────────────────────────────────────


@router.post("/agents")
async def create_agent_config(
    req: AgentConfigCreate,
    tenant: dict = Depends(_get_tenant),
):
    """Register a managed agent configuration with governance profile."""
    tenant_id = tenant["tenant_id"]
    config_id = f"agent-{uuid.uuid4().hex[:12]}"
    conn = _get_db()

    try:
        # Validate parent agent if specified
        if req.parent_agent_id:
            parent = conn.execute(
                "SELECT id, max_delegation_depth FROM managed_agent_configs WHERE id = ? AND tenant_id = ?",
                (req.parent_agent_id, tenant_id),
            ).fetchone()
            if not parent:
                raise HTTPException(status_code=404, detail="Parent agent config not found")

        conn.execute(
            """INSERT INTO managed_agent_configs
               (id, tenant_id, name, anthropic_model, system_prompt,
                governance_profile, allowed_tools, max_session_hours,
                max_daily_sessions, require_human_approval, parent_agent_id,
                max_delegation_depth, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                config_id,
                tenant_id,
                req.name,
                req.anthropic_model,
                req.system_prompt,
                json.dumps(req.governance_profile) if req.governance_profile else None,
                json.dumps(req.allowed_tools) if req.allowed_tools else None,
                req.max_session_hours,
                req.max_daily_sessions,
                json.dumps(req.require_human_approval) if req.require_human_approval else None,
                req.parent_agent_id,
                req.max_delegation_depth,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()

        print(f"[CONTROL-PLANE] Agent config created: {config_id} tenant={tenant_id}", flush=True)

        return {
            "id": config_id,
            "tenant_id": tenant_id,
            "name": req.name,
            "anthropic_model": req.anthropic_model,
            "allowed_tools": req.allowed_tools,
            "max_session_hours": req.max_session_hours,
            "max_daily_sessions": req.max_daily_sessions,
            "max_delegation_depth": req.max_delegation_depth,
        }
    finally:
        conn.close()


@router.get("/agents")
async def list_agent_configs(
    tenant: dict = Depends(_get_tenant),
):
    """List managed agent configurations for this tenant."""
    tenant_id = tenant["tenant_id"]
    conn = _get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM managed_agent_configs WHERE tenant_id = ? ORDER BY created_at DESC",
            (tenant_id,),
        ).fetchall()

        configs = []
        for r in rows:
            configs.append({
                "id": r["id"],
                "name": r["name"],
                "anthropic_model": r["anthropic_model"],
                "allowed_tools": json.loads(r["allowed_tools"]) if r["allowed_tools"] else None,
                "max_session_hours": r["max_session_hours"],
                "max_daily_sessions": r["max_daily_sessions"],
                "max_delegation_depth": r["max_delegation_depth"],
                "parent_agent_id": r["parent_agent_id"],
                "created_at": r["created_at"],
            })
        return {"configs": configs, "count": len(configs)}
    finally:
        conn.close()


@router.get("/agents/{config_id}")
async def get_agent_config(
    config_id: str,
    tenant: dict = Depends(_get_tenant),
):
    """Get a specific managed agent configuration."""
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM managed_agent_configs WHERE id = ? AND tenant_id = ?",
            (config_id, tenant["tenant_id"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Agent config not found")
        return dict(row)
    finally:
        conn.close()


# ── Session Lifecycle Endpoints (Sprint 11.1) ─────────────────────────────


@router.post("/sessions")
async def create_session(
    req: SessionCreate,
    tenant: dict = Depends(_get_tenant),
):
    """
    Create a governed managed agent session.

    Flow:
    1. Validate agent config against tenant policy
    2. Check session budget limits (AG-1.7)
    3. Build governance-injected system prompt (Sprint 11.3)
    4. Call Anthropic POST /v1/sessions (or simulate for tenants without API key)
    5. Auto-attach event consumer to SSE stream
    6. Create managed_sessions record
    7. Return Vargate session ID
    """
    tenant_id = tenant["tenant_id"]
    tenant_name = tenant.get("name", tenant_id)
    session_id = f"vs-{uuid.uuid4().hex[:16]}"
    conn = _get_db()

    try:
        # 1. Validate agent config exists and belongs to tenant
        agent_row = conn.execute(
            "SELECT * FROM managed_agent_configs WHERE id = ? AND tenant_id = ?",
            (req.agent_id, tenant_id),
        ).fetchone()
        if not agent_row:
            raise HTTPException(
                status_code=404,
                detail=f"Agent config '{req.agent_id}' not found for this tenant",
            )
        agent_config = dict(agent_row)

        # 2. Check session limits (AG-1.7)
        limit_error = _check_session_limits(conn, tenant_id, agent_config)
        if limit_error:
            raise HTTPException(status_code=429, detail=limit_error)

        # 3. Build governance-injected system prompt (Sprint 11.3)
        base_prompt = agent_config.get("system_prompt") or ""
        governance_prompt = build_governance_prompt(tenant_name, agent_config)
        full_prompt = f"{base_prompt}\n\n{governance_prompt}" if base_prompt else governance_prompt
        prompt_hash = hash_prompt(full_prompt)

        # 4. Call Anthropic API to create session
        anthropic_session_id = None
        anthropic_api_key = _get_anthropic_key(tenant_id)

        if anthropic_api_key:
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.post(
                        f"{ANTHROPIC_API_BASE}/v1/sessions",
                        headers={
                            "Authorization": f"Bearer {anthropic_api_key}",
                            "anthropic-version": ANTHROPIC_API_VERSION,
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": agent_config.get("anthropic_model", "claude-sonnet-4-6"),
                            "system": full_prompt,
                            "mcp_servers": [{
                                "type": "url",
                                "url": VARGATE_MCP_SERVER_URL,
                                "name": "vargate-governance",
                                "authorization_token": tenant.get("api_key", ""),
                            }],
                        },
                    )
                    if resp.status_code in (200, 201):
                        data = resp.json()
                        anthropic_session_id = data.get("id", data.get("session_id"))
                    else:
                        print(
                            f"[CONTROL-PLANE] Anthropic API error: {resp.status_code} {resp.text[:200]}",
                            flush=True,
                        )
            except Exception as e:
                print(f"[CONTROL-PLANE] Anthropic API call failed: {e}", flush=True)

        # Use a placeholder if Anthropic API not available
        if not anthropic_session_id:
            anthropic_session_id = f"sim-{uuid.uuid4().hex[:16]}"

        # 6. Create managed_sessions record
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """INSERT INTO managed_sessions
               (id, anthropic_session_id, tenant_id, agent_id,
                anthropic_agent_id, environment_id, status,
                governance_profile, system_prompt_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                session_id,
                anthropic_session_id,
                tenant_id,
                req.agent_id,
                None,
                req.environment_id,
                "active",
                json.dumps(agent_config.get("governance_profile")) if agent_config.get("governance_profile") else None,
                prompt_hash,
                now,
            ),
        )
        conn.commit()

        # 5. Auto-attach event consumer if we have a real Anthropic session
        if anthropic_api_key and not anthropic_session_id.startswith("sim-"):
            try:
                import event_consumer
                await event_consumer.start_consumer(
                    session_id=session_id,
                    anthropic_session_id=anthropic_session_id,
                    tenant_id=tenant_id,
                    anthropic_api_key=anthropic_api_key,
                    agent_id=req.agent_id,
                )
            except Exception as e:
                print(f"[CONTROL-PLANE] Event consumer attach failed: {e}", flush=True)

        # Log session creation to audit chain
        import main as gateway_main
        audit_conn = gateway_main.get_db()
        try:
            gateway_main.write_audit_record(
                conn=audit_conn,
                action_id=str(uuid.uuid4()),
                agent_id=req.agent_id,
                tool="control_plane",
                method="create_session",
                params={"session_id": session_id, "agent_config": req.agent_id},
                requested_at=now,
                decision="allow",
                violations=[],
                severity="none",
                alert_tier="P4",
                bundle_revision=gateway_main.DEFAULT_BUNDLE_REVISION,
                tenant_id=tenant_id,
                source="control_plane",
                managed_session_id=session_id,
            )
        finally:
            audit_conn.close()

        print(
            f"[CONTROL-PLANE] Session created: {session_id} "
            f"tenant={tenant_id} agent={req.agent_id} "
            f"anthropic={anthropic_session_id}",
            flush=True,
        )

        return {
            "session_id": session_id,
            "anthropic_session_id": anthropic_session_id,
            "tenant_id": tenant_id,
            "agent_id": req.agent_id,
            "status": "active",
            "system_prompt_hash": prompt_hash,
            "governance": "active",
            "mcp_server_url": VARGATE_MCP_SERVER_URL,
            "created_at": now,
        }
    finally:
        conn.close()


@router.get("/sessions")
async def list_sessions(
    tenant: dict = Depends(_get_tenant),
    status: Optional[str] = Query(default=None, description="Filter by status"),
    agent_id: Optional[str] = Query(default=None, description="Filter by agent config"),
    limit: int = Query(default=50, ge=1, le=200),
):
    """List managed agent sessions for this tenant with optional filtering."""
    tenant_id = tenant["tenant_id"]
    conn = _get_db()
    try:
        query = "SELECT * FROM managed_sessions WHERE tenant_id = ?"
        params: list[Any] = [tenant_id]

        if status:
            query += " AND status = ?"
            params.append(status)
        if agent_id:
            query += " AND agent_id = ?"
            params.append(agent_id)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()

        sessions = []
        for r in rows:
            sessions.append({
                "id": r["id"],
                "anthropic_session_id": r["anthropic_session_id"],
                "agent_id": r["agent_id"],
                "status": r["status"],
                "created_at": r["created_at"],
                "ended_at": r["ended_at"],
                "total_governed_calls": r["total_governed_calls"],
                "total_observed_calls": r["total_observed_calls"],
                "total_denied": r["total_denied"],
                "total_pending": r["total_pending"],
            })

        return {"sessions": sessions, "count": len(sessions), "tenant_id": tenant_id}
    finally:
        conn.close()


@router.get("/sessions/{session_id}/status")
async def get_session_status(
    session_id: str,
    tenant: dict = Depends(_get_tenant),
):
    """Get session status with governance summary."""
    tenant_id = tenant["tenant_id"]
    conn = _get_db()
    try:
        row = conn.execute(
            "SELECT * FROM managed_sessions WHERE id = ? AND tenant_id = ?",
            (session_id, tenant_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Session not found")

        session = dict(row)

        # Count audit entries by source for this session
        audit_counts = conn.execute(
            """SELECT
                 COUNT(*) FILTER (WHERE source = 'mcp_governed') as governed,
                 COUNT(*) FILTER (WHERE source = 'mcp_observed') as observed,
                 COUNT(*) FILTER (WHERE decision = 'deny') as denied,
                 COUNT(*) FILTER (WHERE decision = 'pending_approval') as pending
               FROM audit_log
               WHERE managed_session_id = ? AND tenant_id = ?""",
            (session_id, tenant_id),
        ).fetchone()

        # SQLite doesn't support FILTER — use CASE instead
        audit_counts = conn.execute(
            """SELECT
                 SUM(CASE WHEN source = 'mcp_governed' THEN 1 ELSE 0 END) as governed,
                 SUM(CASE WHEN source = 'mcp_observed' THEN 1 ELSE 0 END) as observed,
                 SUM(CASE WHEN decision = 'deny' THEN 1 ELSE 0 END) as denied,
                 SUM(CASE WHEN decision = 'pending_approval' THEN 1 ELSE 0 END) as pending
               FROM audit_log
               WHERE managed_session_id = ? AND tenant_id = ?""",
            (session_id, tenant_id),
        ).fetchone()

        # Check for active event consumer
        import event_consumer
        consumer = event_consumer.get_consumer(session_id)

        return {
            "session_id": session_id,
            "anthropic_session_id": session["anthropic_session_id"],
            "agent_id": session["agent_id"],
            "status": session["status"],
            "system_prompt_hash": session["system_prompt_hash"],
            "created_at": session["created_at"],
            "ended_at": session["ended_at"],
            "governance_summary": {
                "total_governed_calls": audit_counts["governed"] or 0,
                "total_observed_calls": audit_counts["observed"] or 0,
                "total_denied": audit_counts["denied"] or 0,
                "total_pending": audit_counts["pending"] or 0,
            },
            "event_consumer": {
                "active": consumer is not None and consumer._running,
                "total_events": consumer.total_events if consumer else 0,
                "total_anomalies": consumer.total_anomalies if consumer else 0,
            } if consumer else {"active": False},
        }
    finally:
        conn.close()


@router.get("/sessions/{session_id}/audit")
async def get_session_audit(
    session_id: str,
    tenant: dict = Depends(_get_tenant),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """Get the full audit trail for a managed agent session."""
    tenant_id = tenant["tenant_id"]
    conn = _get_db()
    try:
        # Verify session belongs to tenant
        session = conn.execute(
            "SELECT id FROM managed_sessions WHERE id = ? AND tenant_id = ?",
            (session_id, tenant_id),
        ).fetchone()
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        rows = conn.execute(
            """SELECT * FROM audit_log
               WHERE managed_session_id = ? AND tenant_id = ?
               ORDER BY id ASC LIMIT ?""",
            (session_id, tenant_id, limit),
        ).fetchall()

        records = []
        for r in rows:
            records.append({
                "id": r["id"],
                "action_id": r["action_id"],
                "agent_id": r["agent_id"],
                "tool": r["tool"],
                "method": r["method"],
                "decision": r["decision"],
                "violations": json.loads(r["violations"]) if r["violations"] else [],
                "severity": r["severity"],
                "source": r["source"] if "source" in r.keys() else "direct",
                "created_at": r["created_at"],
                "execution_mode": r["execution_mode"],
            })

        return {"session_id": session_id, "records": records, "count": len(records)}
    finally:
        conn.close()


# ── Emergency Interrupt (Sprint 11.2) ──────────────────────────────────────


@router.post("/sessions/{session_id}/interrupt")
async def interrupt_session(
    session_id: str,
    req: SessionInterrupt,
    tenant: dict = Depends(_get_tenant),
):
    """
    Emergency interrupt — stop a managed agent session.

    Sends user.interrupt event to Anthropic, stops the event consumer,
    and logs the interrupt to the audit chain.
    """
    tenant_id = tenant["tenant_id"]
    conn = _get_db()

    try:
        row = conn.execute(
            "SELECT * FROM managed_sessions WHERE id = ? AND tenant_id = ?",
            (session_id, tenant_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Session not found")

        session = dict(row)
        if session["status"] != "active":
            raise HTTPException(
                status_code=409,
                detail=f"Session is not active (status: {session['status']})",
            )

        anthropic_session_id = session["anthropic_session_id"]

        # Send interrupt to Anthropic if we have a real session
        interrupt_sent = False
        if not anthropic_session_id.startswith("sim-"):
            anthropic_api_key = _get_anthropic_key(tenant_id)
            if anthropic_api_key:
                try:
                    async with httpx.AsyncClient(timeout=10.0) as client:
                        resp = await client.post(
                            f"{ANTHROPIC_API_BASE}/v1/sessions/{anthropic_session_id}/events",
                            headers={
                                "Authorization": f"Bearer {anthropic_api_key}",
                                "anthropic-version": ANTHROPIC_API_VERSION,
                                "Content-Type": "application/json",
                            },
                            json={
                                "type": "user.interrupt",
                                "data": {"reason": req.reason},
                            },
                        )
                        interrupt_sent = resp.status_code in (200, 201, 202)
                except Exception as e:
                    print(f"[CONTROL-PLANE] Interrupt send failed: {e}", flush=True)

        # Stop event consumer
        import event_consumer
        await event_consumer.stop_consumer(session_id)

        # Update session status
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE managed_sessions SET status = 'interrupted', ended_at = ? WHERE id = ?",
            (now, session_id),
        )
        conn.commit()

        # Log interrupt to audit chain
        import main as gateway_main
        audit_conn = gateway_main.get_db()
        try:
            gateway_main.write_audit_record(
                conn=audit_conn,
                action_id=str(uuid.uuid4()),
                agent_id=session["agent_id"],
                tool="control_plane",
                method="interrupt_session",
                params={
                    "session_id": session_id,
                    "reason": req.reason,
                    "auto_triggered": req.auto_triggered,
                },
                requested_at=now,
                decision="allow",
                violations=["session_interrupted"],
                severity="high" if req.auto_triggered else "medium",
                alert_tier="P1" if req.auto_triggered else "P2",
                bundle_revision=gateway_main.DEFAULT_BUNDLE_REVISION,
                tenant_id=tenant_id,
                source="control_plane",
                managed_session_id=session_id,
            )
        finally:
            audit_conn.close()

        # Fire webhook
        try:
            import webhooks as webhooks_module
            await webhooks_module.dispatch_webhook(
                tenant, "session.interrupted",
                {
                    "session_id": session_id,
                    "reason": req.reason,
                    "auto_triggered": req.auto_triggered,
                    "anthropic_interrupt_sent": interrupt_sent,
                },
            )
        except Exception:
            pass

        print(
            f"[CONTROL-PLANE] Session interrupted: {session_id} "
            f"reason={req.reason} auto={req.auto_triggered}",
            flush=True,
        )

        return {
            "session_id": session_id,
            "status": "interrupted",
            "reason": req.reason,
            "anthropic_interrupt_sent": interrupt_sent,
            "ended_at": now,
        }
    finally:
        conn.close()


# ── Auto-Interrupt on Anomaly Threshold (Sprint 11.2) ──────────────────────


async def check_auto_interrupt(
    session_id: str,
    tenant_id: str,
    agent_id: str,
    anomaly_score: float,
    threshold: float = 0.8,
):
    """
    Check if anomaly score exceeds threshold and auto-interrupt if so.

    Called by the event consumer's anomaly detection callback.
    """
    if anomaly_score < threshold:
        return

    import main as gateway_main

    # Look up tenant
    conn = gateway_main.get_db()
    try:
        tenant_row = conn.execute(
            "SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
        if not tenant_row:
            return
        tenant = dict(tenant_row)
    finally:
        conn.close()

    print(
        f"[AUTO-INTERRUPT] Anomaly threshold exceeded for session {session_id}: "
        f"score={anomaly_score:.4f} threshold={threshold}",
        flush=True,
    )

    # Trigger interrupt
    try:
        req = SessionInterrupt(
            reason=f"Automatic interrupt: anomaly score {anomaly_score:.4f} exceeded threshold {threshold}",
            auto_triggered=True,
        )
        await interrupt_session(session_id, req, tenant)
    except HTTPException:
        pass  # Session might already be interrupted
    except Exception as e:
        print(f"[AUTO-INTERRUPT] Failed: {e}", flush=True)


# ── Consumer Status Endpoint ───────────────────────────────────────────────


@router.get("/consumers")
async def list_consumers(
    tenant: dict = Depends(_get_tenant),
):
    """List all active event consumers (admin view)."""
    import event_consumer
    consumers = event_consumer.list_active_consumers()
    # Filter to tenant's consumers
    tenant_consumers = [c for c in consumers if c["tenant_id"] == tenant["tenant_id"]]
    return {"consumers": tenant_consumers, "count": len(tenant_consumers)}
