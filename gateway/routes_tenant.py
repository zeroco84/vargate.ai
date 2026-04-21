"""
Tenant routes: tenant CRUD, settings, public dashboard, transparency,
approval queue, and GTM stats.
Extracted from main.py for maintainability (Audit Item 14).
"""

import json
import secrets
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

router = APIRouter()


# ── Pydantic models ──────────────────────────────────────────────────────────


class CreateTenantRequest(BaseModel):
    tenant_id: str
    name: str
    rate_limit_rps: int = 10
    rate_limit_burst: int = 20


class TenantSettingsRequest(BaseModel):
    public_dashboard: Optional[bool] = None
    name: Optional[str] = None
    anchor_chain: Optional[str] = None  # Sprint 5: polygon, ethereum, sepolia
    policy_template: Optional[str] = None  # Sprint 7.3
    policy_config: Optional[dict] = None  # Sprint 7.3
    webhook_url: Optional[str] = None  # Sprint 7.6
    webhook_events: Optional[list] = None  # Sprint 7.6
    failure_config: Optional[dict] = None  # Sprint 8.4
    auto_approve_tools: Optional[list] = None  # Sprint 15


class ApprovalRequest(BaseModel):
    note: Optional[str] = ""


# ── Tenant management endpoints (Sprint 2) ──────────────────────────────────


@router.post("/tenants", tags=["Tenants"])
async def create_tenant(
    req: CreateTenantRequest,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Create a new tenant with API key. Requires existing tenant auth."""
    import main

    await main.get_session_tenant(authorization, x_api_key, x_vargate_public_tenant)
    api_key = f"vg-{secrets.token_hex(24)}"
    now = datetime.now(timezone.utc).isoformat()
    conn = main.get_db()
    try:
        conn.execute(
            """INSERT INTO tenants (tenant_id, api_key, name, created_at, rate_limit_rps, rate_limit_burst)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                req.tenant_id,
                api_key,
                req.name,
                now,
                req.rate_limit_rps,
                req.rate_limit_burst,
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError as e:
        raise HTTPException(409, f"Tenant already exists or API key collision: {e}")
    finally:
        conn.close()

    main._refresh_tenant_cache()
    print(f"[TENANT] Created tenant: {req.tenant_id} ({req.name})", flush=True)
    return {
        "tenant_id": req.tenant_id,
        "api_key": api_key,
        "name": req.name,
        "rate_limit_rps": req.rate_limit_rps,
        "rate_limit_burst": req.rate_limit_burst,
        "created_at": now,
    }


@router.get("/tenants", tags=["Tenants"])
async def list_tenants(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """List all tenants. Admin endpoint."""
    import main

    await main.get_session_tenant(authorization, x_api_key, x_vargate_public_tenant)
    conn = main.get_db()
    try:
        rows = conn.execute("SELECT * FROM tenants ORDER BY created_at ASC").fetchall()
    finally:
        conn.close()
    return {
        "tenants": [
            {
                "tenant_id": r["tenant_id"],
                "name": r["name"],
                "api_key_prefix": r["api_key"][:12] + "...",
                "created_at": r["created_at"],
                "rate_limit_rps": r["rate_limit_rps"],
                "rate_limit_burst": r["rate_limit_burst"],
            }
            for r in rows
        ]
    }


@router.get("/tenants/{tenant_id}", tags=["Tenants"])
async def get_tenant_info(
    tenant_id: str,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Get tenant details by ID."""
    import main

    await main.get_session_tenant(authorization, x_api_key, x_vargate_public_tenant)
    conn = main.get_db()
    try:
        row = conn.execute(
            "SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,)
        ).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(404, f"Tenant not found: {tenant_id}")
    return {
        "tenant_id": row["tenant_id"],
        "name": row["name"],
        "api_key_prefix": row["api_key"][:12] + "...",
        "created_at": row["created_at"],
        "rate_limit_rps": row["rate_limit_rps"],
        "rate_limit_burst": row["rate_limit_burst"],
    }


# ── Dashboard data endpoints (Sprint 3) ─────────────────────────────────────


@router.get("/dashboard/me", tags=["Tenants"])
async def dashboard_me(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Get dashboard data for the authenticated tenant including audit stats and chain health."""
    import main

    tenant = await main.get_session_tenant(
        authorization, x_api_key, x_vargate_public_tenant
    )
    conn = main.get_db()
    try:
        user = conn.execute(
            "SELECT email, github_login, created_at FROM users WHERE tenant_id = ?",
            (tenant["tenant_id"],),
        ).fetchone()
        tenant_row = conn.execute(
            "SELECT * FROM tenants WHERE tenant_id = ?", (tenant["tenant_id"],)
        ).fetchone()
        stats = conn.execute(
            "SELECT COUNT(*) as total, SUM(CASE WHEN decision='allow' THEN 1 ELSE 0 END) as allowed, "
            "SUM(CASE WHEN decision='deny' THEN 1 ELSE 0 END) as denied "
            "FROM audit_log WHERE tenant_id = ?",
            (tenant["tenant_id"],),
        ).fetchone()
    finally:
        conn.close()

    activated = (stats["total"] or 0) > 0

    return {
        "tenant_id": tenant["tenant_id"],
        "name": tenant["name"],
        "email": user["email"] if user else None,
        "github_login": user["github_login"] if user else None,
        "api_key_prefix": tenant_row["api_key"][:12] + "..." if tenant_row else None,
        "slug": (
            tenant_row["slug"] if tenant_row and "slug" in tenant_row.keys() else None
        ),
        "public_dashboard": (
            bool(tenant_row["public_dashboard"])
            if tenant_row and "public_dashboard" in tenant_row.keys()
            else False
        ),
        "anchor_chain": (
            tenant_row["anchor_chain"]
            if tenant_row and "anchor_chain" in tenant_row.keys()
            else "polygon"
        ),
        "auto_approve_tools": (
            json.loads(tenant_row["auto_approve_tools"])
            if tenant_row
            and "auto_approve_tools" in tenant_row.keys()
            and tenant_row["auto_approve_tools"]
            else []
        ),
        "created_at": tenant["created_at"],
        "activated": activated,
        "stats": {
            "total_actions": stats["total"] or 0,
            "allowed": stats["allowed"] or 0,
            "denied": stats["denied"] or 0,
        },
    }


@router.patch("/dashboard/settings", tags=["Tenants"])
async def update_tenant_settings(
    req: TenantSettingsRequest,
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Update tenant settings (name, slug, public dashboard, rate limits)."""
    import main

    tenant = await main.get_session_tenant(
        authorization, x_api_key, x_vargate_public_tenant
    )
    conn = main.get_db()
    try:
        if req.public_dashboard is not None:
            conn.execute(
                "UPDATE tenants SET public_dashboard = ? WHERE tenant_id = ?",
                (1 if req.public_dashboard else 0, tenant["tenant_id"]),
            )
        if req.name is not None:
            conn.execute(
                "UPDATE tenants SET name = ? WHERE tenant_id = ?",
                (req.name, tenant["tenant_id"]),
            )
        if req.anchor_chain is not None:
            valid_chains = {"polygon", "ethereum", "sepolia", "polygon_amoy"}
            if req.anchor_chain in valid_chains:
                conn.execute(
                    "UPDATE tenants SET anchor_chain = ? WHERE tenant_id = ?",
                    (req.anchor_chain, tenant["tenant_id"]),
                )
        if req.policy_template is not None:
            valid_templates = {"general", "financial", "email", "crm", "data_access"}
            if req.policy_template in valid_templates:
                conn.execute(
                    "UPDATE tenants SET policy_template = ? WHERE tenant_id = ?",
                    (req.policy_template, tenant["tenant_id"]),
                )
        if req.policy_config is not None:
            conn.execute(
                "UPDATE tenants SET policy_config = ? WHERE tenant_id = ?",
                (json.dumps(req.policy_config), tenant["tenant_id"]),
            )
        if req.webhook_url is not None:
            if req.webhook_url and not req.webhook_url.startswith("https://"):
                raise HTTPException(
                    status_code=400, detail="Webhook URL must use HTTPS"
                )
            # Generate a webhook secret on first URL set
            webhook_secret = conn.execute(
                "SELECT webhook_secret FROM tenants WHERE tenant_id = ?",
                (tenant["tenant_id"],),
            ).fetchone()
            secret_val = (
                webhook_secret["webhook_secret"]
                if webhook_secret and webhook_secret["webhook_secret"]
                else secrets.token_hex(32)
            )
            conn.execute(
                "UPDATE tenants SET webhook_url = ?, webhook_secret = ? WHERE tenant_id = ?",
                (req.webhook_url, secret_val, tenant["tenant_id"]),
            )
        if req.webhook_events is not None:
            conn.execute(
                "UPDATE tenants SET webhook_events = ? WHERE tenant_id = ?",
                (json.dumps(req.webhook_events), tenant["tenant_id"]),
            )
        if req.failure_config is not None:
            valid_modes = {"fail_closed", "fail_open", "fail_to_queue"}
            valid_deps = {"opa", "redis", "blockchain"}
            for dep, mode in req.failure_config.items():
                if dep not in valid_deps:
                    raise HTTPException(
                        400, f"Invalid dependency: {dep}. Valid: {valid_deps}"
                    )
                if mode not in valid_modes:
                    raise HTTPException(
                        400, f"Invalid mode: {mode}. Valid: {valid_modes}"
                    )
            conn.execute(
                "UPDATE tenants SET failure_config = ? WHERE tenant_id = ?",
                (json.dumps(req.failure_config), tenant["tenant_id"]),
            )
        if req.auto_approve_tools is not None:
            # Validate: must be list of strings matching "tool/method" pattern
            valid_tools = {
                "substack/create_post",
                "substack/create_note",
                "substack/delete_note",
                "twitter/create_tweet",
                "twitter/delete_tweet",
                "resend/send",
                "gmail/send_email",
                "salesforce/update_record",
                "stripe/create_charge",
                "stripe/create_transfer",
                "slack/post_message",
            }
            for item in req.auto_approve_tools:
                if not isinstance(item, str) or "/" not in item:
                    raise HTTPException(
                        400,
                        f"Invalid auto_approve entry: {item}. Must be 'tool/method'.",
                    )
                if item not in valid_tools:
                    raise HTTPException(
                        400,
                        f"Unknown tool/method: {item}. Valid: {sorted(valid_tools)}",
                    )
            conn.execute(
                "UPDATE tenants SET auto_approve_tools = ? WHERE tenant_id = ?",
                (json.dumps(req.auto_approve_tools), tenant["tenant_id"]),
            )
        conn.commit()
    finally:
        conn.close()

    main._refresh_tenant_cache()

    # Include webhook_secret in response if webhook was configured
    result = {"status": "updated", "tenant_id": tenant["tenant_id"]}
    if req.webhook_url is not None:
        # Re-read to get the secret
        conn2 = main.get_db()
        try:
            row = conn2.execute(
                "SELECT webhook_secret FROM tenants WHERE tenant_id = ?",
                (tenant["tenant_id"],),
            ).fetchone()
            if row:
                result["webhook_secret"] = row["webhook_secret"]
        finally:
            conn2.close()
    return result


@router.post("/webhooks/test", tags=["Tenants"])
async def test_webhook(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Send a test webhook to the tenant's configured URL."""
    import main
    import webhooks as webhooks_module

    tenant = await main.get_session_tenant(
        authorization, x_api_key, x_vargate_public_tenant
    )
    webhook_url = tenant.get("webhook_url")
    webhook_secret = tenant.get("webhook_secret")

    if not webhook_url or not webhook_secret:
        raise HTTPException(
            400, "No webhook URL configured. Set one via PATCH /dashboard/settings."
        )

    test_payload = {
        "action_id": "test-webhook-ping",
        "agent_id": "vargate-system",
        "tool": "webhook-test",
        "method": "PING",
        "decision": "allow",
        "message": "This is a test webhook from Vargate.",
    }

    success = await webhooks_module.send_webhook(
        url=webhook_url,
        secret=webhook_secret,
        event="test.ping",
        payload=test_payload,
        max_retries=0,
    )

    if success:
        return {"status": "delivered", "webhook_url": webhook_url}
    else:
        return JSONResponse(
            status_code=502,
            content={
                "status": "failed",
                "webhook_url": webhook_url,
                "message": "Webhook delivery failed",
            },
        )


@router.get("/dashboard/public/{slug}", tags=["Tenants"])
async def public_dashboard(slug: str):
    """Get public dashboard data for a tenant (if enabled). No auth required."""
    import main

    conn = main.get_db()
    try:
        tenant_row = conn.execute(
            "SELECT * FROM tenants WHERE slug = ?", (slug,)
        ).fetchone()
        if not tenant_row:
            raise HTTPException(404, "Dashboard not found")
        if not tenant_row["public_dashboard"]:
            raise HTTPException(403, "This dashboard is not public")

        tenant_id = tenant_row["tenant_id"]

        stats = conn.execute(
            "SELECT COUNT(*) as total, "
            "SUM(CASE WHEN decision='allow' THEN 1 ELSE 0 END) as allowed, "
            "SUM(CASE WHEN decision='deny' THEN 1 ELSE 0 END) as denied "
            "FROM audit_log WHERE tenant_id = ?",
            (tenant_id,),
        ).fetchone()

        recent = conn.execute(
            "SELECT action_id, agent_id, tool, method, decision, severity, "
            "alert_tier, created_at FROM audit_log WHERE tenant_id = ? "
            "ORDER BY id DESC LIMIT 20",
            (tenant_id,),
        ).fetchall()

        chain_result = main.verify_chain_integrity(conn, tenant_id=tenant_id)

        violation_counts = {}
        all_records = conn.execute(
            "SELECT violations FROM audit_log WHERE tenant_id = ? AND decision = 'deny'",
            (tenant_id,),
        ).fetchall()
        for r in all_records:
            for v in json.loads(r["violations"]):
                violation_counts[v] = violation_counts.get(v, 0) + 1
    finally:
        conn.close()

    return {
        "tenant_name": tenant_row["name"],
        "slug": slug,
        "stats": {
            "total_actions": stats["total"] or 0,
            "allowed": stats["allowed"] or 0,
            "denied": stats["denied"] or 0,
        },
        "chain_integrity": chain_result,
        "violation_breakdown": violation_counts,
        "recent_actions": [
            {
                "action_id": r["action_id"],
                "agent_id": r["agent_id"],
                "tool": r["tool"],
                "method": r["method"],
                "decision": r["decision"],
                "severity": r["severity"],
                "created_at": r["created_at"],
            }
            for r in recent
        ],
    }


# ── Approval Queue API ─────────────────────────────────────────────────────


@router.get("/approvals", tags=["Approval Queue"])
async def list_pending_approvals(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """List actions awaiting human approval for the authenticated tenant."""
    import approval as approval_module
    import main

    tenant = await main.get_session_tenant(
        authorization, x_api_key, x_vargate_public_tenant
    )
    conn = main.get_db()
    try:
        pending = approval_module.get_pending_actions(conn, tenant["tenant_id"])
        stats = approval_module.get_queue_stats(conn, tenant["tenant_id"])
    finally:
        conn.close()
    return {"pending": pending, "stats": stats}


@router.get("/approvals/history", tags=["Approval Queue"])
async def approval_history(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """List completed approval decisions (approved/rejected) for the tenant."""
    import approval as approval_module
    import main

    tenant = await main.get_session_tenant(
        authorization, x_api_key, x_vargate_public_tenant
    )
    conn = main.get_db()
    try:
        history = approval_module.get_approval_history(conn, tenant["tenant_id"])
    finally:
        conn.close()
    return {"history": history}


@router.post("/approve/{action_id}", tags=["Approval Queue"])
async def approve_action(
    action_id: str,
    req: ApprovalRequest = ApprovalRequest(),
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Approve a pending action. Executes via brokered execution if credentials are available."""
    import approval as approval_module
    import execution_engine
    import main

    tenant = await main.get_session_tenant(
        authorization, x_api_key, x_vargate_public_tenant
    )
    conn = main.get_db()
    try:
        user = conn.execute(
            "SELECT email FROM users WHERE tenant_id = ?", (tenant["tenant_id"],)
        ).fetchone()
        reviewer = user["email"] if user else "unknown"

        action_row = conn.execute(
            "SELECT * FROM pending_actions WHERE action_id = ? AND tenant_id = ?",
            (action_id, tenant["tenant_id"]),
        ).fetchone()

        result = approval_module.approve_action(
            conn,
            action_id,
            tenant["tenant_id"],
            reviewer_email=reviewer,
            review_note=req.note or "",
        )
    finally:
        conn.close()

    if result is None:
        raise HTTPException(404, "Action not found")
    if "error" in result:
        raise HTTPException(409, result["error"])

    # Execute the approved action via brokered execution
    execution_result = None
    execution_error = None
    if action_row:
        tool = action_row["tool"]
        method = action_row["method"]
        params = (
            json.loads(action_row["params"])
            if isinstance(action_row["params"], str)
            else action_row["params"]
        )

        try:
            # Fetch credential from HSM (same flow as main.py brokered execution)
            import httpx

            credential_value = None
            agent_id = action_row["agent_id"] if action_row else "unknown"
            async with httpx.AsyncClient(timeout=10.0) as client:
                cred_resp = await client.get(f"{main.HSM_URL}/credentials")
                if cred_resp.status_code == 200:
                    creds = cred_resp.json().get("credentials", [])
                    tool_creds = [c for c in creds if c["tool_id"] == tool]
                    # Prefer OAuth 2.0 over legacy single-secret entries when
                    # both exist for a tool (e.g. twitter/oauth2 vs
                    # twitter/api_key). Newer auth model wins.
                    cred_match = next(
                        (c for c in tool_creds if c["name"] == "oauth2"),
                        tool_creds[0] if tool_creds else None,
                    )
                    if cred_match:
                        fetch_resp = await client.post(
                            f"{main.HSM_URL}/credentials/fetch-for-execution",
                            json={
                                "tool_id": tool,
                                "name": cred_match["name"],
                                "action_id": action_id,
                                "agent_id": agent_id,
                            },
                        )
                        if fetch_resp.status_code == 200:
                            credential_value = fetch_resp.json().get("credential", "")

            exec_resp = await execution_engine.execute_tool_call(
                tool, method, params, credential=credential_value or ""
            )
            if exec_resp:
                execution_result = exec_resp
                # Check if the execution itself returned an API error
                inner = (
                    exec_resp.get("result", {}) if isinstance(exec_resp, dict) else {}
                )
                if "error" in inner:
                    execution_error = inner.get("error", "unknown_error")
                    print(
                        f"[APPROVED-EXEC] API error action_id={action_id} tool={tool}.{method}: {execution_error}",
                        flush=True,
                    )
                else:
                    print(
                        f"[APPROVED-EXEC] Executed action_id={action_id} tool={tool}.{method}",
                        flush=True,
                    )
        except Exception as e:
            execution_error = str(e)
            print(f"[APPROVED-EXEC] ERROR action_id={action_id}: {e}", flush=True)

    if execution_error:
        print(
            f"[APPROVED-EXEC] WARN action_id={action_id}: {execution_error}", flush=True
        )

    # Persist execution result back to the original audit record and pending_actions
    conn = main.get_db()
    try:
        exec_result_json = json.dumps(execution_result) if execution_result else None
        exec_ms = (
            execution_result.get("execution_ms")
            if isinstance(execution_result, dict)
            else None
        )
        exec_mode = (
            "vargate_brokered"
            if execution_result and not execution_error
            else "agent_direct"
        )
        conn.execute(
            "UPDATE audit_log SET execution_result = ?, execution_latency_ms = ?, execution_mode = ? WHERE action_id = ?",
            (exec_result_json, exec_ms, exec_mode, action_id),
        )
        conn.execute(
            "UPDATE pending_actions SET execution_result = ? WHERE action_id = ?",
            (exec_result_json, action_id),
        )
        conn.commit()
    except Exception as e:
        print(f"[APPROVED-EXEC] Failed to persist execution result: {e}", flush=True)

    # Log the approval in the audit trail
    try:
        exec_detail = {
            "target_action": action_id,
            "note": req.note,
            "executed": execution_result is not None,
        }
        if execution_error:
            exec_detail["execution_error"] = execution_error
        if execution_result:
            exec_detail["execution_result"] = execution_result
        main.write_audit_record(
            conn,
            action_id=f"approval-{action_id}",
            agent_id="human-reviewer",
            tool="approval_queue",
            method="approve",
            params=exec_detail,
            requested_at=datetime.now(timezone.utc).isoformat(),
            decision="allow",
            violations=[],
            severity="none",
            alert_tier="none",
            tenant_id=tenant["tenant_id"],
        )
    finally:
        conn.close()

    response = {"status": "approved", **result}
    if execution_result is not None:
        response["execution"] = {"status": "success", "result": execution_result}
    elif execution_error:
        response["execution"] = {"status": "error", "error": execution_error}

    return response


@router.post("/reject/{action_id}", tags=["Approval Queue"])
async def reject_action(
    action_id: str,
    req: ApprovalRequest = ApprovalRequest(),
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """Reject a pending action with an optional reason."""
    import approval as approval_module
    import main

    tenant = await main.get_session_tenant(
        authorization, x_api_key, x_vargate_public_tenant
    )
    conn = main.get_db()
    try:
        user = conn.execute(
            "SELECT email FROM users WHERE tenant_id = ?", (tenant["tenant_id"],)
        ).fetchone()
        reviewer = user["email"] if user else "unknown"

        result = approval_module.reject_action(
            conn,
            action_id,
            tenant["tenant_id"],
            reviewer_email=reviewer,
            review_note=req.note or "",
        )
    finally:
        conn.close()

    if result is None:
        raise HTTPException(404, "Action not found")
    if "error" in result:
        raise HTTPException(409, result["error"])

    # Log the rejection in the audit trail
    conn = main.get_db()
    try:
        main.write_audit_record(
            conn,
            action_id=f"rejection-{action_id}",
            agent_id="human-reviewer",
            tool="approval_queue",
            method="reject",
            params={"target_action": action_id, "note": req.note},
            requested_at=datetime.now(timezone.utc).isoformat(),
            decision="deny",
            violations=[],
            severity="none",
            alert_tier="none",
            tenant_id=tenant["tenant_id"],
        )
    finally:
        conn.close()

    return {"status": "rejected", **result}


# ── Transparency endpoints (public, no auth) ───────────────────────────────


@router.get("/transparency", tags=["Tenants"])
async def transparency_global():
    """Public transparency stats across all tenants."""
    import main
    import transparency as transparency_module

    conn = main.get_db()
    try:
        data = transparency_module.get_transparency_data(conn, tenant_id=None)
    finally:
        conn.close()
    return data


@router.get("/transparency/{tenant_id}", tags=["Tenants"])
async def transparency_tenant(tenant_id: str):
    """Public transparency stats for a specific tenant."""
    import main
    import transparency as transparency_module

    conn = main.get_db()
    try:
        tenant_row = conn.execute(
            "SELECT * FROM tenants WHERE tenant_id = ? OR slug = ?",
            (tenant_id, tenant_id),
        ).fetchone()
        if not tenant_row:
            raise HTTPException(404, "Tenant not found")
        if not tenant_row["public_dashboard"]:
            raise HTTPException(403, "Transparency data not public for this tenant")

        data = transparency_module.get_transparency_data(
            conn, tenant_id=tenant_row["tenant_id"]
        )
    finally:
        conn.close()
    return data


# ── GTM constraints endpoint ────────────────────────────────────────────────


@router.get("/gtm/stats", tags=["Tenants"])
async def gtm_stats(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None),
    x_vargate_public_tenant: Optional[str] = Header(default=None),
):
    """GTM agent constraint statistics (blocked domains, daily cap, cooldown events)."""
    import gtm_constraints
    import main

    tenant = await main.get_session_tenant(
        authorization, x_api_key, x_vargate_public_tenant
    )
    conn = main.get_db()
    try:
        stats = gtm_constraints.get_gtm_stats(conn, tenant["tenant_id"])
    finally:
        conn.close()
    return stats
