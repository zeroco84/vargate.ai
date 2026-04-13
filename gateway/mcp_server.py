"""
Vargate MCP Server — Remote MCP Server for Anthropic Managed Agents (Sprint 9.2)

Implements the MCP (Model Context Protocol) server that managed agents connect to
over HTTP+SSE transport. All tool calls are routed through Vargate's full governance
pipeline: OPA evaluation → behavioral analysis → PII detection → HSM credential
brokering → audit logging.

AGCS Controls: AG-1.1, AG-1.2, AG-1.3, AG-1.4, AG-1.9, AG-1.11
"""

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ── Configuration ──────────────────────────────────────────────────────────

MCP_PROTOCOL_VERSION = "2024-11-05"
MCP_SERVER_NAME = "vargate-governance"
MCP_SERVER_VERSION = "1.0.0"

# IP allowlist for enterprise egress IPs (comma-separated in env)
_IP_ALLOWLIST_RAW = os.getenv("MCP_IP_ALLOWLIST", "")
IP_ALLOWLIST: set[str] = (
    {ip.strip() for ip in _IP_ALLOWLIST_RAW.split(",") if ip.strip()}
    if _IP_ALLOWLIST_RAW
    else set()
)

router = APIRouter(prefix="/mcp/server", tags=["MCP Server"])


# ── Request / Response Models ──────────────────────────────────────────────


class MCPInitializeParams(BaseModel):
    protocolVersion: str
    capabilities: dict = Field(default_factory=dict)
    clientInfo: dict = Field(default_factory=dict)


class MCPInitializeRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Any = None
    method: str = "initialize"
    params: MCPInitializeParams


class MCPToolsListRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Any = None
    method: str = "tools/list"
    params: dict = Field(default_factory=dict)


class MCPToolCallParams(BaseModel):
    name: str
    arguments: dict = Field(default_factory=dict)


class MCPToolCallRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Any = None
    method: str = "tools/call"
    params: MCPToolCallParams


# ── Tool Catalog ───────────────────────────────────────────────────────────
# Full tool catalog — filtered per-agent based on governance profile in
# managed_agent_configs.allowed_tools.

TOOL_CATALOG = [
    {
        "name": "vargate_send_email",
        "description": "Send an email via Gmail. Subject to governance policy — competitor contacts and mass sends are blocked.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email address"},
                "subject": {"type": "string", "description": "Email subject line"},
                "body": {"type": "string", "description": "Email body text"},
            },
            "required": ["to", "subject", "body"],
        },
        "_vargate_tool": "gmail",
        "_vargate_method": "send_email",
    },
    {
        "name": "vargate_read_crm",
        "description": "Read a CRM record from Salesforce. Returns record data for the specified ID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "record_id": {"type": "string", "description": "Salesforce record ID"},
            },
            "required": ["record_id"],
        },
        "_vargate_tool": "salesforce",
        "_vargate_method": "read_record",
    },
    {
        "name": "vargate_update_crm",
        "description": "Update a CRM record in Salesforce. High-value changes may require human approval.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "record_id": {"type": "string", "description": "Salesforce record ID"},
                "fields": {"type": "object", "description": "Fields to update"},
                "amount": {"type": "number", "description": "Transaction amount (GBP)"},
            },
            "required": ["record_id", "fields"],
        },
        "_vargate_tool": "salesforce",
        "_vargate_method": "update_record",
    },
    {
        "name": "vargate_create_charge",
        "description": "Create a Stripe charge. High-value transactions require human approval.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "amount": {"type": "number", "description": "Charge amount (GBP)"},
                "currency": {
                    "type": "string",
                    "description": "Currency code",
                    "default": "gbp",
                },
                "description": {"type": "string", "description": "Charge description"},
            },
            "required": ["amount"],
        },
        "_vargate_tool": "stripe",
        "_vargate_method": "create_charge",
    },
    {
        "name": "vargate_create_transfer",
        "description": "Create a Stripe bank transfer. High-value transfers require human approval.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "amount": {"type": "number", "description": "Transfer amount (GBP)"},
                "destination": {"type": "string", "description": "Destination account"},
                "description": {
                    "type": "string",
                    "description": "Transfer description",
                },
            },
            "required": ["amount", "destination"],
        },
        "_vargate_tool": "stripe",
        "_vargate_method": "create_transfer",
    },
    {
        "name": "vargate_post_slack",
        "description": "Post a message to a Slack channel.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string", "description": "Slack channel name"},
                "text": {"type": "string", "description": "Message text"},
            },
            "required": ["channel", "text"],
        },
        "_vargate_tool": "slack",
        "_vargate_method": "post_message",
    },
    # ── Substack Posts ─────────────────────────────────────────────────────
    {
        "name": "vargate_substack_create_post",
        "description": "Create a draft post on Substack. Requires human approval for content review before publishing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Post title"},
                "body": {"type": "string", "description": "Post body text (paragraphs separated by double newlines)"},
                "is_newsletter": {"type": "boolean", "description": "Whether to create as newsletter (true) or thread post (false)", "default": False},
            },
            "required": ["title", "body"],
        },
        "_vargate_tool": "substack",
        "_vargate_method": "create_post",
    },
    # ── Substack Notes ─────────────────────────────────────────────────────
    {
        "name": "vargate_substack_create_note",
        "description": "Create a short-form Substack Note (similar to a tweet). Requires human approval for content review.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "body": {"type": "string", "description": "Note text content"},
                "attachment_url": {"type": "string", "description": "Optional link attachment URL"},
                "attachment_image": {"type": "string", "description": "Optional image URL to attach"},
            },
            "required": ["body"],
        },
        "_vargate_tool": "substack",
        "_vargate_method": "create_note",
    },
    {
        "name": "vargate_substack_list_notes",
        "description": "List recent Substack Notes with optional pagination. Read-only — no approval required.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "Max number of notes to return", "default": 20},
                "offset": {"type": "integer", "description": "Pagination offset", "default": 0},
            },
            "required": [],
        },
        "_vargate_tool": "substack",
        "_vargate_method": "get_notes",
    },
    {
        "name": "vargate_substack_delete_note",
        "description": "Delete a Substack Note by ID. Requires human approval — destructive action.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "note_id": {"type": "string", "description": "ID of the Note to delete"},
            },
            "required": ["note_id"],
        },
        "_vargate_tool": "substack",
        "_vargate_method": "delete_note",
    },
    # ── Twitter / X ─────────────────────────────────────────────────────
    {
        "name": "vargate_twitter_create_tweet",
        "description": "Post a tweet on Twitter/X. Requires human approval for content review. Max 280 characters.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Tweet text (max 280 characters)", "maxLength": 280},
            },
            "required": ["text"],
        },
        "_vargate_tool": "twitter",
        "_vargate_method": "create_tweet",
    },
    {
        "name": "vargate_twitter_delete_tweet",
        "description": "Delete a tweet by ID. Requires human approval — destructive action.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tweet_id": {"type": "string", "description": "ID of the tweet to delete"},
            },
            "required": ["tweet_id"],
        },
        "_vargate_tool": "twitter",
        "_vargate_method": "delete_tweet",
    },
    {
        "name": "vargate_twitter_get_tweets",
        "description": "Get recent tweets for a user. Read-only — no approval required. Note: requires Twitter Basic tier ($100/mo).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "Twitter user ID"},
                "max_results": {"type": "integer", "description": "Max tweets to return (default 10)", "default": 10},
            },
            "required": ["user_id"],
        },
        "_vargate_tool": "twitter",
        "_vargate_method": "get_user_tweets",
    },
]

# Index by MCP tool name for quick lookup
_TOOL_INDEX = {t["name"]: t for t in TOOL_CATALOG}


# ── IP Allowlist Check ─────────────────────────────────────────────────────


def _check_ip_allowlist(request: Request):
    """Check client IP against allowlist. Skip if allowlist is empty (dev mode)."""
    if not IP_ALLOWLIST:
        return  # No allowlist configured — allow all (dev/test mode)
    client_ip = request.client.host if request.client else "unknown"
    # Check X-Forwarded-For for proxy setups
    forwarded = request.headers.get("x-forwarded-for", "")
    real_ip = forwarded.split(",")[0].strip() if forwarded else client_ip
    if real_ip not in IP_ALLOWLIST:
        raise HTTPException(
            status_code=403,
            detail=f"IP {real_ip} not in MCP server allowlist",
        )


# ── Tenant Auth for MCP ───────────────────────────────────────────────────
# Re-uses the gateway's get_tenant dependency. The MCP server authenticates
# via the same API key mechanism — managed agents include the API key in their
# MCP server configuration.


def _get_db():
    """Get the shared SQLite connection. Imported lazily to avoid circular imports."""
    import main as gateway_main

    return gateway_main.get_db()


async def _get_mcp_tenant(
    request: Request,
    x_api_key: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
) -> dict:
    """Authenticate MCP client and resolve tenant. Also checks IP allowlist."""
    _check_ip_allowlist(request)

    # Import gateway's tenant resolution
    import main as gateway_main

    # Try API key first, then Bearer token
    if x_api_key:
        tenant = gateway_main.resolve_tenant(x_api_key)
        if not tenant:
            raise HTTPException(status_code=401, detail="Invalid API key")
        return tenant

    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:]
        # Try as API key format
        tenant = gateway_main.resolve_tenant(token)
        if tenant:
            return tenant
        # Try as JWT
        try:
            import auth as auth_module

            payload = auth_module.verify_session_token(token)
            tenant = gateway_main._tenant_by_id.get(payload["tenant_id"])
            if tenant:
                return tenant
        except Exception:
            pass

    raise HTTPException(status_code=401, detail="MCP server requires authentication")


# ── Agent Config Helpers ───────────────────────────────────────────────────


def _get_agent_config(
    conn: sqlite3.Connection, agent_id: str, tenant_id: str
) -> Optional[dict]:
    """Look up a managed agent config by ID and tenant."""
    row = conn.execute(
        "SELECT * FROM managed_agent_configs WHERE id = ? AND tenant_id = ?",
        (agent_id, tenant_id),
    ).fetchone()
    return dict(row) if row else None


def _filter_tools_for_agent(agent_config: Optional[dict]) -> list[dict]:
    """Filter tool catalog based on agent's allowed_tools list."""
    if not agent_config:
        return TOOL_CATALOG  # No config = all tools (backward compat)

    allowed_tools_raw = agent_config.get("allowed_tools")
    if not allowed_tools_raw:
        return TOOL_CATALOG  # No restriction

    try:
        allowed = json.loads(allowed_tools_raw)
        if not isinstance(allowed, list):
            return TOOL_CATALOG
    except (json.JSONDecodeError, TypeError):
        return TOOL_CATALOG

    return [t for t in TOOL_CATALOG if t["name"] in allowed]


# ── MCP Protocol Endpoints ─────────────────────────────────────────────────


@router.post("/initialize")
async def mcp_initialize(
    req: MCPInitializeRequest,
    request: Request,
    tenant: dict = Depends(_get_mcp_tenant),
):
    """MCP initialize handler — capability negotiation and session establishment."""
    session_id = str(uuid.uuid4())
    tenant_id = tenant["tenant_id"]

    # Validate protocol version
    client_version = req.params.protocolVersion
    client_info = req.params.clientInfo

    print(
        f"[MCP] Initialize: tenant={tenant_id} client={client_info.get('name', 'unknown')} "
        f"version={client_version} session={session_id}",
        flush=True,
    )

    return JSONResponse(
        content={
            "jsonrpc": "2.0",
            "id": req.id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {"listChanged": True},
                },
                "serverInfo": {
                    "name": MCP_SERVER_NAME,
                    "version": MCP_SERVER_VERSION,
                },
                "vargate": {
                    "session_id": session_id,
                    "tenant_id": tenant_id,
                    "governance": "active",
                    "features": [
                        "opa_policy_evaluation",
                        "behavioral_analysis",
                        "pii_detection",
                        "credential_brokering",
                        "hash_chain_audit",
                        "merkle_tree_anchoring",
                        "blockchain_anchoring",
                    ],
                },
            },
        }
    )


@router.post("/tools/list")
async def mcp_tools_list(
    req: MCPToolsListRequest,
    request: Request,
    tenant: dict = Depends(_get_mcp_tenant),
):
    """MCP tools/list handler — return tenant-scoped, governance-filtered tool catalog."""
    tenant_id = tenant["tenant_id"]

    # Check if a specific agent config is referenced via cursor or params
    agent_id = req.params.get("_vargate_agent_id") if req.params else None

    agent_config = None
    if agent_id:
        conn = _get_db()
        agent_config = _get_agent_config(conn, agent_id, tenant_id)

    tools = _filter_tools_for_agent(agent_config)

    # Strip internal fields before returning to client
    clean_tools = []
    for t in tools:
        clean_tools.append(
            {
                "name": t["name"],
                "description": t["description"],
                "inputSchema": t["inputSchema"],
            }
        )

    print(
        f"[MCP] tools/list: tenant={tenant_id} agent={agent_id or 'default'} "
        f"tools={len(clean_tools)}",
        flush=True,
    )

    return JSONResponse(
        content={
            "jsonrpc": "2.0",
            "id": req.id,
            "result": {
                "tools": clean_tools,
            },
        }
    )


@router.post("/tools/call")
async def mcp_tools_call(
    req: MCPToolCallRequest,
    request: Request,
    tenant: dict = Depends(_get_mcp_tenant),
):
    """
    MCP tools/call handler — route into existing governance pipeline.

    Flow: resolve tool → build ToolCallRequest → call existing /mcp/tools/call
    logic → set source='mcp_governed' → return MCP-formatted result with action_id.
    """
    import main as gateway_main

    tenant_id = tenant["tenant_id"]
    tool_name = req.params.name
    arguments = req.params.arguments

    # Resolve MCP tool name to Vargate tool/method
    catalog_entry = _TOOL_INDEX.get(tool_name)
    if not catalog_entry:
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req.id,
                "error": {
                    "code": -32602,
                    "message": f"Unknown tool: {tool_name}",
                },
            },
            status_code=200,
        )

    vargate_tool = catalog_entry["_vargate_tool"]
    vargate_method = catalog_entry["_vargate_method"]

    # Build a ToolCallRequest-compatible dict for the governance pipeline
    action_id = str(uuid.uuid4())
    requested_at = datetime.now(timezone.utc).isoformat()

    # Extract agent_id from arguments or use default
    agent_id = arguments.pop("_vargate_agent_id", "managed-agent")
    managed_session_id = arguments.pop("_vargate_session_id", None)

    # ── Rate limit check ───────────────────────────────────────────────
    rate_ok = await gateway_main.check_rate_limit(tenant)
    if not rate_ok:
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req.id,
                "error": {
                    "code": -32000,
                    "message": "Rate limit exceeded",
                    "data": {"vargate_action_id": action_id},
                },
            },
            status_code=200,
        )

    # ── OPA Pass 1: Fast path ──────────────────────────────────────────
    conn = _get_db()

    # Check registered credentials
    credentials_registered = []
    try:
        async with gateway_main.httpx.AsyncClient() as client:
            cred_resp = await client.get(
                f"{gateway_main.HSM_URL}/credentials",
                headers={"X-Tenant-Id": tenant_id},
                timeout=5.0,
            )
            if cred_resp.status_code == 200:
                creds = cred_resp.json()
                credentials_registered = [
                    c.get("tool_id", c.get("tool"))
                    for c in creds
                    if isinstance(c, dict)
                ]
    except Exception:
        pass

    # Build OPA input
    class _FakeReq:
        """Minimal request-like object for build_opa_input."""

        def __init__(self, agent_id, tool, method, params):
            self.agent_id = agent_id
            self.agent_type = "managed"
            self.agent_version = "1.0.0"
            self.tool = tool
            self.method = method
            self.params = params
            self.context_override = None

    fake_req = _FakeReq(agent_id, vargate_tool, vargate_method, arguments)
    opa_input = gateway_main.build_opa_input(
        fake_req,
        action_id,
        history=None,
        credentials_registered=credentials_registered,
        tenant=tenant,
    )

    opa_result = await gateway_main.query_opa(opa_input, tenant=tenant)
    allow = opa_result.get("allow", False)
    violations = opa_result.get("violations", [])
    severity = opa_result.get("severity", "none")
    alert_tier = opa_result.get("alert_tier", "P4")
    requires_human = opa_result.get("requires_human", False)
    needs_enrichment = opa_result.get("needs_enrichment", False)

    # ── OPA Pass 2: Behavioral enrichment if needed ────────────────────
    evaluation_pass = 1
    anomaly_score = 0.0

    if needs_enrichment or not allow:
        try:
            history = await gateway_main.fetch_behavioral_history(tenant_id, agent_id)
            if history:
                opa_input_p2 = gateway_main.build_opa_input(
                    fake_req,
                    action_id,
                    history=history,
                    credentials_registered=credentials_registered,
                    tenant=tenant,
                )
                opa_result_p2 = await gateway_main.query_opa(
                    opa_input_p2, tenant=tenant
                )
                allow = opa_result_p2.get("allow", allow)
                violations = opa_result_p2.get("violations", violations)
                severity = opa_result_p2.get("severity", severity)
                alert_tier = opa_result_p2.get("alert_tier", alert_tier)
                requires_human = opa_result_p2.get("requires_human", requires_human)
                evaluation_pass = 2
                anomaly_score = history.get("anomaly_score", 0.0)
                opa_input = opa_input_p2
        except Exception:
            pass

    # ── Determine decision ─────────────────────────────────────────────
    decision = "allow" if allow and not requires_human else "deny"
    if requires_human and allow:
        decision = "pending_approval"

    # ── Brokered execution if allowed ──────────────────────────────────
    execution_mode = "agent_direct"
    execution_result = None
    execution_latency_ms = None
    credential_accessed = None

    if decision == "allow":
        try:
            import execution_engine

            async with gateway_main.httpx.AsyncClient() as client:
                cred_resp = await client.get(
                    f"{gateway_main.HSM_URL}/credentials/{vargate_tool}/status",
                    headers={"X-Tenant-Id": tenant_id},
                    timeout=5.0,
                )
                if cred_resp.status_code == 200:
                    cred_value_resp = await client.get(
                        f"{gateway_main.HSM_URL}/credentials/{vargate_tool}",
                        headers={"X-Tenant-Id": tenant_id},
                        timeout=5.0,
                    )
                    cred_value = None
                    if cred_value_resp.status_code == 200:
                        cred_value = cred_value_resp.json().get("value")

                    exec_start = gateway_main.time.time()
                    exec_result = await execution_engine.execute_tool_call(
                        tool=vargate_tool,
                        method=vargate_method,
                        params=arguments,
                        credential=cred_value,
                    )
                    execution_latency_ms = int(
                        (gateway_main.time.time() - exec_start) * 1000
                    )
                    execution_mode = "vargate_brokered"
                    execution_result = exec_result
                    credential_accessed = vargate_tool
        except Exception as e:
            execution_result = {"error": str(e)}

    # ── PII detection ──────────────────────────────────────────────────
    contains_pii = 0
    pii_subject_id = None
    pii_fields = None
    try:
        detected = gateway_main.detect_pii_fields(arguments)
        if detected:
            contains_pii = 1
            pii_fields = detected
            pii_subject_id = (
                arguments.get("email")
                or arguments.get("to")
                or arguments.get("record_id")
            )
    except Exception:
        pass

    # ── Bundle revision ────────────────────────────────────────────────
    try:
        bundle_revision = await gateway_main.get_bundle_revision()
    except Exception:
        bundle_revision = gateway_main.DEFAULT_BUNDLE_REVISION

    # ── Write audit record with source='mcp_governed' ──────────────────
    gateway_main.write_audit_record(
        conn=conn,
        action_id=action_id,
        agent_id=agent_id,
        tool=vargate_tool,
        method=vargate_method,
        params=arguments,
        requested_at=requested_at,
        decision=decision,
        violations=violations,
        severity=severity,
        alert_tier=alert_tier,
        bundle_revision=bundle_revision,
        evaluation_pass=evaluation_pass,
        anomaly_score_at_eval=anomaly_score,
        opa_input=opa_input,
        contains_pii=contains_pii,
        tenant_id=tenant_id,
        pii_subject_id=pii_subject_id,
        pii_fields=pii_fields,
        execution_mode=execution_mode,
        execution_result=execution_result,
        execution_latency_ms=execution_latency_ms,
        credential_accessed=credential_accessed,
        source="mcp_governed",
        managed_session_id=managed_session_id,
    )

    # ── Update Redis behavioral history ────────────────────────────────
    try:
        await gateway_main.update_behavioral_history(
            agent_id=agent_id,
            action_id=action_id,
            decision=decision,
            amount=arguments.get("amount"),
            tenant_id=tenant_id,
        )
    except Exception:
        pass

    # ── Webhook dispatch ───────────────────────────────────────────────
    try:
        import webhooks as webhooks_module

        event_type = {
            "allow": "action.allowed",
            "deny": "action.denied",
            "pending_approval": "action.pending",
        }.get(decision, "action.denied")
        await webhooks_module.dispatch_webhook(
            tenant,
            event_type,
            {
                "action_id": action_id,
                "tool": vargate_tool,
                "method": vargate_method,
                "decision": decision,
                "source": "mcp_governed",
            },
        )
    except Exception:
        pass

    # ── Build MCP response ─────────────────────────────────────────────
    print(
        f"[MCP] tools/call: tenant={tenant_id} tool={tool_name} "
        f"decision={decision} action_id={action_id}",
        flush=True,
    )

    if decision == "allow":
        content_parts = []
        if execution_result:
            content_parts.append(
                {
                    "type": "text",
                    "text": json.dumps(execution_result),
                }
            )
        else:
            content_parts.append(
                {
                    "type": "text",
                    "text": json.dumps({"status": "allowed", "executed": True}),
                }
            )

        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req.id,
                "result": {
                    "content": content_parts,
                    "isError": False,
                    "_vargate": {
                        "action_id": action_id,
                        "decision": "allowed",
                        "source": "mcp_governed",
                        "execution_mode": execution_mode,
                    },
                },
            }
        )

    elif decision == "pending_approval":
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req.id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "status": "pending_approval",
                                    "action_id": action_id,
                                    "message": "This action requires human approval. "
                                    "Check back using the action_id.",
                                }
                            ),
                        }
                    ],
                    "isError": False,
                    "_vargate": {
                        "action_id": action_id,
                        "decision": "pending_approval",
                        "source": "mcp_governed",
                    },
                },
            }
        )

    else:  # denied
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req.id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(
                                {
                                    "status": "blocked",
                                    "violations": violations,
                                    "severity": severity,
                                }
                            ),
                        }
                    ],
                    "isError": True,
                    "_vargate": {
                        "action_id": action_id,
                        "decision": "denied",
                        "violations": violations,
                        "severity": severity,
                        "source": "mcp_governed",
                    },
                },
            }
        )


# ── Health check for MCP server ────────────────────────────────────────────


@router.get("/health")
async def mcp_health():
    """MCP server health check."""
    return {
        "status": "ok",
        "service": "vargate-mcp-server",
        "protocol_version": MCP_PROTOCOL_VERSION,
    }


# ── Unified JSON-RPC dispatcher (Streamable HTTP transport) ────────────────
# MCP Streamable HTTP sends all requests to a single POST endpoint with the
# JSON-RPC method field determining which handler to invoke.


@router.post("")
async def mcp_dispatch(
    request: Request,
    tenant: dict = Depends(_get_mcp_tenant),
):
    """
    Unified MCP endpoint — dispatches JSON-RPC requests by method field.

    The MCP Streamable HTTP transport POSTs all messages to the base server URL.
    This handler reads the `method` field and delegates to the appropriate handler.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error"},
            },
            status_code=200,
        )

    # JSON-RPC batch requests are not supported — return error for arrays
    if isinstance(body, list):
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32600,
                    "message": "Batch requests are not supported",
                },
            },
            status_code=200,
        )

    if not isinstance(body, dict):
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid request"},
            },
            status_code=200,
        )

    method = body.get("method", "")
    jsonrpc_id = body.get("id")

    print(f"[MCP] Dispatch: method={method} tenant={tenant['tenant_id']}", flush=True)

    if method == "initialize":
        req = MCPInitializeRequest(**body)
        return await mcp_initialize(req, request, tenant)

    elif method == "tools/list":
        req = MCPToolsListRequest(**body)
        return await mcp_tools_list(req, request, tenant)

    elif method == "tools/call":
        req = MCPToolCallRequest(**body)
        return await mcp_tools_call(req, request, tenant)

    elif method == "notifications/initialized":
        # Client acknowledgement after initialize — no response needed
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": jsonrpc_id,
                "result": {},
            }
        )

    elif method == "ping":
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": jsonrpc_id,
                "result": {},
            }
        )

    else:
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": jsonrpc_id,
                "error": {
                    "code": -32601,
                    "message": f"Method not found: {method}",
                },
            },
            status_code=200,
        )


# ── SSE transport endpoint (GET) ──────────────────────────────────────────

from fastapi.responses import StreamingResponse  # noqa: E402


@router.get("")
async def mcp_sse_endpoint(
    request: Request,
    tenant: dict = Depends(_get_mcp_tenant),
):
    """
    SSE transport endpoint for MCP.

    Returns a Server-Sent Events stream. The client POSTs JSON-RPC messages
    to the base URL and receives responses via this SSE connection.
    """
    import asyncio

    async def event_stream():
        # Send initial endpoint message per MCP SSE transport spec
        yield "event: endpoint\ndata: /mcp/server\n\n"

        # Keep connection alive with periodic pings
        try:
            while True:
                await asyncio.sleep(30)
                yield f"event: ping\ndata: {json.dumps({'type': 'ping'})}\n\n"
        except asyncio.CancelledError:
            return

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
