# Managed Agents API Reference

All managed agent endpoints are prefixed with `/managed/`. Authentication is required via `X-API-Key` header or `Authorization: Bearer <JWT>`.

---

## Agent Configurations

### Create Agent Config

Register a managed agent configuration with a governance profile.

```
POST /managed/agents
```

**Request Body:**

```json
{
  "name": "Research Assistant",
  "anthropic_model": "claude-sonnet-4-6",
  "system_prompt": "You are a research assistant...",
  "allowed_tools": ["vargate_web_search", "vargate_send_email"],
  "require_human_approval": ["vargate_send_email"],
  "max_session_hours": 4.0,
  "max_daily_sessions": 20,
  "max_delegation_depth": 1,
  "governance_profile": {"risk_level": "standard"},
  "parent_agent_id": null
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Agent name (1--256 characters) |
| `anthropic_model` | string | No | Claude model (default: `claude-sonnet-4-6`) |
| `system_prompt` | string | No | Base system prompt |
| `allowed_tools` | string[] | No | Governed tools the agent can access |
| `require_human_approval` | string[] | No | Tool patterns requiring human approval |
| `max_session_hours` | float | No | Max session duration (0.1--24.0 hours) |
| `max_daily_sessions` | int | No | Max sessions per day (1--1000) |
| `max_delegation_depth` | int | No | Sub-agent depth limit (1--5, default: 1) |
| `governance_profile` | object | No | Additional governance metadata |
| `parent_agent_id` | string | No | Parent config ID for multi-agent setups |

**Response `200`:**

```json
{
  "id": "agent-a1b2c3d4e5f6",
  "tenant_id": "tenant-xyz",
  "name": "Research Assistant",
  "anthropic_model": "claude-sonnet-4-6",
  "allowed_tools": ["vargate_web_search", "vargate_send_email"],
  "max_session_hours": 4.0,
  "max_daily_sessions": 20,
  "max_delegation_depth": 1
}
```

**Errors:**

| Code | Condition |
|------|-----------|
| `401` | Invalid or missing API key |
| `404` | `parent_agent_id` not found |

---

### List Agent Configs

```
GET /managed/agents
```

**Response `200`:**

```json
{
  "configs": [
    {
      "id": "agent-a1b2c3d4e5f6",
      "name": "Research Assistant",
      "anthropic_model": "claude-sonnet-4-6",
      "allowed_tools": ["vargate_web_search", "vargate_send_email"],
      "max_session_hours": 4.0,
      "max_daily_sessions": 20,
      "max_delegation_depth": 1,
      "parent_agent_id": null,
      "created_at": "2026-04-11T10:00:00Z"
    }
  ],
  "count": 1
}
```

---

### Get Agent Config

```
GET /managed/agents/{config_id}
```

**Response `200`:** Full agent configuration object.

**Errors:**

| Code | Condition |
|------|-----------|
| `404` | Config not found or belongs to another tenant |

---

## Sessions

### Create Session

Create a governed managed agent session. This is the primary entry point.

```
POST /managed/sessions
```

**Request Body:**

```json
{
  "agent_id": "agent-a1b2c3d4e5f6",
  "user_message": "Research AI governance trends and summarize.",
  "environment_id": null,
  "metadata": {}
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | string | Yes | Vargate agent config ID |
| `user_message` | string | No | Initial message to start the session |
| `environment_id` | string | No | Anthropic environment ID |
| `metadata` | object | No | Custom metadata attached to the session |

**What happens under the hood:**

1. Agent config validated against tenant policy
2. Session limits checked (concurrent, daily, per-agent)
3. Governance instructions injected into system prompt
4. Anthropic `POST /v1/sessions` called with Vargate as MCP server
5. Event consumer auto-attached to SSE stream
6. Session record created with `system_prompt_hash`

**Response `200`:**

```json
{
  "session_id": "vs-a1b2c3d4e5f6g7h8",
  "anthropic_session_id": "sess_01abc...",
  "tenant_id": "tenant-xyz",
  "agent_id": "agent-a1b2c3d4e5f6",
  "status": "active",
  "system_prompt_hash": "e3b0c44298fc1c149afbf4c8996fb924...",
  "governance": "active",
  "mcp_server_url": "https://vargate.ai/api/mcp/server",
  "created_at": "2026-04-11T14:30:00Z"
}
```

**Errors:**

| Code | Condition |
|------|-----------|
| `404` | Agent config not found |
| `429` | Session limit exceeded (concurrent, daily, or per-agent) |

---

### List Sessions

```
GET /managed/sessions
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status: `active`, `completed`, `interrupted`, `failed` |
| `agent_id` | string | Filter by agent config ID |

**Response `200`:**

```json
{
  "sessions": [
    {
      "id": "vs-a1b2c3d4e5f6g7h8",
      "agent_id": "agent-a1b2c3d4e5f6",
      "status": "active",
      "total_governed_calls": 5,
      "total_observed_calls": 12,
      "total_denied": 1,
      "total_pending": 0,
      "created_at": "2026-04-11T14:30:00Z"
    }
  ],
  "count": 1
}
```

---

### Get Session Status {: #session-status }

Governance summary with live audit counts.

```
GET /managed/sessions/{session_id}/status
```

**Response `200`:**

```json
{
  "session_id": "vs-a1b2c3d4e5f6g7h8",
  "anthropic_session_id": "sess_01abc...",
  "agent_id": "agent-a1b2c3d4e5f6",
  "status": "active",
  "total_governed_calls": 5,
  "total_observed_calls": 12,
  "total_denied": 1,
  "total_pending": 0,
  "system_prompt_hash": "e3b0c44298fc...",
  "created_at": "2026-04-11T14:30:00Z",
  "ended_at": null
}
```

Counts are computed live from the audit log, not cached.

---

### Get Session Audit Trail

Full audit trail for a specific session.

```
GET /managed/sessions/{session_id}/audit
```

**Query Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | int | 200 | Max records to return |

**Response `200`:**

```json
{
  "session_id": "vs-a1b2c3d4e5f6g7h8",
  "records": [
    {
      "action_id": "550e8400-e29b-41d4-a716-446655440000",
      "tool": "vargate_send_email",
      "method": "send",
      "decision": "requires_human",
      "source": "mcp_governed",
      "severity": "medium",
      "violations": ["External email requires approval"],
      "requested_at": "2026-04-11T14:35:00Z"
    },
    {
      "action_id": "660f9511-f3ac-52e5-b827-557766551111",
      "tool": "bash",
      "method": "execute",
      "decision": "observed",
      "source": "mcp_observed",
      "severity": "none",
      "violations": [],
      "requested_at": "2026-04-11T14:35:12Z"
    }
  ],
  "count": 2
}
```

The `source` field distinguishes actively governed events (`mcp_governed`) from passively observed events (`mcp_observed`) and control plane events (`control_plane`).

---

### Interrupt Session

Emergency stop. Sends a `user.interrupt` event to the Anthropic session.

```
POST /managed/sessions/{session_id}/interrupt
```

**Request Body:**

```json
{
  "reason": "Agent attempted to access production credentials",
  "auto_triggered": false
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `reason` | string | Yes | Reason for interrupt (1--1000 chars) |
| `auto_triggered` | bool | No | `true` if triggered by anomaly detection (default: `false`) |

**Response `200`:**

```json
{
  "status": "interrupted",
  "session_id": "vs-a1b2c3d4e5f6g7h8",
  "reason": "Agent attempted to access production credentials",
  "interrupted_at": "2026-04-11T15:00:00Z",
  "auto_triggered": false,
  "audit_action_id": "770a0622-g4bd-63f6-c938-668877662222"
}
```

The interrupt is logged to the audit chain. If the session is already completed or interrupted, returns `409 Conflict`.

**Errors:**

| Code | Condition |
|------|-----------|
| `404` | Session not found |
| `409` | Session already ended |

---

## Compliance & Replay

### Compliance Export {: #compliance-export }

Generate a compliance artifact for a managed session.

```
GET /managed/sessions/{session_id}/compliance
```

**Response `200`:**

```json
{
  "session": {
    "id": "vs-a1b2c3d4e5f6g7h8",
    "agent_id": "agent-a1b2c3d4e5f6",
    "status": "completed",
    "system_prompt_hash": "e3b0c44298fc...",
    "created_at": "2026-04-11T14:30:00Z",
    "ended_at": "2026-04-11T15:45:00Z",
    "duration_seconds": 4500
  },
  "governance_profile": {
    "allowed_tools": ["vargate_web_search", "vargate_send_email"],
    "require_human_approval": ["vargate_send_email"]
  },
  "summary": {
    "total_events": 17,
    "governed_calls": 5,
    "observed_calls": 12,
    "denied": 1,
    "pending": 0,
    "anomalies_detected": 0,
    "denial_rate": "5.88%",
    "approvals_used": 1
  },
  "timeline": [
    {
      "action_id": "...",
      "tool": "vargate_web_search",
      "decision": "allow",
      "source": "mcp_governed",
      "requested_at": "2026-04-11T14:31:00Z"
    }
  ],
  "agcs_controls": {
    "AG-1.1": "Policy evaluation active",
    "AG-1.2": "Hash-chained audit trail verified",
    "AG-1.3": "Action IDs assigned to all governed calls",
    "AG-1.6": "1 action routed through approval queue",
    "AG-1.9": "Credentials brokered via HSM",
    "AG-2.1": "Structured audit schema applied"
  },
  "generated_at": "2026-04-11T16:00:00Z"
}
```

The compliance artifact is designed to be handed directly to an auditor. It contains everything needed to verify that governance was applied throughout the session.

---

### Replay Session {: #replay-session }

Replay all governed events in a session against the current policy. Useful for policy drift detection and counterfactual analysis.

```
POST /managed/sessions/{session_id}/replay
```

**Response `200`:**

```json
{
  "session_id": "vs-a1b2c3d4e5f6g7h8",
  "total_replayed": 5,
  "consistent": 4,
  "changed": 1,
  "changes": [
    {
      "action_id": "550e8400-...",
      "tool": "vargate_send_email",
      "original_decision": "allow",
      "replayed_decision": "requires_human",
      "new_violations": ["External email now requires approval under current policy"]
    }
  ]
}
```

**Use case:** "If we had deployed the current policy during this session, which calls would have had different outcomes?"

---

## Event Consumers

### List Active Consumers

View active SSE event consumers attached to managed sessions.

```
GET /managed/consumers
```

**Response `200`:**

```json
{
  "consumers": [
    {
      "session_id": "vs-a1b2c3d4e5f6g7h8",
      "anthropic_session_id": "sess_01abc...",
      "tenant_id": "tenant-xyz",
      "agent_id": "agent-a1b2c3d4e5f6",
      "status": "connected",
      "events_processed": 142,
      "connected_since": "2026-04-11T14:30:00Z"
    }
  ],
  "count": 1
}
```

---

## Rate Limits

Session creation is rate-limited per tenant:

| Limit | Default | Description |
|-------|---------|-------------|
| Max concurrent sessions | 10 | Active sessions running simultaneously |
| Max daily sessions | 50 | Sessions created in a 24-hour window |
| Per-agent daily limit | Configurable | Set via `max_daily_sessions` in agent config |
| Max session duration | 8 hours | Set via `max_session_hours` in agent config |

When a limit is exceeded, the API returns `429 Too Many Requests` with a descriptive error message.

---

## Error Codes

| Code | Meaning |
|------|---------|
| `200` | Success |
| `401` | Authentication required or invalid |
| `404` | Resource not found (or belongs to another tenant) |
| `409` | Conflict (e.g., interrupting an already-ended session) |
| `429` | Rate limit or session limit exceeded |
| `500` | Internal server error |

All error responses follow the format:

```json
{
  "detail": "Descriptive error message"
}
```
