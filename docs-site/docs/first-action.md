# Your First Governed Action

This page walks through submitting a tool call to Vargate and understanding every part of the request and response.

---

## The Request

Every agent tool call goes through `POST /mcp/tools/call`:

```json
{
  "agent_id": "my-agent-v1",
  "agent_type": "autonomous",
  "agent_version": "1.0.0",
  "tool": "http",
  "method": "GET",
  "params": {
    "url": "https://api.example.com/data"
  }
}
```

### Field Reference

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `agent_id` | string | Yes | 1-256 chars | Unique identifier for the agent |
| `agent_type` | string | Yes | 1-128 chars | Category (e.g., `autonomous`, `sales`, `finance`) |
| `agent_version` | string | Yes | Semver (`X.Y.Z`) | Agent version for audit trail |
| `tool` | string | Yes | 1-256 chars | The tool being called (e.g., `http`, `gmail`, `stripe`) |
| `method` | string | Yes | 1-256 chars | The operation (e.g., `GET`, `send_email`, `create_transfer`) |
| `params` | object | Yes | Max 64KB JSON | Parameters for the tool call |

!!! note "Params size limit"
    The `params` field has a 64KB size limit to prevent abuse. If you need to send larger payloads, consider chunking or using a reference URL.

---

## The Governance Pipeline

When you submit a tool call, it passes through these layers in order:

```
Request → Gateway Constraints → OPA Policy (Pass 1) → Behavioral Enrichment → OPA Policy (Pass 2) → Decision
```

1. **Gateway constraints** — hard safety blocks (blocked domains, rate limits, cooldowns)
2. **OPA Policy (Pass 1)** — fast-path evaluation against your tenant's policy template
3. **Behavioral enrichment** — if needed, Redis history is fetched (action counts, anomaly score)
4. **OPA Policy (Pass 2)** — enriched evaluation with full behavioral context
5. **Decision** — allow, deny, or escalate to human approval

After the decision:

- The action is logged to the hash-chained audit trail
- Webhook notifications are dispatched (if configured)
- If allowed and credentials are registered, brokered execution occurs

---

## Response Statuses

### Allowed (200)

The action passed all policy checks:

```json
{
  "status": "allowed",
  "action_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

If [brokered execution](api/credentials.md) is configured for the tool:

```json
{
  "status": "allowed",
  "action_id": "550e8400-...",
  "execution_mode": "vargate_brokered",
  "execution_result": { "status_code": 200, "body": "..." },
  "latency": {
    "opa_eval_ms": 12,
    "hsm_fetch_ms": 5,
    "execution_ms": 230,
    "total_ms": 247
  }
}
```

### Denied (403)

The action violated one or more policy rules:

```json
{
  "detail": {
    "action_id": "550e8400-...",
    "violations": [
      "high_value_transaction_unapproved",
      "transaction_outside_business_hours"
    ],
    "severity": "high",
    "alert_tier": "escalate"
  }
}
```

### Pending Approval (202)

The action requires human review:

```json
{
  "status": "pending_approval",
  "action_id": "550e8400-...",
  "message": "Action requires human approval. It has been queued for review."
}
```

The action is held in the [approval queue](api/approvals.md). It will not execute until a human approves it.

---

## Severity Levels

| Level | Meaning |
|-------|---------|
| `none` | No violations |
| `low` | Minor policy concern |
| `medium` | Significant policy concern |
| `high` | Serious violation — action blocked |
| `critical` | Critical violation — action blocked, alert triggered |

---

## Error Responses

| Code | Meaning |
|------|---------|
| `401` | Missing or invalid API key |
| `422` | Validation error (missing fields, bad format) |
| `429` | Rate limit exceeded |
| `502` | OPA unavailable (fail-closed by default) |

---

## What Happens Next

After your action is processed:

1. **Audit record created** — viewable via `GET /audit/log`
2. **Hash chain extended** — verify with `GET /audit/verify`
3. **Merkle tree updated** — inclusion proof available after hourly tree build
4. **Blockchain anchored** — tree root anchored to Polygon/Ethereum on schedule
5. **Webhook dispatched** — if configured, your endpoint receives the decision
