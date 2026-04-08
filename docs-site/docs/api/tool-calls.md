# Tool Calls

`POST /mcp/tools/call` is the core proxy endpoint. Every agent tool call goes through here for governance evaluation.

---

## Request

```bash
POST /mcp/tools/call
Content-Type: application/json
X-API-Key: YOUR_API_KEY
```

### Request Body

```json
{
  "agent_id": "my-agent-v1",
  "agent_type": "autonomous",
  "agent_version": "1.0.0",
  "tool": "http",
  "method": "GET",
  "params": {"url": "https://api.example.com/data"}
}
```

| Field | Type | Required | Constraints | Description |
|-------|------|----------|-------------|-------------|
| `agent_id` | string | Yes | 1-256 chars, `^[a-zA-Z0-9._-]+$` | Unique agent identifier |
| `agent_type` | string | Yes | 1-128 chars | Agent category |
| `agent_version` | string | Yes | Semver `^\d+\.\d+\.\d+.*$` | Agent version |
| `tool` | string | Yes | 1-256 chars | Tool being called |
| `method` | string | Yes | 1-256 chars | Operation on the tool |
| `params` | object | Yes | Max 64KB | Tool call parameters |

---

## Governance Pipeline

Each request passes through these layers:

1. **Rate limiting** — per-tenant sliding window (Redis)
2. **Gateway constraints** — hard safety blocks (blocked domains, daily caps, cooldowns)
3. **OPA Policy (Pass 1)** — fast-path evaluation
4. **Behavioral enrichment** — if needed, fetch agent history from Redis
5. **OPA Policy (Pass 2)** — enriched evaluation with anomaly score
6. **Decision** — allow, deny, or escalate
7. **Brokered execution** — if credentials registered, execute on agent's behalf
8. **Audit logging** — write to hash-chained audit trail
9. **Webhook dispatch** — notify configured endpoints

---

## Responses

### Allowed (200)

```json
{
  "status": "allowed",
  "action_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

With brokered execution:

```json
{
  "status": "allowed",
  "action_id": "550e8400-...",
  "execution_mode": "vargate_brokered",
  "execution_result": {"status_code": 200, "body": "..."},
  "latency": {
    "opa_eval_ms": 12,
    "hsm_fetch_ms": 5,
    "execution_ms": 230,
    "total_ms": 247
  }
}
```

### Denied (403)

```json
{
  "detail": {
    "action_id": "550e8400-...",
    "violations": ["high_value_transaction_unapproved"],
    "severity": "high",
    "alert_tier": "escalate"
  }
}
```

### Pending Approval (202)

```json
{
  "status": "pending_approval",
  "action_id": "550e8400-...",
  "message": "Action requires human approval. It has been queued for review."
}
```

---

## Error Responses

| Code | Reason | Example |
|------|--------|---------|
| `401` | Missing or invalid API key | `{"detail": "Invalid API key"}` |
| `422` | Validation error | `{"detail": [{"loc": ["body", "agent_id"], ...}]}` |
| `429` | Rate limit exceeded | `{"error": "rate_limit_exceeded"}` |
| `502` | OPA unavailable | `{"detail": "OPA unreachable: ..."}` |

!!! note "Failure modes"
    The `502` behavior is configurable per tenant. By default, OPA failure is **fail-closed** (deny all). You can configure fail-open or fail-to-queue via `PATCH /dashboard/settings` with `failure_config`.

---

## Code Examples

=== "Python"

    ```python
    import httpx

    client = httpx.Client(
        base_url="https://vargate.ai/api",
        headers={"X-API-Key": "YOUR_API_KEY"},
        timeout=30,
    )

    response = client.post("/mcp/tools/call", json={
        "agent_id": "my-agent-v1",
        "agent_type": "assistant",
        "agent_version": "1.0.0",
        "tool": "http",
        "method": "GET",
        "params": {"url": "https://api.example.com/data"},
    })

    if response.status_code == 200:
        print("Allowed:", response.json()["action_id"])
    elif response.status_code == 403:
        print("Denied:", response.json()["detail"]["violations"])
    elif response.status_code == 202:
        print("Pending approval:", response.json()["action_id"])
    ```

=== "Node.js"

    ```javascript
    const response = await fetch("https://vargate.ai/api/mcp/tools/call", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": "YOUR_API_KEY",
      },
      body: JSON.stringify({
        agent_id: "my-agent-v1",
        agent_type: "assistant",
        agent_version: "1.0.0",
        tool: "http",
        method: "GET",
        params: { url: "https://api.example.com/data" },
      }),
    });

    if (response.status === 200) {
      const data = await response.json();
      console.log("Allowed:", data.action_id);
    } else if (response.status === 403) {
      const { detail } = await response.json();
      console.log("Denied:", detail.violations);
    }
    ```

=== "cURL"

    ```bash
    curl -X POST https://vargate.ai/api/mcp/tools/call \
      -H "Content-Type: application/json" \
      -H "X-API-Key: YOUR_API_KEY" \
      -d '{
        "agent_id": "my-agent-v1",
        "agent_type": "assistant",
        "agent_version": "1.0.0",
        "tool": "http",
        "method": "GET",
        "params": {"url": "https://api.example.com/data"}
      }'
    ```
