# Quick Start

Get your first AI agent governed in under 10 minutes.

---

## 1. Sign Up

Create a tenant account:

```bash
curl -X POST https://vargate.ai/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "you@company.com",
    "password": "secure-password",
    "tenant_name": "My Company"
  }'
```

Check your email and verify with the link provided.

!!! tip "Dashboard signup"
    You can also sign up at [vargate.ai/signup](https://vargate.ai/signup) for a guided experience.

---

## 2. Get Your API Key

After verification, your API key is returned in the response. You can also retrieve it from the dashboard at [vargate.ai/dashboard](https://vargate.ai/dashboard) under **Settings**.

!!! warning "Keep your API key secret"
    Store it in environment variables. Never commit it to source control. Rotate it regularly via `POST /api-keys/rotate`.

---

## 3. Send Your First Governed Action

Every agent tool call goes through `POST /mcp/tools/call`:

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
        "params": {"url": "https://httpbin.org/get"}
      }'
    ```

=== "Python"

    ```python
    import httpx

    client = httpx.Client(
        base_url="https://vargate.ai/api",
        headers={"X-API-Key": "YOUR_API_KEY"},
    )

    response = client.post("/mcp/tools/call", json={
        "agent_id": "my-agent-v1",
        "agent_type": "assistant",
        "agent_version": "1.0.0",
        "tool": "http",
        "method": "GET",
        "params": {"url": "https://httpbin.org/get"},
    })
    print(response.json())
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
        params: { url: "https://httpbin.org/get" },
      }),
    });
    console.log(await response.json());
    ```

=== "CLI"

    ```bash
    pip install vargate-cli
    vargate init    # enter your API URL and key
    vargate test    # sends a test action
    ```

---

## 4. Understand the Response

| Status | HTTP Code | Meaning |
|--------|-----------|---------|
| `allowed` | `200` | Action passed policy. Result returned. |
| `pending_approval` | `202` | Action queued for human review. |
| `denied` | `403` | Policy violation. Details in response body. |

**Allowed response:**
```json
{
  "status": "allowed",
  "action_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Denied response:**
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

---

## 5. Verify Your Audit Trail

Every decision is recorded. Verify the chain is intact:

=== "cURL"

    ```bash
    curl https://vargate.ai/api/audit/verify \
      -H "X-API-Key: YOUR_API_KEY"
    ```

=== "CLI"

    ```bash
    vargate verify
    ```

Response:
```json
{"valid": true, "record_count": 42}
```

---

## 6. Choose a Policy Template

Vargate includes pre-built policy templates:

```bash
curl https://vargate.ai/api/policy/templates \
  -H "X-API-Key: YOUR_API_KEY"
```

Apply a template:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"policy_template": "financial"}'
```

Available templates: `general`, `financial`, `email`, `crm`, `data_access`. See [Policy Templates](policies/overview.md) for details.

---

## Next Steps

- [Authentication](auth.md) — API keys, JWT sessions, OAuth
- [API Reference](api/overview.md) — full endpoint documentation
- [Managed Agents](managed-agents/overview.md) — govern Anthropic managed agents with full audit and compliance
- [CLI Guide](cli/install.md) — terminal-based management
- [Webhooks](api/webhooks.md) — real-time notifications
