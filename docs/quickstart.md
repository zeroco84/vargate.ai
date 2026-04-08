# Vargate Quick-Start Guide

Get your first AI agent governed in under 10 minutes.

## 1. Sign Up

Create a tenant account at [vargate.ai/signup](https://vargate.ai/signup) or via the API:

```bash
curl -X POST https://vargate.ai/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "you@company.com", "password": "secure-password", "tenant_name": "My Company"}'
```

Check your email and verify with the link provided.

## 2. Get Your API Key

Log in to the dashboard at [vargate.ai/dashboard](https://vargate.ai/dashboard) and copy your API key from the Settings page. Or retrieve it via API:

```bash
# Login
curl -X POST https://vargate.ai/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "you@company.com", "password": "secure-password"}'

# The response includes a session token — use it to access /dashboard/settings
```

## 3. Send Your First Governed Action

Every agent tool call goes through `POST /mcp/tools/call`. Here's a minimal example:

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

**Possible responses:**

| Status | Meaning |
|--------|---------|
| `200` | **Allowed** — action passed policy, result returned |
| `202` | **Pending approval** — action queued for human review |
| `403` | **Denied** — policy violation, details in response body |

## 4. Verify the Audit Trail

Every decision is recorded in a hash-chained audit log:

```bash
# View recent audit entries
curl https://vargate.ai/api/audit/log?limit=5 \
  -H "X-API-Key: YOUR_API_KEY"

# Verify chain integrity
curl https://vargate.ai/api/audit/verify \
  -H "X-API-Key: YOUR_API_KEY"
```

## 5. Integrate with Your Agent

### Python

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
    result = response.json()
    print(f"Allowed: {result['action_id']}")
elif response.status_code == 403:
    detail = response.json()["detail"]
    print(f"Denied: {detail['violations']}")
elif response.status_code == 202:
    result = response.json()
    print(f"Pending approval: {result['action_id']}")
```

### Node.js

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
  console.log(`Allowed: ${data.action_id}`);
} else if (response.status === 403) {
  const { detail } = await response.json();
  console.log(`Denied: ${detail.violations}`);
}
```

### CLI

```bash
pip install -e cli/
vargate init       # enter your API URL and key
vargate test       # send a test action
vargate status     # check gateway health
vargate audit      # view audit log
vargate verify     # verify hash chain
```

## 6. Choose a Policy Template

Vargate includes pre-built policy templates for common use cases:

```bash
# List available templates
curl https://vargate.ai/api/policy/templates \
  -H "X-API-Key: YOUR_API_KEY"
```

Available templates: `general`, `financial`, `email`, `crm`, `data_access`

Apply a template via the dashboard Settings page or API:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{"policy_template": "financial"}'
```

Each template is configurable — pass overrides in `policy_config`:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "policy_template": "financial",
    "policy_config": {
      "max_transaction_amount": 5000,
      "require_human_above": 1000
    }
  }'
```

## 7. Set Up Webhooks (Optional)

Get notified when actions are denied or require approval:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "webhook_url": "https://your-server.com/vargate-webhook",
    "webhook_events": ["action.denied", "action.pending", "chain.anchored"]
  }'
```

Webhook payloads are signed with HMAC-SHA256. The signature is in the `X-Vargate-Signature` header. Your webhook secret is returned when you first set the URL.

## Next Steps

- **API Reference**: Visit `https://vargate.ai/api/docs` for interactive OpenAPI docs
- **Policy Customization**: See `policies/templates/` for Rego policy examples
- **Blockchain Anchoring**: Audit chains are automatically anchored to Polygon
- **Dashboard**: Monitor actions, approve pending requests, and view chain health at `vargate.ai/dashboard`
