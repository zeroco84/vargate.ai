# Managed Agents Setup Guide

This guide walks you through setting up Anthropic managed agents with Vargate governance, from storing your API key to reviewing a complete session audit trail.

---

## Step 1: Register Your Anthropic API Key

Store your Anthropic API key in Vargate's HSM vault. The key is encrypted at rest and never exposed to agents.

=== "cURL"

    ```bash
    curl -X POST https://vargate.ai/api/credentials/register \
      -H "Content-Type: application/json" \
      -H "X-API-Key: YOUR_VARGATE_API_KEY" \
      -d '{
        "tool_id": "anthropic",
        "credential_type": "api_key",
        "value": "sk-ant-..."
      }'
    ```

=== "Python"

    ```python
    import httpx

    client = httpx.Client(
        base_url="https://vargate.ai/api",
        headers={"X-API-Key": os.environ["VARGATE_API_KEY"]},
    )

    client.post("/credentials/register", json={
        "tool_id": "anthropic",
        "credential_type": "api_key",
        "value": os.environ["ANTHROPIC_API_KEY"],
    })
    ```

=== "Node.js"

    ```javascript
    const response = await fetch("https://vargate.ai/api/credentials/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.VARGATE_API_KEY,
      },
      body: JSON.stringify({
        tool_id: "anthropic",
        credential_type: "api_key",
        value: process.env.ANTHROPIC_API_KEY,
      }),
    });
    ```

!!! warning "Never hardcode API keys"
    Always use environment variables or a secrets manager. Vargate's HSM vault encrypts the key with a hardware security module -- it's the safest place for it.

---

## Step 2: Create a Managed Agent Configuration

Define the governance profile for your agent: which tools it can use, which require human approval, and session budget limits.

=== "cURL"

    ```bash
    curl -X POST https://vargate.ai/api/managed/agents \
      -H "Content-Type: application/json" \
      -H "X-API-Key: YOUR_VARGATE_API_KEY" \
      -d '{
        "name": "Research Assistant",
        "anthropic_model": "claude-sonnet-4-6",
        "system_prompt": "You are a research assistant that helps analysts find and summarize information.",
        "allowed_tools": [
          "vargate_web_search",
          "vargate_send_email",
          "vargate_read_database"
        ],
        "require_human_approval": [
          "vargate_send_email"
        ],
        "max_session_hours": 4.0,
        "max_daily_sessions": 20,
        "max_delegation_depth": 1,
        "governance_profile": {
          "risk_level": "standard",
          "pii_detection": true
        }
      }'
    ```

=== "Python"

    ```python
    agent = client.post("/managed/agents", json={
        "name": "Research Assistant",
        "anthropic_model": "claude-sonnet-4-6",
        "system_prompt": "You are a research assistant...",
        "allowed_tools": [
            "vargate_web_search",
            "vargate_send_email",
            "vargate_read_database",
        ],
        "require_human_approval": ["vargate_send_email"],
        "max_session_hours": 4.0,
        "max_daily_sessions": 20,
    }).json()

    agent_id = agent["id"]
    print(f"Agent config created: {agent_id}")
    ```

=== "Node.js"

    ```javascript
    const agent = await fetch("https://vargate.ai/api/managed/agents", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.VARGATE_API_KEY,
      },
      body: JSON.stringify({
        name: "Research Assistant",
        anthropic_model: "claude-sonnet-4-6",
        system_prompt: "You are a research assistant...",
        allowed_tools: [
          "vargate_web_search",
          "vargate_send_email",
          "vargate_read_database",
        ],
        require_human_approval: ["vargate_send_email"],
        max_session_hours: 4.0,
        max_daily_sessions: 20,
      }),
    }).then(r => r.json());

    console.log(`Agent config created: ${agent.id}`);
    ```

### Configuration Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human-readable agent name (required) |
| `anthropic_model` | string | Claude model to use (default: `claude-sonnet-4-6`) |
| `system_prompt` | string | Base system prompt for the agent |
| `allowed_tools` | string[] | List of governed tool names the agent can access |
| `require_human_approval` | string[] | Tool name patterns that require human approval before execution |
| `max_session_hours` | float | Maximum session duration in hours (0.1 -- 24.0) |
| `max_daily_sessions` | int | Maximum sessions per day for this agent config |
| `max_delegation_depth` | int | How many sub-agent levels allowed (1 -- 5) |
| `governance_profile` | object | Additional governance metadata (risk level, PII settings) |
| `parent_agent_id` | string | For multi-agent: parent config ID (null = root agent) |

---

## Step 3: Configure Vargate as MCP Server

When you create a session through Vargate's control plane (Step 4), Vargate automatically registers itself as a remote MCP server on the managed agent. The agent configuration sent to Anthropic includes:

```json
{
  "mcp_servers": [{
    "type": "url",
    "url": "https://vargate.ai/api/mcp/server",
    "name": "vargate-governance",
    "authorization_token": "YOUR_VARGATE_API_KEY"
  }]
}
```

### IP Allowlisting (Recommended)

For enterprise Anthropic accounts with dedicated egress IPs, configure IP allowlisting on your Vargate tenant. This restricts MCP server access to only Anthropic's infrastructure:

```bash
# Set via environment variable on your Vargate deployment
MCP_IP_ALLOWLIST=203.0.113.10,203.0.113.11
```

### Network Configuration

The managed agent's environment needs outbound access to Vargate's MCP endpoint. When creating the Anthropic environment, include:

```json
{
  "network_access": {
    "allowed_domains": ["vargate.ai"]
  }
}
```

!!! tip "Automatic setup"
    You don't need to configure the MCP server manually. Vargate's control plane handles this when you create a session in Step 4. The configuration above is shown for reference.

---

## Step 4: Create a Governed Session

Create a managed agent session through Vargate's control plane. Under the hood, Vargate:

1. Validates the agent config against your tenant policy
2. Checks session budget limits (concurrent, daily, per-agent)
3. Injects governance instructions into the system prompt
4. Calls Anthropic's API to create the session with Vargate as MCP server
5. Auto-attaches the event consumer to the session's SSE stream
6. Creates the session record with a `system_prompt_hash` for audit

=== "cURL"

    ```bash
    curl -X POST https://vargate.ai/api/managed/sessions \
      -H "Content-Type: application/json" \
      -H "X-API-Key: YOUR_VARGATE_API_KEY" \
      -d '{
        "agent_id": "agent-a1b2c3d4e5f6",
        "user_message": "Research the latest trends in enterprise AI governance and draft a summary report."
      }'
    ```

=== "Python"

    ```python
    session = client.post("/managed/sessions", json={
        "agent_id": agent_id,
        "user_message": "Research the latest trends in enterprise AI governance.",
    }).json()

    session_id = session["session_id"]
    print(f"Session: {session_id}")
    print(f"Prompt hash: {session['system_prompt_hash']}")
    print(f"MCP server: {session['mcp_server_url']}")
    ```

=== "Node.js"

    ```javascript
    const session = await fetch("https://vargate.ai/api/managed/sessions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-API-Key": process.env.VARGATE_API_KEY,
      },
      body: JSON.stringify({
        agent_id: agentId,
        user_message: "Research the latest trends in enterprise AI governance.",
      }),
    }).then(r => r.json());

    console.log(`Session: ${session.session_id}`);
    console.log(`Governance: ${session.governance}`);
    ```

### Response

```json
{
  "session_id": "vs-a1b2c3d4e5f6g7h8",
  "anthropic_session_id": "sess_01abc...",
  "tenant_id": "tenant-xyz",
  "agent_id": "agent-a1b2c3d4e5f6",
  "status": "active",
  "system_prompt_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb924...",
  "governance": "active",
  "mcp_server_url": "https://vargate.ai/api/mcp/server",
  "created_at": "2026-04-11T14:30:00Z"
}
```

The `system_prompt_hash` is a SHA-256 digest of the governance-injected system prompt, stored in the audit trail. This cryptographically proves what governance instructions the agent received.

---

## Step 5: Monitor the Session

As the agent works, tool calls flow through two paths:

- **Governed tools** (email, APIs) route through Vargate's MCP server -- policy evaluated, credentials brokered, audit logged with `source: 'mcp_governed'`
- **Built-in tools** (bash, files, web) execute directly -- Vargate's event consumer passively logs them with `source: 'mcp_observed'`

### Check Session Status

=== "cURL"

    ```bash
    curl https://vargate.ai/api/managed/sessions/vs-a1b2c3d4e5f6g7h8/status \
      -H "X-API-Key: YOUR_VARGATE_API_KEY"
    ```

=== "Python"

    ```python
    status = client.get(f"/managed/sessions/{session_id}/status").json()
    print(f"Status: {status['status']}")
    print(f"Governed calls: {status['total_governed_calls']}")
    print(f"Observed calls: {status['total_observed_calls']}")
    print(f"Denied: {status['total_denied']}")
    ```

### Response

```json
{
  "session_id": "vs-a1b2c3d4e5f6g7h8",
  "status": "active",
  "total_governed_calls": 5,
  "total_observed_calls": 12,
  "total_denied": 1,
  "total_pending": 0,
  "system_prompt_hash": "sha256:e3b0c44298fc...",
  "created_at": "2026-04-11T14:30:00Z"
}
```

### View Session Audit Trail

```bash
curl https://vargate.ai/api/managed/sessions/vs-a1b2c3d4e5f6g7h8/audit?limit=50 \
  -H "X-API-Key: YOUR_VARGATE_API_KEY"
```

The response contains every event in chronological order, with `source` indicating whether each action was actively governed or passively observed.

---

## Step 6: Handle Approvals

When an agent calls a tool configured with `require_human_approval`, the action is queued -- not executed. The agent receives a `pending_approval` response and can inform the user or continue with other work.

### What the Agent Sees

The MCP tool result returns:

```json
{
  "content": [{
    "type": "text",
    "text": "Action pending human approval. Action ID: 550e8400-... Your request to send an email has been queued for review."
  }]
}
```

### Approve or Reject

=== "cURL"

    ```bash
    # Approve
    curl -X POST https://vargate.ai/api/approve/550e8400-e29b-41d4-a716-446655440000 \
      -H "X-API-Key: YOUR_VARGATE_API_KEY"

    # Reject
    curl -X POST https://vargate.ai/api/reject/550e8400-e29b-41d4-a716-446655440000 \
      -H "X-API-Key: YOUR_VARGATE_API_KEY" \
      -H "Content-Type: application/json" \
      -d '{"reason": "External email not permitted for this task"}'
    ```

=== "Python"

    ```python
    # Approve
    client.post(f"/approve/{action_id}")

    # Reject
    client.post(f"/reject/{action_id}", json={
        "reason": "External email not permitted for this task",
    })
    ```

### Webhook Notifications

Configure webhooks to get notified when actions need approval:

```bash
curl -X POST https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_VARGATE_API_KEY" \
  -d '{
    "webhook_url": "https://your-app.com/webhooks/vargate",
    "webhook_secret": "whsec_..."
  }'
```

Webhook payloads are HMAC-SHA256 signed. Event types include `action.pending_approval`, `action.denied`, `anomaly.detected`, and `session.interrupted`.

---

## Step 7: Emergency Interrupt

If an agent exhibits concerning behavior, send an emergency interrupt:

=== "cURL"

    ```bash
    curl -X POST https://vargate.ai/api/managed/sessions/vs-a1b2c3d4e5f6g7h8/interrupt \
      -H "Content-Type: application/json" \
      -H "X-API-Key: YOUR_VARGATE_API_KEY" \
      -d '{
        "reason": "Agent attempted to access production database credentials"
      }'
    ```

=== "Python"

    ```python
    client.post(f"/managed/sessions/{session_id}/interrupt", json={
        "reason": "Agent attempted to access production database credentials",
    })
    ```

!!! info "Auto-interrupt"
    Vargate can automatically interrupt sessions when the anomaly score exceeds a configured threshold. This fires when the event consumer detects dangerous bash patterns, credential access attempts, or suspicious network activity.

### Defense-in-Depth Model

Vargate uses two complementary layers for safety:

1. **Prevention (governed tools):** Sensitive tool calls are held in the approval queue *before* execution. The race condition cannot occur because the action hasn't been dispatched.
2. **Interruption (built-in tools):** Anomaly detection triggers the interrupt endpoint. This stops the agent from taking *further* actions, though an in-flight operation may complete.

Both layers are logged to the audit trail.

---

## Step 8: Review Compliance Artifacts

After a session completes (or at any time during an active session), download the compliance export:

=== "cURL"

    ```bash
    curl https://vargate.ai/api/managed/sessions/vs-a1b2c3d4e5f6g7h8/compliance \
      -H "X-API-Key: YOUR_VARGATE_API_KEY"
    ```

=== "Python"

    ```python
    compliance = client.get(
        f"/managed/sessions/{session_id}/compliance"
    ).json()

    print(f"Session: {compliance['session']['id']}")
    print(f"Duration: {compliance['session']['duration_seconds']}s")
    print(f"Total events: {compliance['summary']['total_events']}")
    print(f"Denial rate: {compliance['summary']['denial_rate']}")
    ```

The compliance artifact includes:

- **Session metadata:** agent config, governance profile, system prompt hash, duration
- **Complete event timeline:** governed calls with OPA decisions + observed calls with anomaly flags
- **Summary statistics:** total calls by type, denial rate, anomaly count, approval queue usage
- **Hash chain verification:** proof that audit entries are contiguous and untampered
- **AGCS control mapping:** which controls were exercised during the session

### Policy Replay

Answer counterfactual questions like "If we had deployed Policy v3.2 during this session, which calls would have been blocked?":

```bash
curl -X POST https://vargate.ai/api/managed/sessions/vs-a1b2c3d4e5f6g7h8/replay \
  -H "X-API-Key: YOUR_VARGATE_API_KEY"
```

This replays all governed events against the current policy and reports any decision changes.

---

## Complete Python Example

```python
import os
import time
import httpx

client = httpx.Client(
    base_url="https://vargate.ai/api",
    headers={"X-API-Key": os.environ["VARGATE_API_KEY"]},
    timeout=30,
)

# 1. Create agent config
agent = client.post("/managed/agents", json={
    "name": "Research Assistant",
    "anthropic_model": "claude-sonnet-4-6",
    "allowed_tools": ["vargate_web_search", "vargate_send_email"],
    "require_human_approval": ["vargate_send_email"],
    "max_session_hours": 2.0,
    "max_daily_sessions": 10,
}).json()
print(f"Agent: {agent['id']}")

# 2. Create governed session
session = client.post("/managed/sessions", json={
    "agent_id": agent["id"],
    "user_message": "Find the top 3 AI governance frameworks and email a summary to team@company.com",
}).json()
print(f"Session: {session['session_id']}")

# 3. Poll session status
while True:
    status = client.get(f"/managed/sessions/{session['session_id']}/status").json()
    print(f"  Status: {status['status']} | Governed: {status['total_governed_calls']} | Observed: {status['total_observed_calls']}")
    if status["status"] != "active":
        break
    time.sleep(5)

# 4. Download compliance export
compliance = client.get(f"/managed/sessions/{session['session_id']}/compliance").json()
print(f"Compliance: {compliance['summary']['total_events']} events, {compliance['summary']['denial_rate']} denial rate")
```

---

## Deployment

### Docker Compose (Recommended)

Vargate ships as a Docker Compose stack. The managed agents integration requires no additional services -- the MCP server and event consumer run inside the existing gateway container.

```bash
# Clone and configure
git clone https://github.com/your-org/vargate.git
cd vargate
cp .env.example .env
# Edit .env: set ANTHROPIC_API_KEY, DATABASE_URL, etc.

# Start all services (production)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# Verify health
curl https://your-domain.com/api/health
curl https://your-domain.com/api/mcp/server/health
```

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | Yes | For creating managed agent sessions via Anthropic API |
| `VARGATE_MCP_SERVER_URL` | No | Override MCP server URL (default: `https://vargate.ai/api/mcp/server`) |
| `DEFAULT_MAX_CONCURRENT_SESSIONS` | No | Max active sessions per tenant (default: 10) |
| `SSE_TIMEOUT` | No | Event consumer idle timeout in seconds (default: 300) |

### Nginx Configuration

The production overlay exposes managed agent endpoints through nginx. Ensure your nginx config includes:

```nginx
# MCP server (Streamable HTTP transport)
location /api/mcp/ {
    proxy_pass http://gateway:8000/mcp/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 300s;  # SSE connections need longer timeout
}

# Control plane
location /api/managed/ {
    proxy_pass http://gateway:8000/managed/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

### Database Migrations

Schema migrations run automatically on gateway startup. To verify:

```bash
docker compose exec gateway python3 -c "
import sqlite3
conn = sqlite3.connect('/data/audit.db')
conn.row_factory = sqlite3.Row
rows = conn.execute('SELECT version, description FROM schema_version ORDER BY version').fetchall()
for r in rows:
    print(f'  v{r[\"version\"]}: {r[\"description\"]}')
"
```

Current schema version should be **11** (Sprint 14: managed agent tenant flags).

---

## Next Steps

- [Policy Templates](policies.md) -- pre-built OPA/Rego policies for common governance scenarios
- [API Reference](../api/managed-agents.md) -- full endpoint documentation
- [Webhooks](../api/webhooks.md) -- real-time notification setup
