# cURL Examples

Quick reference for interacting with Vargate from the command line.

---

## Setup

Set your API key as an environment variable:

```bash
export VARGATE_URL="https://vargate.ai/api"
export VARGATE_API_KEY="vg-abc123..."
```

---

## Submit a Governed Tool Call

```bash
curl -X POST "$VARGATE_URL/mcp/tools/call" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $VARGATE_API_KEY" \
  -d '{
    "agent_id": "my-agent-v1",
    "agent_type": "autonomous",
    "agent_version": "1.0.0",
    "tool": "http",
    "method": "GET",
    "params": {"url": "https://api.example.com/data"}
  }'
```

---

## Verify Audit Chain

```bash
curl "$VARGATE_URL/audit/verify" \
  -H "X-API-Key: $VARGATE_API_KEY"
```

---

## View Audit Log

```bash
# Last 10 records
curl "$VARGATE_URL/audit/log?limit=10" \
  -H "X-API-Key: $VARGATE_API_KEY"
```

---

## Replay a Decision

```bash
curl -X POST "$VARGATE_URL/audit/replay" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $VARGATE_API_KEY" \
  -d '{"action_id": "550e8400-e29b-41d4-a716-446655440000"}'
```

---

## Get Merkle Proof

```bash
curl "$VARGATE_URL/audit/merkle/proof/RECORD_HASH_HERE" \
  -H "X-API-Key: $VARGATE_API_KEY"
```

---

## List Policy Templates

```bash
curl "$VARGATE_URL/policy/templates" \
  -H "X-API-Key: $VARGATE_API_KEY"
```

---

## Apply a Policy Template

```bash
curl -X PATCH "$VARGATE_URL/dashboard/settings" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $VARGATE_API_KEY" \
  -d '{
    "policy_template": "financial",
    "policy_config": {
      "transaction_limit": 10000,
      "approval_threshold": 5000
    }
  }'
```

---

## Configure Webhooks

```bash
curl -X PATCH "$VARGATE_URL/dashboard/settings" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $VARGATE_API_KEY" \
  -d '{
    "webhook_url": "https://your-server.com/webhook",
    "webhook_events": ["action.denied", "action.pending"]
  }'
```

---

## Test Webhook Delivery

```bash
curl -X POST "$VARGATE_URL/webhooks/test" \
  -H "X-API-Key: $VARGATE_API_KEY"
```

---

## Check Gateway Health

```bash
curl "$VARGATE_URL/health"
```

---

## Blockchain Anchor Status

```bash
curl "$VARGATE_URL/anchor/status" \
  -H "X-API-Key: $VARGATE_API_KEY"
```

---

## Export Compliance Package

```bash
# JSON format
curl "$VARGATE_URL/compliance/export/YOUR_TENANT_ID?from=2026-01-01&to=2026-12-31&format=json" \
  -H "X-API-Key: $VARGATE_API_KEY" \
  -o compliance-report.json

# PDF format
curl "$VARGATE_URL/compliance/export/YOUR_TENANT_ID?from=2026-01-01&to=2026-12-31&format=pdf" \
  -H "X-API-Key: $VARGATE_API_KEY" \
  -o compliance-report.pdf
```

---

## GDPR Erasure

```bash
# Erase subject data
curl -X POST "$VARGATE_URL/audit/erase/user-123" \
  -H "X-API-Key: $VARGATE_API_KEY"

# Verify erasure
curl "$VARGATE_URL/audit/erase/user-123/verify" \
  -H "X-API-Key: $VARGATE_API_KEY"
```

---

## Rotate API Key

```bash
curl -X POST "$VARGATE_URL/api-keys/rotate" \
  -H "X-API-Key: $VARGATE_API_KEY"
# Save the new key from the response!
```

---

## Managed Agent Sessions

### Create Agent Config

```bash
curl -X POST "$VARGATE_URL/managed/agents" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $VARGATE_API_KEY" \
  -d '{
    "name": "Research Assistant",
    "anthropic_model": "claude-sonnet-4-6",
    "allowed_tools": ["vargate_web_search", "vargate_send_email"],
    "require_human_approval": ["vargate_send_email"],
    "max_session_hours": 2.0,
    "max_daily_sessions": 10
  }'
```

### Create Governed Session

```bash
curl -X POST "$VARGATE_URL/managed/sessions" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $VARGATE_API_KEY" \
  -d '{
    "agent_id": "agent-a1b2c3d4e5f6",
    "user_message": "Research AI governance trends."
  }'
```

### Check Session Status

```bash
curl "$VARGATE_URL/managed/sessions/vs-a1b2c3d4e5f6g7h8/status" \
  -H "X-API-Key: $VARGATE_API_KEY"
```

### View Session Audit Trail

```bash
curl "$VARGATE_URL/managed/sessions/vs-a1b2c3d4e5f6g7h8/audit?limit=50" \
  -H "X-API-Key: $VARGATE_API_KEY"
```

### Emergency Interrupt

```bash
curl -X POST "$VARGATE_URL/managed/sessions/vs-a1b2c3d4e5f6g7h8/interrupt" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $VARGATE_API_KEY" \
  -d '{"reason": "Agent accessed production credentials"}'
```

### Download Compliance Export

```bash
curl "$VARGATE_URL/managed/sessions/vs-a1b2c3d4e5f6g7h8/compliance" \
  -H "X-API-Key: $VARGATE_API_KEY" \
  -o session-compliance.json
```

### Replay Session Decisions

```bash
curl -X POST "$VARGATE_URL/managed/sessions/vs-a1b2c3d4e5f6g7h8/replay" \
  -H "X-API-Key: $VARGATE_API_KEY"
```

See the full [Managed Agents Setup Guide](../managed-agents/setup.md) for detailed walkthrough.
