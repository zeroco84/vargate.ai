# Webhooks

Get real-time notifications when governance events occur. Webhooks are HMAC-SHA256 signed and delivered with retry and exponential backoff.

---

## Configuration

Configure your webhook URL via tenant settings:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "webhook_url": "https://your-server.com/vargate-webhook",
    "webhook_events": ["action.denied", "action.pending", "action.allowed"]
  }'
```

The response includes your webhook secret:

```json
{
  "status": "updated",
  "webhook_secret": "a1b2c3d4e5f6..."
}
```

!!! warning "HTTPS required"
    Webhook URLs must use HTTPS. HTTP URLs are rejected to prevent secrets from being sent over unencrypted connections.

---

## Event Types

| Event | Trigger |
|-------|---------|
| `action.allowed` | A tool call was allowed by policy |
| `action.denied` | A tool call was denied by policy |
| `action.pending` | A tool call was escalated to the approval queue |

---

## Payload Format

```json
{
  "event": "action.denied",
  "timestamp": "2026-04-08T10:00:00Z",
  "data": {
    "action_id": "550e8400-...",
    "agent_id": "my-agent-v1",
    "tool": "stripe",
    "method": "create_transfer",
    "decision": "deny",
    "violations": ["high_value_transaction_unapproved"],
    "severity": "high",
    "requires_human": false
  }
}
```

---

## Signature Verification

Every webhook payload is signed with HMAC-SHA256. The signature is in the `X-Vargate-Signature` header:

```
X-Vargate-Signature: sha256=a1b2c3d4e5f6...
X-Vargate-Event: action.denied
```

### Verification Example (Python)

```python
import hmac
import hashlib

def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)

# In your webhook handler:
from fastapi import Request, HTTPException

@app.post("/vargate-webhook")
async def handle_webhook(request: Request):
    body = await request.body()
    signature = request.headers.get("X-Vargate-Signature", "")

    if not verify_webhook(body, signature, WEBHOOK_SECRET):
        raise HTTPException(401, "Invalid signature")

    data = await request.json()
    event = data["event"]
    payload = data["data"]

    if event == "action.denied":
        alert_security_team(payload)
    elif event == "action.pending":
        notify_approvers(payload)
```

---

## Test Delivery

Send a test webhook to verify your endpoint:

```bash
curl -X POST https://vargate.ai/api/webhooks/test \
  -H "X-API-Key: YOUR_KEY"
```

Response:

```json
{"status": "delivered", "webhook_url": "https://your-server.com/vargate-webhook"}
```

---

## Retry Behavior

| Attempt | Delay |
|---------|-------|
| 1 | Immediate |
| 2 | 2 seconds |
| 3 | 4 seconds |
| 4 | 8 seconds (final) |

After 4 attempts, the webhook is marked as failed. Failed deliveries are logged but don't affect the governance decision.
