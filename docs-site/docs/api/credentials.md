# Credentials Vault

The HSM-backed credentials vault enables **agent-blind execution**: agents submit tool calls, and Vargate looks up credentials from the secure vault and executes on their behalf. The agent never sees the credential value.

---

## How It Works

```
Agent → Vargate Proxy → HSM Vault (fetch credential) → Execute Tool → Return Result
```

1. You register a credential for a tool (e.g., Stripe API key)
2. Agent submits a tool call for that tool
3. If policy allows, Vargate fetches the credential from the HSM
4. Vargate executes the tool call with the credential
5. The result is returned to the agent
6. The credential value is never logged or returned

!!! tip "Security benefit"
    Compromising the agent doesn't compromise your credentials. The agent never has access to secrets.

---

## Endpoints

### Register a Credential

```
POST /credentials/register
Content-Type: application/json
```

```json
{
  "tool_id": "stripe",
  "name": "api_key",
  "value": "sk_live_abc123..."
}
```

The value is encrypted and stored in the SoftHSM2 vault. It cannot be retrieved — only used for execution.

!!! danger "Store securely"
    The credential value is write-only. You cannot read it back after registration. Keep a copy in your organization's secrets manager.

### List Credentials

```
GET /credentials
```

Returns metadata about registered credentials (never the values):

```json
{
  "credentials": [
    {"tool_id": "stripe", "name": "api_key", "registered_at": "2026-04-01T..."},
    {"tool_id": "gmail", "name": "api_key", "registered_at": "2026-04-02T..."}
  ]
}
```

### Credential Status

```
GET /credentials/{tool_id}/status
```

Check if a credential is registered for a specific tool:

```json
{
  "tool_id": "stripe",
  "registered": true,
  "name": "api_key"
}
```

### Remove a Credential

```
DELETE /credentials/{tool_id}/{name}
```

Permanently removes the credential from the vault.

### Access Log

```
GET /credentials/access-log
```

View a history of credential access events — which agents triggered credential usage and when.

---

## Execution Modes

When a tool call is allowed by policy, the response indicates how it was executed:

| Mode | Description |
|------|-------------|
| `agent_direct` | No credential registered. Agent handles execution. |
| `vargate_brokered` | Credential fetched from HSM. Vargate executed the call. |

The `execution_mode` field in the response and audit log tells you which mode was used.
