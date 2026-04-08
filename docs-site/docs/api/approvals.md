# Approval Queue

When OPA policy returns `requires_human: true`, the action is enqueued for human review instead of being executed immediately.

---

## How It Works

1. Agent submits a tool call via `POST /mcp/tools/call`
2. OPA policy evaluates and returns `requires_human: true`
3. The action is placed in the approval queue (HTTP 202 returned to caller)
4. A human reviews the action in the dashboard or via API
5. On approval, the action executes. On rejection, it's discarded.

!!! note "No execution without approval"
    Actions in the queue are **held**, not executed. The agent receives a `pending_approval` status and must poll or wait for a webhook notification.

---

## Endpoints

### List Pending Actions

```
GET /approvals
```

Returns all actions awaiting human review:

```json
{
  "pending": [
    {
      "action_id": "550e8400-...",
      "agent_id": "my-agent-v1",
      "tool": "stripe",
      "method": "create_transfer",
      "params": {"amount": 5000, "destination": "acct_xyz"},
      "queued_at": "2026-04-08T10:00:00Z",
      "opa_result": {
        "requires_human": true,
        "violations": [],
        "severity": "none"
      }
    }
  ]
}
```

### Approve an Action

```
POST /approve/{action_id}
Content-Type: application/json
```

```json
{
  "note": "Approved by finance team lead"
}
```

Response:

```json
{
  "status": "approved",
  "action_id": "550e8400-..."
}
```

### Reject an Action

```
POST /reject/{action_id}
Content-Type: application/json
```

```json
{
  "note": "Amount too high for automated processing"
}
```

Response:

```json
{
  "status": "rejected",
  "action_id": "550e8400-..."
}
```

### Approval History

```
GET /approvals/history
```

View past approval and rejection decisions with timestamps and notes.

---

## When Actions Get Escalated

Actions are escalated to human review when:

- The OPA policy explicitly sets `requires_human: true` (e.g., financial template: transactions above approval threshold)
- The action triggers a template-specific approval rule (e.g., CRM exports, bulk operations)
- The dependency failure mode is set to `fail_to_queue` and a dependency is down

See [Policy Templates](../policies/overview.md) for which actions trigger approval in each template.
