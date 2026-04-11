# Policy Templates for Managed Agents

Pre-built OPA/Rego policy patterns for governing managed agent sessions. These templates work with Vargate's two-pass policy evaluation: a fast path for simple decisions and an enriched path that incorporates behavioral history and anomaly scoring.

---

## How Policies Work with Managed Agents

When a managed agent calls a governed tool through Vargate's MCP server, the request is evaluated against your tenant's OPA/Rego policy bundle. The policy receives the full context:

```json
{
  "input": {
    "agent_id": "research-assistant-v1",
    "agent_type": "autonomous",
    "tool": "vargate_send_email",
    "method": "send",
    "params": {
      "to": "external@example.com",
      "subject": "Research findings",
      "body": "..."
    },
    "behavioral": {
      "action_count_1h": 15,
      "anomaly_score": 0.2,
      "last_action_seconds_ago": 45
    }
  }
}
```

The policy returns one of:

| Decision | Meaning |
|----------|---------|
| `allow` | Action passes policy. Execution proceeds. |
| `deny` | Policy violation. Action blocked. Agent receives denial with reason. |
| `requires_human` | Action queued for human approval. Agent notified. |

### Policy Versioning

Every audit record links to the OPA bundle revision active at the time of evaluation. This enables decision replay: you can later ask "what would this policy version have decided?" for any historical action.

---

## Template: Read-Only Research Agent

The most restrictive starting point. The agent can search and read, but cannot write, send, or modify anything.

```rego
package vargate.policy

# Read-only agent: allow search and read operations only
default decision = "deny"

decision = "allow" {
    input.tool == "vargate_web_search"
}

decision = "allow" {
    input.tool == "vargate_read_database"
    input.method == "SELECT"
}

# Deny all write operations
violations[msg] {
    input.tool == "vargate_send_email"
    msg := "Email sending not permitted for read-only agents"
}

violations[msg] {
    input.tool == "vargate_read_database"
    input.method != "SELECT"
    msg := "Only SELECT queries permitted for read-only agents"
}

violations[msg] {
    input.tool == "vargate_create_invoice"
    msg := "Invoice creation not permitted for read-only agents"
}

severity = "high" { count(violations) > 0 }
alert_tier = "P2" { count(violations) > 0 }
```

**Use case:** Research assistants, data analysts, read-only reporting agents.

---

## Template: Approval-Gated External Communication

Allow all tools, but require human approval for any action that sends data externally.

```rego
package vargate.policy

default decision = "allow"

# Require human approval for external email
decision = "requires_human" {
    input.tool == "vargate_send_email"
    not internal_recipient
}

# Internal recipients don't need approval
internal_recipient {
    endswith(input.params.to, "@yourcompany.com")
}

# Require approval for external API calls
decision = "requires_human" {
    input.tool == "vargate_http_request"
    not internal_domain
}

internal_domain {
    url := input.params.url
    contains(url, "api.yourcompany.com")
}

violations[msg] {
    input.tool == "vargate_send_email"
    not internal_recipient
    msg := sprintf("External email to %s requires approval", [input.params.to])
}

severity = "medium" {
    decision == "requires_human"
}

alert_tier = "P3" {
    decision == "requires_human"
}
```

**Use case:** Customer service agents, outreach agents that need oversight on external communication.

---

## Template: Budget-Capped Session

Deny tool calls after a spend threshold is reached. Uses behavioral history to track session spending.

```rego
package vargate.policy

default decision = "allow"

# Block if spending exceeds session budget
decision = "deny" {
    input.tool == "vargate_create_invoice"
    session_total := input.behavioral.session_total_amount
    session_total > 10000
}

decision = "deny" {
    input.tool == "vargate_create_transfer"
    session_total := input.behavioral.session_total_amount
    session_total > 10000
}

# Require approval for high-value individual transactions
decision = "requires_human" {
    input.tool == "vargate_create_transfer"
    input.params.amount > 1000
}

decision = "requires_human" {
    input.tool == "vargate_create_invoice"
    input.params.amount > 5000
}

violations[msg] {
    input.tool == "vargate_create_transfer"
    input.params.amount > 1000
    msg := sprintf("Transfer of $%d exceeds auto-approval threshold ($1000)", [input.params.amount])
}

violations[msg] {
    session_total := input.behavioral.session_total_amount
    session_total > 10000
    msg := sprintf("Session budget exceeded ($%d / $10,000 limit)", [session_total])
}

severity = "high" {
    input.behavioral.session_total_amount > 10000
}

severity = "medium" {
    input.params.amount > 1000
    not input.behavioral.session_total_amount > 10000
}

alert_tier = "P1" {
    input.behavioral.session_total_amount > 10000
}

alert_tier = "P2" {
    input.params.amount > 1000
}
```

**Use case:** Financial agents, procurement bots, expense management.

---

## Template: PII-Sensitive Session

Auto-detect PII, require approval for external sends containing personal data.

```rego
package vargate.policy

default decision = "allow"

# Require approval when PII detected in outbound communication
decision = "requires_human" {
    input.tool == "vargate_send_email"
    input.pii_detected
    not internal_recipient
}

# Block PII in database writes to non-encrypted tables
decision = "deny" {
    input.tool == "vargate_write_database"
    input.pii_detected
    not encrypted_table
}

internal_recipient {
    endswith(input.params.to, "@yourcompany.com")
}

encrypted_table {
    startswith(input.params.table, "encrypted_")
}

violations[msg] {
    input.pii_detected
    input.tool == "vargate_send_email"
    not internal_recipient
    msg := "PII detected in external email — requires human review"
}

violations[msg] {
    input.pii_detected
    input.tool == "vargate_write_database"
    not encrypted_table
    msg := "PII cannot be written to unencrypted tables"
}

severity = "high" {
    input.pii_detected
    not internal_recipient
}

alert_tier = "P2" {
    input.pii_detected
}
```

**Use case:** Healthcare agents (HIPAA), financial services (PCI DSS), GDPR-regulated environments.

---

## Template: Rate-Limited Agent

Enforce action frequency limits to prevent runaway agents.

```rego
package vargate.policy

default decision = "allow"

# Deny if agent is making too many calls per hour
decision = "deny" {
    input.behavioral.action_count_1h > 100
}

# Require approval if anomaly score is elevated
decision = "requires_human" {
    input.behavioral.anomaly_score > 0.7
}

# Cooldown: deny if last action was less than 2 seconds ago
decision = "deny" {
    input.behavioral.last_action_seconds_ago < 2
}

violations[msg] {
    input.behavioral.action_count_1h > 100
    msg := sprintf("Rate limit exceeded: %d actions in last hour (limit: 100)", [input.behavioral.action_count_1h])
}

violations[msg] {
    input.behavioral.anomaly_score > 0.7
    msg := sprintf("Elevated anomaly score: %.2f — human review required", [input.behavioral.anomaly_score])
}

violations[msg] {
    input.behavioral.last_action_seconds_ago < 2
    msg := "Action cooldown: minimum 2 seconds between tool calls"
}

severity = "high" {
    input.behavioral.anomaly_score > 0.7
}

severity = "medium" {
    input.behavioral.action_count_1h > 100
}

alert_tier = "P2" {
    input.behavioral.anomaly_score > 0.7
}

alert_tier = "P3" {
    input.behavioral.action_count_1h > 100
}
```

**Use case:** Any agent that could enter a rapid tool-calling loop, cost-sensitive deployments.

---

## Combining Templates

Rego policies compose naturally. Combine patterns by importing rules:

```rego
package vargate.policy

import data.vargate.pii
import data.vargate.budget
import data.vargate.rate_limit

# Deny takes highest priority
decision = "deny" {
    rate_limit.decision == "deny"
}

decision = "deny" {
    budget.decision == "deny"
}

# Then requires_human
decision = "requires_human" {
    pii.decision == "requires_human"
}

decision = "requires_human" {
    budget.decision == "requires_human"
}

# Default allow
default decision = "allow"
```

---

## Customizing for Your Tenant

1. Start with the closest template above
2. Modify the rules for your domain
3. Deploy via the Settings page in the Vargate dashboard, or:

```bash
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_VARGATE_API_KEY" \
  -d '{
    "policy_template": "custom",
    "custom_policy": "package vargate.policy\n\ndefault decision = \"allow\"\n..."
  }'
```

### Testing Policy Changes

Use decision replay to test how a policy change would affect historical sessions:

```bash
curl -X POST https://vargate.ai/api/managed/sessions/vs-abc123/replay \
  -H "X-API-Key: YOUR_VARGATE_API_KEY"
```

This replays every governed tool call from the session against your current policy and reports decision changes. See [Decision Replay](../api/managed-agents.md#replay-session) in the API reference.

---

## Next Steps

- [Setup Guide](setup.md) -- end-to-end walkthrough
- [API Reference](../api/managed-agents.md) -- full endpoint documentation
- [General Policy Templates](../policies/overview.md) -- non-managed-agent policy patterns
