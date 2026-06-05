# Vargate Developer Docs

Vargate builds independent, cryptographically verifiable governance for AI. We run two products under one thesis: **the customer should own the record.**

- **Tyr** governs autonomous agents *inline*. It sits between your agent and the tools it calls, evaluates every tool call against policy, and blocks, allows, or escalates before the action happens.
- **Ogma** audits human and API AI usage *independently*, across vendors — Claude and OpenAI today. It pulls from each vendor's management APIs with an admin key — no agents, no proxies — and hash-chains every event into a tamper-evident record that lives outside the vendor's perimeter.

Both products write a hash-chained, blockchain-anchored audit trail. Tyr prevents bad actions; Ogma proves what happened.

---

## Choose your product

<div class="grid cards" markdown>

-   :material-shield-lock:{ .lg .middle } **Tyr — govern agents inline**

    ---

    A supervision proxy for autonomous agents. Policy enforcement, human-in-the-loop approval, and a verifiable audit trail for every tool call.

    [:octicons-arrow-right-24: Tyr quick start](quickstart.md)

-   :material-clipboard-search:{ .lg .middle } **Ogma — audit usage across vendors**

    ---

    The independent audit layer for human + API AI usage. Connect Claude and OpenAI with an admin key; every event is chained and anchored.

    [:octicons-arrow-right-24: Ogma overview](ogma/index.md)

</div>

---

## Tyr quick links

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } **Get started in under 10 minutes**

    ---

    Sign up, get your API key, and send your first governed action.

    [:octicons-arrow-right-24: Quick Start](quickstart.md)

-   :material-api:{ .lg .middle } **API Reference**

    ---

    Full endpoint documentation with request/response schemas.

    [:octicons-arrow-right-24: API Overview](api/overview.md)

-   :material-console:{ .lg .middle } **Install the CLI**

    ---

    `pip install vargate-cli` — manage your governance proxy from the terminal.

    [:octicons-arrow-right-24: CLI Guide](cli/install.md)

-   :material-shield-check:{ .lg .middle } **Policy Templates**

    ---

    Pre-built governance policies for financial, email, CRM, data access, and general use cases.

    [:octicons-arrow-right-24: Browse Templates](policies/overview.md)

-   :material-robot:{ .lg .middle } **Managed Agents**

    ---

    Govern Anthropic managed agents with active policy enforcement, passive observability, and session lifecycle control.

    [:octicons-arrow-right-24: Managed Agents Guide](managed-agents/overview.md)

</div>

---

## How the two products differ

| | Tyr | Ogma |
|---|---|---|
| **What it governs** | Autonomous agents you run | Human + API AI usage across your org |
| **Where it sits** | Inline — between the agent and its tools | Outside the vendor — reads management APIs |
| **Posture** | Active: blocks, allows, or escalates before an action runs | Passive: observes, attributes, and flags after the fact |
| **Integration** | Your agent calls the Tyr gateway | Paste a vendor admin key; no infrastructure changes |
| **Vendors** | Any agent that routes tool calls through the proxy | Claude (Anthropic) and OpenAI today |
| **Shared foundation** | Hash-chained, blockchain-anchored audit trail | Hash-chained, blockchain-anchored audit trail |

Most regulated teams run both: Tyr keeps autonomous agents inside their lane, and Ogma builds the independent ledger of everything your people do with AI.

---

## Key capabilities (Tyr)

### Policy-Based Governance (OPA/Rego)

Every tool call is evaluated against OPA/Rego policy before execution. Two-pass evaluation: a fast path for simple decisions, and an enriched path that incorporates behavioral history and anomaly scoring.

### Hash-Chained Audit Trail

Every decision is written to a hash-chained audit log. Each record's hash includes the previous record's hash, making the trail tamper-evident. Verify integrity at any time with a single API call.

### Merkle Tree Aggregation + Blockchain Anchoring

Audit records are aggregated into hourly Merkle trees with O(log n) inclusion proofs. Tree roots are anchored to Polygon and Ethereum, creating an independently verifiable, immutable record.

### Human-in-the-Loop Approval

When policy requires human review, the action is queued — not executed. A human approves or rejects, and only then does execution proceed. Full audit trail of who approved what and when.

### Crypto-Shredding (GDPR Erasure)

PII in action parameters is automatically detected and encrypted with per-subject HSM keys. GDPR erasure destroys the key, rendering all ciphertext for that subject irrecoverable — without breaking the hash chain.

### Webhook Notifications

Get notified instantly when actions are denied, escalated, or approved. HMAC-SHA256 signed payloads with retry and exponential backoff.
