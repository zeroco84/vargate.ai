# Vargate Developer Docs

Vargate is an AI agent supervision proxy. It intercepts autonomous agent tool calls, evaluates them against policy, logs every decision to a tamper-evident audit trail, and produces legally defensible compliance artifacts.

If you're building or deploying AI agents and need governance, audit, and compliance out of the box, Vargate sits between your agent and the tools it calls. Every action is evaluated, logged, and verifiable.

---

## Quick Links

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

## Key Capabilities

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
