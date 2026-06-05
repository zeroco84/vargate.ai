# Ogma Overview

Ogma is the independent audit layer for **human and API AI usage**, across vendors — **Claude (Anthropic) and OpenAI today.**

It connects to each vendor's management APIs with a read-only admin key, pulls usage, cost, and administrative events, and writes every one into a hash-chained, blockchain-anchored record. No agents, no proxies, no sidecars, and no changes to how your teams use AI. You paste a key; Ogma builds the ledger.

!!! note "Ogma and Tyr are different products"
    **[Tyr](../quickstart.md)** governs autonomous agents *inline* — it sits between an agent and its tools and blocks, allows, or escalates each tool call before it runs. **Ogma** audits AI usage *from outside the vendor's perimeter* — it observes and attributes what already happened. Many teams run both. This section of the docs covers Ogma.

---

## The independence thesis

An audit trail held by the vendor it audits is not an audit trail — it's a vendor report. If your only record of how your organization uses Claude or OpenAI lives in that vendor's console, then retention, format, and integrity are all controlled by the party being audited.

Ogma's record lives somewhere the vendor cannot amend it:

- **Hash-chained.** Every event extends a per-tenant chain. Each record's hash includes the previous record's hash, so altering or removing any event breaks the chain from that point forward.
- **Blockchain-anchored.** Chain roots are anchored to a public ledger on a recurring schedule. Neither the AI vendor, nor Vargate, nor you can backdate or silently rewrite history.
- **Outside the vendor.** Ogma reads what the vendor exposes through its management APIs, then keeps the verifiable copy independently. Self-hostable for enterprise.

The result is a record an auditor can verify on its own terms, rather than one they have to take on trust.

---

## What Ogma captures

Ogma reads from vendor management APIs only. It sees usage aggregates, cost, administrative events, and — for Claude on Enterprise — conversation content. It does **not** sit in the request path, so it never sees live prompts or responses as they happen.

| Vendor | What's captured | Per-user attribution | Content |
|---|---|---|---|
| **Claude (Anthropic)** | Daily token usage, org members, workspaces, API keys; admin events (sign-ins, key changes); per-developer Claude Code sessions; opt-in per-turn summaries via the MCP connector | Yes — via the MCP connector and the Admin API | Chat + message text, **Enterprise only**, via a Compliance Access Key |
| **OpenAI** | Per-(day, model, user, project, key) token usage; authoritative billed spend at line-item grain; admin events | Yes — `group_by=user_id`, populated on Pay-as-you-go (not Enterprise-gated) | **None** — cost + admin events only; no ChatGPT chat content |

Activity from both vendors is stitched into a single person by email, so one user row spans their Claude and OpenAI usage.

!!! warning "Be clear about what each surface does and doesn't capture"
    - **OpenAI is cost + admin events only.** There is no ChatGPT chat-content stream and no per-turn capture equivalent to the Claude MCP connector.
    - **Claude content capture is Enterprise-only** and requires a separate [Compliance Access Key](compliance-key.md). Console, Pro, and Team organizations can use the Admin API and Activity Feed but cannot reach content endpoints.
    - **The MCP connector is opt-in and partial.** It captures only what Claude chooses to summarize when it calls Ogma's logging tool inside a shared Project — enough for compliance metadata and analytics, not a forensic transcript. See [Connect Claude (MCP)](connect-mcp.md).
    - **Some Anthropic depth is plan-gated.** The Activity Feed and per-developer Claude Code sessions require Enterprise or the right entitlement. Where a number isn't available, Ogma shows it as unavailable rather than inventing one.

---

## How Ogma differs from Tyr

| | Tyr | Ogma |
|---|---|---|
| **Subject** | Autonomous agents you operate | Human + API AI usage across your org |
| **Position** | Inline, in the tool-call path | Outside the vendor, reading management APIs |
| **Action** | Blocks, allows, or escalates *before* an action runs | Observes, attributes, and flags *after* the fact |
| **Setup** | Route your agent's tool calls through the gateway | Paste a vendor admin key — no infrastructure changes |
| **Vendors** | Any agent that calls the proxy | Claude and OpenAI today |

Both write the same tamper-evident, blockchain-anchored audit trail. The split is simple: Tyr prevents, Ogma proves.

---

## Getting started

Connect one vendor or both. Each connector is independent — set up what you need, add the rest later.

<div class="grid cards" markdown>

-   :material-key-chain:{ .lg .middle } **Connect Anthropic (Admin key)**

    ---

    Paste an Anthropic Admin API key (`sk-ant-admin01-…`) to ingest Claude usage, members, workspaces, and admin events.

    [:octicons-arrow-right-24: Connect Anthropic](connect-anthropic.md)

-   :material-key-variant:{ .lg .middle } **Connect OpenAI (Admin key)**

    ---

    Paste an OpenAI Admin key (`sk-admin-…`) to ingest usage, authoritative cost, and admin events — with per-user attribution on every paid tier.

    [:octicons-arrow-right-24: Connect OpenAI](connect-openai.md)

-   :material-connection:{ .lg .middle } **Connect Claude (MCP)**

    ---

    Add the Ogma MCP connector to a shared Claude Project to capture opt-in per-turn interaction summaries on any plan tier.

    [:octicons-arrow-right-24: Connect Claude (MCP)](connect-mcp.md)

-   :material-file-lock:{ .lg .middle } **Compliance Access Key**

    ---

    Enterprise only. Add a Compliance Access Key (`sk-ant-api01-…`) to capture Claude chat and message content for compliance review.

    [:octicons-arrow-right-24: Compliance Access Key](compliance-key.md)

-   :material-view-dashboard:{ .lg .middle } **Surfaces**

    ---

    Tour the dashboard: API Usage, Users, Sessions, Content, Budgets and alerts, and Insights.

    [:octicons-arrow-right-24: Explore the surfaces](surfaces.md)

</div>

---

## From admin key to audit-ready

1. **Connect.** Paste an Anthropic or OpenAI admin key — either or both. A read-only key is sufficient and recommended; Ogma only ever issues `GET` requests.
2. **Ingest.** Ogma validates the key against each endpoint, shows you a capability checklist, then enqueues a backfill and polls for new events on a schedule. A scope-limited key simply skips the streams it can't read.
3. **Audit.** Every event is hash-chained as it's ingested, and chain roots are anchored to a public ledger — tamper-evident end to end.
4. **Alert.** Budget thresholds and anomaly signals fire to email, Slack, or PagerDuty before they reach an audit committee. See [Budgets and alerts](surfaces.md).

!!! tip "Connecting both vendors"
    Ogma is built vendor-independent. Connecting both Claude and OpenAI gives you cross-vendor cost, model-mix, and per-user views in one place — and one audit trail that spans every vendor your organization uses.
