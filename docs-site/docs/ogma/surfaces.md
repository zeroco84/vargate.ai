# Surfaces

A tour of the Ogma dashboard. Each surface reads from the same hash-chained, blockchain-anchored record — the difference is the lens it puts on your AI usage.

Ogma audits AI usage from **outside the vendor's perimeter**. It pulls from each vendor's management APIs with an admin key — no agents, no proxies, no sidecars — across **Claude (Anthropic) and OpenAI** today. (If you need to *govern* autonomous agents inline rather than audit usage after the fact, that's the separate Tyr product — see the [Tyr quick start](../quickstart.md).)

!!! note "What you see depends on what you've connected"
    Most surfaces light up as soon as you connect an admin key. A few are plan- or capability-gated (Code Analytics on Sessions, content on the Content surface). Each section below is explicit about what it captures — and what it doesn't.

New here? Connect a vendor first: [Connect Anthropic](connect-anthropic.md), [Connect OpenAI](connect-openai.md), [Connect Claude (MCP)](connect-mcp.md).

---

## API Usage

The cross-vendor view of **API key consumption** — tokens and estimated cost, built on each vendor's daily usage report.

- **Vendor filter:** **All**, **Anthropic**, or **OpenAI**. *All* gives you one cost view across both vendors; switch to a single vendor to drill in.
- **Per model and per project/workspace.** Rows break down by model and by the project (OpenAI) or workspace (Anthropic) the spend landed in.
- **Cost estimate.** Spend is computed against each vendor's published rates, using the rate that was in effect when the usage happened. Cached input is priced at the reduced cache-read rate. Where a model can't be priced (legacy aggregate rows with no model), the cost column shows `—` rather than a guessed number.
- **Cache efficiency panel.** Above the table, a per-model verdict on prompt caching: an overall cache hit rate plus the models where caching is being paid for but under-reused, each with a plain-English recommendation (for example, *"Low reuse — stabilize the cached prefix or raise the cache TTL"*). When every model looks healthy it collapses to a one-line note.

!!! warning "API Usage is API consumption only"
    This surface is built entirely on the vendors' usage reports — it's **API key spend**. It does **not** include Claude Code sessions or human chat usage. For those, see [Sessions](#sessions) and [Users](#users).

OpenAI note: OpenAI exposes an authoritative billed-cost report (used for project totals) in addition to token usage (used for per-user attribution), so OpenAI project spend reflects actual billed amounts, including non-token line items like fine-tune training.

---

## Sessions

Per-developer, per-day activity — *who did work with AI, and on which day*.

A session is one **(day, developer)** roll-up. It's assembled from:

- **Claude Code** activity (Code Analytics), and
- **Claude (chat)** activity captured through the [MCP connector](connect-mcp.md).

A single session can draw from more than one source, so each row carries a badge per contributing source (for example, *"12 events — 8 chat, 3 API key, 1 admin event"*) rather than collapsing everything under one label. Open a session to see its events broken down by source on a timeline.

!!! note "Plan gating"
    Claude Code (Code Analytics) sessions require an Enterprise plan with the Code Analytics entitlement. MCP chat activity is available on every tier (it's opt-in — see [Connect Claude (MCP)](connect-mcp.md)). If you have neither yet, the page points you to the surfaces you *do* have data for (such as [API Usage](#api-usage)).

---

## Users

One person, every surface, **both vendors** — in a single row.

A single human typically shows up as several disconnected identities across a vendor's own console: an API caller, a Claude Code user, a Claude Desktop user, an OpenAI user. Ogma stitches them into one person by **email**, so a user's row spans Claude *and* OpenAI activity together.

Each user surfaces:

- **Spend across vendors** — their share of API cost, Claude and OpenAI combined.
- **An activity heatmap** — a GitHub-style grid of activity density per day, tone-shifted by source, with a per-day breakdown on hover.
- **Top topics** — for Claude chat activity captured via MCP, a breakdown of what kinds of work a person spends their Claude time on. Topics are inferred from Claude's own short, self-reported interaction summaries (never raw transcripts) and constrained to a fixed category set; the panel shows how many interactions were classified so partial coverage is always honest.

### Unmapped activity

When an incoming record's identity can't be auto-matched to a known user by email, it lands in an **Unmapped activity** panel for an admin to link by hand. Once you link an identity manually, that link is protected from being overwritten by later automatic matching.

!!! note "Cross-vendor attribution depth differs by vendor"
    OpenAI per-user attribution works on every paid tier (Pay-as-you-go included). On Anthropic, per-user depth (the Activity Feed) is Enterprise-only. Where a vendor doesn't expose user-level identity, activity attributes to the API-key holder or lands in Unmapped activity.

---

## Insights

A page of analysis cards built on top of your usage data — the layer that turns raw events into something to act on. Cards appear in a fixed order; a card with nothing to flag still shows present-tense copy describing what it watches for, so the page never empties out.

Current cards include:

- **Cost forecasting** — projects month-end spend from your recent trend, per vendor, and flags when you're on pace to cross a budget cap (for example, *"on pace to exceed the cap by the 24th"*). The projection is a deliberately simple trend line; the value is the early warning, not decimal precision, and the card says so.
- **Model mix** — how your spend is distributed across models, including **cross-vendor shift** (e.g. spend moving between Claude and OpenAI over time).
- **Project / workspace cost attribution** — where spend is concentrated by project (OpenAI) or workspace (Anthropic).
- **Cache-efficiency recommendations** — the same prompt-caching analysis surfaced on [API Usage](#api-usage), distilled into actionable callouts.

---

## Content

!!! warning "Enterprise + Compliance Access Key required"
    The entire Content surface — view, export, reveal, and delete — is compliance-tier gated. It requires an **admin** role *and* a **Compliance Access Key** sealed for your tenant. This is an Anthropic Enterprise feature and a different key from the Admin API key. See [Compliance Access Key](compliance-key.md). A caller without it gets an explicit permission error, not an empty page. OpenAI exposes no equivalent content surface — OpenAI capture is cost and admin events only.

When content capture is enabled, Ogma stores Claude chat **message text** in encrypted, hash-chained, per-message records. The Content surface lets you:

- **View chats** — the message transcript for a chat. **PII is masked by default** (emails, phone numbers, SSNs, card numbers, API keys, IPs are replaced with `[redacted:<type>]`). Any tenant member can view masked content; the per-message redaction summary (counts and types, never the values) is shown to everyone.
- **Reveal PII (admins, logged)** — an admin can un-mask a chat. Every reveal appends a tamper-evident `content_reveal` record to the chain noting who revealed it and when. Unmasking is treated as a privileged, audited action.
- **eDiscovery export** — download a tenant's captured content as a verifiable bundle. Choose the format:

    | Format | Output |
    |---|---|
    | `zip` (default) | A machine-readable JSON bundle — chats, a per-record chain proof, and a manifest with the chain-verification result. |
    | `pdf` | A courtroom-readable, **Bates-numbered** transcript (`VARGATE-000001…`) with an integrity attestation cover page and a chain-proof appendix. |
    | `both` | The JSON bundle and the PDF in one ZIP. |

    The bundle's differentiator is its **independent verifiability**: an auditor can confirm the exported text is exactly what was recorded (SHA-256 of the plaintext matches the chained `content_hash`) and that the underlying chain is intact — without trusting Ogma. Exports redact PII by default; a full-content export is an admin action and is itself logged.

- **Delete / crypto-shred** — remove captured content on request (right-to-erasure, retention, offboarding) **without breaking tamper-evidence**:

    | Scope | What it removes |
    |---|---|
    | Per-chat | One chat's message content. |
    | Per-user (DSR) | All of one data subject's content, across every chat. |
    | Per-tenant (offboarding) | Everything — all content *and* the sealed keys — by destroying the tenant encryption key (crypto-shred). Terminal and irreversible. |

    Deletion is **chain-safe**: Ogma never modifies or removes a chain record. It makes the content unreadable and appends a new, append-only deletion event — so the record *that content existed, and that it was deleted* both survive, and chain verification stays green. A deleted chat re-renders as a tombstone (a "content purged" banner with the date and reason; each message shows `[content deleted]`). All deletes are admin-only and require a reason that's recorded in the audit trail.

!!! note "What content capture sees"
    Content capture records chat **message text** (user and assistant). Uploaded files, generated files, and artifacts are out of scope. A message with no text is skipped, not stored.

---

## Budgets & alerts

Spend budgets with threshold and forecast alerting.

- **Thresholds.** A budget fires as current-period spend crosses **70%**, **85%**, and **100%** of its cap. Each threshold fires at most once per period, so crossing all three sends three distinct alerts — not one cumulative one.
- **Forecast alerts.** A budget can also alert when spend is *projected* to cross a threshold by period-end on the current trend — the early-warning companion to the after-the-fact threshold alert. Both ride the same alert pipeline.
- **Channels.** Each budget configures who's notified per channel:

    | Channel | What's sent | Where the credential comes from |
    |---|---|---|
    | **Email** (default) | A branded budget-alert email. | Just an address. |
    | **Slack** | A message to an incoming webhook. | Slack → *Apps → Incoming Webhooks* → copy the `https://hooks.slack.com/services/…` URL. |
    | **PagerDuty** | An Events API v2 event (critical at 100%, warning otherwise). | A PagerDuty service → *Integrations → Events API v2* → copy the routing key. |

- **Test before you rely on it.** Each budget has a **Send test alert** button (admins) that fires a clearly marked `[TEST]` through every configured channel, so you can confirm a webhook delivers before a real threshold is ever crossed.

!!! tip "Channels are best-effort and isolated"
    A failing Slack webhook never blocks email or PagerDuty, and a delivery failure never re-fires an already-recorded alert. The dashboard's alert history is the source of truth for what crossed and when. Slack URLs and PagerDuty keys are stored as delivery targets, redacted in logs, and never shown back in the UI — rotate them in Slack/PagerDuty to revoke.

---

## Related

- [Connect Anthropic (Admin key)](connect-anthropic.md) — usage, members, workspaces.
- [Connect OpenAI (Admin key)](connect-openai.md) — cross-vendor cost and per-user attribution.
- [Connect Claude (MCP)](connect-mcp.md) — per-turn chat activity for Sessions and Users.
- [Compliance Access Key](compliance-key.md) — unlock the Content surface.
