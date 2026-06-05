# Connect Anthropic (Admin key)

The **Anthropic Admin API key** is Ogma's primary Claude connection. With one key, Ogma reads your organization's Claude usage straight from Anthropic's management APIs — no agents, no proxies, no sidecars. Every event is hash-chained and anchored to a public blockchain, so the record lives outside the vendor's perimeter.

This page covers where to create the key, how to connect it during onboarding, what each data stream captures, and which streams depend on your Anthropic plan tier.

!!! note "Ogma vs. Tyr"
    **Ogma** audits AI *usage* — human and API — from outside the vendor. **Tyr** is the separate product that governs *autonomous agents* inline, intercepting tool calls before they run. If you're looking to put policy in front of an agent, see the [Tyr quick start](../quickstart.md). This page is about auditing Claude usage with Ogma.

---

## 1. Create the key in the Anthropic Console

The Admin API key is created by an organization owner in the Anthropic Console.

1. Sign in at [platform.claude.com](https://platform.claude.com) as an **organization owner** (Admin keys are owner-only).
2. Go to **Settings → Organization → API keys**.
3. Create an **Admin key**. It begins with `sk-ant-admin01-…`.
4. Copy the value — it's shown only once.

Ogma only ever issues read (`GET`) requests against the management APIs, so the Admin key is used strictly for read access. Treat it like any production secret.

!!! tip "Admin key vs. standard API key"
    An Admin key (`sk-ant-admin01-…`) reads *organization-level* data — usage, members, workspaces. A standard API key (`sk-ant-api01-…`) calls the model. They are different key types; Ogma's Admin connection needs the Admin key. (A `sk-ant-api01-…` key is used elsewhere, for the [Compliance Access Key](compliance-key.md) content path.)

---

## 2. Connect it in Ogma (about 60 seconds)

In Ogma, the Anthropic connection is one of the parallel onboarding cards — you can connect Anthropic, [OpenAI](connect-openai.md), or both.

1. During onboarding, open the **Anthropic · Admin API** card. (Already onboarded? Use **Settings → Integrations**.)
2. Paste your `sk-ant-admin01-…` key.
3. **Validate.** Ogma probes each management endpoint and shows a capability checklist (see the table below) so you can see exactly what your org exposes. A wrong key type or a malformed key returns a clear inline error — never a 500.
4. **Connect.** On a successful probe, the key is sealed (encrypted with your per-tenant key and never shown to the dashboard again) and a **backfill** of recent usage is enqueued automatically.

Your first usage rows land within a few minutes. From there, Ogma polls on a schedule to keep the record current.

!!! warning "The key is write-once into Ogma"
    Once sealed, the key is never returned by any read endpoint and never logged. Re-pasting a key in **Settings → Integrations** rotates it in place. To revoke, rotate or delete the key in the Anthropic Console.

---

## 3. What each stream captures

A single Admin key unlocks several read-only streams off your Claude organization. They differ in what they see and which plan tier they require.

| Stream | What it captures | Plan tier |
|---|---|---|
| **Usage, members, workspaces, API keys** | Daily token aggregates per workspace and model, your org's members, workspaces, and API key inventory. | Pro / Team / Enterprise |
| **Code Analytics** | Per-developer Claude Code sessions — one row per developer per day. | Broadly available (with the entitlement) |
| **Activity Feed** | Event *metadata* — chat-created, file-uploaded, sign-in, admin events. No prompt or response text. | Enterprise only |

**Daily usage** is the always-on baseline: every Admin-keyed tenant gets it. Ogma computes a cost estimate from published per-model rates, so you see spend alongside token counts.

**Code Analytics** gives you per-developer sessions — useful for seeing who is using Claude Code and how much. It's broadly available across plans once your org is entitled to it.

**Activity Feed** surfaces event metadata (what kind of activity happened and when), not content. It's an Enterprise-tier capability.

!!! note "Usage is aggregate, not per-person"
    The daily usage stream reports tokens per workspace and model — it has no per-user dimension on its own. For per-developer detail you need Code Analytics (sessions), and for per-person *chat* attribution you need the MCP connector (next section).

---

## 4. The plan-tier asymmetry

What the Admin key surfaces depends on your Anthropic plan:

- **Code Analytics is broadly available.** Most entitled organizations get per-developer Claude Code sessions, not just Enterprise.
- **Activity Feed is Enterprise-only.** On Console, Pro, and Team plans the Admin key still works for usage, members, and workspaces, but the Activity Feed endpoints aren't reachable.

When you validate the key, the capability checklist reflects exactly which streams *your* org exposes — so you're never guessing. The checklist maps one-to-one to the `anthropic` block of `GET /me/capabilities`:

| Capability flag | Meaning |
|---|---|
| `admin_api` | The Admin key works — usage, members, and workspaces are reachable. |
| `code_analytics` | Per-developer Claude Code sessions are available. |
| `activity_feed` | The Activity Feed (event metadata) is reachable — Enterprise. |
| `content_capture` | A [Compliance Access Key](compliance-key.md) is connected (full chat content). |
| `mcp_connector` | The [Claude MCP connector](connect-mcp.md) is set up (per-turn chat attribution). |

---

## 5. Going further: per-user chat and full content

The Admin key is the foundation, but two things sit outside it by design:

- **Per-user *chat* attribution** — to attribute claude.ai chat activity to individual people, add the **MCP connector**. It captures a per-turn summary of what each person works on. See [Connect Claude (MCP)](connect-mcp.md).
- **Full chat *content*** — to capture the actual prompt and response text from claude.ai for compliance review, add a **Compliance Access Key**. This is an Enterprise capability and a different key type (`sk-ant-api01-…`). See [Compliance Access Key](compliance-key.md).

!!! tip "These stack"
    You don't choose one path — they're complementary. The Admin key gives you org-wide usage and cost. The MCP connector adds per-person attribution on every plan. The Compliance Access Key adds full content on Enterprise. Connect what your use case needs.

---

## Next steps

- [Connect OpenAI (Admin key)](connect-openai.md) — add your OpenAI org for a cross-vendor view (per-user attribution works on Pay-as-you-go, not just Enterprise).
- [Connect Claude (MCP)](connect-mcp.md) — per-user chat attribution across every plan tier.
- [Compliance Access Key](compliance-key.md) — full chat content capture for Enterprise tenants.
- [Surfaces](surfaces.md) — the dashboard views your connected data flows into.
