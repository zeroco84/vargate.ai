# Connect OpenAI (Admin key)

Ogma audits your organization's OpenAI usage the same way it audits Claude: by reading what the vendor already exposes through its management API, then hash-chaining and anchoring every event independently of the vendor. No agents, no proxies, no sidecars — just one read-only admin key.

A single **OpenAI Admin key** (`sk-admin-…`) unlocks four read-only streams off your OpenAI organization.

!!! note "OpenAI vs. Claude"
    OpenAI and Claude are complementary, not exclusive. Connect either or both — usage stitches together by email, so one person's OpenAI and Claude activity lands on a single user row. New to Ogma? Start with the [Ogma overview](index.md).

---

## What you get

| Stream | What it captures |
|--------|------------------|
| **Usage** | Per-(day, model, user, project, API key) token counts. Drives per-user attribution and Ogma's cost estimate. |
| **Costs** | Authoritative billed spend at project and line-item grain — including non-token items like fine-tune training. |
| **Audit logs** | Admin events: logins, API key changes, member changes, and other organization-level activity. |
| **Projects / keys / users** | The names and email map that make the other streams human-readable and stitch OpenAI activity to the right person. |

This is the same model as the [Anthropic Admin key](connect-anthropic.md): daily aggregates plus admin events, pulled server-side. Ogma only ever issues `GET` requests, so a **read-only** admin key is sufficient — and recommended.

!!! note "Region"
    OpenAI has no EU data residency, so OpenAI organizations are always region **US**. If your tenant requires EU residency, scope it to your Claude integrations.

---

## 1. Create a read-only Admin key

You need to be an **Organization Owner** to create an admin key.

1. Go to [platform.openai.com](https://platform.openai.com) → **Settings → Organization → Admin keys**.
2. Click **Create**, and grant it **read-only** access.
3. Copy the `sk-admin-…` value. OpenAI shows it once — store it somewhere safe until you've pasted it into Ogma.

!!! warning "Use an Admin key, not a project key"
    A standard `sk-…` project (API) key is the wrong type and cannot read organization usage, costs, or audit logs. Only an `sk-admin-…` key works. If you paste a project key, Ogma returns a clear inline error during validation — it never silently half-connects.

---

## 2. Validate, connect, backfill

In Ogma, open **Onboarding** and pick the **OpenAI · Admin API** card (or, for an already-onboarded tenant, go to **Settings → Integrations**). Paste your `sk-admin-…` key.

=== "Validate"

    Ogma probes each endpoint and shows you a [capability checklist](#capability-checklist) before anything is saved. A bad or wrong-type key returns a clear, specific error — never a generic failure.

=== "Connect"

    On a successful probe, the key is sealed: encrypted with your per-tenant key and never shown to the dashboard again. Ogma enqueues a **90-day backfill** of usage, costs, and project/user metadata. Audit logs are picked up on the regular poll.

=== "Backfill"

    First usage and cost rows typically land within about 15 minutes. Usage and costs poll roughly every 15 minutes; audit logs and project/user metadata refresh hourly.

!!! tip "Keys are write-only into Ogma"
    Once sealed, your admin key is never returned to the browser or the API. To replace it, paste a new one — validation and re-seal happen the same way.

---

## Capability checklist

When you validate a key, Ogma reports exactly what your organization exposes. These flags also appear under the `openai` block of `GET /me/capabilities`.

| Flag | Meaning |
|------|---------|
| `admin` | The usage endpoint is reachable — the key works. |
| `costs` | The cost endpoint is reachable. |
| `audit_logs` | An audit event has actually been ingested. Stays `false` below Enterprise (see below). |
| `project_users` | Your organization exposes user-level data. |
| `per_user_breakdown` | Grouping usage by user returns populated user IDs, so **per-user attribution works**. |

### Per-user attribution works on Pay-as-you-go

This is where OpenAI is more generous than Anthropic. OpenAI's `per_user_breakdown` populates on **Pay-as-you-go**, not just Enterprise — so per-user attribution works on every paid tier. Ogma requests usage grouped by user on every pull, maps each OpenAI user to their email, and stitches that activity into the same unified user as their Claude usage.

!!! note "When user IDs aren't exposed"
    If your organization doesn't expose user-level data, OpenAI activity attributes to the API key holder instead and surfaces in the **Unmapped activity** panel, where you can link it manually.

### Audit logs populate on Enterprise

The `audit_logs` flag reflects whether audit events have actually been **ingested** — not just whether the endpoint responds. OpenAI only populates audit logs on Enterprise organizations; below Enterprise the endpoint is reachable but returns no events, so the flag stays `false` until a row lands. Reachable is not the same as populated.

---

## What it does NOT capture

Be clear-eyed about the boundary. The OpenAI integration captures **cost and admin events only** — there is no chat content.

- **No ChatGPT web or desktop turn-level capture.** OpenAI has no equivalent of the [Claude MCP connector](connect-mcp.md), so per-user ChatGPT.com activity is not visible through the Admin API.
- **No chat content or transcript text.** OpenAI exposes no compliance interface for message content. (For Claude, full-content capture is available to Enterprise organizations via a [Compliance Access Key](compliance-key.md) — there is no OpenAI counterpart today.)

If you need a record of *what kinds of work* your team does with OpenAI, plus authoritative spend and admin-event accountability, this integration delivers it. If you need every prompt and response, that is not something OpenAI's management API exposes.

---

## Verify and troubleshoot

- **Confirm the key is live:** `GET /me/capabilities` shows `openai.admin: true` as soon as the key is sealed, before the first pull completes.
- **Wait for the first rows:** usage and cost data lands within about 15 minutes; if it's still empty after that, re-check the key type and that you're an Organization Owner.
- **Scope-limited keys soft-skip:** if a key can read some streams but not others, Ogma quietly skips the ones it can't read and keeps the others flowing. The cursor for the skipped stream is left untouched, so upgrading the key later backfills the window you missed — no data is lost.
- **No key, no problem:** a tenant without an OpenAI key is simply a no-op for the OpenAI pollers. There's no error and no retry storm.

---

## What you'll see after connecting

- **[API Usage](surfaces.md)** — switch the vendor filter to **OpenAI** (or **All** for a cross-vendor view). Costs use OpenAI's published rates; cached input is billed at the reduced rate, with no separate cache-write charge.
- **[Users](surfaces.md)** — OpenAI activity stitches into the same person as their Claude usage by email, so one user row spans both vendors.
- **Insights** — cost forecasting, model mix (including any cross-vendor shift), and project attribution all include OpenAI.

---

## Next steps

- [Connect Anthropic (Admin key)](connect-anthropic.md) — the same flow for Claude usage and admin events.
- [Connect Claude (MCP)](connect-mcp.md) — per-turn capture of human Claude chat usage.
- [Surfaces](surfaces.md) — what the API Usage, Users, and Insights views show.
- [Ogma overview](index.md) — how the independent audit layer fits together.
