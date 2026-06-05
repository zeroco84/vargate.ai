# Compliance Access Key (content capture)

By default, Ogma audits Claude usage from your **Admin API key** — token totals, members, workspaces, and event metadata. That metadata tells you *that* a chat happened, who started it, and which model ran, but it never includes the conversation text itself.

To capture the actual **chat and message content** for compliance review, Ogma needs a second, different credential: a **Compliance Access Key**. This page covers what that key is, how it differs from the Admin key, and what Ogma does with the content once it's connected.

!!! warning "Enterprise-only"
    Content capture is available to **Anthropic Enterprise** organizations only. Console, Pro, and Team organizations can connect an Admin key and audit usage + activity, but the content endpoints return `403` — there's no content stream to capture. If you're not on Enterprise, [Connect Anthropic (Admin key)](connect-anthropic.md) is as far as you can go, and that's expected.

---

## A different key from the Admin key

The Admin key and the Compliance Access Key are two distinct credentials, created in two different places, that unlock two different things. Ogma keeps them separate.

| | Admin API key | Compliance Access Key |
|---|---|---|
| Prefix | `sk-ant-admin01-…` | `sk-ant-api01-…` |
| Created in | Anthropic Console | claude.ai (by an Enterprise owner) |
| Unlocks | Token usage, members, workspaces, activity **metadata** | Chat + message **content** (the conversation text) |
| Plan required | Any paid plan | **Enterprise only** |

!!! note "You need both"
    The Compliance Access Key does not replace the Admin key — it sits alongside it. Connect the Admin key first ([Connect Anthropic](connect-anthropic.md)) for usage and per-user attribution, then add the Compliance Access Key to layer content capture on top.

If you paste an Admin key (`sk-ant-admin01-…`) into the Compliance Access Key field, Ogma rejects it with a clear message rather than silently accepting a key that can't reach content.

---

## Two scopes — grant both

When an Enterprise owner creates the Compliance Access Key in claude.ai, it must carry **both** of these compliance scopes:

| Scope | Why it's needed |
|---|---|
| `read:compliance_org_data` | Enumerate the organizations under your account. |
| `read:compliance_user_data` | List users and pull their chats — the content itself. |

Ogma reads content by walking a chain: **organizations → users → chats → messages.** That chain spans both scopes, so a key with only one of them passes the first step and then fails when it reaches the content. To save you that surprise, Ogma validates **both scopes up front** when you connect the key, and rejects a half-scoped key with a message naming the scope that's missing.

---

## Connect the key

Connecting a Compliance Access Key is an **admin-only** action in your Ogma workspace.

1. Create the key in claude.ai as an Enterprise owner, granting both `read:compliance_org_data` and `read:compliance_user_data`.
2. In the Ogma dashboard, go to **Settings → Integrations → Compliance Access Key**.
3. Paste the key (`sk-ant-api01-…`) and click **Connect**.

Ogma then runs a quick live check before storing anything — it confirms the key reaches the compliance endpoints, that your organization is on Enterprise, and that both scopes are present. Only after that check passes is the key sealed.

!!! tip "Connecting again rotates the key"
    Submitting a new key in the same place replaces the old one in place. There's no separate "rotate" step — just connect the new key.

Once the key is sealed, your content surface unlocks and Ogma begins capturing chat content on its regular pull schedule.

---

## How the key is protected

A Compliance Access Key is the most sensitive credential you'll give Ogma, and it's handled accordingly:

- **Encrypted at rest.** The key is sealed with AES-GCM under a per-tenant encryption key, isolated so one tenant's secrets are never reachable from another's.
- **Never returned, never logged.** No read endpoint ever echoes the key back, and it never appears in logs. Ogma unseals it only for the duration of a content pull, then drops it from memory.

---

## What gets captured — and what doesn't

When the key is connected, Ogma captures the **text** of chat messages — both your users' prompts and Claude's responses — from claude.ai. Be clear-eyed about the boundaries:

| | |
|---|---|
| **Captured** | The text content of chat messages (user and assistant). |
| **Not captured** | Uploaded files, Claude-generated files, artifacts, and projects. A message with no text (for example, a file-only upload) is skipped. |

!!! note "OpenAI captures no content"
    Content capture is a Claude-Enterprise feature. Ogma's OpenAI integration audits **cost and admin events only** — it never reads chat content, because OpenAI's management APIs don't expose it. See [Connect OpenAI](connect-openai.md).

Soft-deleted chats are still captured (and flagged as deleted in their metadata). Chats that were hard-deleted in claude.ai never appear in the source API, so Ogma can't retrieve them.

---

## What happens to captured content

Every captured message goes through the same tamper-evident pipeline as the rest of your audit data, plus content-specific encryption:

- **Encrypted blob.** The message text is encrypted with AES-256-GCM under your per-tenant key before it's written to object storage. The storage layer never sees plaintext.
- **Hash-chained record.** Ogma appends one record per message to your tamper-evident hash chain. The record holds searchable metadata (chat, role, model, user, timestamps) and a SHA-256 hash of the plaintext — not the text itself, which stays in the encrypted blob. Because each record extends the chain, content capture is tamper-evident end to end and inherits the same [blockchain anchoring](../index.md) as your other audit records.

That plaintext hash is stored in the clear on the record, so an auditor can later recompute it from exported content and prove the content is exactly what was recorded.

---

## What you can do with content

Once content is captured, it powers Ogma's compliance workflows. All of these live on the [Content surface](surfaces.md#content) and require both an **admin** role and a connected Compliance Access Key:

| Capability | What it does |
|---|---|
| **View** | Read message transcripts in the dashboard, decrypted on read. PII is **masked by default**. |
| **eDiscovery export** | Download a content bundle (JSON, or a Bates-numbered PDF) with an embedded chain-verification proof, so an auditor can confirm the export is exactly what was recorded. |
| **PII redaction** | Emails, phone numbers, SSNs, card numbers, API keys, and IPs are masked automatically. Revealing full PII is admin-only and **recorded in the audit log** as its own tamper-evident event. |
| **Deletion** | Delete a single chat's content, all of one data subject's content (for a right-to-erasure request), or — at offboarding — every blob and key for the tenant via crypto-shredding. |

!!! note "Deletion is chain-safe"
    Ogma never edits or removes a chain record. It makes the content unreadable (deletes the encrypted blob, or destroys the per-tenant key) and appends a new deletion event. The result: you can prove the content existed *and* prove it was deleted — and the chain still verifies before and after. This is how Ogma satisfies GDPR/CCPA erasure without breaking tamper-evidence.

---

## Next steps

- [Surfaces → Content](surfaces.md#content) — view, export, redact, and delete captured content
- [Connect Anthropic (Admin key)](connect-anthropic.md) — the usage + activity layer the Compliance Access Key sits on top of
- [Connect Claude (MCP)](connect-mcp.md) — per-user attribution via the MCP connector
