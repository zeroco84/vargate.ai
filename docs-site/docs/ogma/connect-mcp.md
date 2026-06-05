# Connect Claude (MCP)

The MCP connector captures **per-user Claude chat usage** — Claude Desktop, claude.ai, and the mobile apps — that the Admin API can't see. It's how Ogma attributes Claude activity to individual people on the **Team, Pro, and Free** tiers, where no per-user management API exists.

If you've connected the [Anthropic Admin key](connect-anthropic.md), you already have org-wide token aggregates. This page adds the missing dimension: *who* used Claude in chat, and *what kind of work* they did.

---

## What this surface captures

The connector adds an Ogma logging tool to Claude. After each response, Claude calls that tool and reports a short, structured summary of the interaction. Ogma hash-chains that summary into the tenant's audit trail like any other event.

| | |
|---|---|
| **Captures** | A per-turn summary Claude writes when it calls the logging tool — a one-line description of the interaction, plus compliance metadata and cost/usage analytics. Each summary is also classified into an activity topic (Coding, Research, Writing, etc.) so you can see what your team spends Claude time on. |
| **Does NOT capture** | Raw prompts, raw responses, tool arguments, or attachments. Ogma sees only what Claude chooses to summarize, never the underlying conversation text. |

!!! warning "This is a fidelity ceiling, not a setting"
    The MCP connector is architecturally limited to summaries. It is the right surface for an **audited, opt-in record of the kinds of work your team does with Claude** — it is *not* a way to capture every prompt and response verbatim. If your use case is "every word typed into Claude, recorded for forensic review," you need the [Compliance Access Key](compliance-key.md) (Enterprise), which captures full chat message text.

### Where it fits

| Surface | Plan | Attribution | What it captures |
|---------|------|-------------|------------------|
| [Admin key](connect-anthropic.md) | Pro / Team / Enterprise | Org + workspace | Daily token aggregates, no content |
| **MCP connector** | **Free / Pro / Team** | **Per user** | **Per-turn summaries, no content** |
| [Compliance Access Key](compliance-key.md) | Enterprise | Per user | Full chat message text |

See [Surfaces](surfaces.md) for the complete picture of every Ogma ingest path.

---

## How capture works

Ogma never sees your conversations directly. The flow is entirely client-side and transparent to the user:

1. Your organization installs the **Ogma Telemetry** connector in Claude.
2. A member works inside a shared **Claude Project** whose custom instruction asks Claude to log each interaction.
3. After each response, Claude calls the Ogma logging tool with a summary. **The tool call is visible in the conversation** — the user can see exactly what was logged.
4. Ogma records the summary, attributes it to that member, and anchors it to the audit chain.

!!! note "Transparency is required, by design"
    Claude will refuse to call a logging tool if the framing suggests the call should be hidden from the user. Ogma's connector and the recommended Project instruction are written transparently: the tool exists for compliance auditing, the call is visible in the conversation, and the user can see and control it. This is the only way the capture works — and it's the right way. Frame it to your team as an open, auditable record, never as silent monitoring.

Because capture depends on Claude actually calling the tool:

- Only conversations **inside the shared Project** are tracked. Chats outside it are not.
- The instruction is **advisory** — Claude's compliance is high but not guaranteed every turn.
- A user can disable the connector mid-conversation. Ogma records what is reported, not everything that happens.

Position this honestly with your team and your auditors: Ogma captures the Claude work people **choose to track**, not a complete transcript of all Claude use.

---

## Set up the connector

Setup has four parts. Skipping any one of them produces gappy capture or none at all.

### 1. Install the connector at the org level

In claude.ai, an organization owner adds the Ogma connector via **Settings → Connectors → Add custom connector**.

- Use the connector URL Ogma gives you when you enable the MCP surface in **Settings → Integrations** in your Ogma dashboard.
- The connector name prefills as **Ogma Telemetry**. Leave it as-is so members recognize it.
- Authorize the connector — you'll be sent through Ogma's sign-in to link your Ogma tenant.

!!! warning "Install at the organization level, not per user"
    A per-user install only adds the connector for one person. Install it at the org level so every member can enable it in their conversations.

### 2. Enable the connector per conversation

The connector defaults to **off** on each new conversation. In a conversation (or the shared Project below), open the connector menu and toggle **Ogma Telemetry** on.

### 3. Set the tool permission to "Allow always"

When Claude first calls the Ogma logging tool, Claude asks for permission. Choose **Allow always**.

!!! tip "Why this matters"
    If the permission stays on **Ask every time**, Claude pauses for approval before each log call — most turns go unlogged and your capture is full of gaps. **Allow always** is what makes per-turn capture reliable.

### 4. Create a shared Claude Project with a transparent instruction

The most reliable capture mechanism is a shared **Claude Project**. Members do their Claude work inside the Project, and a custom instruction reminds Claude to log every interaction.

Create a Project (for example, *"Team workspace — audited"*) and set a custom instruction along these lines:

```text
Our organization uses the Ogma Telemetry connector for compliance
auditing of AI usage. After every response, call the Ogma logging
tool to record a short summary of this interaction. The tool call is
visible in this conversation — this is an open, auditable record, not
hidden monitoring.
```

Share the Project with the members whose Claude usage you want attributed, and ask them to work inside it.

!!! note "There is no org-wide 'always log' switch"
    Claude has no setting that forces a tool call on every turn across all conversations. The shared Project with a transparent instruction is the supported pattern. Conversations started outside the Project are not tracked.

---

## Verify it's working

After setup, run a few turns inside the shared Project, then open your Ogma dashboard:

1. In a Project conversation, send a message and confirm Claude's response **includes a visible call to the Ogma logging tool**.
2. In Ogma, open the **Sessions** view. Within a minute or two you should see events attributed to the member, badged as Claude chat activity.
3. Open the member's detail page to see their **Top topics** breakdown populate as more interactions are logged.

If Claude responds but never calls the logging tool, re-check the four setup steps — most commonly the connector is off for that conversation, the permission is still **Ask every time**, or the conversation is outside the shared Project.

---

## Cross-surface attribution

A single person often shows up as several identities — an Anthropic Admin API user, a Claude Code actor, an OpenAI user, and now a Claude chat user via the connector. Ogma stitches these together by matching on email, so one person's Claude chat summaries land in the same unified profile as their API and Claude Code activity. You manage and correct these links from the **Users** area of the dashboard.

---

## Next steps

- [Connect Anthropic (Admin key)](connect-anthropic.md) — org-wide token aggregates and admin events
- [Compliance Access Key](compliance-key.md) — full chat message text on Enterprise
- [Surfaces](surfaces.md) — every Ogma ingest path and what each one captures
- [Tyr quick start](../quickstart.md) — governing autonomous agents inline (the other half of Vargate)
