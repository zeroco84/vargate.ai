# Feature Spec: Anthropic Managed Agents Integration

**Author:** Rick Larkin / Vargate.ai  
**Date:** April 10, 2026  
**Status:** Draft  
**AGCS Controls:** AG-1.1 through AG-1.11, AG-2.1 through AG-2.9

---

## 1. Executive Summary

Anthropic launched Managed Agents (public beta, April 8, 2026) — a hosted agent runtime where Claude autonomously executes tools inside cloud containers. The platform has **zero built-in governance**: no policy enforcement, no audit trail, no approval gates, no compliance artifacts.

Vargate fills this gap entirely. This spec describes a three-layer integration that makes Vargate the governance and compliance layer for any enterprise deploying Anthropic managed agents.

**Integration layers:**

1. **Active governance** — Vargate as a remote MCP server. Governed tool calls (email, payments, APIs) route through Vargate's policy engine before execution.
2. **Passive observability** — Vargate consumes the managed agent's SSE event stream, logging all tool activity (including built-in tools like bash and file ops) to the audit chain.
3. **Control plane** — Vargate wraps the managed agents API, controlling session creation, agent configuration, and tool availability per tenant policy.

---

## 2. Background

### 2.1 What Are Managed Agents?

Managed agents is a hosted agent runtime built around four concepts:

- **Agent**: A configuration bundle — model, system prompt, tools, MCP servers, skills.
- **Environment**: A container template — installed packages, network access rules, mounted files.
- **Session**: A running agent instance performing a specific task, producing outputs.
- **Events**: Messages exchanged between the calling application and the agent via SSE.

Key API surface:

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/agents` | Create/configure agent |
| `POST /v1/environments` | Create execution environment |
| `POST /v1/sessions` | Start agent session |
| `POST /v1/sessions/{id}/events` | Send events, stream responses (SSE) |
| `GET /v1/sessions/{id}/events` | Retrieve event history |

Pricing: standard Claude token rates + $0.08/session-hour of active runtime.

### 2.2 Why This Integration Matters

Enterprises adopting managed agents face a compliance gap:

- **No policy enforcement.** The agent executes any tool it has access to, with no governance layer.
- **No audit trail.** Tool executions are visible in the event stream but not logged to any tamper-evident store.
- **No approval gates.** No mechanism for human-in-the-loop review of sensitive actions.
- **No credential isolation.** The agent's environment has direct access to any credentials mounted in it.
- **No compliance export.** No way to produce auditor-ready artifacts proving what the agent did and why.

Vargate addresses every one of these gaps through AGCS controls AG-1.1 through AG-2.9.

### 2.3 Competitive Positioning

Vargate is not competing with managed agents — it's completing them. The positioning:

> "Anthropic provides the brain. Vargate provides the governance."

This also advances AGCS as a runtime-agnostic standard. If Vargate can certify a managed agent deployment against AGCS controls, it proves the standard isn't tied to Vargate's own proxy — strengthening the case for independent adoption.

---

## 3. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Customer Application                       │
│                                                               │
│  Instead of calling Anthropic directly, the customer calls   │
│  Vargate's control plane, which wraps the managed agents API │
└──────────────────────────┬───────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │   VARGATE   │
                    │ CONTROL     │
                    │ PLANE       │◄──── Layer 3: Session creation,
                    │             │      agent config, tool policy
                    └──────┬──────┘
                           │
              ┌────────────▼────────────────┐
              │   Anthropic Managed Agents   │
              │                              │
              │  ┌────────────────────────┐  │
              │  │   Agent Session        │  │
              │  │                        │  │
              │  │  Built-in tools ───────┼──┼──► SSE Events ──► VARGATE
              │  │  (bash, files, web)    │  │                   EVENT
              │  │                        │  │                   CONSUMER
              │  │  Governed tools ───────┼──┼──► MCP call ───► VARGATE
              │  │  (email, pay, APIs)    │  │                   MCP SERVER
              │  │                        │  │                   │
              │  └────────────────────────┘  │                   ▼
              │                              │              OPA Policy
              └──────────────────────────────┘              Audit Log
                                                            HSM Vault
                                                            Merkle/Chain
                                                            Approval Queue
```

### Layer 1: Vargate MCP Server (Active Governance)

**What it does:** The managed agent connects to Vargate as a remote MCP server via HTTP+SSE transport. When the agent invokes a governed tool, the request routes through Vargate's full governance pipeline before execution.

**Confirmed feasibility:** Managed agents support remote MCP servers over HTTP+SSE transport, including authentication (OAuth, API key) and private networking. Outbound network access from agent containers is configurable per environment.

**Flow:**

1. Agent session starts with Vargate configured as an MCP server.
2. Agent decides to call a tool (e.g., `send_email`).
3. Managed agents platform makes an MCP `tools/call` request to Vargate's public endpoint.
4. Vargate receives the call, identifies the tenant and agent from the MCP session context.
5. **AG-1.1**: OPA/Rego policy evaluation (two-pass: fast path + behavioral enrichment).
6. **AG-1.10**: Redis behavioral analysis — anomaly scoring, action frequency checks.
7. **AG-1.11**: PII detection and encryption on parameters.
8. If policy returns `requires_human`:
   - **AG-1.6**: Action enqueued to approval queue. MCP response returns a "pending approval" result.
   - Agent receives this as a tool result and can inform the user or proceed with other work.
   - On approval, Vargate could notify via webhook or the agent could poll.
9. If policy allows:
   - **AG-1.9**: HSM vault brokers execution. Vargate fetches credentials, executes the real API call, returns the result.
   - Agent never sees credentials.
10. **AG-1.2**: Decision logged to hash-chained audit trail.
11. **AG-1.3**: Action UUID returned as part of the MCP tool result (enables traceability).
12. MCP response sent back to managed agent with tool result.

**New component: `gateway/mcp_server.py`**

This module implements the MCP server protocol (as distinct from the existing `/mcp/tools/call` simplified endpoint):

- `initialize` — MCP handshake, capability negotiation.
- `tools/list` — Returns the tenant's governed tool catalog. Tools are dynamically scoped based on the agent's policy profile.
- `tools/call` — Routes to existing governance pipeline in `main.py`.
- `resources/list` — Optional: expose audit log entries as MCP resources for agent self-awareness.
- Transport: HTTP+SSE (Streamable HTTP), compatible with managed agents' remote MCP support.

**Authentication:** The MCP server endpoint authenticates the managed agent's connection using one of:
- Vargate API key (passed as bearer token in MCP auth)
- OAuth client credentials (Vargate acts as OAuth provider)
- Mutual TLS for private networking deployments

**Tool catalog design:**

Rather than exposing raw API tools (send_email, create_invoice), Vargate exposes *governed capabilities* — tools with built-in policy metadata:

```json
{
  "name": "vargate_send_email",
  "description": "Send an email through Vargate governance. Subject to policy review, PII detection, and audit logging. May require human approval for external recipients.",
  "inputSchema": {
    "type": "object",
    "properties": {
      "to": { "type": "string", "description": "Recipient email address" },
      "subject": { "type": "string" },
      "body": { "type": "string" },
      "urgency": { "type": "string", "enum": ["low", "normal", "high"] }
    },
    "required": ["to", "subject", "body"]
  }
}
```

The tool descriptions inform the agent about governance constraints, making it more likely to provide complete information and less likely to attempt policy-violating calls.

### Layer 2: Event Stream Consumer (Passive Observability)

**What it does:** Vargate subscribes to the managed agent session's SSE event stream, parsing every tool execution event and logging it to the audit chain. This captures activity from built-in tools (bash, file ops, web fetch) that don't route through the MCP server.

**Flow:**

1. Control plane creates a session via the Anthropic API.
2. Vargate's event consumer connects to `GET /v1/sessions/{id}/events` with the Anthropic API key.
3. For each `agent.tool_use` event:
   - Extract tool name, arguments, result, timing.
   - **AG-2.1**: Log to structured audit schema (tool, method, params, decision="observed", source="builtin").
   - **AG-1.2**: Append to tenant's hash chain.
   - **AG-1.10**: Feed into Redis behavioral analysis. Flag anomalies.
4. For `agent.message` events:
   - Log agent reasoning/output for decision transparency (AG-1.5).
5. **AG-2.2**: Include passively observed events in hourly Merkle tree aggregation.
6. **AG-2.3**: Anchor to blockchain alongside governed events.

**New component: `gateway/event_consumer.py`**

```python
class ManagedAgentEventConsumer:
    """
    Subscribes to Anthropic managed agent SSE streams.
    Logs all tool executions to Vargate audit chain.
    Feeds behavioral analysis for anomaly detection.
    """

    async def connect(self, session_id: str, tenant_id: str):
        """Open SSE connection to managed agent session."""

    async def process_tool_use(self, event: dict, tenant_id: str):
        """Parse tool_use event, log to audit chain."""

    async def process_message(self, event: dict, tenant_id: str):
        """Log agent reasoning for transparency."""

    async def detect_anomaly(self, event: dict, tenant_id: str) -> bool:
        """Check behavioral patterns, alert if anomalous."""
```

**Anomaly detection on passive events:**

Even without enforcement power over built-in tools, Vargate can:
- Alert when bash commands match dangerous patterns (rm -rf, credential access, network exfiltration).
- Flag unusual file access patterns (reading many files rapidly, accessing unexpected directories).
- Detect web fetches to suspicious domains.
- Trigger a human notification or even send an interrupt event to the session via the control plane.

**Key design decision:** Passive events are logged with `decision: "observed"` (not "allowed") to clearly distinguish them from governed events in compliance exports. Auditors see: "12 tool calls went through active policy enforcement; 8 built-in operations were passively logged."

### Layer 3: Control Plane Wrapper (Session Governance)

**What it does:** Vargate wraps the Anthropic managed agents API, becoming the customer's entry point for creating and managing agent sessions. This gives Vargate control over what agents can do *before they start*.

**Flow:**

1. Customer calls Vargate's control plane: `POST /managed/sessions`.
2. Vargate validates the request against tenant policy:
   - Is this agent configuration approved for this tenant?
   - Are the requested tools within the tenant's allowed set?
   - Has the tenant exceeded their session budget?
3. Vargate calls the Anthropic API to create the session, injecting:
   - Vargate as a remote MCP server in the agent config.
   - Governance instructions in the system prompt (disclosure requirements, reasoning expectations).
   - Environment network rules scoped to tenant policy.
4. Vargate returns the session ID to the customer.
5. Vargate's event consumer auto-attaches to the session's SSE stream.
6. Customer sends events to the session (directly to Anthropic, or proxied through Vargate for full interception).

**New endpoints:**

| Endpoint | Purpose |
|----------|---------|
| `POST /managed/agents` | Register a managed agent config with governance profile |
| `POST /managed/sessions` | Create a governed session (wraps Anthropic's session API) |
| `GET /managed/sessions/{id}/status` | Session status + governance summary |
| `POST /managed/sessions/{id}/interrupt` | Emergency stop — sends interrupt event |
| `GET /managed/sessions/{id}/audit` | Full audit trail for this session |
| `GET /managed/sessions/{id}/compliance` | Compliance export (PDF/JSON) for this session |
| `POST /managed/environments` | Create governed environment template |

**System prompt injection:**

When Vargate creates a session, it appends governance context to the agent's system prompt:

```
## Governance Context (injected by Vargate)

This agent session is governed by Vargate (vargate.ai). All tool calls 
through the Vargate MCP server are subject to policy evaluation, audit 
logging, and may require human approval.

When using governed tools:
- Provide complete context for why you are taking this action.
- If a tool call returns "pending_approval", inform the user and proceed 
  with other work while awaiting approval.
- Never attempt to bypass governed tools by using built-in tools to 
  achieve the same effect (e.g., using bash + curl instead of the 
  governed API tool).
- All actions are logged and auditable.
```

**Emergency stop (defense-in-depth model):**

The control plane exposes an interrupt endpoint that sends a `user.interrupt` event to the Anthropic session. Confirmed: interrupt latency is sub-second, but a non-idempotent tool call already in flight may complete before the signal arrives.

Vargate addresses this with two complementary layers:

1. **Prevention (governed tools):** Sensitive tool calls routed through the MCP server are held in the approval queue (AG-1.6) *before* execution. This is the "confirmation gate" that Anthropic's own documentation recommends. The race condition cannot occur because the action hasn't been dispatched yet.
2. **Interruption (built-in tools):** For passively observed tools (bash, file ops), anomaly detection triggers the interrupt endpoint. This is best-effort — it will stop the agent from taking *further* actions, but may not prevent the in-flight action from completing. The audit chain captures the full sequence regardless.

Both layers are logged to the audit trail with full context.

---

## 4. AGCS Control Mapping

Every AGCS control maps to the managed agents integration:

| Control | Description | Integration Layer | How |
|---------|-------------|-------------------|-----|
| AG-1.1 | Policy-Based Action Evaluation | MCP Server | OPA/Rego evaluation on every governed tool call |
| AG-1.2 | Immutable Audit Trail | MCP Server + Event Consumer | All events (governed + observed) hash-chained |
| AG-1.3 | Action Identification | MCP Server | UUID returned in MCP tool result |
| AG-1.4 | Agent Identification | Control Plane | agent_id, agent_type, agent_version from config |
| AG-1.5 | Decision Transparency | Event Consumer | Agent reasoning captured from message events |
| AG-1.6 | Human Override | MCP Server | Approval queue for governed tools; interrupt for emergencies |
| AG-1.7 | Rate Limiting | MCP Server + Control Plane | Per-tenant session limits + per-tool rate limits |
| AG-1.8 | Per-Tenant Isolation | All layers | Tenant-scoped audit chains, Redis state, policies |
| AG-1.9 | Credential Brokering | MCP Server | HSM vault executes on agent's behalf |
| AG-1.10 | Behavioral Analysis | Event Consumer | Full session activity feeds anomaly scoring |
| AG-1.11 | PII Detection | MCP Server | Params scanned and encrypted before logging |
| AG-2.1 | Structured Audit Schema | MCP Server + Event Consumer | Unified schema for governed + observed events |
| AG-2.2 | Merkle Tree Aggregation | Event Consumer | Session events included in hourly tenant Merkle trees |
| AG-2.3 | Blockchain Anchoring | Event Consumer | Merkle roots anchored on-chain per existing schedule |
| AG-2.4 | Crypto-Shredding | MCP Server | Per-subject HSM keys; erasure via key destruction |
| AG-2.5 | Policy Versioning | MCP Server | OPA bundle revision linked to every audit record |
| AG-2.6 | External Blockchain | Event Consumer | Multi-chain support (Polygon, Ethereum, Sepolia) |
| AG-2.7 | Webhook Notifications | All layers | Governance events fire webhooks (denied, pending, anomaly) |
| AG-2.8 | Decision Replayability | MCP Server | Full OPA input snapshot stored; replay against any policy version |
| AG-2.9 | Safety Constraints | MCP Server + Control Plane | Hard blocks evaluated before OPA |

---

## 5. Data Model Changes

### 5.1 New: `managed_sessions` table

```sql
CREATE TABLE managed_sessions (
    id TEXT PRIMARY KEY,                    -- Vargate session ID
    anthropic_session_id TEXT NOT NULL,     -- Anthropic's session ID
    tenant_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,                 -- Vargate agent config ID
    anthropic_agent_id TEXT,               -- Anthropic's agent ID
    environment_id TEXT,
    status TEXT DEFAULT 'active',           -- active, completed, interrupted, failed
    governance_profile TEXT,                -- JSON: policy overrides, tool restrictions
    system_prompt_hash TEXT,                -- SHA-256 of injected system prompt
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP,
    total_governed_calls INTEGER DEFAULT 0,
    total_observed_calls INTEGER DEFAULT 0,
    total_denied INTEGER DEFAULT 0,
    total_pending INTEGER DEFAULT 0,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);
```

### 5.2 Audit log extension

Add a `source` field to distinguish event origins:

```sql
ALTER TABLE audit_log ADD COLUMN source TEXT DEFAULT 'direct';
-- Values: 'direct' (existing), 'mcp_governed', 'mcp_observed', 'control_plane'
```

Add a `managed_session_id` field to link audit entries to managed sessions:

```sql
ALTER TABLE audit_log ADD COLUMN managed_session_id TEXT;
ALTER TABLE audit_log ADD COLUMN delegation_chain TEXT;
-- JSON array of agent_ids showing delegation path, e.g. ["root_agent", "researcher_agent"]
-- Populated for multi-agent sessions; null for single-agent sessions
```

### 5.3 New: `managed_agent_configs` table

```sql
CREATE TABLE managed_agent_configs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    name TEXT NOT NULL,
    anthropic_model TEXT DEFAULT 'claude-sonnet-4-6',
    system_prompt TEXT,
    governance_profile TEXT,        -- JSON: allowed tools, approval rules, budget
    allowed_tools TEXT,             -- JSON array of tool names
    max_session_hours REAL,
    max_daily_sessions INTEGER,
    require_human_approval TEXT,    -- JSON: tool patterns that need approval
    parent_agent_id TEXT,           -- For multi-agent: parent config ID (null = root agent)
    max_delegation_depth INTEGER DEFAULT 1,  -- How many sub-agent levels allowed
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id),
    FOREIGN KEY (parent_agent_id) REFERENCES managed_agent_configs(id)
);
```

---

## 6. Implementation Phases

### Phase 1: MCP Server (Weeks 1-3)

Build `gateway/mcp_server.py` implementing the MCP protocol over HTTP+SSE transport. This is the highest-value deliverable — it enables active governance.

**Tasks:**
- Implement MCP `initialize`, `tools/list`, `tools/call` handlers.
- Wire `tools/call` into existing governance pipeline (OPA, HSM, audit).
- Implement authentication (API key + OAuth client credentials).
- Add `source` field to audit log.
- Build tenant-scoped tool catalog (dynamic `tools/list` based on policy).
- Test with a real managed agent session.

**Exit criteria:** A managed agent session can call tools through Vargate's MCP server, with policy evaluation, audit logging, and credential brokering all functioning.

### Phase 2: Event Consumer (Weeks 3-5)

Build `gateway/event_consumer.py` to subscribe to managed agent SSE streams.

**Tasks:**
- Implement SSE client for Anthropic's event stream API.
- Parse `agent.tool_use` and `agent.message` events.
- Log observed events to audit chain with `source: 'mcp_observed'`.
- Feed events into Redis behavioral analysis.
- Implement anomaly detection rules for built-in tools.
- Include observed events in Merkle tree aggregation.

**Exit criteria:** All tool executions in a managed agent session (governed and built-in) appear in the tenant's audit log and Merkle trees.

### Phase 3: Control Plane (Weeks 5-8)

Build the API wrapper that makes Vargate the entry point for managed agent sessions.

**Tasks:**
- Implement `/managed/agents`, `/managed/sessions`, `/managed/environments` endpoints.
- System prompt injection with governance context.
- Agent config validation against tenant policy.
- Session budget enforcement.
- Auto-attach event consumer on session creation.
- Emergency interrupt endpoint.
- Per-session compliance export.

**Exit criteria:** A customer can create, govern, monitor, and audit a complete managed agent session lifecycle through Vargate's API.

### Phase 4: Dashboard & Compliance (Weeks 8-10)

Extend the React dashboard and compliance export for managed agent sessions.

**Tasks:**
- Session list view with real-time status.
- Session detail view: timeline of governed + observed events.
- Visual distinction between actively governed and passively observed actions.
- Per-session compliance PDF export with Merkle proofs.
- Anomaly alerts in dashboard.

**Exit criteria:** An auditor can view any managed agent session's complete history, download a compliance artifact, and verify the cryptographic proofs.

---

## 7. Latency Considerations

Adding Vargate as a remote MCP server introduces a network round trip on every governed tool call. The managed agent's container makes an HTTP request to Vargate, which evaluates policy and brokers execution, then returns the result.

**Estimated latency budget:**

| Component | Current (direct) | With Vargate |
|-----------|-------------------|--------------|
| Network RTT (agent → Vargate) | — | 20-80ms |
| OPA policy evaluation | — | 5-15ms |
| Redis behavioral lookup | — | 2-5ms |
| HSM credential fetch | — | 5-10ms |
| Actual tool execution | 100-2000ms | 100-2000ms |
| **Total overhead** | **—** | **~30-110ms** |

For most tool calls (API calls, email, database queries), the tool execution itself dominates. 30-110ms of governance overhead is negligible. For latency-sensitive use cases, consider:

- **Policy evaluation caching:** Cache OPA decisions for identical inputs within a short TTL.
- **Edge deployment:** Run a Vargate node in the same cloud region as Anthropic's managed agent infrastructure.
- **Async audit logging:** Log to audit chain asynchronously after returning the tool result (trades some consistency for speed).

---

## 8. Security Considerations

### 8.1 Credential Flow

The managed agent never sees real credentials. The flow:

1. Agent calls `vargate_send_email` via MCP.
2. Vargate receives the call. The agent's MCP auth token identifies the tenant.
3. Vargate fetches the email API credential from HSM vault.
4. Vargate executes the API call with the real credential.
5. Vargate returns only the result to the agent.

This is identical to Vargate's existing credential brokering (AG-1.9), extended to managed agents.

### 8.2 MCP Authentication

The MCP server endpoint must be hardened:

- **IP allowlisting (primary layer):** Enterprise-tier managed agents have dedicated static egress IPs per workspace. Vargate's MCP endpoint should allowlist these IPs at the firewall level. Non-enterprise tiers use stable regional IP pools that can also be allowlisted.
- Rate limiting per API key.
- Mutual TLS for private networking deployments.
- Request signing to prevent replay attacks.
- Persistent session auth: authenticate once on MCP `initialize`, maintain session context for duration. No per-call re-auth needed (confirmed: connections are persistent per session).

### 8.3 Event Stream Security

The event consumer connects to Anthropic's API using the customer's API key. Vargate must:

- Store API keys encrypted in HSM vault (never in config files or environment variables).
- Scope API key access per tenant.
- Rotate keys on schedule.

### 8.4 Governance Bypass Risk

The primary risk: an agent could use built-in tools (bash + curl) to bypass governed MCP tools and call APIs directly. Mitigations:

- System prompt injection explicitly instructs the agent not to bypass.
- Passive event consumer detects curl/wget/HTTP calls in bash events and flags them.
- Environment network rules can restrict outbound access to only Vargate's MCP server (strongest mitigation).
- Anomaly detection alerts on bypass attempts.

---

## 9. Pricing Model Implications

This integration creates a new pricing surface for Vargate:

| Tier | What's included | Target |
|------|----------------|--------|
| **Observe** | Passive event logging + audit chain + compliance export | Compliance-first teams |
| **Govern** | Active MCP governance + credential brokering + approval queue | Security-first teams |
| **Platform** | Full control plane + session management + budget enforcement | Enterprise platform teams |

Per-session pricing aligns naturally with Anthropic's $0.08/session-hour model. Vargate could charge per governed tool call, per session-hour of monitoring, or a flat monthly fee per tenant.

---

## 10. Resolved Questions (from Anthropic Documentation)

The following questions were open at initial drafting and have since been confirmed via Anthropic's managed agents documentation.

### 10.1 Egress IPs: CONFIRMED — Stable IPs Available

Enterprise-tier accounts get **dedicated egress IPs** that are static and assigned per workspace. Smaller tiers share a stable regional pool. This means Vargate's MCP server endpoint can be secured with standard IP allowlisting — no dynamic DNS or fragile workarounds needed.

**Impact on spec:** Section 8.2 (MCP Authentication) can rely on IP allowlisting as a primary security layer. This is the simplest and most reliable approach.

### 10.2 MCP Connection Lifecycle: CONFIRMED — Persistent per Session

The managed agent harness maintains a **persistent MCP transport** for the session duration, with lazy-loading on first tool call. When sessions idle (`session.status_idled`), the compute environment may suspend but connection state is preserved in the event log and resumes without re-handshake.

**Impact on spec:** Vargate's MCP server should maintain per-session state (tenant context, behavioral history) in memory for the session duration. On idle-resume, re-hydrate from the event log. No need for per-call auth overhead — authenticate once on `initialize`, maintain session.

### 10.3 Event Stream Completeness: CONFIRMED — Full Arguments and Results

The SSE stream emits `agent.tool_use` events with **full JSON arguments** and `agent.tool_result` events with **complete output**. This is forensic-grade — no summaries, no lossy compression.

**Impact on spec:** The passive event consumer (Layer 2) can produce audit records with the same fidelity as actively governed calls. This is critical for compliance — auditors get full visibility into built-in tool usage, not just metadata. The `decision: "observed"` distinction in audit records is a presentation choice, not a data quality compromise.

### 10.4 Interrupt Latency: CONFIRMED — Sub-second, but Race Condition Exists

The `user.interrupt` event signals the execution sandbox with **sub-second latency**. However, if a non-idempotent tool call is already in flight (e.g., funds transfer), the call may complete before the interrupt arrives. Anthropic's documentation recommends "confirmation gates" for sensitive tools.

**Impact on spec:** Vargate's human approval queue (AG-1.6) is exactly the "confirmation gate" Anthropic recommends. For governed tools routed through the MCP server, Vargate already holds non-idempotent actions in the approval queue. The interrupt endpoint is a second line of defense for anomaly detection on passively observed tools. The spec should document this as a **defense-in-depth** model: approval gates prevent dangerous governed calls from executing; interrupts stop runaway built-in tool usage.

### 10.5 Multi-agent Sessions: CONFIRMED — Delegation Model with Per-Agent Governance

In the multi-agent coordination preview, each agent inherits the parent agent's permissions unless explicitly scoped. Agent-to-agent calls are treated as `subagent_call` events. Separate governance profiles can be assigned per agent.

**Impact on spec:** Vargate should model multi-agent governance as a hierarchy. The control plane (Layer 3) assigns governance profiles per agent in a multi-agent session. When Agent A delegates to Agent B via `subagent_call`, Vargate's event consumer logs the delegation chain. The MCP server can enforce that sub-agents have equal or more restrictive policies than their parent — never more permissive. This maps naturally to AGCS AG-1.8 (per-tenant isolation) extended to per-agent isolation within a session.

**New design consideration for Phase 3:** Add a `parent_agent_id` field to `managed_agent_configs` and a `delegation_chain` field to audit log entries for multi-agent sessions.

### 10.6 Anthropic's Governance Roadmap: RESOLVED — Not a Competitive Threat

Anthropic's native governance roadmap focuses on **infrastructure-level guardrails**: sandboxing, CIDR allowlisting, and basic RBAC. These are safety features to make their platform enterprise-viable — not independent governance.

No model provider can credibly offer independent governance over their own models. It is a structural conflict of interest. CISOs, auditors, and SOC2/HIPAA assessors require separation of duties. Vargate's position as a non-model-building "Switzerland" is the durable moat.

Furthermore, Vargate can govern cross-vendor sessions — an Anthropic agent delegating to a Gemini sub-agent — which Anthropic has no incentive to support. Anthropic building governance features validates the category and moves agent governance from "niche security concern" to "mandatory enterprise requirement," expanding Vargate's addressable market.

---

## 10A. Remaining Open Questions

1. **Anthropic's regional infrastructure** — Where are managed agent containers hosted geographically? This affects Vargate edge deployment strategy for latency optimization (Section 7).

2. **MCP server rate limits** — Are there per-session or per-agent limits on MCP server calls beyond the documented 60 req/min create and 600 req/min read limits? Heavy governance workloads could hit undocumented ceilings.

3. **Event stream retention** — How long does Anthropic retain session event history? If Vargate's event consumer misses events (network interruption), can it backfill from Anthropic's event history API?

4. **Multi-agent GA timeline** — Multi-agent coordination is in research preview. Implementation of Phase 3 multi-agent governance features should be sequenced after GA to avoid building against an unstable API.

---

## 11. Strategic Value

This integration positions Vargate uniquely:

- **First mover:** No other governance product has announced managed agents integration.
- **AGCS validation:** Proves the standard is runtime-agnostic, not tied to Vargate's proxy.
- **Enterprise unlock:** Managed agents are aimed squarely at enterprise buyers — the same buyers who need governance and compliance. Vargate becomes a natural companion purchase.
- **Anthropic partnership potential:** Vargate could become a recommended governance partner in Anthropic's managed agents documentation, similar to how cloud providers recommend security partners.
- **Design partner leverage:** This is a compelling pitch to potential AGCS co-signatories — "help us define the governance standard for the most advanced agent runtime on the market."
- **Structural independence as moat:** No model provider (Anthropic, OpenAI, Google) can credibly offer independent governance over their own models — it is a fundamental conflict of interest. As long as Vargate does not build models, it occupies the "Switzerland" position: a neutral, independent governance layer that auditors and regulators can trust across any AI vendor. This is not a feature advantage — it is a structural one that cannot be replicated by any model provider, no matter how good their tooling.
