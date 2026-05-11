# Sprint Plan: Anthropic Managed Agents Integration

**Reference:** `specs/managed-agents-integration-spec.md`  
**Start Date:** TBD  
**Duration:** 6 sprints, 12 weeks  
**Cadence:** 2-week sprints  

---

## Sprint 9: MCP Server Protocol & Schema Migration

**Goal:** Stand up Vargate as a fully functional remote MCP server that managed agents can connect to, with active governance on every tool call.

**AGCS Controls:** AG-1.1, AG-1.2, AG-1.3, AG-1.4, AG-1.9, AG-1.11

### 9.1 — Schema migration for managed agent support

Add the new columns and tables required by the integration.

**Tasks:**

- Add `source TEXT DEFAULT 'direct'` column to `audit_log` table. Values: `direct`, `mcp_governed`, `mcp_observed`, `control_plane`.
- Add `managed_session_id TEXT` column to `audit_log` table.
- Add `delegation_chain TEXT` column to `audit_log` table (JSON array, null for single-agent sessions).
- Create `managed_sessions` table (see spec Section 5.1).
- Create `managed_agent_configs` table with `parent_agent_id` and `max_delegation_depth` fields (see spec Section 5.3).
- Write migration script. Test against existing audit data to confirm no regressions.
- Run existing test suite: `test_demo.py`, `test_hotswap.py`, `test_behavioral.py`, `test_replay.py`, `test_crypto_shredding.py`, `test_blockchain.py`.

**Exit criteria:** All existing tests pass with new schema. New columns default correctly. No impact on current `/mcp/tools/call` flow.

### 9.2 — MCP server protocol implementation

Build `gateway/mcp_server.py` — the MCP server that managed agents connect to over HTTP+SSE transport.

**Tasks:**

- Implement MCP `initialize` handler: capability negotiation, session establishment, tenant identification from auth token.
- Implement MCP `tools/list` handler: return tenant-scoped tool catalog. Tools are dynamically filtered based on the agent's governance profile in `managed_agent_configs`.
- Implement MCP `tools/call` handler: route into existing governance pipeline in `main.py` (OPA evaluation → behavioral analysis → PII detection → HSM credential brokering → audit logging).
- Set `source: 'mcp_governed'` on all audit records from this path.
- Return Vargate `action_id` (AG-1.3) in every MCP tool result for traceability.
- Implement MCP server authentication: API key bearer token with IP allowlisting for enterprise egress IPs.
- Add `/mcp/server` endpoint group to FastAPI app, separate from existing `/mcp/tools/call`.
- Write `test_mcp_server.py`: test initialize handshake, tools/list filtering, tools/call → OPA → audit pipeline, auth rejection.

**Exit criteria:** A local test client can connect to Vargate's MCP server, list tools, call a governed tool, and see the full audit chain entry with `source: 'mcp_governed'`.

### 9.3 — End-to-end test with Anthropic managed agent

**Tasks:**

- Create a test managed agent on Anthropic's platform configured with Vargate as a remote MCP server.
- Configure the agent's environment with network access to Vargate's endpoint.
- Run a session where the agent calls a governed tool (e.g., `vargate_send_email`).
- Verify: OPA policy evaluation fires, audit log entry created with correct `source`, credential never exposed to agent, action_id returned in tool result.
- Document any protocol compatibility issues or required adjustments.

**Exit criteria:** A real Anthropic managed agent session successfully calls tools through Vargate's MCP server with full governance.

---

## Sprint 10: Event Stream Consumer & Passive Observability

**Goal:** Full passive observability — every tool execution in a managed agent session (governed and built-in) appears in Vargate's audit trail and Merkle trees.

**AGCS Controls:** AG-1.2, AG-1.5, AG-1.10, AG-2.1, AG-2.2

### 10.1 — SSE event stream client

Build `gateway/event_consumer.py` — subscribes to Anthropic's managed agent SSE streams and logs all activity.

**Tasks:**

- Implement async SSE client for `GET /v1/sessions/{id}/events` using `httpx` or `aiohttp`.
- Handle connection lifecycle: initial connect, reconnect on failure, idle/resume handling (managed agents preserve connection state across `session.status_idled`).
- Parse `agent.tool_use` events: extract full JSON arguments (confirmed: SSE stream includes complete arguments, not summaries).
- Parse `agent.tool_result` events: extract complete tool output.
- Parse `agent.message` events: capture agent reasoning for decision transparency (AG-1.5).
- Store Anthropic API keys per tenant in HSM vault (never in config or env vars).
- Write `test_event_consumer.py` with mock SSE stream.

**Exit criteria:** Event consumer can connect to a managed agent session's SSE stream, parse all event types, and output structured event data.

### 10.2 — Passive audit logging pipeline

Wire event consumer output into Vargate's existing audit and behavioral analysis systems.

**Tasks:**

- Log observed tool executions to audit chain with `source: 'mcp_observed'`, `decision: 'observed'`.
- Link entries to `managed_session_id` for session-level querying.
- Feed observed events into Redis behavioral analysis: action counts, tool usage patterns, anomaly scoring (AG-1.10).
- Include passively observed events in hourly Merkle tree aggregation (AG-2.2).
- Ensure blockchain anchoring picks up observed events alongside governed events (AG-2.3).
- Verify hash chain integrity with mixed `source` types (direct + mcp_governed + mcp_observed).

**Exit criteria:** A managed agent session's complete tool history (governed + built-in) appears in the tenant's audit log, Merkle trees, and blockchain anchors.

### 10.3 — Anomaly detection for built-in tools

**Tasks:**

- Define anomaly rules for passively observed built-in tools:
  - Bash: flag commands matching dangerous patterns (`rm -rf`, `curl` to non-allowlisted domains, credential file access, base64-encoded payloads).
  - File ops: flag rapid bulk reads, access to unexpected directories, large file writes.
  - Web fetch: flag requests to domains outside tenant's allowlist.
- Implement pattern matching in event consumer (regex-based, configurable per tenant).
- When anomaly detected: log alert to audit chain, fire webhook (AG-2.7), increment Redis anomaly score.
- Write `test_anomaly_detection.py` with test cases for each pattern category.

**Exit criteria:** Anomalous built-in tool usage is detected, logged, and surfaced via webhook. False positive rate validated against normal session activity.

---

## Sprint 11: Control Plane & Session Governance

**Goal:** Vargate becomes the entry point for managed agent session lifecycle — creation, configuration, monitoring, and termination.

**AGCS Controls:** AG-1.6, AG-1.7, AG-1.8, AG-2.7, AG-2.9

### 11.1 — Session lifecycle API

Build the control plane endpoints that wrap the Anthropic managed agents API.

**Tasks:**

- Implement `POST /managed/agents` — register a managed agent configuration with governance profile. Validate against tenant policy: allowed tools, approval rules, budget caps, delegation depth.
- Implement `POST /managed/sessions` — create a governed session:
  - Validate agent config against tenant policy.
  - Check session budget (max_session_hours, max_daily_sessions).
  - Call Anthropic `POST /v1/sessions` with Vargate injected as remote MCP server.
  - Inject governance context into system prompt (see spec Section 3, Layer 3).
  - Auto-attach event consumer to the new session's SSE stream.
  - Create `managed_sessions` record.
  - Return Vargate session ID to caller.
- Implement `GET /managed/sessions/{id}/status` — session status with governance summary (total governed/observed/denied/pending counts).
- Implement `GET /managed/sessions` — list sessions for tenant with filtering (status, date range, agent).
- Write `test_control_plane.py`.

**Exit criteria:** A customer can create a fully governed managed agent session through Vargate's API. Session automatically has MCP governance + passive monitoring attached.

### 11.2 — Emergency interrupt & safety controls

**Tasks:**

- Implement `POST /managed/sessions/{id}/interrupt` — sends `user.interrupt` event to Anthropic session. Log interrupt to audit chain with reason and context.
- Wire anomaly detection (Sprint 10.3) to auto-interrupt: when anomaly score exceeds tenant-configured threshold, trigger interrupt automatically.
- Implement rate limiting per tenant on session creation (AG-1.7): max concurrent sessions, max daily sessions, max session-hours per billing period.
- Implement gateway constraint checks (AG-2.9) at session creation time: blocked agent configurations, required approval for high-risk tool sets.
- Document defense-in-depth model: approval gates prevent dangerous governed calls; interrupts stop runaway built-in tool usage.
- Write `test_interrupt.py`, `test_session_limits.py`.

**Exit criteria:** Emergency interrupt works end-to-end. Auto-interrupt fires on anomaly threshold. Session rate limits enforced.

### 11.3 — System prompt governance injection

**Tasks:**

- Build configurable system prompt injection templates per tenant. Default template covers: governance disclosure, approval queue behavior, bypass prohibition, audit transparency.
- Store `system_prompt_hash` (SHA-256) in `managed_sessions` for audit trail — proves what governance instructions the agent received.
- Allow tenant-level customization of injection template (add domain-specific rules, compliance language).
- Ensure injected prompt is appended (not prepended) to preserve the agent's primary instructions.
- Test: verify agent behavior with and without governance injection. Confirm agent correctly handles `pending_approval` tool results.

**Exit criteria:** Every session created through the control plane has governance instructions injected and hashed for audit.

---

## Sprint 12: Dashboard & Compliance Export

**Goal:** Auditors can view any managed agent session's complete history, download compliance artifacts, and verify cryptographic proofs.

**AGCS Controls:** AG-1.5, AG-2.1, AG-2.3, AG-2.4, AG-2.8

### 12.1 — Managed sessions dashboard

Extend the React UI with managed agent session views.

**Tasks:**

- New component: `ManagedSessionList.jsx` — table of managed sessions with status indicators (active/green, completed/grey, interrupted/red), governed/observed call counts, anomaly alerts.
- New component: `ManagedSessionDetail.jsx` — session timeline showing every event (governed and observed) in chronological order:
  - Governed calls: show tool name, args, OPA decision, violations, execution result. Green/red indicators.
  - Observed calls: show tool name, args, result. Blue "observed" indicator. Anomaly flags in orange.
  - Agent messages: show reasoning text (collapsible).
  - Interrupts: show timestamp, reason, who triggered (auto vs. manual).
- Visual distinction between actively governed and passively observed actions (different colors, icons, labels).
- Filter/search: by tool type, decision, source, time range.
- Link from session detail to existing audit log, Merkle proof viewer, and blockchain anchor verification.
- Wire into existing dashboard navigation.

**Exit criteria:** A user can browse managed agent sessions and drill into any session's full timeline with governed/observed distinction.

### 12.2 — Per-session compliance export

**Tasks:**

- Implement `GET /managed/sessions/{id}/compliance` — generate compliance artifact for a single managed session:
  - Session metadata: agent config, governance profile, system prompt hash, start/end time, duration.
  - Complete event timeline: governed calls with OPA decisions + observed calls with anomaly flags.
  - Hash chain verification: prove audit entries are contiguous and untampered.
  - Merkle inclusion proofs: prove session events are included in tenant Merkle trees.
  - Blockchain anchor references: link to on-chain transaction hashes.
  - Summary statistics: total calls by type, denial rate, anomaly count, approval queue usage.
- Output formats: JSON (machine-readable) and PDF (auditor-readable).
- Extend existing `/compliance/export/{tenant_id}` to include managed session data.
- Write `test_compliance_export.py`.

**Exit criteria:** An auditor can download a self-contained compliance artifact for any managed agent session with cryptographic proofs that can be independently verified.

### 12.3 — Decision replay for managed agent sessions

**Tasks:**

- Extend `POST /audit/replay` (AG-2.8) to support replaying managed agent session events.
- For governed calls: replay the OPA evaluation using the stored `opa_input` snapshot against current or historical policy.
- For observed calls: replay anomaly detection rules against stored event data to check if current rules would have flagged them.
- Add session-level bulk replay: `POST /managed/sessions/{id}/replay` — replays all governed events in a session against a specified policy version.
- Use case: "If we had deployed Policy v3.2 during this session, which calls would have been blocked?"

**Exit criteria:** Policy drift detection works for managed agent sessions. Auditors can answer counterfactual questions about governance outcomes.

---

## Sprint 13: Docs Site — Managed Agents Setup Guide

**Goal:** A comprehensive, developer-facing guide on the docs site that walks users through setting up Claude managed agents with Vargate governance, from first connection to production deployment.

### 13.1 — Docs site: managed agents overview & architecture

Create `docs-site/docs/managed-agents/overview.md`.

**Content:**

- What are Anthropic managed agents (brief, link to Anthropic's docs for detail).
- Why managed agents need independent governance (the compliance gap).
- Vargate's three-layer integration model: diagram + plain-English explanation of active governance (MCP server), passive observability (event consumer), and control plane.
- AGCS control mapping summary — which controls apply and how.
- Prerequisites: Vargate account, Anthropic API key, enterprise egress IPs (recommended).

### 13.2 — Docs site: step-by-step setup guide

Create `docs-site/docs/managed-agents/setup.md`.

**Content — structured as a walkthrough with code examples at every step:**

**Step 1: Register your Anthropic API key with Vargate**
- Store Anthropic API key in Vargate's HSM vault.
- Curl example: `POST /credentials/register` with `tool_id: "anthropic"`.

**Step 2: Create a managed agent configuration**
- Define governance profile: allowed tools, approval rules, budget caps.
- Curl + Python + Node.js examples: `POST /managed/agents`.
- Explain each field: `allowed_tools`, `require_human_approval`, `max_session_hours`, `max_daily_sessions`.

**Step 3: Configure Vargate as a remote MCP server on your managed agent**
- Anthropic agent config JSON showing Vargate's MCP server URL, auth, and timeout.
- How to set up IP allowlisting (enterprise egress IPs → Vargate firewall).
- How to configure environment network rules for Vargate access.
- Show the complete agent creation API call to Anthropic with Vargate as MCP server.

**Step 4: Create a governed session**
- Curl + Python + Node.js examples: `POST /managed/sessions`.
- Explain what happens under the hood: Vargate calls Anthropic, injects governance prompt, attaches event consumer.
- Show the response with Vargate session ID.

**Step 5: Interact with the session**
- Send events to the session (directly to Anthropic or proxied through Vargate).
- Watch governed tool calls flow through: agent calls tool → Vargate evaluates → OPA decision → execution or denial → audit log.
- Show real-time audit log entries appearing with `source: 'mcp_governed'` and `source: 'mcp_observed'`.

**Step 6: Handle approvals**
- When a tool call requires human approval: what the agent sees, what the dashboard shows, how to approve/reject.
- Curl example: `POST /approve/{action_id}`.
- Webhook configuration for approval notifications.

**Step 7: Review session audit trail**
- View session timeline in dashboard.
- Download compliance export: `GET /managed/sessions/{id}/compliance`.
- Verify Merkle proofs and blockchain anchors.

### 13.3 — Docs site: policy templates for managed agents

Create `docs-site/docs/managed-agents/policies.md`.

**Content:**

- Recommended OPA/Rego policy patterns for managed agent governance.
- Template: "Allow read-only tools, require approval for writes" — common starting point.
- Template: "Budget-capped session" — deny tool calls after spend threshold.
- Template: "PII-sensitive session" — auto-encrypt, require approval for external sends.
- Template: "Research-only agent" — block all mutation tools, allow only read/search.
- How to customize: extend templates with tenant-specific rules.
- How policy versioning works with managed sessions (bundle revision linked to every audit record).

### 13.4 — Docs site: API reference for managed agent endpoints

Create `docs-site/docs/api/managed-agents.md`.

**Content:**

- Full API reference for all `/managed/*` endpoints:
  - `POST /managed/agents` — create agent config (request/response schema, field descriptions).
  - `GET /managed/agents` — list agent configs.
  - `POST /managed/sessions` — create governed session.
  - `GET /managed/sessions` — list sessions (filters: status, agent, date range).
  - `GET /managed/sessions/{id}/status` — session status + governance summary.
  - `POST /managed/sessions/{id}/interrupt` — emergency stop.
  - `GET /managed/sessions/{id}/audit` — session audit trail.
  - `GET /managed/sessions/{id}/compliance` — compliance export.
  - `POST /managed/sessions/{id}/replay` — session-level policy replay.
- Error codes and troubleshooting.
- Rate limit documentation.

### 13.5 — Docs site: update mkdocs.yml and cross-references

**Tasks:**

- Add "Managed Agents" section to `mkdocs.yml` nav:
  ```yaml
  - Managed Agents:
    - Overview: managed-agents/overview.md
    - Setup Guide: managed-agents/setup.md
    - Policy Templates: managed-agents/policies.md
  ```
- Add `managed-agents.md` to API Reference section.
- Add cross-links from existing pages: link to managed agents from quickstart.md, auth.md, and policy overview.
- Add managed agents examples to `examples/python.md`, `examples/nodejs.md`, `examples/curl.md`.

**Exit criteria:** A developer can follow the docs from zero to a fully governed managed agent session. All pages render correctly in MkDocs. Cross-references work. Code examples are copy-pasteable.

---

## Sprint 14: Integration Testing, Hardening & Launch

**Goal:** Production-ready managed agents integration with comprehensive test coverage, performance validation, and launch materials.

### 14.1 — Integration test suite

**Tasks:**

- End-to-end test: create agent config → create session → agent calls governed tool → OPA evaluates → HSM brokers → audit logged → Merkle tree includes → blockchain anchors.
- End-to-end test: passive monitoring — agent uses built-in tools → event consumer logs → anomaly detection fires → webhook sent.
- End-to-end test: approval flow — governed tool requires approval → agent gets pending result → human approves → tool executes → audit updated.
- End-to-end test: emergency interrupt — anomaly detected → auto-interrupt fires → session stopped → audit records complete.
- End-to-end test: compliance export — run a full session, generate PDF + JSON export, verify all Merkle proofs and blockchain references.
- Load test: simulate 50 concurrent managed agent sessions with mixed governed and observed tool calls. Measure latency overhead, audit throughput, Redis/OPA performance.
- Failure test: event consumer disconnect/reconnect. Verify no events lost (backfill from Anthropic event history API).
- Failure test: Vargate MCP server goes down mid-session. Verify managed agent gets clean error, audit records the failure.

**Exit criteria:** All integration tests pass. Latency overhead confirmed under 150ms p99. No data loss on failure scenarios.

### 14.2 — Security hardening

**Tasks:**

- Audit all new endpoints for auth/authz correctness: tenant isolation, API key scoping, rate limiting.
- Verify IP allowlisting works with Anthropic's enterprise egress IPs.
- Penetration test: attempt governance bypass via bash + curl in managed agent session. Confirm anomaly detection catches it.
- Verify Anthropic API keys are stored only in HSM vault, never logged, never in config.
- Review system prompt injection for prompt injection vulnerabilities — ensure governance instructions can't be overridden by user-supplied prompts.
- Run existing test suite in full: `test_demo.py`, `test_hotswap.py`, `test_behavioral.py`, `test_replay.py`, `test_crypto_shredding.py`, `test_blockchain.py`.

**Exit criteria:** Security review complete. No tenant isolation violations. No credential leaks. Bypass detection confirmed.

### 14.3 — Production deployment & launch

**Tasks:**

- Update `docker-compose.yml` and `docker-compose.prod.yml` for any new services or configuration.
- Deploy to production (`vargate@204.168.135.95`) using prod overlay.
- Verify health checks pass for all services.
- Enable managed agents feature for early-access tenants.
- Update marketing site (`site/`) with managed agents integration announcement.
- Publish blog post / changelog entry.

**Exit criteria:** Managed agents integration live in production. Early-access tenants onboarded. Docs site published.

---

## Sprint Summary

| Sprint | Weeks | Focus | Key Deliverable |
|--------|-------|-------|-----------------|
| 9 | 1–2 | MCP Server Protocol | Vargate as remote MCP server with active governance |
| 10 | 3–4 | Event Consumer | Passive observability for all tool activity |
| 11 | 5–6 | Control Plane | Session lifecycle governance + emergency interrupt |
| 12 | 7–8 | Dashboard & Compliance | Auditor-facing UI + cryptographic compliance exports |
| 13 | 9–10 | Documentation | Complete developer guide on docs site |
| 14 | 11–12 | Testing & Launch | Integration tests, security hardening, production deploy |

---

## Dependencies & Risks

**Dependencies:**

- Anthropic managed agents API remains stable through beta. Breaking changes could require rework in Sprints 9-11.
- Enterprise egress IP feature available to our test account (needed for Sprint 9.3 end-to-end test).
- Multi-agent coordination moves to GA before we build delegation governance (deferred — not in this plan).

**Risks:**

- **MCP protocol compatibility:** The MCP spec is evolving. Our implementation may need updates if Anthropic's managed agent harness uses a newer protocol version. Mitigation: build protocol version detection in `initialize` handler.
- **Event stream reliability:** If Anthropic's SSE stream drops events or has gaps, our passive audit records will be incomplete. Mitigation: implement backfill from event history API on reconnect (Sprint 14.1).
- **Latency sensitivity:** Some customers may be concerned about the ~30-110ms governance overhead on MCP calls. Mitigation: publish benchmarks, offer async audit logging mode, consider edge deployment for latency-sensitive accounts.
- **Managed agents pricing:** At $0.08/session-hour + Vargate governance fees, the total cost may concern price-sensitive customers. Mitigation: position Observe tier as low-cost entry point; Govern and Platform tiers for compliance-mandatory workloads.
