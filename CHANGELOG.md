# Changelog

All notable changes to Vargate are documented here.

---

## [Unreleased] — 2026-04-11

### Added — Managed Agents Integration (Sprints 9–14)

Vargate now provides full governance for [Anthropic Managed Agents](https://docs.anthropic.com/en/docs/agents/managed-agents) through a three-layer integration: active MCP governance, passive SSE observability, and session lifecycle control.

#### Active Governance (MCP Server)
- Vargate registers as a remote MCP server on managed agents
- Governed tools (email, payments, APIs) route through OPA policy, PII detection, HSM credential brokering, and approval gates before execution
- Six governed tools in the MCP catalog: `vargate_send_email`, `vargate_read_crm`, `vargate_update_crm`, `vargate_create_charge`, `vargate_create_transfer`, `vargate_post_slack`
- Every MCP tool result includes a Vargate `action_id` for end-to-end traceability

#### Passive Observability (Event Consumer)
- SSE event consumer subscribes to managed agent sessions and logs all built-in tool activity (bash, file ops, web fetch)
- Anomaly detection with 15 bash dangerous patterns, file access rules, and domain allowlisting
- Auto-interrupt when anomaly score exceeds configurable threshold
- Reconnect with backfill from Anthropic event history API on disconnect

#### Control Plane (Session Governance)
- `POST /managed/agents` — register agent configurations with governance profiles
- `POST /managed/sessions` — create governed sessions with automatic MCP server injection, governance prompt injection, and event consumer attachment
- `GET /managed/sessions/{id}/status` — live governance summary
- `POST /managed/sessions/{id}/interrupt` — emergency stop (manual or auto-triggered)
- `GET /managed/sessions/{id}/compliance` — per-session compliance export (JSON and PDF)
- `POST /managed/sessions/{id}/replay` — session-level policy replay for counterfactual analysis
- Rate limiting: max concurrent sessions, daily limits, per-agent quotas

#### Dashboard
- Managed Sessions view with status indicators, governed/observed/denied counts
- Session detail view with timeline, source/decision filters, emergency stop dialog
- Compliance export download and policy replay from the UI

#### Documentation
- Complete developer guide at [developer.vargate.ai/managed-agents/](https://developer.vargate.ai/managed-agents/)
- Step-by-step setup walkthrough with cURL, Python, and Node.js examples
- Five OPA/Rego policy templates for managed agent governance
- Full API reference for all `/managed/*` endpoints

#### AGCS Controls
Maps to all 18 AGCS controls (AG-1.1 through AG-2.9). See the [overview](https://developer.vargate.ai/managed-agents/overview/) for the complete control mapping.

---

## [Sprint 8] — 2026-03-28

### Added
- Failure mode configuration per tenant (fail-open, fail-closed, last-known)
- Blockchain anchor verification improvements

## [Sprint 7] — 2026-03-14

### Added
- Webhook notifications (HMAC-SHA256 signed, retry with backoff)
- Policy template system (financial, email, CRM, data access, general)
- Developer docs site at developer.vargate.ai

## [Sprint 6] — 2026-02-28

### Added
- Crypto-shredding for GDPR erasure (per-subject HSM keys)
- Merkle tree audit aggregation (AG-2.2)
- Blockchain anchoring with inclusion proofs (AG-2.3)

## [Sprint 5] — 2026-02-14

### Added
- Multi-chain blockchain anchoring (Polygon, Sepolia)
- Compliance export (JSON and PDF)
- Policy replay / decision replayability (AG-2.8)

## [Sprint 4] — 2026-01-31

### Added
- GTM agent safety constraints (blocked domains, daily cap, cooldown)
- Human-in-the-loop approval queue
- Credential brokering via HSM vault

## [Sprint 3] — 2026-01-17

### Added
- GitHub OAuth and email signup
- Multi-tenant isolation
- Onboarding wizard

## [Sprint 2] — 2026-01-03

### Added
- React dashboard with real-time activity feed
- Hash-chained audit trail
- OPA/Rego policy evaluation (two-pass)

## [Sprint 1] — 2025-12-20

### Added
- Initial Vargate proxy gateway
- Core MCP tool call interception
- SQLite audit logging
