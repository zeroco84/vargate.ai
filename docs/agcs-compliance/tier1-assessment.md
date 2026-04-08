# AGCS Tier 1 Self-Assessment — Vargate v1.0

Assessment date: 2026-04-08
Assessor: Automated (Claude Code)
System: Vargate Gateway v1.0.0
AGCS version: 0.9

---

## AG-1.1: Policy-Based Action Evaluation

**Status:** PASS

**Evidence:** Every tool call submitted to `POST /mcp/tools/call` is evaluated against OPA/Rego policy before execution. Two-pass evaluation (fast path + enriched with behavioral history) implemented in `gateway/main.py` lines 1691-1721. Policy rules in `policies/vargate/policy.rego` and `policies/vargate/gtm_policy.rego`. Five parameterized policy templates in `policies/templates/`.

**Verification:**
```bash
curl -X POST https://vargate.ai/api/mcp/tools/call \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_KEY" \
  -d '{"agent_id":"test","agent_type":"test","agent_version":"1.0.0","tool":"http","method":"GET","params":{"url":"https://example.com"}}'
# Returns: {"status": "allowed", "action_id": "..."} or HTTP 403 with violations
```

---

## AG-1.2: Immutable Audit Trail

**Status:** PASS

**Evidence:** Every action decision is written to a hash-chained SQLite audit log via `write_audit_record()` in `gateway/main.py`. Each record's `record_hash` includes the previous record's hash (`prev_hash`), creating a tamper-evident chain. Per-tenant isolation ensures one tenant's chain never includes another's records. Chain integrity verified via `GET /audit/verify`.

**Verification:**
```bash
curl https://vargate.ai/api/audit/verify -H "X-API-Key: YOUR_KEY"
# Returns: {"valid": true, "records_verified": N}
```

---

## AG-1.3: Action Identification

**Status:** PASS

**Evidence:** Every action receives a unique `action_id` (UUID v4) assigned at submission time in `gateway/main.py` line 1674. The action_id is returned to the caller in the API response and stored in the audit log. It serves as the primary key for replay, proof, and erasure operations.

**Verification:**
```bash
# Response from /mcp/tools/call always includes action_id
{"status": "allowed", "action_id": "550e8400-e29b-41d4-a716-446655440000"}
```

---

## AG-1.4: Agent Identification

**Status:** PASS

**Evidence:** Every tool call requires `agent_id` in the request body. The `ToolCallRequest` Pydantic model enforces `agent_id` as a required string field with `min_length=1` and `max_length=256`. Additional fields `agent_type` and `agent_version` (semver format) provide further identification. All are stored in the audit log.

**Verification:**
```bash
# Submitting without agent_id returns HTTP 422 validation error
curl -X POST https://vargate.ai/api/mcp/tools/call \
  -H "Content-Type: application/json" -H "X-API-Key: YOUR_KEY" \
  -d '{"tool":"http","method":"GET","params":{}}'
# Returns: 422 with "agent_id: field required"
```

---

## AG-1.5: Decision Transparency

**Status:** PASS

**Evidence:** The governance decision (allow/deny/pending_approval), violation list, severity, and alert tier are returned in the API response and stored in the audit log. Public transparency endpoints at `GET /transparency` and `GET /transparency/{tenant_id}` in `gateway/transparency.py`. Public dashboards via `GET /dashboard/public/{slug}` provide aggregate statistics without authentication.

**Verification:**
```bash
curl https://vargate.ai/api/transparency
# Returns aggregate decision statistics across all public tenants

curl https://vargate.ai/api/audit/log?limit=5 -H "X-API-Key: YOUR_KEY"
# Returns recent audit records with full decision details
```

---

## AG-1.6: Human Override Capability

**Status:** PASS

**Evidence:** Human-in-the-loop approval queue implemented in `gateway/approval.py` and `gateway/routes_tenant.py`. When OPA returns `requires_human=true`, the action is enqueued (not executed). Execution only proceeds after explicit human approval via `POST /approve/{action_id}`. Rejection via `POST /reject/{action_id}`. Pending queue viewable via `GET /approvals`.

**Verification:**
```bash
curl https://vargate.ai/api/approvals -H "X-API-Key: YOUR_KEY"
# Returns list of actions pending human review

curl -X POST https://vargate.ai/api/approve/{action_id} \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"note": "Approved by admin"}'
# Returns: {"status": "approved", "action_id": "..."}
```

---

## AG-1.7: Rate Limiting and Abuse Prevention

**Status:** PASS

**Evidence:** Two-layer rate limiting:
1. **Per-tenant:** Redis sliding window rate limiting with configurable `rate_limit_rps` and `rate_limit_burst` per tenant. Implemented in `gateway/main.py` lines 948-979.
2. **Per-IP:** IP-based rate limiting via Redis sorted set sliding window in `gateway/rate_limit.py`. Applied to auth endpoints (signup: 5/min, verify-email: 10/min, github callback: 10/min) and sensitive operations (erase: 5/min, backup: 5/min).

Exceeding limits returns HTTP 429 with rate limit details.

**Verification:**
```bash
# Rapid requests trigger 429
for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST https://vargate.ai/api/mcp/tools/call ...; done
# Eventually returns: 429
```

---

## AG-1.8: Per-Tenant Isolation

**Status:** PASS

**Evidence:** Multi-tenancy with strict isolation implemented in Sprint 2. Each tenant has:
- Independent hash chain (GENESIS per tenant) — `gateway/main.py` line 547
- Scoped Redis state (keys prefixed with `t:{tenant_id}:`) — behavioral history, rate limits
- Tenant-scoped database queries (`WHERE tenant_id = ?` on all audit/approval queries)
- Independent API keys with rotation support (`POST /api-keys/rotate`)
- Separate Merkle trees per tenant (hourly, `gateway/merkle.py` line 145)

Architecture constraint documented in `CLAUDE.md`: "One tenant's audit chain must never include another tenant's records."

**Verification:**
```bash
# Each tenant's audit log only shows their own records
curl https://vargate.ai/api/audit/log -H "X-API-Key: TENANT_A_KEY"
curl https://vargate.ai/api/audit/log -H "X-API-Key: TENANT_B_KEY"
# Results are disjoint — no cross-tenant leakage
```

---

## AG-1.9: Credential Brokering (Agent-Blind Execution)

**Status:** PASS

**Evidence:** Agents never see credentials. The HSM vault (`hsm/hsm_service.py`) brokers execution: agents submit tool calls, the proxy looks up credentials from the SoftHSM2-backed vault and executes on their behalf. Implemented in `gateway/execution_engine.py` with brokered execution path in `gateway/main.py` lines 1777-1833. Credential access is logged in the audit trail (`credential_accessed` field) but credential values are never stored or returned.

**Verification:**
```bash
# Register a credential (admin operation)
curl -X POST https://vargate.ai/api/credentials \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"tool_id":"stripe","name":"api_key","value":"sk_live_..."}'

# Subsequent tool calls to "stripe" are brokered — agent never sees the key
# Audit log shows execution_mode="vargate_brokered"
```

---

## AG-1.10: Behavioral Analysis

**Status:** PASS

**Evidence:** Two-pass evaluation with behavioral history enrichment. Pass 1 is a fast path (no Redis). If the action needs enrichment or the agent has prior violations, Pass 2 fetches behavioral history from Redis including: action counts, denied counts, high-value transaction counts, anomaly score, and cooldown status. Anomaly scoring is stored per-agent and influences subsequent policy decisions. Implemented in `gateway/main.py` lines 1700-1721.

**Verification:**
```bash
curl https://vargate.ai/api/agents/{agent_id}/anomaly_score -H "X-API-Key: YOUR_KEY"
# Returns: {"agent_id": "...", "anomaly_score": 0.123456}
```

---

## AG-1.11: PII Detection and Protection

**Status:** PASS

**Evidence:** Automatic PII detection via regex patterns in `gateway/main.py` line 58+. Detected PII fields are encrypted via HSM before storage in the audit log. Crypto-shredding enables GDPR erasure: destroying the HSM key renders ciphertext irrecoverable. PII metadata tracked via `contains_pii`, `pii_subject_id`, and `pii_fields` columns in `audit_log`.

**Verification:**
```bash
# Submit action with PII in params — PII is auto-detected and encrypted
# Verify with audit log: contains_pii=1, pii_fields listed

# GDPR erasure
curl -X POST https://vargate.ai/api/audit/erase/{subject_id} -H "X-API-Key: YOUR_KEY"
# Verify irreversibility
curl https://vargate.ai/api/audit/erase/{subject_id}/verify -H "X-API-Key: YOUR_KEY"
```

---

## Summary

| Control | Status | Implementation |
|---------|--------|----------------|
| AG-1.1 | PASS | OPA/Rego two-pass policy evaluation |
| AG-1.2 | PASS | Hash-chained SQLite audit log |
| AG-1.3 | PASS | UUID v4 action identification |
| AG-1.4 | PASS | Required agent_id with validation |
| AG-1.5 | PASS | Decision transparency + public dashboards |
| AG-1.6 | PASS | Human-in-the-loop approval queue |
| AG-1.7 | PASS | Per-tenant + per-IP rate limiting |
| AG-1.8 | PASS | Strict per-tenant isolation |
| AG-1.9 | PASS | HSM-backed credential brokering |
| AG-1.10 | PASS | Two-pass behavioral analysis |
| AG-1.11 | PASS | PII detection + crypto-shredding |

**Overall Tier 1 Status: PASS (11/11 controls)**

> Note: This self-assessment is based on codebase analysis. The full AGCS v0.9 standard should be referenced for any controls not listed here. A third-party assessment is recommended for formal certification.
