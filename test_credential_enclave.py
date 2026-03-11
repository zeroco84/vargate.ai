#!/usr/bin/env python3
"""
Vargate Stage 8 — Credential Enclave & Agent-Blind Execution Tests

Tests the complete brokered execution pipeline:
1. Register credentials in HSM vault
2. Brokered tool calls (credential fetched, tool executed, result returned)
3. Denied actions (competitor, high-value OOH) still blocked
4. Missing credential causes OPA denial
5. Chain integrity preserved
6. Credential access log populated
"""

import json
import sys
import time
import requests

API = "http://localhost:8000"
PASS = 0
FAIL = 0


def test(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name} — {detail}")


def section(title):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}")


# ── 1. Register Credentials ────────────────────────────────────────────────

section("1. Register Tool Credentials in HSM Vault")

# Register credentials that match the mock tool server tokens
credentials_to_register = [
    {"tool_id": "gmail", "name": "api_key", "value": "mock-gmail-key-001"},
    {"tool_id": "salesforce", "name": "api_key", "value": "mock-salesforce-key-001"},
    {"tool_id": "stripe", "name": "api_key", "value": "mock-stripe-key-001"},
    {"tool_id": "slack", "name": "api_key", "value": "mock-slack-key-001"},
]

for cred in credentials_to_register:
    resp = requests.post(f"{API}/credentials/register", json=cred)
    data = resp.json()
    test(
        f"Register {cred['tool_id']}/{cred['name']}",
        resp.status_code == 200 and data.get("registered") is True,
        f"status={resp.status_code} body={data}",
    )

# Verify credentials are listed (no values returned)
resp = requests.get(f"{API}/credentials")
cred_list = resp.json()
test(
    "Credentials listed (no values)",
    len(cred_list.get("credentials", [])) >= 4,
    f"count={len(cred_list.get('credentials', []))}",
)

# Verify no credential values are exposed
for c in cred_list.get("credentials", []):
    test(
        f"No value exposed for {c['tool_id']}",
        "value" not in c and "encrypted" not in c and "secret" not in c,
        f"keys={list(c.keys())}",
    )


# ── 2. Brokered Execution — Salesforce Read ────────────────────────────────

section("2. Brokered Execution — Salesforce Read")

# Clean agent history
requests.delete(f"{API}/agents/agent-sales-001/history")

resp = requests.post(f"{API}/mcp/tools/call", json={
    "agent_id": "agent-sales-001",
    "tool": "salesforce",
    "method": "read_record",
    "params": {"object_type": "Opportunity", "record_id": "006Dn000003gZJH"},
})
data = resp.json()

test("Status 200 (allowed)", resp.status_code == 200)
test("Brokered mode", data.get("execution_mode") == "vargate_brokered", f"mode={data.get('execution_mode')}")
test("Has execution result", data.get("execution_result") is not None)
test("Result is simulated", data.get("execution_result", {}).get("simulated") is True)
test("Has latency breakdown", data.get("latency") is not None)
test(
    "Latency has all fields",
    all(k in data.get("latency", {}) for k in ["opa_eval_ms", "hsm_fetch_ms", "execution_ms", "total_ms"]),
)


# ── 3. Brokered Execution — Gmail Send ─────────────────────────────────────

section("3. Brokered Execution — Gmail Send")

requests.delete(f"{API}/agents/agent-comms-001/history")

resp = requests.post(f"{API}/mcp/tools/call", json={
    "agent_id": "agent-comms-001",
    "tool": "gmail",
    "method": "send_email",
    "params": {
        "to": "friendly@customer.com",
        "subject": "Meeting Confirmation",
        "body": "Looking forward to our call tomorrow.",
    },
})
data = resp.json()

test("Status 200 (allowed)", resp.status_code == 200)
test("Brokered mode", data.get("execution_mode") == "vargate_brokered", f"mode={data.get('execution_mode')}")
test("Gmail result has message_id", "message_id" in data.get("execution_result", {}))
test("Gmail result simulated", data.get("execution_result", {}).get("simulated") is True)


# ── 4. Denied — Competitor Contact Attempt ──────────────────────────────────

section("4. Denied — Competitor Contact Attempt (still blocked)")

requests.delete(f"{API}/agents/agent-bad-001/history")

resp = requests.post(f"{API}/mcp/tools/call", json={
    "agent_id": "agent-bad-001",
    "tool": "gmail",
    "method": "send_email",
    "params": {
        "to": "recruit@competitor.com",
        "subject": "Job offer",
        "body": "We'd like to discuss an opportunity.",
    },
    "context_override": {"is_business_hours": True},
})

test("Status 403 (denied)", resp.status_code == 403)
detail = resp.json().get("detail", {})
test(
    "Competitor violation",
    "competitor_contact_attempt" in detail.get("violations", []),
    f"violations={detail.get('violations')}",
)


# ── 5. Brokered Execution — Stripe Charge ──────────────────────────────────

section("5. Brokered Execution — Stripe Charge (within limits)")

requests.delete(f"{API}/agents/agent-billing-001/history")

resp = requests.post(f"{API}/mcp/tools/call", json={
    "agent_id": "agent-billing-001",
    "tool": "stripe",
    "method": "create_charge",
    "params": {
        "amount": 99.99,
        "currency": "gbp",
        "description": "Monthly subscription",
        "customer_id": "cus_test_001",
    },
    "context_override": {"is_business_hours": True},
})
data = resp.json()

test("Status 200 (allowed)", resp.status_code == 200)
test("Brokered mode", data.get("execution_mode") == "vargate_brokered", f"mode={data.get('execution_mode')}")
test("Stripe charge_id", "charge_id" in data.get("execution_result", {}))
test("Stripe simulated", data.get("execution_result", {}).get("simulated") is True)


# ── 6. Brokered Execution — Slack Post ─────────────────────────────────────

section("6. Brokered Execution — Slack Post")

requests.delete(f"{API}/agents/agent-notify-001/history")

resp = requests.post(f"{API}/mcp/tools/call", json={
    "agent_id": "agent-notify-001",
    "tool": "slack",
    "method": "post_message",
    "params": {
        "channel": "#deals",
        "text": "New opportunity created: Acme Corp $42K",
    },
    "context_override": {"is_business_hours": True},
})
data = resp.json()

test("Status 200 (allowed)", resp.status_code == 200)
test("Brokered mode", data.get("execution_mode") == "vargate_brokered", f"mode={data.get('execution_mode')}")
test("Slack ok", data.get("execution_result", {}).get("ok") is True)


# ── 7. Delete Credential — OPA Should Block ────────────────────────────────

section("7. Delete Credential — Missing Credential Denial")

# Delete the Stripe credential
resp = requests.delete(f"{API}/credentials/stripe/api_key")
test("Credential deleted", resp.status_code == 200)

# Give OPA time to get updated policy
time.sleep(1)

# Now try a Stripe call — should be denied
requests.delete(f"{API}/agents/agent-billing-002/history")

resp = requests.post(f"{API}/mcp/tools/call", json={
    "agent_id": "agent-billing-002",
    "tool": "stripe",
    "method": "create_charge",
    "params": {"amount": 50.00, "currency": "gbp"},
    "context_override": {"is_business_hours": True},
})

test("Status 403 (denied — no credential)", resp.status_code == 403)
detail = resp.json().get("detail", {})
test(
    "no_credential violation",
    "no_credential_registered_for_tool" in detail.get("violations", []),
    f"violations={detail.get('violations')}",
)

# Re-register for future tests
requests.post(f"{API}/credentials/register", json={
    "tool_id": "stripe", "name": "api_key", "value": "mock-stripe-key-001",
})


# ── 8. Credential Access Log ───────────────────────────────────────────────

section("8. Credential Access Log Verification")

resp = requests.get(f"{API}/credentials/access-log")
log_data = resp.json()
entries = log_data.get("entries", [])

test("Access log has entries", len(entries) > 0, f"count={len(entries)}")

# Verify log entries don't contain credential values
for entry in entries[:5]:
    test(
        f"No value in log entry ({entry.get('tool_id')}/{entry.get('name')})",
        "value" not in entry and "credential" not in entry and "secret" not in entry,
        f"keys={list(entry.keys())}",
    )


# ── 9. Audit Log — Execution Columns ──────────────────────────────────────

section("9. Audit Log — Stage 8 Columns")

resp = requests.get(f"{API}/audit/log?limit=10")
records = resp.json().get("records", [])

# Find a brokered record
brokered = [r for r in records if r.get("execution_mode") == "vargate_brokered"]
test("Brokered records in audit log", len(brokered) > 0)

if brokered:
    rec = brokered[0]
    test("execution_mode present", rec.get("execution_mode") == "vargate_brokered")
    test("execution_result present", rec.get("execution_result") is not None)
    test("execution_latency_ms present", rec.get("execution_latency_ms") is not None)
    test("credential_accessed present", rec.get("credential_accessed") is not None)
    test(
        "credential_accessed format",
        ":" in (rec.get("credential_accessed") or ""),
        f"value={rec.get('credential_accessed')}",
    )

# Find a denied record — should be agent_direct
denied = [r for r in records if r.get("decision") == "deny"]
if denied:
    test("Denied record is agent_direct", denied[0].get("execution_mode") == "agent_direct")


# ── 10. Chain Integrity ────────────────────────────────────────────────────

section("10. Chain Integrity After Stage 8")

resp = requests.get(f"{API}/audit/verify")
chain = resp.json()

test("Chain valid", chain.get("valid") is True, f"chain={chain}")
test(
    "Record count > 0",
    chain.get("record_count", 0) > 0,
    f"count={chain.get('record_count')}",
)


# ── Summary ────────────────────────────────────────────────────────────────

section("Test Summary")
total = PASS + FAIL
print(f"\n  PASSED: {PASS}/{total}")
print(f"  FAILED: {FAIL}/{total}")
if FAIL > 0:
    print(f"\n  ⚠ {FAIL} test(s) failed!")
    sys.exit(1)
else:
    print("\n  ✓ All Stage 8 tests passed!")
    sys.exit(0)
