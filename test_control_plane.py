#!/usr/bin/env python3
"""
Vargate — Control Plane Test Suite (Sprint 11)

Tests managed agent session lifecycle: agent config creation, session
creation, status, listing, interrupt, and governance prompt injection.
"""

import json
import os
import sys
import time

import requests

GATEWAY_URL = os.environ.get("VARGATE_URL", "http://localhost:8000")
MANAGED_BASE = f"{GATEWAY_URL}/managed"

# ── ANSI colours ─────────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"

passed = 0
failed = 0


def check(label, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  {GREEN}PASS{RESET} {label}")
    else:
        failed += 1
        print(f"  {RED}FAIL{RESET} {label}")
        if detail:
            print(f"       {DIM}{detail}{RESET}")


def get_api_key():
    key = os.environ.get("VARGATE_API_KEY")
    if key:
        return key
    print(f"{RED}ERROR: Set VARGATE_API_KEY environment variable{RESET}")
    sys.exit(1)


def wait_for_gateway():
    print(f"{DIM}Waiting for gateway to be ready...{RESET}", end=" ", flush=True)
    for _ in range(30):
        try:
            r = requests.get(f"{GATEWAY_URL}/health", timeout=2)
            if r.status_code == 200:
                print(f"{GREEN}ready!{RESET}")
                return
        except Exception:
            pass
        time.sleep(1)
    print(f"{RED}timeout{RESET}")
    sys.exit(1)


def headers(api_key):
    return {"X-API-Key": api_key, "Content-Type": "application/json"}


# ── Tests ────────────────────────────────────────────────────────────────────


def test_create_agent_config(api_key):
    """Test creating a managed agent configuration."""
    print(f"\n{BOLD}Test 1: Create Agent Config{RESET}")
    r = requests.post(
        f"{MANAGED_BASE}/agents",
        headers=headers(api_key),
        json={
            "name": "test-research-agent",
            "anthropic_model": "claude-sonnet-4-6",
            "allowed_tools": ["vargate_read_crm", "vargate_send_email"],
            "max_session_hours": 2.0,
            "max_daily_sessions": 10,
            "require_human_approval": ["vargate_send_email"],
            "max_delegation_depth": 1,
        },
    )
    check("Returns 200", r.status_code == 200, f"Got {r.status_code}: {r.text[:200]}")
    data = r.json()
    check("Has ID", "id" in data)
    check("Name matches", data.get("name") == "test-research-agent")
    check("Model matches", data.get("anthropic_model") == "claude-sonnet-4-6")
    check("Allowed tools set", data.get("allowed_tools") == ["vargate_read_crm", "vargate_send_email"])
    check("Max session hours set", data.get("max_session_hours") == 2.0)
    check("Max daily sessions set", data.get("max_daily_sessions") == 10)

    return data.get("id")


def test_list_agent_configs(api_key, expected_id):
    """Test listing agent configs."""
    print(f"\n{BOLD}Test 2: List Agent Configs{RESET}")
    r = requests.get(f"{MANAGED_BASE}/agents", headers=headers(api_key))
    check("Returns 200", r.status_code == 200)
    data = r.json()
    check("Has configs array", "configs" in data)
    check("At least 1 config", data.get("count", 0) >= 1)

    ids = [c["id"] for c in data.get("configs", [])]
    check("Created config in list", expected_id in ids)


def test_get_agent_config(api_key, config_id):
    """Test getting a specific agent config."""
    print(f"\n{BOLD}Test 3: Get Agent Config{RESET}")
    r = requests.get(f"{MANAGED_BASE}/agents/{config_id}", headers=headers(api_key))
    check("Returns 200", r.status_code == 200)
    data = r.json()
    check("ID matches", data.get("id") == config_id)

    # 404 for nonexistent
    r2 = requests.get(f"{MANAGED_BASE}/agents/nonexistent-id", headers=headers(api_key))
    check("404 for nonexistent config", r2.status_code == 404)


def test_create_session(api_key, agent_id):
    """Test creating a governed managed agent session."""
    print(f"\n{BOLD}Test 4: Create Governed Session{RESET}")
    r = requests.post(
        f"{MANAGED_BASE}/sessions",
        headers=headers(api_key),
        json={
            "agent_id": agent_id,
            "user_message": "Please research our latest CRM records.",
        },
    )
    check("Returns 200", r.status_code == 200, f"Got {r.status_code}: {r.text[:200]}")
    data = r.json()
    check("Has session_id", "session_id" in data)
    check("Has anthropic_session_id", "anthropic_session_id" in data)
    check("Status is active", data.get("status") == "active")
    check("Governance is active", data.get("governance") == "active")
    check("Has system_prompt_hash", bool(data.get("system_prompt_hash")))
    check("Has MCP server URL", bool(data.get("mcp_server_url")))
    check("Has created_at", bool(data.get("created_at")))

    # Invalid agent ID
    r2 = requests.post(
        f"{MANAGED_BASE}/sessions",
        headers=headers(api_key),
        json={"agent_id": "nonexistent-agent"},
    )
    check("404 for nonexistent agent", r2.status_code == 404)

    return data.get("session_id")


def test_list_sessions(api_key, expected_session_id):
    """Test listing sessions with filters."""
    print(f"\n{BOLD}Test 5: List Sessions{RESET}")
    r = requests.get(f"{MANAGED_BASE}/sessions", headers=headers(api_key))
    check("Returns 200", r.status_code == 200)
    data = r.json()
    check("Has sessions array", "sessions" in data)
    check("At least 1 session", data.get("count", 0) >= 1)

    ids = [s["id"] for s in data.get("sessions", [])]
    check("Created session in list", expected_session_id in ids)

    # Filter by status
    r2 = requests.get(
        f"{MANAGED_BASE}/sessions",
        headers=headers(api_key),
        params={"status": "active"},
    )
    check("Status filter works", r2.status_code == 200)


def test_session_status(api_key, session_id):
    """Test getting session status with governance summary."""
    print(f"\n{BOLD}Test 6: Session Status{RESET}")
    r = requests.get(
        f"{MANAGED_BASE}/sessions/{session_id}/status",
        headers=headers(api_key),
    )
    check("Returns 200", r.status_code == 200)
    data = r.json()
    check("Has session_id", data.get("session_id") == session_id)
    check("Has status", "status" in data)
    check("Has governance_summary", "governance_summary" in data)
    check("Has system_prompt_hash", bool(data.get("system_prompt_hash")))

    summary = data.get("governance_summary", {})
    check("Summary has governed count", "total_governed_calls" in summary)
    check("Summary has observed count", "total_observed_calls" in summary)
    check("Summary has denied count", "total_denied" in summary)

    # 404 for nonexistent
    r2 = requests.get(
        f"{MANAGED_BASE}/sessions/nonexistent/status",
        headers=headers(api_key),
    )
    check("404 for nonexistent session", r2.status_code == 404)


def test_session_audit(api_key, session_id):
    """Test getting session audit trail."""
    print(f"\n{BOLD}Test 7: Session Audit Trail{RESET}")
    r = requests.get(
        f"{MANAGED_BASE}/sessions/{session_id}/audit",
        headers=headers(api_key),
    )
    check("Returns 200", r.status_code == 200)
    data = r.json()
    check("Has records array", "records" in data)

    # Should have at least the session creation audit entry
    records = data.get("records", [])
    check("Has audit records", len(records) >= 1, f"Got {len(records)}")

    if records:
        # Check the session creation record
        create_rec = [r for r in records if r.get("method") == "create_session"]
        check("Session creation logged", len(create_rec) >= 1)
        if create_rec:
            check("Source is control_plane", create_rec[0].get("source") == "control_plane")


def test_interrupt_session(api_key, session_id):
    """Test emergency interrupt."""
    print(f"\n{BOLD}Test 8: Emergency Interrupt{RESET}")
    r = requests.post(
        f"{MANAGED_BASE}/sessions/{session_id}/interrupt",
        headers=headers(api_key),
        json={
            "reason": "Test interrupt — verifying emergency stop functionality",
            "auto_triggered": False,
        },
    )
    check("Returns 200", r.status_code == 200, f"Got {r.status_code}: {r.text[:200]}")
    data = r.json()
    check("Status is interrupted", data.get("status") == "interrupted")
    check("Reason preserved", "Test interrupt" in data.get("reason", ""))
    check("Has ended_at", bool(data.get("ended_at")))

    # Verify session status updated
    r2 = requests.get(
        f"{MANAGED_BASE}/sessions/{session_id}/status",
        headers=headers(api_key),
    )
    check("Session shows interrupted", r2.json().get("status") == "interrupted")

    # Double-interrupt should fail
    r3 = requests.post(
        f"{MANAGED_BASE}/sessions/{session_id}/interrupt",
        headers=headers(api_key),
        json={"reason": "Second interrupt attempt"},
    )
    check("Double interrupt returns 409", r3.status_code == 409)


def test_interrupt_audit_trail(api_key, session_id):
    """Test that interrupt is logged in audit trail."""
    print(f"\n{BOLD}Test 9: Interrupt Audit Trail{RESET}")
    r = requests.get(
        f"{MANAGED_BASE}/sessions/{session_id}/audit",
        headers=headers(api_key),
    )
    data = r.json()
    records = data.get("records", [])

    interrupt_recs = [r for r in records if r.get("method") == "interrupt_session"]
    check("Interrupt logged in audit", len(interrupt_recs) >= 1)
    if interrupt_recs:
        check("Interrupt source is control_plane", interrupt_recs[0].get("source") == "control_plane")
        check("Interrupt has violations", "session_interrupted" in interrupt_recs[0].get("violations", []))


def test_governance_prompt():
    """Test governance prompt building and hashing."""
    print(f"\n{BOLD}Test 10: Governance Prompt Injection{RESET}")

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "gateway"))
    from gateway.control_plane import build_governance_prompt, hash_prompt

    # Basic prompt
    prompt = build_governance_prompt("Test Corp", {})
    check("Prompt contains governance header", "Governance Context" in prompt)
    check("Prompt contains vargate.ai", "vargate.ai" in prompt)
    check("Prompt contains audit notice", "logged and auditable" in prompt)
    check("Prompt contains org name", "Test Corp" in prompt)

    # Prompt with agent constraints
    prompt2 = build_governance_prompt(
        "Acme Inc",
        {
            "allowed_tools": '["vargate_read_crm", "vargate_send_email"]',
            "require_human_approval": '["vargate_send_email"]',
            "max_session_hours": 4.0,
        },
    )
    check("Prompt includes allowed tools", "vargate_read_crm" in prompt2)
    check("Prompt includes approval rules", "vargate_send_email" in prompt2)
    check("Prompt includes time limit", "4.0 hours" in prompt2)

    # Hash consistency
    h1 = hash_prompt(prompt)
    h2 = hash_prompt(prompt)
    check("Hash is consistent", h1 == h2)
    check("Hash is 64-char hex (SHA-256)", len(h1) == 64)

    # Different prompts = different hashes
    h3 = hash_prompt(prompt2)
    check("Different prompts = different hashes", h1 != h3)


def test_chain_integrity(api_key):
    """Test that chain integrity holds with control_plane source entries."""
    print(f"\n{BOLD}Test 11: Chain Integrity{RESET}")
    r = requests.get(
        f"{GATEWAY_URL}/audit/verify",
        headers=headers(api_key),
    )
    check("Returns 200", r.status_code == 200)
    check("Chain is valid", r.json().get("valid") is True)


# ── Main ─────────────────────────────────────────────────────────────────────


def main():
    print(f"{BOLD}{CYAN}{'=' * 70}{RESET}")
    print(f"{BOLD}  VARGATE — CONTROL PLANE TEST SUITE (Sprint 11){RESET}")
    print(f"{BOLD}{CYAN}{'=' * 70}{RESET}")

    wait_for_gateway()
    api_key = get_api_key()
    print(f"{DIM}Using API key: {api_key[:20]}...{RESET}")

    # Unit tests
    test_governance_prompt()

    # Integration tests
    agent_id = test_create_agent_config(api_key)
    test_list_agent_configs(api_key, agent_id)
    test_get_agent_config(api_key, agent_id)

    session_id = test_create_session(api_key, agent_id)
    test_list_sessions(api_key, session_id)
    test_session_status(api_key, session_id)
    test_session_audit(api_key, session_id)

    test_interrupt_session(api_key, session_id)
    test_interrupt_audit_trail(api_key, session_id)

    test_chain_integrity(api_key)

    print(f"\n{BOLD}{CYAN}{'=' * 70}{RESET}")
    print(f"{BOLD}  CONTROL PLANE TEST SUMMARY{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 70}{RESET}")
    print(f"  {GREEN}{passed}{RESET} passed, {RED}{failed}{RESET} failed")

    if failed == 0:
        print(f"\n  {GREEN}{BOLD}ALL TESTS PASSED{RESET}")
    else:
        print(f"\n  {RED}{BOLD}{failed} TEST(S) FAILED{RESET}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
