#!/usr/bin/env python3
"""
Vargate — MCP Server Test Suite (Sprint 9.2)
Tests the MCP server protocol implementation: initialize handshake,
tools/list filtering, tools/call governance pipeline, and auth rejection.
"""

import json
import os
import sys
import time

import requests

GATEWAY_URL = os.environ.get("VARGATE_URL", "http://localhost:8000")
MCP_BASE = f"{GATEWAY_URL}/mcp/server"

# ── ANSI colours ─────────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"

# ── Helpers ──────────────────────────────────────────────────────────────────

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
    """Get a valid API key from environment or use default internal key."""
    key = os.environ.get("VARGATE_API_KEY")
    if key:
        return key
    # Try to get from the gateway's tenant list
    try:
        resp = requests.get(f"{GATEWAY_URL}/tenants", timeout=5)
        if resp.status_code == 200:
            tenants = resp.json()
            for t in tenants:
                if t.get("api_key"):
                    return t["api_key"]
    except Exception:
        pass
    # Fallback — caller should set VARGATE_API_KEY
    print(f"{RED}ERROR: Set VARGATE_API_KEY environment variable{RESET}")
    sys.exit(1)


def wait_for_gateway():
    """Wait for gateway to be ready."""
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


# ── Tests ────────────────────────────────────────────────────────────────────


def test_health():
    """Test MCP server health endpoint."""
    print(f"\n{BOLD}Test 1: MCP Server Health{RESET}")
    r = requests.get(f"{MCP_BASE}/health", timeout=5)
    data = r.json()
    check("Health returns 200", r.status_code == 200)
    check("Service name correct", data.get("service") == "vargate-mcp-server")
    check("Protocol version present", "protocol_version" in data)


def test_auth_rejection():
    """Test that unauthenticated requests are rejected."""
    print(f"\n{BOLD}Test 2: Auth Rejection (no API key){RESET}")
    r = requests.post(
        f"{MCP_BASE}/initialize",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {},
            },
        },
        timeout=5,
    )
    check("Returns 401 without API key", r.status_code == 401)

    # Invalid API key
    r2 = requests.post(
        f"{MCP_BASE}/initialize",
        headers={"X-API-Key": "vg-invalid-key-12345"},
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {},
            },
        },
        timeout=5,
    )
    check("Returns 401 with invalid API key", r2.status_code == 401)


def test_initialize(api_key):
    """Test MCP initialize handshake."""
    print(f"\n{BOLD}Test 3: MCP Initialize Handshake{RESET}")
    r = requests.post(
        f"{MCP_BASE}/initialize",
        headers={"X-API-Key": api_key},
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-agent", "version": "1.0.0"},
            },
        },
        timeout=5,
    )
    check("Returns 200", r.status_code == 200)
    data = r.json()
    result = data.get("result", {})

    check("Has protocol version", "protocolVersion" in result)
    check("Has server info", "serverInfo" in result)
    check("Server name is vargate-governance",
          result.get("serverInfo", {}).get("name") == "vargate-governance")
    check("Has capabilities", "capabilities" in result)
    check("Tools capability present", "tools" in result.get("capabilities", {}))
    check("Has vargate metadata", "vargate" in result)
    check("Session ID generated", bool(result.get("vargate", {}).get("session_id")))
    check("Governance is active",
          result.get("vargate", {}).get("governance") == "active")

    return result.get("vargate", {}).get("session_id")


def test_tools_list(api_key):
    """Test MCP tools/list returns tool catalog."""
    print(f"\n{BOLD}Test 4: MCP Tools List{RESET}")
    r = requests.post(
        f"{MCP_BASE}/tools/list",
        headers={"X-API-Key": api_key},
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        },
        timeout=5,
    )
    check("Returns 200", r.status_code == 200)
    data = r.json()
    tools = data.get("result", {}).get("tools", [])

    check("Has tools array", isinstance(tools, list))
    check("At least 4 tools returned", len(tools) >= 4, f"Got {len(tools)} tools")

    # Check tool structure
    if tools:
        t = tools[0]
        check("Tool has name", "name" in t)
        check("Tool has description", "description" in t)
        check("Tool has inputSchema", "inputSchema" in t)
        check("No internal fields exposed", "_vargate_tool" not in t)

    tool_names = [t["name"] for t in tools]
    check("vargate_send_email in catalog", "vargate_send_email" in tool_names)
    check("vargate_read_crm in catalog", "vargate_read_crm" in tool_names)
    check("vargate_update_crm in catalog", "vargate_update_crm" in tool_names)
    check("vargate_create_transfer in catalog", "vargate_create_transfer" in tool_names)

    return tools


def test_tools_call_blocked(api_key):
    """Test MCP tools/call — blocked by OPA policy (competitor email)."""
    print(f"\n{BOLD}Test 5: Tools/Call — Blocked (Competitor Email){RESET}")
    r = requests.post(
        f"{MCP_BASE}/tools/call",
        headers={"X-API-Key": api_key},
        json={
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "vargate_send_email",
                "arguments": {
                    "to": "ceo@competitor.com",
                    "subject": "Secret partnership",
                    "body": "Let's discuss competitive intel.",
                    "_vargate_agent_id": "mcp-test-agent-001",
                },
            },
        },
        timeout=10,
    )
    check("Returns 200 (MCP wraps errors in result)", r.status_code == 200)
    data = r.json()
    result = data.get("result", {})

    check("isError is true", result.get("isError") is True)
    check("Has content array", isinstance(result.get("content"), list))

    vargate = result.get("_vargate", {})
    check("Decision is denied", vargate.get("decision") == "denied")
    check("Source is mcp_governed", vargate.get("source") == "mcp_governed")
    check("Has action_id (AG-1.3)", bool(vargate.get("action_id")))
    check("Has violations", len(vargate.get("violations", [])) > 0)
    check("competitor_contact_attempt in violations",
          "competitor_contact_attempt" in vargate.get("violations", []))

    return vargate.get("action_id")


def test_tools_call_high_value(api_key):
    """Test MCP tools/call — high value transfer blocked."""
    print(f"\n{BOLD}Test 6: Tools/Call — High Value Transfer{RESET}")
    r = requests.post(
        f"{MCP_BASE}/tools/call",
        headers={"X-API-Key": api_key},
        json={
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "vargate_create_transfer",
                "arguments": {
                    "amount": 75000,
                    "destination": "GB82WEST12345698765432",
                    "description": "Large wire transfer",
                    "_vargate_agent_id": "mcp-test-agent-001",
                },
            },
        },
        timeout=10,
    )
    data = r.json()
    result = data.get("result", {})
    vargate = result.get("_vargate", {})

    check("High value transfer blocked", vargate.get("decision") == "denied")
    check("Source is mcp_governed", vargate.get("source") == "mcp_governed")
    check("Has action_id", bool(vargate.get("action_id")))


def test_tools_call_unknown(api_key):
    """Test MCP tools/call — unknown tool returns proper error."""
    print(f"\n{BOLD}Test 7: Tools/Call — Unknown Tool{RESET}")
    r = requests.post(
        f"{MCP_BASE}/tools/call",
        headers={"X-API-Key": api_key},
        json={
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "nonexistent_tool",
                "arguments": {},
            },
        },
        timeout=5,
    )
    data = r.json()
    check("Returns error object", "error" in data)
    check("Error code is -32602 (invalid params)", data.get("error", {}).get("code") == -32602)


def test_audit_trail_source(api_key, action_id):
    """Test that audit log entry has source='mcp_governed'."""
    print(f"\n{BOLD}Test 8: Audit Trail Source Verification{RESET}")
    r = requests.get(
        f"{GATEWAY_URL}/audit/log",
        headers={"X-API-Key": api_key},
        params={"limit": 20},
        timeout=5,
    )
    check("Audit log accessible", r.status_code == 200)

    if r.status_code == 200:
        data = r.json()
        records = data.get("records", data) if isinstance(data, dict) else data
        # Find our specific action
        found = None
        for rec in records:
            rec_dict = rec if isinstance(rec, dict) else {}
            if rec_dict.get("action_id") == action_id:
                found = rec_dict
                break

        check("MCP action found in audit log", found is not None, f"Looking for {action_id}")
        if found:
            check("source field is 'mcp_governed'",
                  found.get("source") == "mcp_governed",
                  f"Got: {found.get('source')}")


def test_chain_integrity(api_key):
    """Test that chain integrity holds with mixed source types."""
    print(f"\n{BOLD}Test 9: Chain Integrity with Mixed Sources{RESET}")
    r = requests.get(
        f"{GATEWAY_URL}/audit/verify",
        headers={"X-API-Key": api_key},
        timeout=10,
    )
    check("Verify returns 200", r.status_code == 200)
    data = r.json()
    check("Chain is valid", data.get("valid") is True,
          f"Record count: {data.get('record_count')}")


# ── Main ─────────────────────────────────────────────────────────────────────


def main():
    print(f"{BOLD}{CYAN}{'=' * 70}{RESET}")
    print(f"{BOLD}  VARGATE — MCP SERVER TEST SUITE (Sprint 9.2){RESET}")
    print(f"{BOLD}{CYAN}{'=' * 70}{RESET}")

    wait_for_gateway()
    api_key = get_api_key()
    print(f"{DIM}Using API key: {api_key[:20]}...{RESET}")

    test_health()
    test_auth_rejection()
    session_id = test_initialize(api_key)
    test_tools_list(api_key)
    action_id = test_tools_call_blocked(api_key)
    test_tools_call_high_value(api_key)
    test_tools_call_unknown(api_key)
    test_audit_trail_source(api_key, action_id)
    test_chain_integrity(api_key)

    print(f"\n{BOLD}{CYAN}{'=' * 70}{RESET}")
    print(f"{BOLD}  MCP SERVER TEST SUMMARY{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 70}{RESET}")
    print(f"  {GREEN}{passed}{RESET} passed, {RED}{failed}{RESET} failed")

    if failed == 0:
        print(f"\n  {GREEN}{BOLD}ALL TESTS PASSED{RESET}")
    else:
        print(f"\n  {RED}{BOLD}{failed} TEST(S) FAILED{RESET}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
