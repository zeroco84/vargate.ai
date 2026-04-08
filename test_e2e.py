#!/usr/bin/env python3
"""
End-to-end integration test: full lifecycle from tool call to Merkle-anchored
audit to GDPR erasure.

Tests the complete path a real customer would take:
  1. Health check — gateway, Redis, blockchain all healthy
  2. Submit tool call — receive governance decision
  3. Verify audit record exists in hash chain
  4. Verify chain integrity
  5. Get Merkle roots
  6. Check blockchain anchor status
  7. Compliance export (JSON)
  8. Policy templates available
  9. Erase subject data (GDPR)
  10. Verify erasure

Run: python3 test_e2e.py
Requires: all services running (docker compose up)
"""

import json
import os
import sys
import time

import requests

GATEWAY_URL = os.environ.get("VARGATE_URL", "http://localhost:8000")
API_KEY = os.environ.get("VARGATE_API_KEY", "")
AUTH_HEADERS = {"X-API-Key": API_KEY} if API_KEY else {}

# ANSI colours
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"

results = []


def step(name, fn):
    """Run a test step and record result."""
    print(f"\n{BOLD}Step: {name}{RESET}")
    try:
        fn()
        print(f"  {GREEN}PASS{RESET}")
        results.append({"name": name, "passed": True})
    except AssertionError as e:
        print(f"  {RED}FAIL{RESET} — {e}")
        results.append({"name": name, "passed": False, "error": str(e)})
    except Exception as e:
        print(f"  {RED}ERROR{RESET} — {e}")
        results.append({"name": name, "passed": False, "error": str(e)})


# ── State shared across steps ──────────────────────────────────────────────

state = {}


def test_01_health():
    """Gateway health check."""
    r = requests.get(f"{GATEWAY_URL}/health", timeout=10)
    assert r.status_code == 200, f"Health check returned {r.status_code}"
    data = r.json()
    assert data["status"] == "ok", f"Health status: {data['status']}"
    assert data["redis"] is True, "Redis not connected"
    assert data["blockchain"] is True, "Blockchain not connected"
    print(f"  {DIM}Redis: {data['redis']}, Blockchain: {data['blockchain']}, "
          f"Merkle trees: {data.get('merkle_tree_count', 0)}{RESET}")


def test_02_tool_call():
    """Submit a governed tool call."""
    payload = {
        "agent_id": "e2e-test-agent",
        "agent_type": "integration_test",
        "agent_version": "1.0.0",
        "tool": "http",
        "method": "GET",
        "params": {"url": "https://httpbin.org/get"},
    }
    r = requests.post(f"{GATEWAY_URL}/mcp/tools/call", json=payload, timeout=15)
    assert r.status_code in [200, 202, 403], f"Unexpected status: {r.status_code}: {r.text}"
    data = r.json()

    if r.status_code == 200:
        assert "action_id" in data, "No action_id in allow response"
        state["action_id"] = data["action_id"]
        state["decision"] = "allow"
        print(f"  {DIM}Allowed: action_id={data['action_id']}{RESET}")
    elif r.status_code == 403:
        detail = data.get("detail", {})
        state["action_id"] = detail.get("action_id", "unknown")
        state["decision"] = "deny"
        print(f"  {DIM}Denied: violations={detail.get('violations', [])}{RESET}")
    elif r.status_code == 202:
        state["action_id"] = data.get("action_id", "unknown")
        state["decision"] = "pending"
        print(f"  {DIM}Pending approval: action_id={data.get('action_id')}{RESET}")


def test_03_audit_chain_valid():
    """Verify the audit hash chain is intact."""
    r = requests.get(f"{GATEWAY_URL}/audit/verify", timeout=15)
    assert r.status_code == 200, f"Verify returned {r.status_code}: {r.text}"
    data = r.json()
    assert data.get("valid") is True, f"Chain invalid: {data}"
    count = data.get("record_count", 0)
    print(f"  {DIM}Chain valid: {count} records verified{RESET}")


def test_04_audit_record_exists():
    """Verify our action appears in the audit log."""
    r = requests.get(f"{GATEWAY_URL}/audit/log?limit=20", timeout=15)
    assert r.status_code == 200, f"Audit log returned {r.status_code}"
    data = r.json()
    records = data.get("records", data.get("log", []))
    if isinstance(data, list):
        records = data

    action_id = state.get("action_id")
    found = [rec for rec in records if rec.get("action_id") == action_id]
    assert len(found) > 0, f"Action {action_id} not found in last 20 audit records"

    state["record_hash"] = found[0].get("record_hash")
    state["record_id"] = found[0].get("id")
    print(f"  {DIM}Found: record_id={state['record_id']}, "
          f"hash={state['record_hash'][:16]}...{RESET}")


def test_05_merkle_roots():
    """Check Merkle tree roots exist."""
    r = requests.get(f"{GATEWAY_URL}/audit/merkle/roots", timeout=15)
    assert r.status_code == 200, f"Merkle roots returned {r.status_code}"
    data = r.json()
    trees = data.get("trees", data) if isinstance(data, dict) else data
    if isinstance(trees, list):
        tree_count = len(trees)
    else:
        tree_count = 0
    print(f"  {DIM}Merkle trees: {tree_count}{RESET}")
    # Don't assert > 0 — trees are built hourly, may not exist yet


def test_06_merkle_proof():
    """Get a Merkle inclusion proof for our record."""
    record_hash = state.get("record_hash")
    if not record_hash:
        print(f"  {YELLOW}SKIP — no record hash from previous step{RESET}")
        return

    r = requests.get(f"{GATEWAY_URL}/audit/merkle/proof/{record_hash}", timeout=15)
    if r.status_code == 200:
        data = r.json()
        print(f"  {DIM}Proof found: merkle_root={str(data.get('merkle_root', ''))[:16]}...{RESET}")
    elif r.status_code in [404, 422]:
        print(f"  {DIM}No proof yet (tree not built for this record) — OK{RESET}")
    else:
        assert False, f"Unexpected status: {r.status_code}: {r.text}"


def test_07_anchor_status():
    """Check blockchain anchor status."""
    r = requests.get(f"{GATEWAY_URL}/anchor/status", timeout=15)
    assert r.status_code == 200, f"Anchor status returned {r.status_code}"
    data = r.json()
    print(f"  {DIM}Anchor status: {json.dumps(data)[:200]}{RESET}")


def test_08_compliance_export():
    """Export a compliance package (JSON)."""
    r = requests.get(
        f"{GATEWAY_URL}/compliance/export/vargate-internal?from=2020-01-01&to=2030-12-31",
        headers=AUTH_HEADERS,
        timeout=30,
    )
    assert r.status_code == 200, f"Compliance export returned {r.status_code}: {r.text}"
    data = r.json()
    assert "metadata" in data, "Missing metadata in compliance package"
    assert "audit_records" in data, "Missing audit_records"
    assert "chain_verification" in data, "Missing chain_verification"
    assert data["metadata"].get("export_hash", "").startswith("sha256:"), "Missing or invalid export_hash"
    count = data["metadata"]["record_count"]
    valid = data["chain_verification"]["valid"]
    print(f"  {DIM}Export: {count} records, chain valid: {valid}, "
          f"hash: {data['metadata']['export_hash'][:30]}...{RESET}")


def test_09_policy_templates():
    """Verify policy templates are available."""
    r = requests.get(f"{GATEWAY_URL}/policy/templates", timeout=10)
    assert r.status_code == 200, f"Templates returned {r.status_code}"
    data = r.json()
    templates = data.get("templates", [])
    assert len(templates) >= 5, f"Expected >= 5 templates, got {len(templates)}"
    names = [t["id"] for t in templates]
    print(f"  {DIM}Templates: {', '.join(names)}{RESET}")


def test_10_erasure():
    """GDPR erasure of the test agent's data."""
    r = requests.post(f"{GATEWAY_URL}/audit/erase/e2e-test-agent", headers=AUTH_HEADERS, timeout=15)
    # May succeed or return 404/422 if no PII or no such subject
    assert r.status_code in [200, 404, 422], f"Erasure returned {r.status_code}: {r.text}"
    if r.status_code == 200:
        print(f"  {DIM}Erased: {r.json()}{RESET}")
    else:
        print(f"  {DIM}No PII data to erase ({r.status_code}) — OK{RESET}")


def test_11_verify_erasure():
    """Verify erasure status."""
    r = requests.get(f"{GATEWAY_URL}/audit/erase/e2e-test-agent/verify", headers=AUTH_HEADERS, timeout=15)
    assert r.status_code in [200, 404], f"Verify erasure returned {r.status_code}"
    if r.status_code == 200:
        print(f"  {DIM}Erasure verification: {r.json()}{RESET}")
    else:
        print(f"  {DIM}No erasure record ({r.status_code}) — OK{RESET}")


def test_12_openapi():
    """Verify OpenAPI docs are accessible."""
    r = requests.get(f"{GATEWAY_URL}/openapi.json", timeout=10)
    assert r.status_code == 200, f"OpenAPI returned {r.status_code}"
    data = r.json()
    paths = len(data.get("paths", {}))
    assert paths > 50, f"Expected > 50 endpoints, got {paths}"
    print(f"  {DIM}OpenAPI: {paths} endpoints documented{RESET}")


# ── Main ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  Vargate End-to-End Integration Test{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"{DIM}  Gateway: {GATEWAY_URL}{RESET}")

    steps = [
        ("Health check", test_01_health),
        ("Tool call (governed action)", test_02_tool_call),
        ("Audit chain integrity", test_03_audit_chain_valid),
        ("Audit record exists", test_04_audit_record_exists),
        ("Merkle tree roots", test_05_merkle_roots),
        ("Merkle inclusion proof", test_06_merkle_proof),
        ("Blockchain anchor status", test_07_anchor_status),
        ("Compliance export (JSON)", test_08_compliance_export),
        ("Policy templates", test_09_policy_templates),
        ("GDPR erasure", test_10_erasure),
        ("Verify erasure", test_11_verify_erasure),
        ("OpenAPI docs", test_12_openapi),
    ]

    for name, fn in steps:
        step(name, fn)

    # Summary
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  RESULTS: {passed}/{total} steps passed{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")

    for r in results:
        icon = f"{GREEN}PASS{RESET}" if r["passed"] else f"{RED}FAIL{RESET}"
        print(f"  {icon}  {r['name']}")
        if not r["passed"] and r.get("error"):
            print(f"        {RED}{r['error']}{RESET}")

    if passed == total:
        print(f"\n  {GREEN}{BOLD}ALL STEPS PASSED{RESET}")
        sys.exit(0)
    else:
        print(f"\n  {RED}{BOLD}{total - passed} STEP(S) FAILED{RESET}")
        sys.exit(1)
