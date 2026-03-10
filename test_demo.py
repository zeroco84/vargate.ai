#!/usr/bin/env python3
"""
Vargate Prototype — Test Demo Script
Runs 3 scenarios against the gateway and validates outcomes.
"""

import json
import sys
import time

import requests

GATEWAY_URL = "http://localhost:8000"
TOOL_CALL_URL = f"{GATEWAY_URL}/mcp/tools/call"
VERIFY_URL = f"{GATEWAY_URL}/audit/verify"
AUDIT_LOG_URL = f"{GATEWAY_URL}/audit/log"

# ── ANSI colours ─────────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"

# ── Scenarios ────────────────────────────────────────────────────────────────

SCENARIOS = [
    {
        "name": "Competitor email",
        "payload": {
            "agent_id": "agent-sales-eu-007",
            "agent_type": "sales_qualification",
            "agent_version": "2.1.4",
            "tool": "gmail",
            "method": "send_email",
            "params": {
                "to": "deal@rival.com",
                "subject": "Partnership?",
                "body": "Hi",
            },
        },
        "expected_status": 403,
        "expected_decision": "blocked",
        "expected_violation": "competitor_contact_attempt",
        "expected_severity": "critical",
    },
    {
        "name": "CRM update £3,000",
        "payload": {
            "agent_id": "agent-sales-eu-007",
            "agent_type": "sales_qualification",
            "agent_version": "2.1.4",
            "tool": "salesforce",
            "method": "update_record",
            "params": {
                "object": "Opportunity",
                "record_id": "006abc",
                "amount": 3000,
            },
        },
        "expected_status": 200,
        "expected_decision": "allowed",
        "expected_violation": None,
        "expected_severity": None,
    },
    {
        "name": "High value transfer £75,000 no approval",
        "payload": {
            "agent_id": "agent-finance-eu-001",
            "agent_type": "finance_ops",
            "agent_version": "1.0.0",
            "tool": "stripe",
            "method": "create_transfer",
            "params": {
                "amount": 75000,
                "currency": "GBP",
                "destination": "acct_xyz",
            },
        },
        "expected_status": 403,
        "expected_decision": "blocked",
        "expected_violation": "high_value_transaction_unapproved",
        "expected_severity": "high",
    },
]


def print_header():
    print()
    print(f"{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}{CYAN}  VARGATE PROTOTYPE — TEST DEMO{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}")
    print()


def wait_for_gateway(max_retries=30, delay=2):
    """Wait for the gateway to be healthy."""
    print(f"{DIM}Waiting for gateway to be ready...{RESET}", end="", flush=True)
    for i in range(max_retries):
        try:
            resp = requests.get(f"{GATEWAY_URL}/health", timeout=2)
            if resp.status_code == 200:
                print(f" {GREEN}ready!{RESET}")
                return True
        except requests.ConnectionError:
            pass
        print(".", end="", flush=True)
        time.sleep(delay)
    print(f" {RED}FAILED{RESET}")
    return False


def run_scenario(idx: int, scenario: dict) -> dict:
    """Run a single test scenario and return the result."""
    print(f"{BOLD}Scenario {idx + 1}: {scenario['name']}{RESET}")
    print(f"  {DIM}POST {TOOL_CALL_URL}{RESET}")
    print(f"  {DIM}Agent: {scenario['payload']['agent_id']}{RESET}")
    print(f"  {DIM}Tool:  {scenario['payload']['tool']}.{scenario['payload']['method']}{RESET}")

    try:
        resp = requests.post(TOOL_CALL_URL, json=scenario["payload"], timeout=10)
    except requests.RequestException as e:
        print(f"  {RED}ERROR: {e}{RESET}")
        return {"passed": False, "error": str(e)}

    status_code = resp.status_code
    body = resp.json()

    # Extract results based on status code
    if status_code == 200:
        action_id = body.get("action_id", "?")
        decision = "allowed"
        violations = []
        severity = "none"
    elif status_code == 403:
        detail = body.get("detail", {})
        action_id = detail.get("action_id", "?")
        decision = "blocked"
        violations = detail.get("violations", [])
        severity = detail.get("severity", "?")
    else:
        print(f"  {RED}Unexpected HTTP {status_code}: {body}{RESET}")
        return {"passed": False, "error": f"HTTP {status_code}"}

    # Check expectations
    passed = True
    status_match = status_code == scenario["expected_status"]
    if not status_match:
        passed = False

    violation_match = True
    if scenario["expected_violation"]:
        violation_match = scenario["expected_violation"] in violations
        if not violation_match:
            passed = False

    severity_match = True
    if scenario["expected_severity"]:
        severity_match = severity == scenario["expected_severity"]
        if not severity_match:
            passed = False

    # Print results
    status_colour = GREEN if passed else RED
    decision_icon = "✅" if decision == "allowed" else "🚫"

    print(f"  {status_colour}{'PASS' if passed else 'FAIL'}{RESET} "
          f"{decision_icon} {BOLD}{decision.upper()}{RESET}")
    print(f"  Action ID:  {action_id}")
    if violations:
        print(f"  Violations: {violations}")
    print(f"  Severity:   {severity}")
    if not status_match:
        print(f"  {RED}Expected HTTP {scenario['expected_status']}, got {status_code}{RESET}")
    if not violation_match:
        print(f"  {RED}Expected violation '{scenario['expected_violation']}' not found{RESET}")
    if not severity_match:
        print(f"  {RED}Expected severity '{scenario['expected_severity']}', got '{severity}'{RESET}")
    print()

    return {"passed": passed, "action_id": action_id, "decision": decision}


def check_chain_verification() -> bool:
    """Call the chain verification endpoint and print the result."""
    print(f"{BOLD}Chain Verification{RESET}")
    try:
        resp = requests.get(VERIFY_URL, timeout=10)
        result = resp.json()
        valid = result.get("valid", False)
        count = result.get("record_count", 0)

        if valid:
            print(f"  {GREEN}✅ VALID — {count} records verified{RESET}")
        else:
            failed_at = result.get("failed_at_action_id", "?")
            reason = result.get("reason", "unknown")
            print(f"  {RED}❌ INVALID — failed at {failed_at} ({reason}){RESET}")
        print()
        return valid
    except requests.RequestException as e:
        print(f"  {RED}ERROR: {e}{RESET}")
        print()
        return False


def print_audit_log():
    """Fetch and display the last 5 audit records."""
    print(f"{BOLD}Audit Log (last 5 records){RESET}")
    try:
        resp = requests.get(f"{AUDIT_LOG_URL}?limit=5", timeout=10)
        data = resp.json()
        records = data.get("records", [])

        if not records:
            print(f"  {YELLOW}No records found{RESET}")
            return

        # Print table header
        print(f"  {'ID':<4} {'Decision':<10} {'Agent':<25} {'Tool':<12} "
              f"{'Method':<18} {'Severity':<10} {'Hash (first 16)':<18}")
        print(f"  {'─'*4} {'─'*10} {'─'*25} {'─'*12} {'─'*18} {'─'*10} {'─'*18}")

        for rec in reversed(records):  # Show oldest first
            hash_short = rec["record_hash"][:16] + "…"
            decision_colour = GREEN if rec["decision"] == "allow" else RED
            print(
                f"  {rec['id']:<4} "
                f"{decision_colour}{rec['decision']:<10}{RESET} "
                f"{rec['agent_id']:<25} "
                f"{rec['tool']:<12} "
                f"{rec['method']:<18} "
                f"{rec['severity']:<10} "
                f"{DIM}{hash_short}{RESET}"
            )

        print()
    except requests.RequestException as e:
        print(f"  {RED}ERROR: {e}{RESET}")
        print()


def main():
    print_header()

    if not wait_for_gateway():
        print(f"{RED}Gateway not available. Is docker-compose running?{RESET}")
        sys.exit(1)

    print()

    # Run scenarios
    results = []
    for i, scenario in enumerate(SCENARIOS):
        result = run_scenario(i, scenario)
        results.append(result)

    # Chain verification
    chain_valid = check_chain_verification()

    # Audit log
    print_audit_log()

    # Summary
    passed = sum(1 for r in results if r.get("passed"))
    total = len(results)
    chain_status = f"{GREEN}VALID{RESET}" if chain_valid else f"{RED}INVALID{RESET}"

    print(f"{BOLD}{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}")
    print(f"{BOLD}{CYAN}{'='*70}{RESET}")

    summary_colour = GREEN if passed == total else RED
    print(f"  {summary_colour}{passed}/{total} scenarios produced expected outcomes{RESET}")
    print(f"  Chain integrity: {chain_status}")

    if passed == total and chain_valid:
        print(f"\n  {GREEN}{BOLD}🎉 ALL CHECKS PASSED{RESET}")
    else:
        print(f"\n  {RED}{BOLD}⚠ SOME CHECKS FAILED{RESET}")

    print()
    sys.exit(0 if (passed == total and chain_valid) else 1)


if __name__ == "__main__":
    main()
