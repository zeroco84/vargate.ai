#!/usr/bin/env python3
"""
Vargate Prototype — Behavioral History Test Script
Demonstrates history-aware policy enforcement with two-pass evaluation.
"""

import json
import os
import sys
import time

import requests

GATEWAY_URL = os.environ.get("VARGATE_URL", "http://localhost:8000")
TOOL_CALL_URL = f"{GATEWAY_URL}/mcp/tools/call"
VERIFY_URL = f"{GATEWAY_URL}/audit/verify"
AUDIT_LOG_URL = f"{GATEWAY_URL}/audit/log"

TEST_AGENT = "agent-test-behavioral-001"

# ── ANSI colours ─────────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[2m"


def print_header():
    print()
    print(f"{BOLD}{MAGENTA}{'='*70}{RESET}")
    print(f"{BOLD}{MAGENTA}  VARGATE — BEHAVIORAL HISTORY DEMO{RESET}")
    print(f"{BOLD}{MAGENTA}  Two-Pass Evaluation with Redis History{RESET}")
    print(f"{BOLD}{MAGENTA}{'='*70}{RESET}")
    print()


def print_step(num: int, title: str):
    print(f"{BOLD}{CYAN}── Step {num}: {title} {'─'*(52 - len(title))}{RESET}")


def wait_for_services(max_retries=30, delay=2):
    print(f"{DIM}Waiting for services...{RESET}", end="", flush=True)
    for _ in range(max_retries):
        try:
            resp = requests.get(f"{GATEWAY_URL}/health", timeout=2)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("redis"):
                    print(f" {GREEN}ready! (Redis connected){RESET}")
                    return True
        except requests.ConnectionError:
            pass
        print(".", end="", flush=True)
        time.sleep(delay)
    print(f" {RED}FAILED{RESET}")
    return False


def send_tool_call(payload: dict) -> tuple[int, dict]:
    resp = requests.post(TOOL_CALL_URL, json=payload, timeout=10)
    return resp.status_code, resp.json()


def get_anomaly_score() -> float:
    resp = requests.get(f"{GATEWAY_URL}/agents/{TEST_AGENT}/anomaly_score", timeout=5)
    return resp.json().get("anomaly_score", 0.0)


def main():
    print_header()

    if not wait_for_services():
        print(f"{RED}Services not available. Is docker-compose running?{RESET}")
        sys.exit(1)

    print()
    passed_steps = 0
    total_steps = 7
    pass1_count = 0
    pass2_count = 0
    history_blocks = 0

    # ── STEP 1: Clean slate ──────────────────────────────────────────────

    print_step(1, "Clean slate")
    try:
        resp = requests.delete(f"{GATEWAY_URL}/agents/{TEST_AGENT}/history", timeout=5)
        if resp.status_code == 200:
            print(f"  {GREEN}✓ Redis cleared for {TEST_AGENT}{RESET}")
            passed_steps += 1
        else:
            print(f"  {RED}✗ Failed to clear Redis: {resp.text}{RESET}")
    except Exception as e:
        print(f"  {RED}✗ Error: {e}{RESET}")
    print()

    # ── STEP 2: Build up violation history ───────────────────────────────

    print_step(2, "Build up violation history")
    print(f"  {DIM}Sending 3 high-value requests (£6,000 each, no approval)...{RESET}")

    denial_payload = {
        "agent_id": TEST_AGENT,
        "agent_type": "finance_ops",
        "agent_version": "1.0.0",
        "tool": "stripe",
        "method": "create_transfer",
        "params": {
            "amount": 6000,
            "currency": "GBP",
            "destination": "acct_test",
        },
        "context_override": {"is_business_hours": True},
    }

    all_denials_ok = True
    for i in range(3):
        code, body = send_tool_call(denial_payload)
        score = get_anomaly_score()
        if code == 403:
            detail = body.get("detail", {})
            violations = detail.get("violations", [])
            print(
                f"  {DIM}  Denial {i+1}/3: violations={violations} "
                f"anomaly_score={score:.4f}{RESET}"
            )
        else:
            print(f"  {RED}  Expected denial {i+1}/3, got HTTP {code}{RESET}")
            all_denials_ok = False
        time.sleep(0.3)

    final_score = get_anomaly_score()
    print(f"  {YELLOW}→ After 3 denials: anomaly_score={final_score:.4f}{RESET}")

    if all_denials_ok:
        print(f"  {GREEN}✓ 3 denials recorded in behavioral history{RESET}")
        passed_steps += 1
        pass1_count += (
            3  # High-value stripe → needs_enrichment → but denied on P1 anyway
        )
    else:
        print(f"  {RED}✗ Some denials failed{RESET}")
    print()

    # ── STEP 3: Demonstrate history-aware block ──────────────────────────

    print_step(3, "Demonstrate history-aware block")
    print(f"  {DIM}Sending £600 CRM update (would normally be ALLOWED)...{RESET}")

    clean_payload = {
        "agent_id": TEST_AGENT,
        "agent_type": "sales_qualification",
        "agent_version": "2.1.4",
        "tool": "salesforce",
        "method": "update_record",
        "params": {
            "object": "Opportunity",
            "record_id": "006test",
            "amount": 600,
        },
        "context_override": {"is_business_hours": True},
    }

    code, body = send_tool_call(clean_payload)
    score = get_anomaly_score()

    if code == 403:
        detail = body.get("detail", {})
        violations = detail.get("violations", [])
        severity = detail.get("severity", "?")
        history_violation = (
            "violation_cooldown_active" in violations
            or "repeated_violations_today" in violations
        )
        if history_violation:
            print(
                f"  {GREEN}✓ £600 request BLOCKED due to 3 violations in history "
                f"(would normally be allowed){RESET}"
            )
            print(f"  {GREEN}  Violations: {violations}{RESET}")
            print(
                f"  {GREEN}  Pass 2 enriched input used. "
                f"Anomaly score: {score:.4f}{RESET}"
            )
            passed_steps += 1
            pass2_count += 1
            history_blocks += 1
        else:
            print(
                f"  {YELLOW}⚠ Blocked, but not for history-related violation: "
                f"{violations}{RESET}"
            )
    elif code == 200:
        print(
            f"  {RED}✗ Expected BLOCKED, got ALLOWED. "
            f"History enrichment may not be working.{RESET}"
        )
    else:
        print(f"  {RED}✗ Unexpected HTTP {code}: {body}{RESET}")
    print()

    # ── STEP 4: Show evaluation modes in audit log ───────────────────────

    print_step(4, "Show evaluation modes in audit log")

    resp = requests.get(f"{AUDIT_LOG_URL}?agent_id={TEST_AGENT}&limit=10", timeout=10)
    records = resp.json().get("records", [])
    records.reverse()  # oldest first

    if records:
        print(
            f"  {'#':<3} {'Decision':<8} {'Tool':<12} {'Method':<18} "
            f"{'Pass':<6} {'Anomaly':<10} {'Violations'}"
        )
        print(f"  {'─'*3} {'─'*8} {'─'*12} {'─'*18} {'─'*6} {'─'*10} {'─'*30}")

        for i, rec in enumerate(records):
            dec_colour = GREEN if rec["decision"] == "allow" else RED
            pass_label = f"P{rec.get('evaluation_pass', 1)}"
            anomaly = rec.get("anomaly_score_at_eval", 0.0)
            viols = rec.get("violations", [])
            viols_short = ", ".join(v[:25] for v in viols) if viols else "—"
            print(
                f"  {i+1:<3} "
                f"{dec_colour}{rec['decision']:<8}{RESET} "
                f"{rec['tool']:<12} "
                f"{rec['method']:<18} "
                f"{pass_label:<6} "
                f"{anomaly:<10.4f} "
                f"{DIM}{viols_short}{RESET}"
            )

            ep = rec.get("evaluation_pass", 1)
            if ep == 1:
                pass1_count = pass1_count  # already counted
            elif ep == 2:
                pass2_count = pass2_count  # already counted

        passed_steps += 1
    else:
        print(f"  {RED}✗ No records found for {TEST_AGENT}{RESET}")
    print()

    # ── STEP 5: Anomaly score decay demonstration ────────────────────────

    print_step(5, "Anomaly score decay demonstration")
    print(f"  {DIM}Resetting violation counters (keeping anomaly score)...{RESET}")

    # Reset counters so repeated_violations_today doesn't block clean requests
    # But keep the anomaly_score so we can show it decaying
    requests.delete(f"{GATEWAY_URL}/agents/{TEST_AGENT}/counters", timeout=5)

    print(f"  {DIM}Sending 5 clean requests (£100 CRM reads)...{RESET}")

    clean_read_payload = {
        "agent_id": TEST_AGENT,
        "agent_type": "sales_qualification",
        "agent_version": "2.1.4",
        "tool": "salesforce",
        "method": "read_record",
        "params": {
            "object": "Contact",
            "record_id": "003test",
            "amount": 100,
        },
        "context_override": {"is_business_hours": True},
    }

    score_before = get_anomaly_score()
    print(f"  {DIM}  Starting anomaly score: {score_before:.4f}{RESET}")

    decay_ok = True
    for i in range(5):
        code, body = send_tool_call(clean_read_payload)
        score = get_anomaly_score()
        decision = "ALLOWED" if code == 200 else "BLOCKED"
        colour = GREEN if code == 200 else RED
        print(
            f"  {colour}  → After clean request {i+1}: "
            f"anomaly_score={score:.4f} ({decision}){RESET}"
        )
        time.sleep(0.3)

    score_after = get_anomaly_score()
    if score_after < score_before:
        print(
            f"  {GREEN}✓ Anomaly score decayed: {score_before:.4f} → {score_after:.4f}{RESET}"
        )
        passed_steps += 1
    else:
        print(
            f"  {RED}✗ Anomaly score did not decay: {score_before:.4f} → {score_after:.4f}{RESET}"
        )
    print()

    # ── STEP 6: Chain verification ───────────────────────────────────────

    print_step(6, "Chain verification")
    resp = requests.get(VERIFY_URL, timeout=10)
    result = resp.json()
    valid = result.get("valid", False)
    count = result.get("record_count", 0)

    if valid:
        print(f"  {GREEN}✓ Chain VALID across {count} records{RESET}")
        passed_steps += 1
    else:
        failed_at = result.get("failed_at_action_id", "?")
        reason = result.get("reason", "?")
        print(f"  {RED}✗ Chain INVALID at {failed_at} ({reason}){RESET}")
    print()

    # ── STEP 7: Summary ─────────────────────────────────────────────────

    print_step(7, "Summary")

    # Recount from audit log
    resp = requests.get(f"{AUDIT_LOG_URL}?agent_id={TEST_AGENT}&limit=50", timeout=10)
    all_recs = resp.json().get("records", [])
    p1_total = sum(1 for r in all_recs if r.get("evaluation_pass", 1) == 1)
    p2_total = sum(1 for r in all_recs if r.get("evaluation_pass", 1) == 2)
    hist_blocks = sum(
        1
        for r in all_recs
        if "violation_cooldown_active" in r.get("violations", [])
        or "repeated_violations_today" in r.get("violations", [])
        or "high_value_frequency_limit_exceeded" in r.get("violations", [])
    )

    print(f"  Pass 1 (fast path, no Redis):   {BOLD}{p1_total}{RESET} decisions")
    print(f"  Pass 2 (enriched, with Redis):  {BOLD}{p2_total}{RESET} decisions")
    print(f"  History-triggered blocks:       {BOLD}{hist_blocks}{RESET}")
    passed_steps += 1

    print()

    # ── Final summary ────────────────────────────────────────────────────

    print(f"{BOLD}{MAGENTA}{'='*70}{RESET}")
    print(f"{BOLD}  BEHAVIORAL HISTORY DEMO SUMMARY{RESET}")
    print(f"{BOLD}{MAGENTA}{'='*70}{RESET}")

    summary_colour = GREEN if passed_steps == total_steps else YELLOW
    print(
        f"  {summary_colour}{passed_steps}/{total_steps} steps completed successfully{RESET}"
    )

    if passed_steps == total_steps:
        print(f"\n  {GREEN}{BOLD}🎉 BEHAVIORAL HISTORY DEMO COMPLETE{RESET}")
        print(
            f"  {GREEN}Same agent. Same request. Different history. Different outcome.{RESET}"
        )
    else:
        print(f"\n  {YELLOW}{BOLD}⚠ Some steps did not complete as expected{RESET}")

    print()
    sys.exit(0 if passed_steps == total_steps else 1)


if __name__ == "__main__":
    main()
