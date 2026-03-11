#!/usr/bin/env python3
"""
Vargate — Policy Replay Demo (Session 5)

7-step demonstration of decision replayability:
  1. Generate fresh records with opa_input stored
  2. Replay a BLOCK decision (competitor email)
  3. Replay an ALLOW decision (CRM update)
  4. Tamper + replay (show input integrity vs chain integrity)
  5. Bulk verify last 10 records
  6. Chain verification
  7. Summary
"""

import json
import os
import subprocess
import sys
import time

import requests

GW = os.environ.get("VARGATE_URL", "http://localhost:8000")
SEP = "─" * 60
HEADER = "=" * 70

# ── Helpers ──────────────────────────────────────────────────────────────────

def wait_for_gateway(timeout=30):
    print("Waiting for gateway...", end=" ", flush=True)
    for _ in range(timeout):
        try:
            r = requests.get(f"{GW}/health", timeout=2)
            if r.status_code == 200:
                print("ready!")
                return
        except requests.ConnectionError:
            pass
        time.sleep(1)
    print("TIMEOUT")
    sys.exit(1)


def send_tool_call(agent_id, tool, method, params, context_override=None):
    payload = {
        "agent_id": agent_id,
        "agent_type": "autonomous",
        "agent_version": "2.1.4",
        "tool": tool,
        "method": method,
        "params": params,
    }
    if context_override:
        payload["context_override"] = context_override
    r = requests.post(f"{GW}/mcp/tools/call", json=payload, timeout=10)
    data = r.json()
    # Blocked responses come as 403 with detail containing the response
    if r.status_code == 403:
        return data.get("detail", data)
    return data


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print()
    print(HEADER)
    print("  VARGATE — POLICY REPLAY DEMO")
    print("  Decision Replayability (AGCS AG-2.8)")
    print(HEADER)
    print()

    wait_for_gateway()

    # ── Step 1: Generate fresh records with opa_input ──────────────────────
    print(f"\n{SEP}")
    print(f"── Step 1: Generate fresh records with opa_input stored")
    print(SEP)

    # Clean up behavioral history from previous tests
    for agent in ["agent-sales-eu-007", "agent-finance-eu-001"]:
        requests.delete(f"{GW}/agents/{agent}/history", timeout=5)

    # Scenario 1: Competitor email (BLOCK)
    r1 = send_tool_call(
        agent_id="agent-sales-eu-007",
        tool="gmail",
        method="send_email",
        params={
            "to": "deal@rival.com",
            "subject": "Partnership proposal",
            "body": "Let's discuss terms",
        },
    )
    action_id_block = r1["action_id"]
    assert r1["status"] == "blocked", f"Expected blocked, got {r1['status']}"
    print(f"  Scenario 1: Competitor email → BLOCKED (action_id: {action_id_block[:16]}...)")

    # Scenario 2: CRM update £3,000 (ALLOW)
    r2 = send_tool_call(
        agent_id="agent-sales-eu-007",
        tool="salesforce",
        method="update_record",
        params={
            "object": "Opportunity",
            "record_id": "OPP-2024-1234",
            "fields": {"amount": 3000, "stage": "Proposal"},
        },
    )
    action_id_allow = r2["action_id"]
    assert r2["status"] == "allowed", f"Expected allowed, got {r2['status']}"
    print(f"  Scenario 2: CRM update £3k → ALLOWED (action_id: {action_id_allow[:16]}...)")

    # Scenario 3: High-value transfer (BLOCK)
    r3 = send_tool_call(
        agent_id="agent-finance-eu-001",
        tool="stripe",
        method="create_transfer",
        params={
            "amount": 75000,
            "currency": "GBP",
            "destination": "acct_external_vendor",
        },
    )
    action_id_hv = r3["action_id"]
    assert r3["status"] == "blocked", f"Expected blocked, got {r3['status']}"
    print(f"  Scenario 3: £75k transfer → BLOCKED (action_id: {action_id_hv[:16]}...)")

    # Verify opa_input is stored
    time.sleep(0.5)
    log = requests.get(f"{GW}/audit/log?limit=3").json()
    records_with_input = sum(1 for rec in log["records"] if rec.get("opa_input") is not None)
    print(f"  ✓ {records_with_input} fresh records generated with opa_input stored")

    # ── Step 2: Replay the competitor email block ──────────────────────────
    print(f"\n{SEP}")
    print(f"── Step 2: Replay the competitor email BLOCK")
    print(SEP)

    replay_resp = requests.post(
        f"{GW}/audit/replay",
        json={"action_id": action_id_block},
        timeout=30,
    ).json()

    assert replay_resp["replay_status"] == "MATCH", f"Expected MATCH, got {replay_resp['replay_status']}"
    print(f"  Action ID:     {action_id_block}")
    print(f"  Original:      {replay_resp['original']['decision'].upper()} / {', '.join(replay_resp['original']['violations'])}")
    print(f"  Replayed:      {replay_resp['replayed']['decision'].upper()} / {', '.join(replay_resp['replayed']['violations'])}")
    print(f"  Decision:      {'✓ MATCH' if replay_resp['match']['decision'] else '✗ MISMATCH'}")
    print(f"  Violations:    {'✓ MATCH' if replay_resp['match']['violations'] else '✗ MISMATCH'}")
    print(f"  Severity:      {'✓ MATCH' if replay_resp['match']['severity'] else '✗ MISMATCH'}")
    print(f"  ✓ BLOCK decision verified — competitor_contact_attempt reproducible")

    # ── Step 3: Replay the CRM allow ───────────────────────────────────────
    print(f"\n{SEP}")
    print(f"── Step 3: Replay the CRM update ALLOW")
    print(SEP)

    replay_resp2 = requests.post(
        f"{GW}/audit/replay",
        json={"action_id": action_id_allow},
        timeout=30,
    ).json()

    assert replay_resp2["replay_status"] == "MATCH", f"Expected MATCH, got {replay_resp2['replay_status']}"
    print(f"  Action ID:     {action_id_allow}")
    print(f"  Original:      {replay_resp2['original']['decision'].upper()}")
    print(f"  Replayed:      {replay_resp2['replayed']['decision'].upper()}")
    print(f"  Decision:      {'✓ MATCH' if replay_resp2['match']['decision'] else '✗ MISMATCH'}")
    print(f"  ✓ ALLOW decision verified — clean CRM update reproducible")

    # ── Step 4: Tamper + replay (chain vs input integrity) ─────────────────
    print(f"\n{SEP}")
    print(f"── Step 4: Tamper + replay (chain vs input integrity)")
    print(SEP)

    # Find the record number for the competitor email
    log_all = requests.get(f"{GW}/audit/log?limit=500").json()
    record_num = None
    for rec in log_all["records"]:
        if rec["action_id"] == action_id_block:
            record_num = rec["id"]
            break
    assert record_num is not None, "Could not find competitor email record"

    # Tamper the record hash
    print(f"  Tampering record #{record_num} (competitor email)...")
    tamper_resp = requests.post(
        f"{GW}/audit/tamper-simulate",
        json={"record_number": record_num},
        timeout=10,
    ).json()
    print(f"  Chain: BROKEN — {tamper_resp['message']}")

    # Replay the tampered record — opa_input is unchanged, so replay should still MATCH
    replay_tampered = requests.post(
        f"{GW}/audit/replay",
        json={"action_id": action_id_block},
        timeout=30,
    ).json()

    assert replay_tampered["replay_status"] == "MATCH", \
        f"Expected MATCH (opa_input intact), got {replay_tampered['replay_status']}"
    print(f"  Replay status: {replay_tampered['replay_status']}")
    print(f"  ✓ Replay still MATCH — input document integrity separate from chain integrity")
    print(f"  → record_hash was corrupted (chain broken)")
    print(f"  → opa_input was NOT altered (replay verified)")
    print(f"  → A sophisticated attacker would need to tamper with BOTH")

    # Restore
    requests.post(f"{GW}/audit/tamper-restore", timeout=10)
    print(f"  ✓ Record restored, chain intact")

    # ── Step 5: Bulk verify last 10 records ────────────────────────────────
    print(f"\n{SEP}")
    print(f"── Step 5: Bulk verify last 10 records")
    print(SEP)

    bulk_resp = requests.post(
        f"{GW}/audit/replay-bulk",
        json={"count": 10},
        timeout=120,
    ).json()

    summary = bulk_resp["summary"]
    print(f"  {'#':<4} {'Action ID':<18} {'Decision':<10} {'Violations':<30} {'Match'}")
    print(f"  {'──':<4} {'──────────────────':<18} {'─────────':<10} {'─────────────────────────────':<30} {'─────'}")

    for i, r in enumerate(bulk_resp["results"], 1):
        action_short = r["action_id"][:14] + "..."
        if r["replay_status"] == "ERROR":
            print(f"  {i:<4} {action_short:<18} {'ERROR':<10} {r.get('error', '?')[:30]:<30} ⚠")
            continue
        orig = r["original"]
        decision = orig["decision"].upper()
        viols = ", ".join(orig["violations"])[:28] if orig["violations"] else "—"
        icon = "✓" if r["replay_status"] == "MATCH" else "✗"
        print(f"  {i:<4} {action_short:<18} {decision:<10} {viols:<30} {icon}")

    print()
    print(f"  {summary['matched']}/{summary['total']} records verified. "
          f"{summary['mismatched']} mismatches.")
    assert summary["mismatched"] == 0, f"Expected 0 mismatches, got {summary['mismatched']}"
    print(f"  ✓ All decisions reproducible from archived policy bundles")

    # ── Step 6: Chain verification ─────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"── Step 6: Chain verification")
    print(SEP)

    chain = requests.get(f"{GW}/audit/verify").json()
    assert chain["valid"], "Chain should be valid"
    print(f"  ✓ Chain VALID across {chain['record_count']} records")

    # ── Step 7: Summary ───────────────────────────────────────────────────
    print(f"\n{SEP}")
    print(f"── Step 7: Summary")
    print(SEP)

    total_log = requests.get(f"{GW}/audit/log?limit=500").json()
    records_with_opa = sum(1 for r in total_log["records"] if r.get("opa_input") is not None)
    records_without = sum(1 for r in total_log["records"] if r.get("opa_input") is None)

    print(f"  Records with opa_input stored:   {records_with_opa}")
    print(f"  Records without (pre-Session 5): {records_without}")
    print(f"  Records verified by replay:      {summary['total']}")
    print(f"  Mismatches found:                {summary['mismatched']}")

    print()
    print(HEADER)
    print("  POLICY REPLAY DEMO SUMMARY")
    print(HEADER)
    print(f"  7/7 steps completed successfully")
    print()
    print(f"  🎉 POLICY REPLAY DEMO COMPLETE")
    print(f"  Any decision can be replayed from first principles.")
    print(f"  The math does the work.")
    print()


if __name__ == "__main__":
    main()
