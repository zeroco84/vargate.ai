#!/usr/bin/env python3
"""
Vargate Policy Replay CLI
Reproduce any historical policy decision from its archived input document
and policy bundle.

Usage:
    python replay.py --action-id <uuid>
    python replay.py --last-block
    python replay.py --record <N>
    python replay.py --verify-last <N>
"""

import argparse
import json
import sys

import requests

GATEWAY_URL = "http://localhost:8000"

LINE = "━" * 60


def print_single_replay(result: dict):
    """Pretty-print a single replay result."""
    action_id = result["action_id"]
    orig = result["original"]
    repl = result["replayed"]
    match = result["match"]
    status = result["replay_status"]

    opa_input = result.get("opa_input_used", {})
    agent_id = opa_input.get("agent", {}).get("id", "unknown") if opa_input else "unknown"
    tool = opa_input.get("action", {}).get("tool", "?") if opa_input else "?"
    method = opa_input.get("action", {}).get("method", "?") if opa_input else "?"
    requested_at = opa_input.get("action", {}).get("requested_at", "?") if opa_input else "?"

    print()
    print(LINE)
    print(f"VARGATE POLICY REPLAY — Action {action_id}")
    print(LINE)

    print()
    print(f"  Agent        {agent_id}")
    print(f"  Tool         {tool} / {method}")
    print(f"  Requested    {requested_at}")
    print(f"  Policy       {orig['bundle_revision']}")

    print()
    print("  ORIGINAL DECISION")
    print("  ─────────────────")
    decision_icon = "✗" if orig["decision"] == "deny" else "✓"
    print(f"  Decision     {orig['decision'].upper()} {decision_icon}")
    viols = ", ".join(orig["violations"]) if orig["violations"] else "—"
    print(f"  Violations   {viols}")
    print(f"  Severity     {orig['severity'].upper()}")

    print()
    print(f"  REPLAYED DECISION (bundle {repl['bundle_revision']})")
    print(f"  {'─' * 45}")
    replay_icon = "✗" if repl["decision"] == "deny" else "✓"
    print(f"  Decision     {repl['decision'].upper()} {replay_icon}")
    r_viols = ", ".join(repl["violations"]) if repl["violations"] else "—"
    print(f"  Violations   {r_viols}")
    print(f"  Severity     {repl['severity'].upper()}")

    print()
    print("  VERIFICATION")
    print("  ────────────")
    for field in ["decision", "violations", "severity", "bundle_revision"]:
        icon = "✓ MATCH" if match[field] else "✗ MISMATCH"
        label = field.replace("_", " ").title()
        pad = max(0, 13 - len(label))
        print(f"  {label}{' ' * pad}{icon}")

    print()
    print(LINE)
    if status == "MATCH":
        viols_str = ", ".join(orig["violations"]) if orig["violations"] else "clean operation"
        action_verb = "denied" if orig["decision"] == "deny" else "allowed"
        print(f"  ✅ VERIFIED — Decision is reproducible and tamper-evident.")
        print(f"  Policy {orig['bundle_revision']} correctly {action_verb} this action")
        if orig["violations"]:
            print(f"  for {viols_str} at {requested_at[:19]}.")
        else:
            print(f"  at {requested_at[:19]}.")
    else:
        print(f"  ⚠  MISMATCH DETECTED — Recommend forensic investigation.")
        print(f"  Original: {orig['decision'].upper()} / {orig['severity']}")
        print(f"  Replayed: {repl['decision'].upper()} / {repl['severity']}")
    print(LINE)
    print()


def print_bulk_replay(data: dict):
    """Pretty-print bulk replay results."""
    results = data["results"]
    summary = data["summary"]

    print()
    print(f"VARGATE BULK REPLAY — Verifying {summary['total']} records")
    print("─" * 60)
    print(f"  {'#':<4} {'Action ID':<18} {'Decision':<10} {'Violations':<30} {'Match':<6}")
    print(f"  {'──':<4} {'──────────────────':<18} {'─────────':<10} {'─────────────────────────────':<30} {'─────':<6}")

    for i, r in enumerate(results, 1):
        action_short = r["action_id"][:14] + "..."
        if r["replay_status"] == "ERROR":
            print(f"  {i:<4} {action_short:<18} {'ERROR':<10} {r.get('error', '?')[:30]:<30} {'⚠':<6}")
            continue

        orig = r["original"]
        decision = orig["decision"].upper()
        viols = ", ".join(orig["violations"])[:28] if orig["violations"] else "—"
        icon = "✓" if r["replay_status"] == "MATCH" else "✗"
        print(f"  {i:<4} {action_short:<18} {decision:<10} {viols:<30} {icon:<6}")

    print()
    print("─" * 60)
    print(f"  {summary['matched']}/{summary['total']} records verified. "
          f"{summary['mismatched']} mismatches.")
    if summary["mismatched"] == 0:
        print(f"  All decisions reproducible from archived policy bundles.")
    else:
        print(f"  ⚠ {summary['mismatched']} record(s) require forensic investigation.")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Vargate Policy Replay — Reproduce any historical policy decision"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--action-id", type=str, help="Replay a specific action by UUID")
    group.add_argument("--last-block", action="store_true", help="Replay the most recent BLOCK decision")
    group.add_argument("--record", type=int, help="Replay a specific record by sequential number")
    group.add_argument("--verify-last", type=int, metavar="N",
                       help="Replay and verify the last N records")

    args = parser.parse_args()

    try:
        if args.verify_last:
            resp = requests.post(
                f"{GATEWAY_URL}/audit/replay-bulk",
                json={"count": args.verify_last},
                timeout=120,
            )
            if resp.status_code != 200:
                print(f"Error: {resp.status_code} — {resp.text}")
                sys.exit(1)
            print_bulk_replay(resp.json())

        else:
            payload = {}
            if args.action_id:
                payload["action_id"] = args.action_id
            elif args.last_block:
                payload["last_block"] = True
            elif args.record:
                payload["record_number"] = args.record

            resp = requests.post(
                f"{GATEWAY_URL}/audit/replay",
                json=payload,
                timeout=60,
            )
            if resp.status_code != 200:
                print(f"Error: {resp.status_code} — {resp.text}")
                sys.exit(1)
            print_single_replay(resp.json())

    except requests.ConnectionError:
        print("Error: Cannot connect to gateway. Is docker-compose running?")
        sys.exit(1)


if __name__ == "__main__":
    main()
