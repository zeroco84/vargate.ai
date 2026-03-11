#!/usr/bin/env python3
"""
Vargate — Crypto-Shredding Demo (Session 6)

7-step demonstration of the complete crypto-shredding lifecycle:
  1. Enroll a data subject
  2. Send an action with PII in params
  3. Verify decryption works (key still exists)
  4. Send 3 more actions for the same subject
  5. Execute GDPR erasure
  6. Verify erasure — show irrecoverability
  7. Verify chain integrity survives erasure
"""

import json
import os
import sys
import time

import requests

GW = os.environ.get("VARGATE_URL", "http://localhost:8000")
SEP = "─" * 60
HEADER = "=" * 70

SUBJECT_ID = "user-eu-demo-001"


def wait_for_gateway(timeout=60):
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


def send_tool_call(agent_id, tool, method, params):
    r = requests.post(f"{GW}/mcp/tools/call", json={
        "agent_id": agent_id,
        "agent_type": "autonomous",
        "agent_version": "2.1.4",
        "tool": tool,
        "method": method,
        "params": params,
    }, timeout=15)
    data = r.json()
    if r.status_code == 403:
        return data.get("detail", data)
    return data


def main():
    print()
    print(HEADER)
    print("  VARGATE — CRYPTO-SHREDDING DEMO")
    print("  GDPR Right to Erasure via SoftHSM2")
    print(HEADER)
    print()

    wait_for_gateway()

    # Clean up from previous runs
    requests.delete(f"{GW}/agents/agent-sales-eu-007/history", timeout=5)

    # ── Step 1: Enroll a data subject ──────────────────────────────────
    print(f"\n{SEP}")
    print(f"── Step 1: Enroll a data subject")
    print(SEP)

    r = requests.post(f"{GW}/hsm/keys", json={"subject_id": SUBJECT_ID}, timeout=10)
    key_data = r.json()
    assert "key_id" in key_data, f"Key creation failed: {key_data}"
    print(f"  Key generated: {key_data['key_id']}")
    print(f"  Subject:       {key_data['subject_id']}")
    print(f"  ✓ Key generated for {SUBJECT_ID}")

    # ── Step 2: Send an action with PII in params ──────────────────────
    print(f"\n{SEP}")
    print(f"── Step 2: Send an action with PII in params")
    print(SEP)

    r2 = send_tool_call(
        agent_id="agent-sales-eu-007",
        tool="salesforce",
        method="update_record",
        params={
            "object": "Contact",
            "record_id": "CON-2024-0001",
            "customer_id": SUBJECT_ID,
            "email": "alice@example.com",
            "amount": 1500,
        },
    )
    action_id_1 = r2["action_id"]
    print(f"  Action ID: {action_id_1}")
    print(f"  Decision:  {r2.get('status', 'blocked').upper()}")

    # Fetch the audit record to verify encryption
    time.sleep(0.5)
    log = requests.get(f"{GW}/audit/log?limit=1").json()
    record = log["records"][0]
    email_value = record["params"].get("email", "")
    assert "[ENCRYPTED:" in email_value, f"Expected encrypted email, got: {email_value}"
    print(f"  Params.email: {email_value[:60]}...")
    print(f"  PII fields:   {record.get('pii_fields')}")
    print(f"  Subject ID:   {record.get('pii_subject_id')}")
    print(f"  ✓ Action logged. Email field encrypted in audit record.")

    # Extract the ciphertext for later use
    # Parse [ENCRYPTED:key_id:ciphertext_b64]
    inner = email_value[len("[ENCRYPTED:"):-1]
    key_id_part, ciphertext_b64 = inner.split(":", 1)

    # ── Step 3: Verify decryption works ────────────────────────────────
    print(f"\n{SEP}")
    print(f"── Step 3: Verify decryption works (key still exists)")
    print(SEP)

    decrypt_resp = requests.post(f"{GW}/hsm/decrypt", json={
        "subject_id": SUBJECT_ID,
        "ciphertext_b64": ciphertext_b64,
    }, timeout=10).json()

    assert "plaintext" in decrypt_resp, f"Decryption failed: {decrypt_resp}"
    assert decrypt_resp["plaintext"] == "alice@example.com", \
        f"Wrong plaintext: {decrypt_resp['plaintext']}"
    print(f"  Decrypted:  {decrypt_resp['plaintext']}")
    print(f"  ✓ Decryption successful: alice@example.com")
    print(f"  Key exists. PII accessible while key is active.")

    # ── Step 4: Send 3 more actions for the same subject ───────────────
    print(f"\n{SEP}")
    print(f"── Step 4: Send 3 more actions for the same subject")
    print(SEP)

    for i in range(3):
        r_extra = send_tool_call(
            agent_id="agent-sales-eu-007",
            tool="salesforce",
            method="update_record",
            params={
                "object": "Contact",
                "record_id": f"CON-2024-000{i + 2}",
                "customer_id": SUBJECT_ID,
                "email": f"alice.update{i + 1}@example.com",
                "amount": 500 * (i + 1),
            },
        )
        print(f"  Action {i + 2}: {r_extra['action_id'][:16]}... "
              f"({r_extra.get('status', 'blocked').upper()})")

    # Verify 4 total
    time.sleep(0.5)
    log_full = requests.get(f"{GW}/audit/log?limit=500").json()
    pii_records = [r for r in log_full["records"]
                   if r.get("pii_subject_id") == SUBJECT_ID]
    assert len(pii_records) >= 4, f"Expected 4+ PII records, got {len(pii_records)}"
    print(f"  ✓ {len(pii_records)} total records encrypted for {SUBJECT_ID}")

    # ── Step 5: Execute GDPR erasure ───────────────────────────────────
    print(f"\n{SEP}")
    print(f"── Step 5: Execute GDPR erasure")
    print(SEP)

    erase_resp = requests.post(
        f"{GW}/audit/erase/{SUBJECT_ID}", timeout=15
    ).json()

    assert "erasure_certificate" in erase_resp, f"Erasure failed: {erase_resp}"
    print(f"  Subject:      {erase_resp['subject_id']}")
    print(f"  Records:      {erase_resp['records_affected']} marked erased")
    print(f"  Certificate:  {erase_resp['erasure_certificate']}")
    print(f"  Erased at:    {erase_resp['erased_at']}")
    print(f"  ✓ Key deleted. Erasure certificate: {erase_resp['erasure_certificate'][:16]}...")
    print(f"  {erase_resp['records_affected']} records marked erased. Ciphertext irrecoverable.")

    # ── Step 6: Verify erasure — show irrecoverability ─────────────────
    print(f"\n{SEP}")
    print(f"── Step 6: Verify erasure — show irrecoverability")
    print(SEP)

    # Try to decrypt with same ciphertext
    decrypt_after = requests.post(f"{GW}/hsm/decrypt", json={
        "subject_id": SUBJECT_ID,
        "ciphertext_b64": ciphertext_b64,
    }, timeout=10).json()

    assert "error" in decrypt_after, f"Expected error, got: {decrypt_after}"
    assert decrypt_after["error"] == "key_not_found", \
        f"Expected key_not_found, got: {decrypt_after['error']}"
    print(f"  Decrypt attempt: error='{decrypt_after['error']}'")
    print(f"  ✓ Decryption failed: key_not_found")

    # Verify via the verify endpoint
    verify_resp = requests.get(
        f"{GW}/audit/erase/{SUBJECT_ID}/verify", timeout=10
    ).json()
    assert verify_resp["decryption_result"] == "failed", \
        f"Expected failed, got: {verify_resp['decryption_result']}"
    print(f"  Verify endpoint: {verify_resp['decryption_result']}")
    print(f"  ✓ PII is irrecoverable. Erasure complete.")

    # ── Step 7: Verify chain integrity survives erasure ────────────────
    print(f"\n{SEP}")
    print(f"── Step 7: Verify chain integrity survives erasure")
    print(SEP)

    chain = requests.get(f"{GW}/audit/verify").json()
    assert chain["valid"], f"Chain should be valid, got: {chain}"
    print(f"  ✓ Chain VALID — {chain['record_count']} records.")
    print(f"  Erasure does not break chain integrity.")
    print(f"  Audit completeness preserved. Only the key was deleted.")

    # ── Summary ────────────────────────────────────────────────────────
    print()
    print(HEADER)
    print("  CRYPTO-SHREDDING DEMO SUMMARY")
    print(HEADER)
    print(f"  7/7 steps completed successfully")
    print()
    print(f"  Subject:             {SUBJECT_ID}")
    print(f"  Records encrypted:   {len(pii_records)}")
    print(f"  Records erased:      {erase_resp['records_affected']}")
    print(f"  Chain integrity:     VALID ({chain['record_count']} records)")
    print(f"  Erasure certificate: {erase_resp['erasure_certificate'][:32]}...")
    print()
    print(f"  🎉 CRYPTO-SHREDDING DEMO COMPLETE")
    print(f"  GDPR compliance achieved. Audit trail preserved.")
    print(f"  The key is gone. The ciphertext remains. No conflict.")
    print()


if __name__ == "__main__":
    main()
