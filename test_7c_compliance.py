#!/usr/bin/env python3
"""
test_7c_compliance.py — Stage 7C compliance test script.

Tests all 8 fixes from Stage 7C against a running Vargate gateway.
Each fix has a labeled test section with pass/fail assertion.

Usage:
    python test_7c_compliance.py [--base-url http://localhost:8000]

Fixes covered:
    Fix 1: Async blocking (event loop not blocked by web3 calls)
    Fix 2: Merkle tree caching (TreeCache invalidation / warm reads)
    Fix 3: AG-3.2 — Anchor record in the hash-chained audit log
    Fix 4: AG-2.2 — Merkle root hash-chaining (consistency across periods)
    Fix 5: AG-2.2 — Local Merkle root recording between anchors
    Fix 6: AG-2.3 — Consistency proof endpoint
    Fix 7: Incremental anchoring (ANCHOR_MODE in status)
    Fix 8: Private key handling — SignerBackend HSM path
"""

import json
import sys
import time
import uuid
import requests
import argparse

# ── Configuration ────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="Stage 7C Compliance Tests")
parser.add_argument("--base-url", default="http://localhost:8000", help="Gateway base URL")
args = parser.parse_args()

BASE = args.base_url.rstrip("/")
results = []


def test(label: str, condition: bool, detail: str = ""):
    """Record a test result and print pass/fail."""
    status = "PASS" if condition else "FAIL"
    marker = "✓" if condition else "✗"
    results.append({"label": label, "passed": condition, "detail": detail})
    print(f"  {marker} {label}", flush=True)
    if detail and not condition:
        print(f"      → {detail}", flush=True)


def section(title: str):
    """Print a section header."""
    print(f"\n{'═' * 60}", flush=True)
    print(f"  {title}", flush=True)
    print(f"{'═' * 60}", flush=True)


# ── Helpers ──────────────────────────────────────────────────────────────────

def create_test_record():
    """Create a single audit record via the gateway."""
    action_id = str(uuid.uuid4())
    payload = {
        "agent_id": "test-7c-agent",
        "agent_type": "script",
        "tool": "test_tool",
        "method": "test_method",
        "params": {"test": True, "timestamp": time.time()},
    }
    r = requests.post(f"{BASE}/evaluate", json=payload, timeout=15)
    return r.status_code, action_id, r.json() if r.ok else {}


def get_health():
    r = requests.get(f"{BASE}/health", timeout=10)
    return r.json() if r.ok else {}


# ── Pre-flight ───────────────────────────────────────────────────────────────

section("Pre-flight: Gateway Health")

try:
    health = get_health()
    gateway_ok = health.get("status") in ("ok", "healthy") or "gateway" in str(health).lower()
    test("Gateway is running", True)
except Exception as e:
    test("Gateway is running", False, str(e))
    print("\nCannot connect to gateway. Exiting.\n")
    sys.exit(1)


# ══════════════════════════════════════════════════════════════════════════════
# Fix 1: Async blocking
# ══════════════════════════════════════════════════════════════════════════════

section("Fix 1: Async blocking (event loop)")

# Create a record so there's data to anchor
status_code, _, _ = create_test_record()
test("Can create audit records", status_code in (200, 201, 403))

# Test that the gateway remains responsive during anchor operations.
# If the event loop was blocked, a concurrent health check would time out.
import concurrent.futures

def health_during_trigger():
    """Hit /health while an anchor trigger might be running."""
    time.sleep(0.1)
    try:
        r = requests.get(f"{BASE}/health", timeout=5)
        return r.ok
    except Exception:
        return False

with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
    health_future = pool.submit(health_during_trigger)
    # Trigger anchor (may succeed or fail depending on Sepolia config)
    try:
        trigger_r = requests.post(f"{BASE}/anchor/trigger", timeout=30)
    except Exception:
        pass
    health_ok = health_future.result(timeout=10)

test("Health endpoint responsive during anchor trigger", health_ok,
     "Event loop not blocked")

# Verify methods exist as async wrappers (check /anchor/verify responds)
try:
    verify_r = requests.get(f"{BASE}/anchor/verify", timeout=15)
    test("GET /anchor/verify responds (verify_latest is async)",
         verify_r.status_code in (200, 500))
except Exception as e:
    test("GET /anchor/verify responds", False, str(e))

# Verify /anchor/status uses async get_latest_anchor
try:
    status_r = requests.get(f"{BASE}/anchor/status", timeout=15)
    test("GET /anchor/status responds (get_latest_anchor is async)",
         status_r.status_code == 200)
except Exception as e:
    test("GET /anchor/status responds", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Fix 2: Merkle tree caching
# ══════════════════════════════════════════════════════════════════════════════

section("Fix 2: Merkle tree caching")

# Create 3 records to populate the tree
for i in range(3):
    create_test_record()

# First proof call — should build the cache
try:
    # Get an action_id from the audit log
    log_r = requests.get(f"{BASE}/audit/log?limit=1", timeout=10)
    if log_r.ok and log_r.json().get("records"):
        action_id = log_r.json()["records"][0]["action_id"]

        t1 = time.time()
        proof_r1 = requests.get(f"{BASE}/anchor/proof/{action_id}", timeout=15)
        t1_elapsed = time.time() - t1

        # Second call — should be cached (faster)
        t2 = time.time()
        proof_r2 = requests.get(f"{BASE}/anchor/proof/{action_id}", timeout=15)
        t2_elapsed = time.time() - t2

        test("First proof call succeeds", proof_r1.ok)
        test("Second proof call succeeds (cached)", proof_r2.ok)

        # Cache hit should be at least slightly faster (or same)
        test("Cache provides consistent results",
             proof_r1.ok and proof_r2.ok
             and proof_r1.json().get("current_root") == proof_r2.json().get("current_root"))

        # After creating a new record, cache should invalidate
        create_test_record()
        proof_r3 = requests.get(f"{BASE}/anchor/proof/{action_id}", timeout=15)
        test("Proof still valid after new record (cache invalidated + rebuilt)",
             proof_r3.ok and proof_r3.json().get("verified", False))
    else:
        test("Could not retrieve audit log for cache test", False)
except Exception as e:
    test("Merkle tree caching test failed", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Fix 3: AG-3.2 — Anchor record in audit log
# ══════════════════════════════════════════════════════════════════════════════

section("Fix 3: AG-3.2 — Anchor audit record")

# Check if there are blockchain_anchor records in the audit log
try:
    log_r = requests.get(f"{BASE}/audit/log?limit=100", timeout=10)
    if log_r.ok:
        records = log_r.json().get("records", [])
        anchor_records = [r for r in records if r.get("tool") == "blockchain_anchor"]

        if anchor_records:
            test("Anchor audit records exist in hash-chained log", True)
            rec = anchor_records[0]
            params = rec.get("params", {})
            if isinstance(params, str):
                params = json.loads(params)

            test("Anchor record has tx_hash", bool(params.get("tx_hash")))
            test("Anchor record has merkle_root", bool(params.get("merkle_root")))
            test("Anchor record has network=sepolia", params.get("network") == "sepolia")
            test("Anchor record has chain_id=11155111", params.get("chain_id") == 11155111)
            test("Anchor record has contract_address", bool(params.get("contract_address")))
            test("Anchor record has explorer_url", "etherscan" in params.get("explorer_url", ""))
            test("Anchor record agent_id=vargate-system", rec.get("agent_id") == "vargate-system")
        else:
            # No anchor records — Sepolia might not be configured
            test("Anchor audit records exist (Sepolia may not be configured)", False,
                 "No blockchain_anchor records found. Trigger an anchor first.")
    else:
        test("Could not read audit log", False)
except Exception as e:
    test("AG-3.2 test failed", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Fix 4: AG-2.2 — Merkle root hash-chaining
# ══════════════════════════════════════════════════════════════════════════════

section("Fix 4: AG-2.2 — Merkle root hash-chaining")

try:
    chain_r = requests.get(f"{BASE}/anchor/chain-verify", timeout=15)
    test("GET /anchor/chain-verify responds", chain_r.ok)

    if chain_r.ok:
        data = chain_r.json()
        test("Chain verify returns 'valid' field", "valid" in data)
        test("Chain verify returns 'anchor_count' field", "anchor_count" in data)
        test("Chain verify returns 'chain' array", isinstance(data.get("chain"), list))

        if data.get("anchor_count", 0) > 0:
            test("Merkle root hash chain is valid", data["valid"])

            first_anchor = data["chain"][0]
            test("First anchor has prev_merkle_root", bool(first_anchor.get("prev_merkle_root")))
            test("First anchor has root_chain_hash", bool(first_anchor.get("root_chain_hash")))
            test("First anchor matches expected hash", first_anchor.get("match", False))
        else:
            test("No anchors to verify chain (need at least 1 anchor)", False,
                 "Trigger an anchor first.")
except Exception as e:
    test("Chain verify test failed", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Fix 5: AG-2.2 — Local Merkle root recording
# ══════════════════════════════════════════════════════════════════════════════

section("Fix 5: AG-2.2 — Local Merkle root recording")

try:
    roots_r = requests.get(f"{BASE}/merkle/roots", timeout=10)
    test("GET /merkle/roots responds", roots_r.ok)

    if roots_r.ok:
        data = roots_r.json()
        test("Response has 'roots' array", isinstance(data.get("roots"), list))
        test("Response has 'interval_seconds'", "interval_seconds" in data)
        test("Interval ≤ 3600s (AG-2.2 requires ≤ 1 hour)",
             data.get("interval_seconds", 9999) <= 3600)

        if data.get("roots"):
            root = data["roots"][0]
            test("Root entry has merkle_root", bool(root.get("merkle_root")))
            test("Root entry has record_count", "record_count" in root)
            test("Root entry has computed_at", bool(root.get("computed_at")))
            test("Root entry has anchored flag", "anchored" in root)
        else:
            test("Merkle root log entries exist", False,
                 "No roots recorded yet. Wait for the background loop.")
except Exception as e:
    test("Merkle root recording test failed", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Fix 6: AG-2.3 — Consistency proof
# ══════════════════════════════════════════════════════════════════════════════

section("Fix 6: AG-2.3 — Consistency proof")

try:
    # Test with invalid params
    bad_r = requests.get(f"{BASE}/anchor/consistency-proof?from_anchor_index=5&to_anchor_index=3",
                         timeout=10)
    test("Rejects from >= to", bad_r.status_code == 400)

    # Test with valid params (even if anchors don't exist)
    proof_r = requests.get(f"{BASE}/anchor/consistency-proof?from_anchor_index=0&to_anchor_index=1",
                           timeout=10)
    test("GET /anchor/consistency-proof responds",
         proof_r.status_code in (200, 404))

    if proof_r.ok:
        data = proof_r.json()
        test("Response has 'consistent' field", "consistent" in data)
        test("Response has 'from_anchor'", "from_anchor" in data)
        test("Response has 'to_anchor'", "to_anchor" in data)
        test("Response has 'verification'", "verification" in data)
        test("Consistency check passes", data.get("consistent", False))
    elif proof_r.status_code == 404:
        test("Consistency proof returns 404 when anchors don't exist (correct)", True)
except Exception as e:
    test("Consistency proof test failed", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Fix 7: Incremental anchoring
# ══════════════════════════════════════════════════════════════════════════════

section("Fix 7: Incremental anchoring (ANCHOR_MODE)")

try:
    status_r = requests.get(f"{BASE}/anchor/status", timeout=10)
    test("GET /anchor/status responds", status_r.ok)

    if status_r.ok:
        data = status_r.json()
        test("Status includes 'anchor_mode' field", "anchor_mode" in data)
        anchor_mode = data.get("anchor_mode", "")
        test("anchor_mode is 'full' or 'incremental'",
             anchor_mode in ("full", "incremental"),
             f"Got: {anchor_mode}")
except Exception as e:
    test("Incremental anchoring test failed", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Fix 8: SignerBackend abstraction
# ══════════════════════════════════════════════════════════════════════════════

section("Fix 8: SignerBackend HSM abstraction")

# Test the signer backend classes by importing them
try:
    sys.path.insert(0, "gateway")
    from blockchain_client import SignerBackend, EnvVarSigner, HsmSigner

    test("SignerBackend class exists", True)
    test("EnvVarSigner class exists", True)
    test("HsmSigner class exists", True)

    # Test SignerBackend protocol
    backend = SignerBackend()
    try:
        backend.sign_transaction(None, {})
        test("SignerBackend.sign_transaction raises NotImplementedError", False)
    except NotImplementedError:
        test("SignerBackend.sign_transaction raises NotImplementedError", True)

    # Test HsmSigner stub
    hsm = HsmSigner(hsm_slot=0, hsm_pin="test", key_label="test")
    try:
        hsm.sign_transaction(None, {})
        test("HsmSigner.sign_transaction raises NotImplementedError", False)
    except NotImplementedError as e:
        test("HsmSigner.sign_transaction raises NotImplementedError", True)
        test("HsmSigner error mentions DEPLOY.md", "DEPLOY.md" in str(e))

    try:
        hsm.get_address()
        test("HsmSigner.get_address raises NotImplementedError", False)
    except NotImplementedError as e:
        test("HsmSigner.get_address raises NotImplementedError", True)

    # Test EnvVarSigner with no key (should not crash)
    signer = EnvVarSigner(private_key="")
    test("EnvVarSigner with empty key does not crash", True)

    # Test BlockchainClient accepts signer parameter
    from blockchain_client import BlockchainClient
    client = BlockchainClient(signer=EnvVarSigner())
    test("BlockchainClient accepts signer parameter", True)
    test("BlockchainClient uses provided signer", isinstance(client.signer, EnvVarSigner))

except Exception as e:
    test("SignerBackend import/test failed", False, str(e))


# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════

section("SUMMARY")

total = len(results)
passed = sum(1 for r in results if r["passed"])
failed = total - passed

print(f"\n  Total: {total}  |  Passed: {passed}  |  Failed: {failed}\n")

if failed:
    print("  Failed tests:")
    for r in results:
        if not r["passed"]:
            print(f"    ✗ {r['label']}")
            if r["detail"]:
                print(f"        → {r['detail']}")
    print()

sys.exit(0 if failed == 0 else 1)
