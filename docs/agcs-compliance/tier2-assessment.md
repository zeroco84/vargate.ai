# AGCS Tier 2 Self-Assessment — Vargate v1.0

Assessment date: 2026-04-08
Assessor: Automated (Claude Code)
System: Vargate Gateway v1.0.0
AGCS version: 0.9

---

## AG-2.1: Structured Audit Schema

**Status:** PASS

**Evidence:** Audit records follow a structured schema with 20+ typed fields defined in the SQLite `audit_log` table (`gateway/main.py` lines 370-410). Schema includes: `action_id`, `agent_id`, `tool`, `method`, `params` (JSON), `decision`, `violations` (JSON array), `severity`, `alert_tier`, `record_hash`, `prev_hash`, `requested_at`, `decided_at`, `bundle_revision`, `evaluation_pass`, `anomaly_score_at_eval`, `opa_input` (full decision input snapshot), `contains_pii`, `pii_subject_id`, `pii_fields`, `execution_mode`, `execution_result`, `execution_latency_ms`, `credential_accessed`, `tenant_id`.

Forward-only schema migrations managed via `gateway/migrations.py` with an ordered version table.

**Verification:**
```bash
curl https://vargate.ai/api/audit/log?limit=1 -H "X-API-Key: YOUR_KEY"
# Returns structured record with all typed fields
```

---

## AG-2.2: Merkle Tree Audit Aggregation

**Status:** PASS

**Evidence:** Implemented in `gateway/merkle.py`. Hourly tenant-scoped Merkle trees built as background tasks (`gateway/main.py` line 178). Each tree covers a batch of audit records with O(log n) inclusion proofs. Trees stored in `merkle_trees` table with `merkle_root`, `record_count`, `from_record_id`, `to_record_id`, `tenant_id`, and timestamp. Consistency proofs between tree periods available.

**Files:**
- `gateway/merkle.py` — `MerkleTree` class, `build_hourly_merkle_trees()`, proof generation
- `gateway/routes_anchor.py` — API endpoints for tree queries
- `test_7c_compliance.py` — Compliance tests for AG-2.2

**Endpoints:**
- `GET /audit/merkle/roots` — List all Merkle trees with roots
- `GET /audit/merkle/proof/{record_hash}` — Get inclusion proof for a specific record
- `GET /audit/merkle/consistency/{tree_n}/{tree_m}` — Consistency proof between tree periods

**Verification:**
```bash
curl https://vargate.ai/api/audit/merkle/roots -H "X-API-Key: YOUR_KEY"
# Returns: list of Merkle trees with roots, record ranges, timestamps

curl https://vargate.ai/api/audit/merkle/proof/{record_hash} -H "X-API-Key: YOUR_KEY"
# Returns: {"proof": [...], "merkle_root": "...", "verified": true}
```

---

## AG-2.3: Blockchain Anchoring with Inclusion Proofs

**Status:** PASS

**Evidence:** Multi-chain blockchain anchoring implemented in `gateway/blockchain_client.py`. Supports Polygon (production), Ethereum mainnet, and Sepolia testnet. Merkle roots are submitted to the `MerkleAuditAnchor` smart contract (`blockchain/contracts/MerkleAuditAnchor.sol`) which stores the root on-chain with `prevMerkleRoot` for hash-chaining across anchor periods. Gas-optimized with skip logic when root unchanged. Anchor events recorded in `merkle_anchor_log` table with tx hash, block number, and chain name.

**Files:**
- `gateway/blockchain_client.py` — `BlockchainClient` class, `_anchor_now_sync()`, multi-chain support
- `blockchain/contracts/MerkleAuditAnchor.sol` — Smart contract with `submitAnchor()` and `getAnchor()`
- `gateway/routes_anchor.py` — Anchor status and proof endpoints
- `test_blockchain.py`, `test_sepolia_blockchain.py` — Blockchain integration tests

**Endpoints:**
- `GET /anchor/status` — Current anchor status (last anchor, chain, tx hash)
- `GET /anchor/verify` — Verify on-chain anchor matches local Merkle root
- `GET /anchor/proof/{action_id}` — Get blockchain-anchored inclusion proof for an action
- `POST /anchor/trigger` — Manually trigger an anchor cycle

**Verification:**
```bash
curl https://vargate.ai/api/anchor/status -H "X-API-Key: YOUR_KEY"
# Returns: {"chain": "polygon", "last_anchor": "...", "tx_hash": "0x...", "block_number": ...}

curl https://vargate.ai/api/anchor/verify -H "X-API-Key: YOUR_KEY"
# Returns: {"verified": true, "on_chain_root": "...", "local_root": "..."}
```

**On-chain verification:** Anchor transactions viewable on Polygonscan at the contract address.

---

## AG-2.4: GDPR/Retention Reconciliation (Crypto-Shredding)

**Status:** PASS

**Evidence:** Crypto-shredding via SoftHSM2. PII fields in action parameters are detected automatically and encrypted with per-subject HSM keys before storage. GDPR erasure implemented via `POST /audit/erase/{subject_id}` which destroys the HSM encryption key, rendering all ciphertext for that subject irrecoverable. Erasure is verified via `GET /audit/erase/{subject_id}/verify` which confirms the key no longer exists.

**Files:**
- `gateway/main.py` — `detect_pii_fields()`, `encrypt_pii_in_params()`
- `hsm/hsm_service.py` — HSM key management, encryption/decryption, key destruction
- `gateway/routes_audit.py` — Erasure and verification endpoints
- `test_crypto_shredding.py` — Crypto-shredding test suite

**Endpoints:**
- `POST /audit/erase/{subject_id}` — Destroy HSM key for subject (irreversible)
- `GET /audit/erase/{subject_id}/verify` — Verify erasure is complete

**Verification:**
```bash
# Erase subject data
curl -X POST https://vargate.ai/api/audit/erase/user-123 -H "X-API-Key: YOUR_KEY"
# Returns: {"status": "erased", "subject_id": "user-123", "records_affected": N}

# Verify irreversibility
curl https://vargate.ai/api/audit/erase/user-123/verify -H "X-API-Key: YOUR_KEY"
# Returns: {"erased": true, "key_exists": false}
```

---

## AG-2.5: Policy Versioning and Bundle Management

**Status:** PASS

**Evidence:** OPA policy bundles are versioned and served by the bundle-server (`bundle-server/`). Each bundle has a revision identifier (e.g., `v1.0.0-1775678973`) recorded in every audit log entry (`bundle_revision` field). This enables historical policy reconstruction: given an audit record's `bundle_revision` and `opa_input`, the exact policy evaluation can be reproduced.

**Verification:**
```bash
# Every audit record includes the policy bundle revision used for the decision
curl https://vargate.ai/api/audit/log?limit=1 -H "X-API-Key: YOUR_KEY"
# Record includes: "bundle_revision": "v1.0.0-..."
```

---

## AG-2.6: External Blockchain Anchoring

**Status:** PASS

**Evidence:** Same implementation as AG-2.3. Multi-chain support with Polygon (production primary), Ethereum mainnet, and Sepolia testnet. Chain selection configurable per-tenant via `anchor_chain` setting. Smart contract deployed on all supported chains.

**Verification:**
```bash
# Configure chain preference
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"anchor_chain": "polygon"}'
```

---

## AG-2.7: Webhook Notifications for Governance Events

**Status:** PASS

**Evidence:** Webhook delivery system in `gateway/webhooks.py`. HMAC-SHA256 signed payloads with retry and exponential backoff. Tenants configure webhook URL (HTTPS required), events, and receive a signing secret. Supported events: `action.denied`, `action.pending`, `action.allowed`, `chain.anchored`. Test endpoint at `POST /webhooks/test`.

**Verification:**
```bash
# Configure webhook
curl -X PATCH https://vargate.ai/api/dashboard/settings \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://your-server.com/webhook", "webhook_events": ["action.denied"]}'
# Returns: {"status": "updated", "webhook_secret": "..."}

# Test delivery
curl -X POST https://vargate.ai/api/webhooks/test -H "X-API-Key: YOUR_KEY"
# Returns: {"status": "delivered"}
```

---

## AG-2.8: Decision Replayability

**Status:** PASS

**Evidence:** Implemented via `POST /audit/replay` and `POST /audit/replay-bulk` in `gateway/routes_audit.py`. Replays historical actions against current or archived policy to verify consistency. Each audit record stores the complete `opa_input` snapshot used for the original decision, enabling exact reproduction. Tested in `test_replay.py`.

**Files:**
- `gateway/routes_audit.py` — `replay_decision()`, `replay_bulk()`
- `test_replay.py` — Decision replayability tests (AGCS AG-2.8)

**Endpoints:**
- `POST /audit/replay` — Replay a single action against current policy
- `POST /audit/replay-bulk` — Replay multiple actions for drift detection

**Verification:**
```bash
curl -X POST https://vargate.ai/api/audit/replay \
  -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"action_id": "550e8400-e29b-41d4-a716-446655440000"}'
# Returns: {"original_decision": "allow", "replay_decision": "allow", "consistent": true}
```

---

## AG-2.9: GTM Agent Safety Constraints

**Status:** PASS

**Evidence:** Go-to-market agent safety constraints in `gateway/gtm_constraints.py`. Hard safety blocks that run before OPA: blocked domains (competitor sites, social media), daily outreach cap (50/day), cooldown between actions (60s), AI disclosure requirements. These constraints cannot be overridden by policy — they are gateway-level blocks.

**Files:**
- `gateway/gtm_constraints.py` — `check_gtm_constraints()`
- `policies/vargate/gtm_policy.rego` — GTM-specific OPA policy

**Verification:**
```bash
# GTM agent blocked from competitor domains
# GTM agent rate-limited to 50 actions/day
# GTM agent required to include AI disclosure
```

---

## Summary

| Control | Status | Implementation |
|---------|--------|----------------|
| AG-2.1 | PASS | Structured 20+ field audit schema with migrations |
| AG-2.2 | PASS | Hourly Merkle trees with O(log n) inclusion proofs |
| AG-2.3 | PASS | Multi-chain blockchain anchoring (Polygon, ETH, Sepolia) |
| AG-2.4 | PASS | Crypto-shredding via SoftHSM2 for GDPR erasure |
| AG-2.5 | PASS | Versioned OPA policy bundles with audit linkage |
| AG-2.6 | PASS | External blockchain anchoring (Polygon production) |
| AG-2.7 | PASS | HMAC-SHA256 signed webhooks with retry |
| AG-2.8 | PASS | Decision replay against current/historical policy |
| AG-2.9 | PASS | GTM agent hard safety constraints |

**Overall Tier 2 Status: PASS (9/9 controls)**

### AG-3.x Controls (Tier 3 — Partial)

| Control | Status | Notes |
|---------|--------|-------|
| AG-3.2 | PASS | Blockchain anchor events written to audit log (`gateway/main.py` line 642) |
| AG-3.4 | PARTIAL | SoftHSM2 in use (software). FIPS 140-2 Level 3 HSM required for full Tier 3. HSM signer abstraction ready (`gateway/blockchain_client.py` line 58). |

> Note: Tier 3 certification requires hardware HSM (FIPS 140-2 Level 3) and TEE attestation. See enterprise roadmap for planned implementation.

> This self-assessment is based on codebase analysis. The full AGCS v0.9 standard should be referenced for completeness. A third-party assessment is recommended for formal certification.
