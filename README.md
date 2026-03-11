# Vargate — AI Agent Supervision Gateway

Vargate sits in the execution path of autonomous AI agents and intercepts every tool call they make. Before forwarding a call to the real tool (Salesforce, Gmail, Stripe, etc.), Vargate evaluates it against an OPA policy. If the policy allows it, the call goes through. If not, it is blocked and logged. Every decision — allow or deny — is written to a hash-chained append-only audit log.

## Quick Start (Local Dev)

```bash
# Start all 7 services
docker-compose up --build

# In another terminal, run the test scripts
pip install requests
python test_demo.py              # Session 1 — 3 core scenarios
python test_hotswap.py           # Session 2 — live policy hot-swap
python test_behavioral.py        # Session 3 — behavioral history demo
python test_replay.py            # Session 5 — policy replay verification
python test_crypto_shredding.py  # Session 6 — GDPR crypto-shredding
python test_blockchain.py        # Session 7 — blockchain anchoring

# Open the audit dashboard
open http://localhost:3000
```

## Production Deployment (Hetzner)

```bash
# On the server:
git clone https://github.com/your-org/vargate.git ~/vargate
cd ~/vargate
cp .env.example .env
nano .env                        # Set REDIS_PASSWORD (openssl rand -hex 32)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

# See DEPLOYMENT.md for the full guide (TLS, hardening, DNS)
```


## Architecture

```
                                ┌─────────────────┐
                                │  Bundle Server   │── ETag polling ──► OPA
                                │   (port 8080)    │
                                └─────────────────┘
                                         │
Agent ─► POST /mcp/tools/call ─► Vargate Gateway ──► OPA Policy Check ──► Allow / Block
                                    │         │
                                    │    ┌────┘
                                    ▼    ▼
                            SQLite Audit Log   Redis Behavioral History
                            (hash-chained)     (counters, anomaly score)
                                    │                    │
                                    ▼                    ▼
                    ┌───────────────────────────────────────────────┐
                    │                                               │
              SoftHSM2 (PKCS#11)         Hardhat Ethereum (local)  │
              AES-256 per-subject        AuditAnchor contract      │
              crypto-shredding           periodic chain anchoring  │
                    │                                               │
                    └───────────────────────────────────────────────┘
                                    │
                                    ▼
                            React Dashboard ── http://localhost:3000
                              (port 3000)
```

## Services

| Service         | Port | Description                                             |
|-----------------|------|---------------------------------------------------------|
| `bundle-server` | 8080 | Serves OPA policy bundles with ETag polling              |
| `redis`         | 6379 | Behavioral history (counters, anomaly scores, actions)   |
| `opa`           | 8181 | Open Policy Agent — pulls bundles from bundle-server     |
| `gateway`       | 8000 | FastAPI MCP proxy with two-pass OPA evaluation           |
| `hsm`           | 8300 | SoftHSM2 PKCS#11 service for per-subject AES-256 keys   |
| `blockchain`    | 8545 | Hardhat local Ethereum network + AuditAnchor contract    |
| `ui`            | 3000 | React audit dashboard (nginx + Vite build)               |

---

## Build Sessions — Detailed Breakdown

### Stage 1 — MCP Proxy, OPA Policy & Hash-Chained Audit Log

The foundation of Vargate: a FastAPI gateway that intercepts every AI agent tool call, evaluates it against an OPA policy engine, and records every decision in a tamper-evident audit log.

**Gateway (`gateway/main.py`)**

The gateway exposes a single interception endpoint — `POST /mcp/tools/call` — that accepts a structured request containing the agent's identity, the tool being called, the method, and parameters. For each request it:

1. Generates a unique `action_id` (UUID v4)
2. Assembles an OPA input document containing agent metadata (id, type, version, jurisdiction, roles), action details, temporal context, and data classification
3. Sends the input to OPA for evaluation
4. Writes the result to the SQLite audit log

**OPA Policy (`policies/vargate/policy.rego`)**

The initial Rego policy defines 5 violation rules evaluated against every tool call:

| Rule | Condition | Severity |
|------|-----------|----------|
| `high_value_transaction_unapproved` | `params.amount ≥ £5,000` and no approval granted | high |
| `competitor_contact_attempt` | Gmail `send_email` to a competitor domain (`rival.com`, `competitor.com`, `acmecorp.com`) | critical |
| `gdpr_pii_residency_violation` | PII leaving the EU when residency is required | critical |
| `anomaly_score_threshold_exceeded` | Agent anomaly score > 0.7 | medium |
| `high_value_out_of_hours` | Amount ≥ £1,000 outside business hours (Mon–Fri 09:00–18:00 UTC) | medium |

The policy returns a structured decision object: `{ allow, violations, severity, requires_human, alert_tier }`. Severity is derived via an else-chain (`critical → high → medium → none`), and alert routing maps to SOC page, SOC ticket, Slack alert, or none.

**Hash-Chained Audit Log (SQLite)**

Every decision is written to a SQLite database with WAL journaling. Each record includes a SHA-256 hash computed over its fields plus the hash of the preceding record, forming an append-only chain anchored to a `GENESIS` block:

```
GENESIS → hash₁ → hash₂ → hash₃ → ... → hashₙ
```

The hash is computed in a canonical JSON order over: `action_id`, `agent_id`, `tool`, `method`, `params`, `requested_at`, `decision`, `violations`, `severity`, `bundle_revision`, `prev_hash`. Tampering with any record breaks the chain from that point forward.

**Audit columns:** `id`, `action_id`, `agent_id`, `tool`, `method`, `params`, `requested_at`, `decision`, `violations`, `severity`, `alert_tier`, `bundle_revision`, `prev_hash`, `record_hash`, `created_at`

**Chain verification:** `GET /audit/verify` walks the entire chain and reports validity by recomputing each hash and checking `prev_hash` linkage.

**Test script:** `test_demo.py` runs 3 core scenarios — an allowed low-value CRM read, a blocked high-value unapproved transaction, and a blocked competitor email — then verifies the hash chain is intact.

---

### Stage 2 — Bundle Server, ETag Polling & Live Policy Hot-Swap

Replaces static policy files with a dynamic bundle server that generates, serves, and archives OPA policy bundles. Policies can be changed at runtime without restarting any service.

**Bundle Server (`bundle-server/main.py`)**

A FastAPI service that:

1. **Generates Rego from state** — maintains an in-memory `BundleState` object (competitor domains list, high-value thresholds) and dynamically generates the `.rego` policy file from a template
2. **Builds OPA bundles** — packages the generated Rego + `.manifest` JSON into a `tar.gz` bundle
3. **Serves via ETag** — OPA polls `GET /bundles/vargate` every 5–10 seconds. The response includes an `ETag` header (SHA-256 prefix of the bundle bytes). If the `If-None-Match` header matches the current ETag, the server returns `304 Not Modified`
4. **Archives every revision** — each bundle build writes a timestamped `.tar.gz` to `/data/archive/` for later replay (used in Stage 5)

**Live update operations** via `POST /bundles/vargate/update`:

| Operation | Payload | Effect |
|-----------|---------|--------|
| `add_competitor_domain` | `{ "domain": "newcorp.com" }` | Adds domain to blocklist, rebuilds bundle |
| `remove_competitor_domain` | `{ "domain": "rival.com" }` | Removes domain from blocklist, rebuilds bundle |
| `set_high_value_threshold` | `{ "threshold": 10000 }` | Changes the £ threshold for high-value violations |
| `restore_defaults` | — | Resets all thresholds and domains to defaults |

Each operation increments the revision (format: `v1.0.0-{unix_timestamp}`), rebuilds the bundle, archives it, and updates the ETag. OPA detects the ETag change on its next poll and hot-swaps to the new policy.

**OPA Configuration (`config/opa-config.yaml`)**

OPA is configured to poll the bundle server with a 5–10 second interval for bundle discovery and updates.

**Test script:** `test_hotswap.py` demonstrates live policy changes — adds a new competitor domain mid-session, shows that OPA blocks emails to the new domain, then removes it and verifies the block is lifted. All policy transitions are logged with their revision numbers.

---

### Stage 3 — Redis Behavioral History & Two-Pass Evaluation

Adds stateful, per-agent behavioral tracking and a two-pass evaluation architecture that balances speed with context-awareness.

**Two-Pass Evaluation**

| Phase | Latency | Redis Calls | What Happens |
|-------|---------|-------------|--------------|
| **Pass 1 — Fast path** | ~5ms | 1 (violation check) | OPA evaluates with neutral history defaults. Returns `evaluation_mode`: `"fast"` (no risk) or `"needs_enrichment"` (risk indicators detected) |
| **Pass 2 — Enriched** | ~20ms | Full pipeline | Full behavioral history fetched from Redis and injected into OPA input. History-aware rules can now fire |

The gateway also performs a cheap single-key Redis check (`HGET violation_count_24h`) on every request. If the agent has any recorded violations, Pass 2 is forced regardless of OPA's recommendation.

**Risk indicators** that trigger Pass 2 escalation:
- `elevated_action_type` — tool is `stripe`, `wire_transfer`, or `payroll`
- `large_params` — `params.amount ≥ 1000`
- `off_hours` — request is outside business hours

**Redis Data Model**

Per-agent state stored across 3 Redis keys:

| Key Pattern | Type | TTL | Contents |
|-------------|------|-----|----------|
| `agent:{id}:counters` | Hash | 25h | `action_count_10min`, `action_count_24h`, `denied_count_10min`, `violation_count_24h`, `high_value_count_24h` |
| `agent:{id}:anomaly_score` | String | 7 days | Float 0.0–1.0 |
| `agent:{id}:actions` | Sorted Set | trimmed to 24h | Action timeline scored by Unix timestamp |

**Anomaly Score Formula**

After each decision the anomaly score is updated:
- **Decay:** `score × 0.95` per action (natural recovery)
- **On denial:** `+0.15` (sharp increase)
- **On high-value allow:** `+0.03` (mild increase for amount ≥ £1,000)
- Score is clamped to `[0.0, 1.0]`

**Two additional Pass 2 violation rules** (added to the bundle-generated policy):

| Rule | Condition | Severity |
|------|-----------|----------|
| `repeated_violations_today` | ≥ 3 policy violations in 24h | high |
| `high_value_frequency_limit_exceeded` | ≥ 5 high-value transactions in 24h with amount ≥ £1,000 | medium |

**Test script:** `test_behavioral.py` demonstrates anomaly score escalation across multiple violations, the two-pass evaluation flow, history-aware blocking, and agent history reset.

---

### Stage 4 — React Audit Dashboard

A real-time React dashboard served via nginx that visualises the audit log, policy timeline, and chain integrity status.

**Dashboard features:**

| Feature | Description |
|---------|-------------|
| **Chain status banner** | Green when the hash chain is intact, red with broken-link details when tampered |
| **Stats cards** | Total actions, allowed count, blocked count, active policy revision |
| **Audit table** | Decision pills (green/red), severity badges, Pass 1/2 indicators, chain ✓/✗ per record |
| **Expandable detail** | Click any row for full params, hashes, OPA input, evaluation metadata |
| **Tamper simulation** | Corrupt a specific record's hash and watch the chain break visually, then restore |
| **Policy timeline** | Visual history showing policy version transitions with timestamps |
| **Live mode** | Auto-refreshes all data every 3 seconds via polling |

**Tamper simulation endpoints (demo only):**
- `POST /audit/tamper-simulate` — corrupts a specific record's hash with a random value, breaking the chain from that point onward
- `POST /audit/tamper-restore` — restores all original hashes from an in-memory store

**Tech stack:** React (Vite build) → nginx reverse proxy → gateway API on port 8000. The nginx config proxies `/api/` requests to the gateway.

---

### Stage 5 — Policy Replay & Decision Replayability

Any historical decision can be reproduced from the original OPA input document and the archived policy bundle. This satisfies AGCS control AG-2.8 — Decision Replayability.

**How replay works:**

1. Every audit record now stores the complete OPA input document used for the decision (`opa_input` column added to SQLite)
2. Every policy bundle is archived by revision in the bundle server's `/data/archive/` directory
3. The replay endpoint fetches the archived bundle, extracts it to a temp directory, starts an **ephemeral OPA instance** on a random port, evaluates the stored input, and compares the result
4. Decision, violations, and severity must all match for a **VERIFIED** status

**Replay endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /audit/replay` | Single record | Replay by `action_id`, `record_number`, or `last_block=true` |
| `POST /audit/replay-bulk` | Batch | Replay the last N records (default 10) |

**Replay response structure:**
```json
{
  "action_id": "...",
  "replay_status": "MATCH",
  "original": { "decision": "deny", "violations": [...], "severity": "high" },
  "replayed": { "decision": "deny", "violations": [...], "severity": "high" },
  "match": { "decision": true, "violations": true, "severity": true },
  "interpretation": "The recorded decision is verified..."
}
```

A `MISMATCH` status indicates either: (a) the stored input document was modified, or (b) the archived bundle does not match what was deployed at the time — recommending forensic investigation.

**CLI tool (`replay.py`):**

```bash
# Replay a specific action by UUID
python replay.py --action-id def456-7890-abcd-...

# Replay the most recent BLOCK decision
python replay.py --last-block

# Bulk verify the last 20 records
python replay.py --verify-last 20

# Replay by sequential record number
python replay.py --record 7
```

**Bundle archive endpoints:**

| Endpoint | Description |
|----------|-------------|
| `GET /bundles/vargate/archive/list` | List all archived revisions |
| `GET /bundles/vargate/archive/{revision}` | Download an archived bundle by revision |

**Test script:** `test_replay.py` creates actions under one policy version, hot-swaps the policy, creates more actions, then replays all of them to verify each decision matches its original bundle.

---

### Stage 6 — Crypto-Shredding via SoftHSM2 (GDPR Erasure)

Audit records must be kept for compliance, but GDPR requires that personal data be erasable. These two requirements conflict. Crypto-shredding resolves the conflict: PII is encrypted at rest with a per-subject AES-256 key managed by SoftHSM2 (PKCS#11). Deleting the key makes the ciphertext irrecoverable while preserving the audit record and hash chain.

**HSM Service (`hsm/hsm_service.py`)**

A FastAPI service wrapping SoftHSM2 via the PKCS#11 interface:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /keys` | Create | Generate (or return existing) AES-256 key for a data subject |
| `POST /encrypt` | Encrypt | AES-CBC + PKCS7 padding, 16-byte random IV prepended to ciphertext |
| `POST /decrypt` | Decrypt | Decrypt using subject's key; fails with `key_not_found` after erasure |
| `DELETE /keys/{subject_id}` | Delete | **Irreversible** — destroys the PKCS#11 key object, returns erasure certificate |
| `GET /keys/{subject_id}/status` | Status | Check if key exists or has been erased |
| `GET /keys` | List | List all subjects with key status |

Key properties: `EXTRACTABLE=False`, `SENSITIVE=True`, `TOKEN=True` — keys never leave the HSM boundary.

**PII Detection (Gateway)**

The gateway automatically scans incoming `params` for PII before writing audit records. Detection patterns:

| Pattern | Detection Method |
|---------|-----------------|
| Email addresses | Regex: `[^@\s]+@[^@\s]+\.[^@\s]+` |
| Name fields | Key matching: `name`, `customer_name`, `full_name`, `first_name`, `last_name` |
| Sort codes | Regex: `\d{2}-\d{2}-\d{2}` |
| NI numbers | Regex: `[A-Z]{2}\d{6}[A-Z]` |

When PII is detected, the gateway:
1. Extracts the subject ID from `customer_id`, `subject_id`, or `user_id` (falling back to `agent_id`)
2. Ensures an HSM key exists for the subject
3. Encrypts each PII field individually via the HSM
4. Stores the encrypted value as `[ENCRYPTED:{key_id}:{ciphertext_b64}]` in the audit record

**Erasure workflow:**

1. `POST /audit/erase/{subject_id}` — deletes the HSM key, marks all audit records as `erasure_status='erased'`, returns an SHA-256 erasure certificate
2. `GET /audit/erase/{subject_id}/verify` — attempts decryption of the first encrypted field to prove irrecoverability
3. Chain integrity is preserved — only the key is destroyed, not the records

**Additional audit columns:** `contains_pii`, `pii_subject_id`, `pii_fields`, `erasure_status`

**Test script:** `test_crypto_shredding.py` creates tool calls containing PII (email, name, sort code), verifies encryption in the audit log, performs erasure, and confirms decryption fails with the key destroyed.

---

### Stage 7 — Blockchain Anchoring via Hardhat

The hash chain in SQLite is tamper-evident but mutable: an attacker with database access could corrupt and recompute the entire chain. A periodic anchor to an external, immutable ledger makes this attack infeasible.

**AuditAnchor Smart Contract (`blockchain/contracts/AuditAnchor.sol`)**

A Solidity contract (^0.8.24) deployed to a local Hardhat Ethereum network:

```solidity
struct Anchor {
    uint256 blockNumber;
    uint256 timestamp;
    bytes32 chainTipHash;
    uint256 recordCount;
    string  systemId;
}
```

| Function | Description |
|----------|-------------|
| `submitAnchor(bytes32, uint256, string)` | Store chain state on-chain, emit `AnchorSubmitted` event |
| `getAnchor(uint256)` | Retrieve an anchor by index |
| `getLatestAnchor()` | Get the most recent anchor and its index |
| `getAnchorCount()` | Total number of anchors submitted |

**Blockchain Client (Gateway)**

The gateway includes a `BlockchainClient` class that uses `web3.py` to interact with the deployed contract. On startup, it reads the contract address and ABI from a shared Docker volume (written by the Hardhat deploy script).

**Anchor loop:** A background `asyncio` task runs every 60 seconds (configurable via `ANCHOR_INTERVAL_SECONDS`):
1. Reads the current chain tip hash and record count from SQLite
2. Calls `submitAnchor()` on the smart contract
3. Waits for the transaction receipt
4. Extracts the `anchorIndex` from the `AnchorSubmitted` event log
5. Writes the anchor to the local `anchor_log` SQLite table

**Anchor endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /anchor/trigger` | Trigger | Submit an immediate anchor (bypasses the 60s interval) |
| `GET /anchor/log` | Log | Return all anchor records with tx hashes and block numbers |
| `GET /anchor/verify` | Verify | Compare current chain tip against the latest on-chain anchor |
| `GET /anchor/status` | Status | Blockchain connection status, contract address, anchor count |

**Three-layer tamper evidence:**

| Layer | Mechanism | Detects |
|-------|-----------|---------|
| **Layer 1: Hash chain (SQLite)** | SHA-256 linked records | Any individual record modification |
| **Layer 2: Policy replay (OPA)** | Ephemeral OPA re-evaluation | Decision correctness / input tampering |
| **Layer 3: Blockchain anchor** | On-chain Ethereum state | Full chain recomputation attacks |

**Hardhat setup:**
- `blockchain/hardhat.config.js` — configures Hardhat with Solidity 0.8.24
- `blockchain/scripts/deploy.js` — deploys the `AuditAnchor` contract and writes the address + ABI to `/shared/` for the gateway to consume
- `blockchain/entrypoint.sh` — starts the Hardhat node, waits for it to be ready, deploys the contract

**Anchor log columns:** `anchor_index`, `chain_tip_hash`, `record_count`, `tx_hash`, `block_number`, `anchored_at`

**Test script:** `test_blockchain.py` creates audit records, triggers an anchor, verifies the chain tip matches the on-chain anchor, creates more records, re-anchors, and validates the full anchor log history.

---

## Full Endpoint Reference

| Method | Path                        | Stage | Description                                      |
|--------|-----------------------------|-------|--------------------------------------------------|
| POST   | `/mcp/tools/call`           | 1 | Submit a tool call for evaluation                |
| GET    | `/audit/verify`             | 1 | Verify hash chain integrity                      |
| GET    | `/audit/log`                | 1 | Retrieve audit records (with `limit`, `agent_id`)|
| GET    | `/health`                   | 1 | Gateway health check (includes Redis, blockchain)|
| GET    | `/bundles/vargate/status`   | 2 | Current policy revision, ETag, rule count        |
| POST   | `/bundles/vargate/update`   | 2 | Live policy update (add/remove domains, etc.)    |
| GET    | `/bundles/vargate/archive/list` | 5 | List all archived bundle revisions            |
| GET    | `/bundles/vargate/archive/{revision}` | 5 | Retrieve an archived bundle by revision |
| GET    | `/agents/{id}/anomaly_score`| 3 | Get current anomaly score for an agent           |
| DELETE | `/agents/{id}/history`      | 3 | Clear behavioral history for an agent            |
| POST   | `/audit/tamper-simulate`    | 4 | DEMO: corrupt a record hash to break the chain   |
| POST   | `/audit/tamper-restore`     | 4 | DEMO: restore corrupted hashes                   |
| POST   | `/audit/replay`             | 5 | Replay a policy decision from archived input/bundle |
| POST   | `/audit/replay-bulk`        | 5 | Bulk replay the last N records                   |
| POST   | `/audit/erase/{subject_id}` | 6 | GDPR erasure: delete HSM key, mark records       |
| GET    | `/audit/erase/{subject_id}/verify` | 6 | Verify erasure is irrecoverable           |
| GET    | `/audit/subjects`           | 6 | List all subjects with encrypted PII             |
| POST   | `/hsm/keys`                 | 6 | Generate AES-256 key for a data subject          |
| POST   | `/hsm/encrypt`              | 6 | Encrypt plaintext with subject's key             |
| POST   | `/hsm/decrypt`              | 6 | Decrypt ciphertext (fails after erasure)         |
| DELETE | `/hsm/keys/{subject_id}`    | 6 | Delete subject's key (erasure event)             |
| GET    | `/hsm/keys/{subject_id}/status` | 6 | Check key status                             |
| POST   | `/anchor/trigger`           | 7 | Trigger an immediate blockchain anchor           |
| GET    | `/anchor/log`               | 7 | Return all anchor records                        |
| GET    | `/anchor/verify`            | 7 | Verify chain tip against latest on-chain anchor  |
| GET    | `/anchor/status`            | 7 | Blockchain connection and anchor status          |

## Docker Volumes

| Volume | Purpose |
|--------|---------|
| `audit-data` | SQLite audit database (`audit.db`) |
| `bundle-archive` | Archived policy bundles by revision |
| `hsm-tokens` | SoftHSM2 PKCS#11 token storage |
| `shared-data` | Contract address + ABI shared between blockchain and gateway |

## Build Sessions Summary

| Session | What was built |
|---------|---------------|
| 1 | MCP proxy, OPA policy (5 rules), hash-chained audit log, `test_demo.py` |
| 2 | Bundle server, ETag polling, live policy hot-swap, `test_hotswap.py` |
| 3 | Redis behavioral history, two-pass evaluation, anomaly scoring, `test_behavioral.py` |
| 4 | React audit dashboard, tamper simulation, policy timeline |
| 5 | Policy replay, bundle archival, replay UI panel, `replay.py` CLI, `test_replay.py` |
| 6 | Crypto-shredding via SoftHSM2, PII detection, GDPR erasure, `test_crypto_shredding.py` |
| 7 | Blockchain anchoring via Hardhat, AuditAnchor smart contract, `test_blockchain.py` |

## License

Proprietary — Vargate.ai
