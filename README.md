# Vargate — AI Agent Supervision Gateway

Vargate sits in the execution path of autonomous AI agents and intercepts every tool call they make. Before forwarding a call to the real tool (Salesforce, Gmail, Stripe, etc.), Vargate evaluates it against an OPA policy. If the policy allows it, the call goes through. If not, it is blocked and logged. Every decision — allow or deny — is written to a hash-chained append-only audit log.

## Quick Start

```bash
# Start all 5 services
docker-compose up --build

# In another terminal, run the test scripts
pip install requests
python test_demo.py        # Session 1 — 3 core scenarios
python test_hotswap.py     # Session 2 — live policy hot-swap
python test_behavioral.py  # Session 3 — behavioral history demo

# Open the audit dashboard
open http://localhost:3000
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
| `ui`            | 3000 | React audit dashboard (nginx + Vite build)               |

## Endpoints

| Method | Path                        | Description                                      |
|--------|-----------------------------|--------------------------------------------------|
| POST   | `/mcp/tools/call`           | Submit a tool call for evaluation                |
| GET    | `/audit/verify`             | Verify hash chain integrity                      |
| GET    | `/audit/log`                | Retrieve audit records (with `limit`, `agent_id`)|
| GET    | `/health`                   | Gateway health check (includes Redis status)     |
| GET    | `/agents/{id}/anomaly_score`| Get current anomaly score for an agent           |
| DELETE | `/agents/{id}/history`      | Clear behavioral history for an agent            |
| POST   | `/audit/tamper-simulate`    | DEMO: corrupt a record hash to break the chain   |
| POST   | `/audit/tamper-restore`     | DEMO: restore corrupted hashes                   |
| POST   | `/audit/replay`             | Replay a policy decision from archived input/bundle |
| POST   | `/audit/replay-bulk`        | Bulk replay the last N records                   |
| POST   | `/audit/erase/{subject_id}` | GDPR erasure: delete HSM key, mark records       |
| GET    | `/audit/erase/{subject_id}/verify` | Verify erasure is irrecoverable           |
| GET    | `/audit/subjects`           | List all subjects with encrypted PII             |
| POST   | `/hsm/keys`                 | Generate AES-256 key for a data subject          |
| POST   | `/hsm/encrypt`              | Encrypt plaintext with subject's key             |
| POST   | `/hsm/decrypt`              | Decrypt ciphertext (fails after erasure)         |
| DELETE | `/hsm/keys/{subject_id}`    | Delete subject's key (erasure event)             |
| GET    | `/hsm/keys/{subject_id}/status` | Check key status                             |
| GET    | `/bundles/vargate/status`   | Current policy revision, ETag, rule count        |
| POST   | `/bundles/vargate/update`   | Live policy update (add/remove domains, etc.)    |
| GET    | `/bundles/vargate/archive/list` | List all archived bundle revisions            |
| GET    | `/bundles/vargate/archive/{revision}` | Retrieve an archived bundle by revision |
| POST   | `/anchor/trigger`           | Trigger an immediate blockchain anchor           |
| GET    | `/anchor/log`               | Return all anchor records                        |
| GET    | `/anchor/verify`            | Verify chain tip against latest on-chain anchor  |
| GET    | `/anchor/status`            | Blockchain connection and anchor status          |

## Policy Rules

The OPA policy evaluates each tool call against 7 violation rules:

| Rule | Triggers on | Severity |
|------|-------------|----------|
| `high_value_transaction_unapproved` | Amount ≥ £5,000, no approval | high |
| `competitor_contact_attempt` | Email to a competitor domain | critical |
| `gdpr_pii_residency_violation` | PII leaving the EU | critical |
| `anomaly_score_threshold_exceeded` | Anomaly score > 0.7 | medium |
| `high_value_out_of_hours` | High-value action outside business hours | medium |
| `repeated_violations_today` | 3+ policy violations in 24h (Pass 2) | high |
| `high_value_frequency_limit_exceeded` | 5+ high-value actions in 24h (Pass 2) | medium |

## Two-Pass Evaluation

Vargate uses a two-pass evaluation pattern to balance speed with context-awareness:

**Pass 1 — Fast path** (~5ms, no Redis):
OPA evaluates with neutral history defaults. Returns `evaluation_mode`:
- `"fast"` — no risk indicators, allow/deny immediately
- `"needs_enrichment"` — risk indicators detected, proceed to Pass 2

The gateway also checks a single Redis key to see if the agent has recent violations. If so, it escalates to Pass 2 even if OPA said "fast".

**Pass 2 — Enriched** (~20ms, with Redis):
Full behavioral history is fetched from Redis and injected into the OPA input. History-aware rules like `repeated_violations_today` can now fire.

## Behavioral History

Redis stores per-agent behavioral state:

| Key | Type | Description |
|-----|------|-------------|
| `agent:{id}:counters` | Hash | Rolling counts: actions, denials, violations, high-value |
| `agent:{id}:anomaly_score` | String | 0.0–1.0 score with 7-day TTL |
| `agent:{id}:actions` | Sorted Set | Action timeline (scored by timestamp) |

**Anomaly score formula:**
- Decay: `score × 0.95` per action
- On denial: `+0.15`
- On high-value allow: `+0.03`

## Live Policy Hot-Swap

The bundle server enables policy changes without restarts:

```bash
# Add a competitor domain
curl -X POST http://localhost:8080/bundles/vargate/update \
  -H "Content-Type: application/json" \
  -d '{"operation": "add_competitor_domain", "value": "newcompetitor.com"}'

# OPA polls for changes every 5–10 seconds and hot-swaps automatically
```

Available operations: `add_competitor_domain`, `remove_competitor_domain`, `set_high_value_threshold`, `restore_defaults`.

## Audit Dashboard

Open `http://localhost:3000` for the real-time audit dashboard:

- **Chain status** — green when intact, red when tampered
- **Stats cards** — total actions, allowed, blocked, active policy revision
- **Audit table** — decision pills, severity badges, Pass 1/2 indicators, chain ✓/✗
- **Expandable detail** — click any row for full params, hashes, evaluation info
- **Tamper simulation** — corrupt a record and watch the chain break, then restore
- **Policy timeline** — visual history of policy version transitions
- **Live mode** — auto-refreshes every 3 seconds

## Hash-Chained Audit Log

Every audit record includes a SHA-256 hash computed over its fields plus the hash of the preceding record, forming an append-only chain anchored to a `GENESIS` block. Tampering with any record breaks the chain from that point forward.

```
GENESIS → hash₁ → hash₂ → hash₃ → ... → hashₙ
```

The `GET /audit/verify` endpoint walks the full chain and reports validity.

**Audit columns:** `id`, `action_id`, `agent_id`, `tool`, `method`, `params`, `requested_at`, `decision`, `violations`, `severity`, `alert_tier`, `bundle_revision`, `prev_hash`, `record_hash`, `created_at`, `evaluation_pass`, `anomaly_score_at_eval`, `opa_input`

## Policy Replay

Any historical decision can be reproduced from the original OPA input document and the archived policy bundle (AGCS control AG-2.8 — Decision Replayability).

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

**How it works:**
1. Every record now stores the full OPA input document (`opa_input` column)
2. Every policy bundle is archived by revision in the bundle server
3. The replay endpoint fetches the archived bundle, spins up an ephemeral OPA instance, evaluates the stored input, and compares the result to what was recorded
4. If decision, violations, and severity all match → **VERIFIED**

## Crypto-Shredding (GDPR Erasure)

Audit records must be kept for compliance, but GDPR requires that personal data be erasable. These requirements conflict. Crypto-shredding resolves the conflict: PII is encrypted at rest with a per-subject AES-256 key managed by SoftHSM2 (PKCS#11). Deleting the key makes the ciphertext irrecoverable while preserving the audit record and hash chain.

**PII detection:** The gateway scans `params` for emails, names, sort codes, and NI numbers. Detected fields are encrypted via the HSM before being stored in the audit log.

**Erasure workflow:**
1. `POST /audit/erase/{subject_id}` — deletes the HSM key, marks records as erased, returns erasure certificate
2. `GET /audit/erase/{subject_id}/verify` — attempts decryption to prove irrecoverability
3. Chain integrity is preserved — only the key is deleted, not the records

**Audit columns:** `contains_pii`, `pii_subject_id`, `pii_fields`, `erasure_status`

## Blockchain Anchoring

The hash chain in SQLite is tamper-evident but mutable: an attacker with database access could corrupt and recompute the entire chain. A periodic anchor to an external, immutable ledger makes this attack infeasible.

Every 60 seconds (configurable), the gateway computes the chain tip hash and record count, then submits a transaction to the `AuditAnchor` smart contract on a local Hardhat Ethereum network. The contract stores the chain state immutably on-chain.

**Three-layer tamper evidence:**
1. **Layer 1: Hash chain (SQLite)** — detects any record modification
2. **Layer 2: Policy replay (OPA)** — verifies decision correctness
3. **Layer 3: Blockchain anchor** — proves chain state to external parties

**Anchor table columns:** `anchor_index`, `chain_tip_hash`, `record_count`, `tx_hash`, `block_number`, `anchored_at`

## Build Sessions

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
