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
| GET    | `/bundles/vargate/status`   | Current policy revision, ETag, rule count        |
| POST   | `/bundles/vargate/update`   | Live policy update (add/remove domains, etc.)    |

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

**Audit columns:** `id`, `action_id`, `agent_id`, `tool`, `method`, `params`, `requested_at`, `decision`, `violations`, `severity`, `alert_tier`, `bundle_revision`, `prev_hash`, `record_hash`, `created_at`, `evaluation_pass`, `anomaly_score_at_eval`

## Build Sessions

| Session | What was built |
|---------|---------------|
| 1 | MCP proxy, OPA policy (5 rules), hash-chained audit log, `test_demo.py` |
| 2 | Bundle server, ETag polling, live policy hot-swap, `test_hotswap.py` |
| 3 | Redis behavioral history, two-pass evaluation, anomaly scoring, `test_behavioral.py` |
| 4 | React audit dashboard, tamper simulation, policy timeline |

## License

Proprietary — Vargate.ai
