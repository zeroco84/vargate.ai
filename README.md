# Vargate — AI Agent Governance Proxy

[![CI](https://github.com/zeroco84/vargate.ai/actions/workflows/ci.yml/badge.svg)](https://github.com/zeroco84/vargate.ai/actions/workflows/ci.yml)
[![Security Scan](https://github.com/zeroco84/vargate.ai/actions/workflows/security.yml/badge.svg)](https://github.com/zeroco84/vargate.ai/actions/workflows/security.yml)

Vargate intercepts autonomous AI agent tool calls, evaluates them against governance policy, and logs every decision to a tamper-evident audit trail anchored to blockchain.

**[Documentation](https://developer.vargate.ai)** · **[Live Demo](https://vargate.ai/dashboard/vargate-gtm-agent)** · **[API Reference](https://vargate.ai/api/docs)** · **[Quick Start](https://developer.vargate.ai/quickstart/)**

---

## What It Does

Agents submit tool calls through Vargate instead of calling tools directly. Vargate evaluates every call against OPA/Rego policy, writes each decision to a SHA-256 hash-chained audit log, aggregates records into hourly Merkle trees, and anchors roots to blockchain. Enterprise buyers get legally defensible compliance artifacts with cryptographic inclusion proofs. Developers get a single integration point for policy enforcement, audit logging, and governance.

## Key Features

- **Policy-Based Governance** — OPA/Rego evaluation on every tool call. 5 policy templates (financial, email, CRM, data access, general). Two-pass evaluation with behavioral enrichment.

- **Hash-Chained Audit Trail** — Every decision written to an append-only, SHA-256 hash-chained log. Chain integrity verifiable via API.

- **Merkle Tree Aggregation** — Hourly Merkle trees with O(log n) inclusion and consistency proofs (RFC 6962). AGCS AG-2.2.

- **Multi-Chain Blockchain Anchoring** — Merkle roots anchored to Polygon and Ethereum mainnet. On-chain verification. AGCS AG-2.3.

- **Human-in-the-Loop Approval** — Actions flagged by policy are queued for human review. Execution only after explicit approval.

- **Crypto-Shredding (GDPR)** — Per-subject HSM keys. Erase a subject's data by destroying the key. Irreversibility verified. AGCS AG-2.4.

- **Credential Vault** — HSM-backed agent-blind execution. Agents never see credentials. The proxy brokers tool calls on their behalf.

- **Decision Replay** — Replay any historical decision against current or past policy. AGCS AG-2.8.

- **Webhook Notifications** — HMAC-SHA256 signed POST on every allow/deny/escalate decision. Configurable per tenant.

- **Compliance Export** — Full audit trail + Merkle proofs + blockchain anchors as a signed JSON/PDF package.

- **Monitoring** — Prometheus metrics, Grafana dashboards, Alertmanager, chaos-tested graceful degradation.

- **Configurable Failure Modes** — Per-tenant choice of fail-closed, fail-open, or fail-to-queue when dependencies are unavailable.

## Architecture

```
                                ┌─────────────────┐
                                │  Bundle Server   │── ETag polling ──► OPA
                                │   (port 8080)    │
                                └─────────────────┘
                                         │
Agent ─► POST /mcp/tools/call ─► Vargate Gateway ──► OPA Policy Check ──► Allow / Deny / Escalate
                                    │         │                │
                                    │    ┌────┘                ▼
                                    ▼    ▼              Approval Queue
                            SQLite Audit Log       (human-in-the-loop)
                            (hash-chained)
                                    │         Redis Behavioral History
                                    │         (counters, anomaly scores)
                                    ▼
                            Merkle Trees (hourly)
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
              Polygon PoS    Ethereum Mainnet   Hardhat (dev)
              (primary)      (high-value)       (local testing)
                    │
                    ▼
              Compliance Export
              (JSON / PDF package)

Supporting Services:
  SoftHSM2 ─── Per-subject AES-256 keys, credential vault, crypto-shredding
  Prometheus ── Metrics collection (scrapes gateway + all services)
  Grafana ───── Monitoring dashboards (audit rate, latency, chain health)
  Alertmanager ─ Alert routing (email, webhook)
```

## Quick Start

### Local Development

```bash
git clone https://github.com/zeroco84/vargate.ai.git
cd vargate.ai
docker compose up --build

# Open the dashboard
open http://localhost:3000

# Send a governed action
curl -X POST http://localhost:8000/mcp/tools/call \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "my-agent",
    "tool": "http",
    "method": "GET",
    "params": {"url": "https://example.com"}
  }'
```

### CLI

```bash
pip install vargate-cli
vargate init
vargate test
vargate status
```

Full quickstart guide: [developer.vargate.ai/quickstart](https://developer.vargate.ai/quickstart/)

## Services

| Service | Port | Description |
|---------|------|-------------|
| `gateway` | 8000 | FastAPI proxy — policy evaluation, audit log, Merkle trees |
| `opa` | 8181 | Open Policy Agent — Rego policy evaluation |
| `bundle-server` | 8080 | OPA policy bundle server with ETag-based hot-swap |
| `redis` | 6379 | Behavioral history, rate limiting, anomaly scores |
| `hsm` | 8300 | SoftHSM2 — per-subject AES-256 keys, crypto-shredding |
| `blockchain` | 8545 | Hardhat local Ethereum (dev) |
| `ui` | 3000 | React dashboard — audit log, approvals, Merkle proofs |
| `prometheus` | 9090 | Metrics collection |
| `grafana` | 3001 | Monitoring dashboards |
| `alertmanager` | 9093 | Alert routing (email) |
| `docs` | 3002 | Developer documentation (MkDocs Material) |

## API Overview

> **63 endpoints** across 9 groups. Full interactive reference at [vargate.ai/api/docs](https://vargate.ai/api/docs).

| Group | Description |
|-------|-------------|
| **Tool Calls** | `POST /mcp/tools/call` — the core interception endpoint |
| **Auth** | GitHub OAuth, email signup, JWT sessions, API key management |
| **Tenants** | Multi-tenant provisioning, settings, policy templates, failure modes |
| **Approval Queue** | Human-in-the-loop review, approve/reject, escalation |
| **Audit** | Hash chain verification, audit log queries, GDPR erasure |
| **Blockchain & Merkle** | Anchor trigger, Merkle proofs, on-chain verification, anchor log |
| **Credentials** | HSM vault registration, agent-blind execution, access log |
| **Policy** | Template listing, replay, bulk replay, bundle management |
| **System** | Health, metrics, OpenAPI spec, transparency endpoints |

## Policy Templates

Vargate includes 5 ready-to-use OPA/Rego policy templates that can be applied per-tenant with custom configuration. Each template defines violation rules, severity levels, and escalation thresholds tuned for a specific domain: **Financial**, **Email**, **CRM**, **Data Access**, and **General**. Templates are composable — apply one as a baseline and override specific parameters via the tenant settings API. See the [Policy Templates documentation](https://developer.vargate.ai/policies/overview/) for details.

## AGCS Compliance

Vargate implements the [Agent Governance Certification Standard (AGCS v0.9)](https://vargate.ai/AGCS-v0.9.pdf). Self-assessments for Tier 1 and Tier 2 are in [`docs/agcs-compliance/`](docs/agcs-compliance/).

| Control | Description | Status |
|---------|-------------|--------|
| AG-2.2 | Merkle tree audit aggregation with inclusion proofs | Pass |
| AG-2.3 | Multi-chain blockchain anchoring with on-chain verification | Pass |
| AG-2.4 | Crypto-shredding with HSM-backed per-subject keys | Pass |
| AG-2.8 | Decision replay against archived policy bundles | Pass |

## Testing

```bash
# Core test suite
python test_demo.py
python test_hotswap.py
python test_behavioral.py
python test_replay.py
python test_crypto_shredding.py
python test_blockchain.py

# End-to-end lifecycle
python test_e2e.py

# Chaos testing (requires running services)
python test_chaos.py

# Performance benchmark
python test_benchmark.py --concurrency 50 --duration 30
```

## Production Deployment

See [DEPLOY.md](DEPLOY.md) and [DEPLOYMENT.md](DEPLOYMENT.md) for the full guide including TLS, DNS, hardening, and Sepolia/Polygon configuration.

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

The production overlay binds all services to localhost, puts them on an internal Docker network, and relies on host nginx for TLS termination. Only ports 80 and 443 are externally reachable.

## Links

- [Developer Documentation](https://developer.vargate.ai)
- [API Reference (Swagger)](https://vargate.ai/api/docs)
- [API Reference (ReDoc)](https://vargate.ai/api/redoc)
- [Live Demo Dashboard](https://vargate.ai/dashboard/vargate-gtm-agent)
- [AGCS Standard (PDF)](https://vargate.ai/AGCS-v0.9.pdf)
- [Enterprise Roadmap](docs/enterprise-roadmap.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

Copyright 2025-2026 Vargate.ai
