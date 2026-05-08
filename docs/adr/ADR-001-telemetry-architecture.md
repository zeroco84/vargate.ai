# ADR-001: Vargate Telemetry — System Architecture

**Status:** Proposed
**Date:** 2026-05-08
**Deciders:** Founders (technical sign-off), eng lead once hired

---

## Context

Vargate Telemetry is a new product line, adjacent to the existing Vargate Pro proxy. Telemetry is read-only and pull-based: it fetches usage data from Anthropic's Admin, Compliance, and Claude Code Analytics APIs using customer-supplied admin credentials, ingests it into our own infrastructure, and runs analytics, compliance alerts, and anomaly detection on top.

This ADR proposes the system architecture, anchored in the current Vargate Pro stack but reflecting where Telemetry's volume, sensitivity, and access pattern force additions or changes.

### Forces at play

- **Reuse vs. redesign.** Pro's stack (FastAPI, SQLite, Redis, SoftHSM2, OPA, Sepolia anchoring, React) is small and operates well at Pro's volumes. Telemetry's record volumes and analytics needs push past where SQLite + ad-hoc Python is comfortable.
- **Architecture commitments are non-negotiable.** Region isolation, per-tenant region pinning, no cross-region content movement, per-tenant key separation, read-only against Anthropic — all decided in the product brief and treated as constraints here, not options.
- **Per-record pricing requires metering accuracy.** Without trustworthy counts, pricing is fiction.
- **The product brief flags anomaly detection as the heaviest data-science lift.** Architecture should make that pillar additive (a separate worker pool, swappable models) rather than load-bearing in v1.

### What's different from Pro

+-------------------+--------------------------+------------------------------------+
| Dimension         | Pro                      | Telemetry                          |
+===================+==========================+====================================+
| Posture           | Inline, synchronous      | Pull-based, asynchronous           |
+-------------------+--------------------------+------------------------------------+
| Granularity       | Per-tool-call            | Per-prompt + per-response          |
+-------------------+--------------------------+------------------------------------+
| Volume per tenant | Low (governed agents)    | High (all human Claude usage)      |
+-------------------+--------------------------+------------------------------------+
| Latency budget    | Tight (in-band)          | Loose (minutes acceptable)         |
+-------------------+--------------------------+------------------------------------+
| Action            | Block / approve / forward| Detect, alert, report              |
+-------------------+--------------------------+------------------------------------+
| Sensitive payload | Tool-call args           | Full prompt + response content     |
+-------------------+--------------------------+------------------------------------+

---

## Decision (high level)

Telemetry runs as a **region cell**: a self-contained per-region stack with no shared services across regions. The cell extends the existing Pro container set with three new infrastructure dependencies (Postgres, MinIO, Celery) and reuses Pro's hash-chain audit pipeline, HSM key vault, OPA policy engine, React dashboard shell, and nginx ingress.

A small **global control plane** handles signup routing (which region a new tenant lands in) and billing rollups (record counts only — never content). The control plane never sees a prompt or response.

The data flow inside one region cell:

1. **Customer onboards** — Anthropic admin key validated, region selected, credentials wrapped in HSM, tenant provisioned.
2. **Pull scheduler** (Celery Beat) dispatches per-tenant pull jobs every 15 minutes (configurable).
3. **Anthropic connector** calls Admin / Compliance / Code Analytics APIs with the tenant's read-only credentials, paginating and rate-limit-aware.
4. **Ingest pipeline** normalizes the response, splits content (prompts/responses) from metadata, encrypts content with the tenant's DEK, writes the blob to MinIO and the metadata + reference to Postgres, and hash-chains the record onto the existing per-tenant audit chain.
5. **Analyzers** consume the ingest queue: PII detector, behavioral analytics, anomaly detection. Outputs feed the policy alert engine.
6. **Policy alert engine** (OPA) evaluates analyzer outputs against the tenant's policies and routes alerts to Slack / email / SIEM webhook.
7. **Merkle aggregator** periodically rolls hash-chain heads into a Merkle root and anchors that root to Sepolia. No content, no tenant identifiers cross the chain — just the integrity root.
8. **Read API + dashboard** serves tenant-scoped queries with redaction controls.

Each region cell is its own Docker Compose stack. The US cell and EU cell are not network-connected at the data plane — only the global control plane connects to both, and only for billing-counter rollups and signup routing.

---

## Sub-decisions (mini-ADRs)

The major decisions follow. Each lists the alternatives considered, the trade-offs, and the recommendation.

### a. Storage tier — Postgres replaces SQLite for Telemetry workloads

| Option | Complexity | Cost | Scalability | Team fit |
|---|---|---|---|---|
| A. Per-tenant SQLite (status quo) | Low | Low | **Poor** at telemetry volumes | High (already running) |
| B. Postgres per region, row-level tenancy | Medium | Medium | **Good** to billions of rows | Medium (one of us has run it) |
| C. ClickHouse for analytics + Postgres for transactional | High | Medium-high | **Excellent** | Low |

**Decision: Option B.** Postgres per region. Tenant ID is the leading column on every index, and Postgres RLS is enabled as defense-in-depth. SQLite stays in Pro — it's right-sized there.

**Rationale:** Even a midmarket customer with 200 active Claude users could produce 10K–100K records per day. Across N tenants per region, SQLite's write contention and analytical-query weakness become real. Postgres is a known quantity with mature tooling. ClickHouse is the right answer at v2 if Postgres analytics queries become the bottleneck — premature now.

### b. Compliance content storage — MinIO + per-tenant KMS, not Postgres

| Option | Complexity | Cost | Crypto-shred fit | Scale fit |
|---|---|---|---|---|
| A. Postgres TOAST | Low | Medium | **Poor** (DB backups carry plaintext) | Medium |
| B. Self-hosted MinIO + per-tenant DEK | Medium | Low-Medium | **Good** (delete key → ciphertext garbage) | High |
| C. Local encrypted volume | Low | Low | OK | Single-host only |

**Decision: Option B.** Per-region MinIO. Postgres holds metadata and an integrity hash; the prompt/response blob lives in MinIO encrypted with the tenant's DEK.

**Rationale:** Compliance API content is the most sensitive data we touch. Storing it in Postgres bloats backups and replicas, and crypto-shredding becomes painful. MinIO is S3-compatible, self-hostable (lines up with the "infra independence" pitch and avoids cloud lock-in for region commitments), and decouples content lifecycle from metadata.

### c. Pull scheduler & worker queue — Celery on Redis

| Option | Complexity | Cost | Capability | Team fit |
|---|---|---|---|---|
| A. Cron + Python scripts | Low | Low | **Poor** (no retries, no visibility) | High |
| B. Celery on existing Redis | Low-Medium | Low | Good | High |
| C. Temporal | High | Medium | **Excellent** (durable workflows) | Low |
| D. Custom scheduler | Medium | Low | Reinvents Celery | Medium |

**Decision: Option B.** Celery with Redis as broker. Beat handles per-tenant cron schedules; tasks handle pulls, analyzer fan-out, and HR sync.

**Rationale:** Redis is already in the stack. Celery is mature in Python and plays well with FastAPI. Temporal is the right tool for complex multi-step workflows (a year out, possibly), not for v1.

### d. Region cells — separate stacks per region from day one

**Decision:** Each region (US, EU, future APAC) is a self-contained Docker Compose deployment of the entire Telemetry stack, with no shared content paths. The control plane is a tiny global service for signup routing and billing roll-ups (counts only).

**Rationale:**
- Compliance API content provably never crosses regions because the infrastructure doesn't connect.
- Different compliance regimes per region (US: SOC 2, optional HIPAA; EU: GDPR, ISO 27001).
- Per-tenant blast radius is bounded by region.
- Operational cost is real but identical per-region stacks limit the burden — same compose file, same CI pipeline, different hosts.

This is a Day-1 commitment. Retrofitting region isolation later is the architecture equivalent of unscrambling an egg.

### e. Per-tenant credential storage — extend SoftHSM2 with envelope encryption

| Option | Complexity | Cost | Security | Team fit |
|---|---|---|---|---|
| A. Direct HSM slots per tenant | Low | Low | High | High but slot-limited |
| B. Envelope encryption (DEK per tenant, KEK in HSM) | Medium | Low | High | Medium |
| C. HashiCorp Vault | Medium | Medium | High | Low |
| D. Application-layer encryption | Low | Low | Medium | High |

**Decision: Option B.** Each tenant gets a Data Encryption Key (DEK) generated at provisioning. The DEK is wrapped by a Key Encryption Key (KEK) held in SoftHSM2. Wrapped DEKs live in Postgres in an `encrypted_secrets` table. Anthropic admin keys, MinIO content blobs, and any other tenant-scoped secrets are encrypted with the tenant's DEK.

**Rationale:** SoftHSM2 has practical slot-count limits. Envelope encryption sidesteps that, scales to millions of tenants, and gives us per-tenant key rotation and crypto-shredding for free. Same HSM operational pattern Pro already uses, so we're not adding a vault dependency.

### f. Analyzer compute — regex + NER local, LLM classifier via Claude (v1) → self-hosted (v2)

| Option | Complexity | Cost | Quality | Coherence with positioning |
|---|---|---|---|---|
| A. Claude API for everything | Low | High per-record | High | **Awkward** ("independent from Anthropic" while hammering their API) |
| B. Self-hosted small model (Llama / Mistral fine-tuned) | High | Low per-record | High after tuning | Good |
| C. Layered: regex + spaCy NER local, Claude API for ambiguous tail | Medium | Low | High | OK for v1; flag for v2 migration |

**Decision: Option C for v1, with a roadmap to Option B by the end of year one.**

**Rationale:** ~90% of structured-pattern detections (account-number formats, identifier patterns) hit cleanly on regex. Names and addresses route through spaCy NER locally. Only context-ambiguous cases — where the call is whether a given exchange matches a configured policy — need an LLM classifier, at which point we hit the Claude API. Volume implication: at 1M records/day per large tenant, even 5% LLM-routed traffic is 50K classifier calls/day. Pricing model has to absorb this — get it into the per-record cost calculation now.

The migration to a self-hosted classifier (Llama 3 8B fine-tuned, or similar) becomes urgent when (a) per-record economics break, or (b) an EU customer requires zero egress to AI vendors. Both are foreseeable.

### g. Anomaly detection — phased build, separate worker pool

**Decision:** Per the product brief's phasing.

- **Day 1:** Rolling-window mean ± 3σ thresholds, configurable per entity. Baselines stored in Postgres, one row per (entity, metric, window). Detection runs as a Celery task post-ingest.
- **Day 90:** Robust statistics (MAD-based), seasonal baselines via Prophet or similar. Move heavy dependencies to a dedicated `analyzer-stats` worker pool to avoid bloating the main worker image.
- **Day 180:** Cross-entity correlation. Revisit whether a real time-series store (TimescaleDB extension on the existing Postgres, most likely) is warranted.

**Rationale:** Front-loading the ML investment delays everything else. The brief acknowledges this is a stats-hire-required pillar; architecture honors that by making it additive, not load-bearing.

### h. Audit chain integration — Telemetry records hash-chain into the existing per-tenant chain

**Decision:** Reuse Pro's existing per-tenant hash chain (genesis-per-tenant) and the AG-2.2 Merkle aggregator + Sepolia anchor. Telemetry records become a new record type appended to the same chain.

**Rationale:** A single audit chain per tenant is much easier to reason about and to defend in audit than two parallel chains. The chain doesn't care what kind of record is being appended; it just needs the canonical content hash. We do need to define the Telemetry record schema carefully (record type, content hash, MinIO blob reference, metadata) so chain verification stays cheap. Note: only the Merkle root is anchored to Sepolia — never content, never tenant identifiers.

### i. Metering — Redis counters with periodic Postgres flush

**Decision:** Per-tenant record counts are incremented in Redis (`HINCRBY` keyed by tenant + minute bucket) on every successful ingest. A Celery task flushes to a Postgres `usage_records` table every 60 seconds. Postgres is the canonical source for billing.

**Rationale:** Direct Postgres counters create write contention at ingest scale. Redis absorbs the high-write rate; Postgres holds the durable, billable record. Stream processors (Kafka, Flink) are over-engineering for v1.

### j. Onboarding — extend existing FastAPI + React, no new infra

**Decision:** New routes in `gateway/onboarding.py` for SSO callback, deep-link generation, key validation, region selection, tenant provisioning. Frontend extends the existing React dashboard with an "Onboarding" flow.

**Rationale:** Onboarding doesn't need infra, it needs UX. The 60-seconds-on-our-side budget is achievable with the existing stack:
- SSO sign-in: ~5s
- Key paste + Anthropic validation call + tenant provisioning: ~10s
- Region selection + first ingest job dispatch: ~5s
- **Total: ~20s.** Headroom for polish and error-handling.

---

## Stack delta summary

| Component | Status | Notes |
|---|---|---|
| FastAPI gateway | **Reuse + extend** | New onboarding, read API, alert routes |
| SQLite | **Reuse for Pro only** | Telemetry doesn't write to SQLite |
| Postgres | **NEW** | Per region; metadata, baselines, alerts, billing canon |
| MinIO | **NEW** | Per region; encrypted content blobs |
| Redis | **Reuse + extend** | Now also Celery broker, metering counters |
| Celery + Beat | **NEW** | Pull scheduler, analyzer fan-out, HR sync |
| SoftHSM2 | **Reuse + extend** | Now wraps per-tenant DEKs (envelope encryption) |
| OPA / Rego | **Reuse + extend** | Telemetry policies for alerting (PII, explicit, illegal, anomaly thresholds) |
| Hash chain + Merkle aggregator | **Reuse** | Telemetry records appended to existing per-tenant chain |
| Sepolia anchoring | **Reuse** | Same root anchor; Telemetry records ride the existing aggregation |
| React dashboard | **Reuse + extend** | New views: usage, AI-leverage, alerts, onboarding |
| nginx | **Reuse** | Same TLS termination, same single-domain pattern |
| Docker Compose | **Reuse + extend** | New services (Postgres, MinIO, Celery worker, Celery beat) in compose.prod overlay |

---

## Consequences

### What becomes easier
- Selling into regulated buyers — region isolation and per-tenant key separation are real, not marketing.
- Crypto-shredding a single tenant — delete the DEK, content becomes ciphertext garbage.
- Adding a new region — same stack, different host.
- Composing Pro and Telemetry deals — same audit chain, same dashboard shell.

### What becomes harder
- Operating two databases (SQLite for Pro, Postgres for Telemetry) until we eventually migrate Pro to Postgres or accept the split forever.
- Cross-region analytics for our own internal use (e.g., comparing US vs EU tenant behavior) — by design, not a bug.
- Onboarding a region — new VPC, new Postgres, new MinIO, new HSM keys. Worth automating from the start.
- Capacity planning per region — needs separate forecasting once volumes diverge.

### What we'll need to revisit
- Postgres → ClickHouse migration if analytics queries dominate cost (likely v2).
- Claude API → self-hosted classifier if per-record economics break or an EU customer mandates zero-egress (likely within 12 months).
- Celery → Temporal if multi-step workflows (e.g., complex backfill recovery) get hairy.
- SoftHSM2 → HashiCorp Vault if HSM ops become a bottleneck (likely several years out, or never).

---

## Action items

1. [ ] Add `postgres`, `minio`, `celery-worker`, `celery-beat` services to `docker-compose.prod.yml` overlay; bring up in the dev environment.
2. [ ] Spike: SoftHSM2 envelope encryption (DEK/KEK pattern). Confirm performance at 1K simulated tenants.
3. [ ] Spike: Anthropic Compliance API rate limits, pagination, and content shape. Build a fixture set.
4. [ ] Define the Telemetry record schema and confirm it appends cleanly to the existing per-tenant hash chain.
5. [ ] Build the metering service before any analyzer work — pricing model needs validated counts.
6. [ ] V1 region: launch US-only. EU as second region within ~3 months.
7. [ ] Write the v1 PII regex + spaCy NER set; benchmark false-positive rate on a synthetic corpus.
8. [ ] Document the Claude-classifier cost per record; confirm it's absorbed by per-1K-records pricing with margin.
9. [ ] Decide v1 monitoring stack (Prometheus + Grafana most likely) — needs to land before we ingest production data.
10. [ ] Brief Anthropic on what we're building (per the open question in the product brief) before we ship.

---

## Open architectural questions for the team

- **Postgres deployment model.** Self-hosted with replication, or managed (Crunchy Bridge per region)? Self-hosted lines up with the "infra independence" narrative; managed reduces ops load. Lean self-hosted; revisit at >5 production regions.
- **HR connectors.** Build SCIM endpoint first (security-sensitive, table stakes for enterprise), then add an iPaaS-style integration (Workato, Tray.io) for the long tail of HR systems.
- **Frontend.** Stay in the existing React monorepo for v1; consider splitting into a Telemetry-specific frontend when SKUs diverge or we hit build-time pain.
- **LLM-classifier offline mode.** Some EU customers will require no AI-vendor egress at all. That's a forcing function for the self-hosted classifier; expect it within 12 months.
- **Pro-Telemetry migration path for SQLite.** If Pro stays on SQLite and Telemetry runs on Postgres, do we eventually migrate Pro? Probably, but not before Pro outgrows SQLite organically.
