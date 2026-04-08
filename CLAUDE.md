# CLAUDE.md — Vargate Proxy

## Project Overview

Vargate is an AI agent supervision proxy. It intercepts autonomous agent tool calls, evaluates them against OPA/Rego policy, logs every decision to a hash-chained audit trail, and anchors to blockchain. The product serves enterprise buyers (CISOs, auditors) and produces legally defensible compliance artifacts.

Stack: FastAPI gateway, OPA, SQLite (WAL mode), Redis, SoftHSM2, Hardhat/Sepolia, React dashboard, nginx, Docker Compose.

## Environments

- **Production:** `vargate@204.168.135.95` — customer-facing, serves vargate.ai
- **Dev:** `root@178.104.37.3` — demo box, do not modify for production purposes
- **GTM Agent (Sera):** `rick@159.69.192.130` — OpenClaw agent, routes tool calls through prod proxy

## Critical Rules

- **NEVER delete files.** Move or rename if needed, but never delete.
- **NEVER commit secrets, API keys, or .env files.** Check with `git diff --cached` before every commit.
- **NEVER expose internal service ports.** Always use the prod overlay (`docker-compose.prod.yml`) on the production box. Only nginx (80/443) should be externally reachable.
- **NEVER modify the dev box** (`178.104.37.3`) when working on production tasks.

## Git Workflow

- Commit after completing each discrete feature or fix, not at the end of a sprint.
- Write clear commit messages: `"Sprint X.Y: [concise description of what was done]"`
- Push to origin after each commit:
  ```
  GIT_SSH_COMMAND="ssh -i /root/.ssh/deploy_key" git push origin main
  ```
- Never squash multiple features into one commit.
- Never commit `.env`, `*.docx` (sprint plans), or key material.
- Stage specific files by name — never use `git add -A` or `git add .`

## Quality Standards

- **Every feature must work end-to-end before committing.** Don't build stub routes or placeholder endpoints. Wire up the full data pipeline — backend, frontend, and verify the user can actually use it.
- **Test after every change.** Run the existing test suite (`test_demo.py`, `test_hotswap.py`, `test_behavioral.py`, `test_replay.py`, `test_crypto_shredding.py`, `test_blockchain.py`) plus any new tests. Don't commit if tests fail.
- **Verify your own work.** After implementing a feature, curl every new endpoint. If there's a UI component, describe what the user would see and confirm the data pipeline is connected.
- **Public-facing features must work without auth when designed to be public.** If a feature is described as "public" (e.g., public dashboard), it must be accessible without login. Don't put it behind auth guards.

## Architecture Constraints

- **Per-tenant isolation is sacred.** One tenant's audit chain must never include another tenant's records. One tenant's Redis state must never leak into another's. Always scope queries by `tenant_id`.
- **Hash chains start from GENESIS per tenant.** Each tenant has an independent chain.
- **Gateway constraints run before OPA.** Hard safety blocks (blocked domains, rate limits, cooldowns) are in `gateway/gtm_constraints.py`. OPA policies are for governance. Both layers must agree.
- **Approval queue holds actions, doesn't execute.** When `requires_human=true`, the action is enqueued. Execution only happens after human approval.
- **Agents never see credentials.** The HSM vault brokers execution. Agents submit tool calls, the proxy looks up credentials and executes on their behalf.

## File Structure (Key Files)

- `gateway/main.py` — Core proxy gateway (large file, contains multi-tenancy, audit log, chain verification)
- `gateway/auth.py` — GitHub OAuth, email signup, JWT sessions, API key rotation
- `gateway/approval.py` — Human-approval queue
- `gateway/gtm_constraints.py` — GTM agent safety constraints (blocked domains, daily cap, cooldown, AI disclosure)
- `gateway/transparency.py` — Public transparency endpoints
- `gateway/execution_engine.py` — Credential-brokered tool execution via HSM
- `gateway/merkle.py` — Merkle tree implementation (AG-2.2)
- `policies/vargate/policy.rego` — General OPA governance policy
- `policies/vargate/gtm_policy.rego` — GTM agent-specific policy (requires human approval)
- `docker-compose.yml` — Base compose (dev)
- `docker-compose.prod.yml` — Production overlay (internal networks, nginx, restart policies)
- `nginx/conf.d/vargate-host.conf` — Production nginx config (single-domain, vargate.ai)
- `site/` — Static marketing site served by nginx
- `ui/src/` — React dashboard

## Sprint Context

Development follows a staged sprint plan (8 sprints, 16 weeks). Sprints 1-4 are complete (repo cleanup, multi-tenancy, signup/auth, GTM agent). The sprint plan is in `Vargate_Technical_Sprint_Plan.docx` (do NOT commit this file).

## Docker

- Always use the prod overlay on the production box:
  ```
  docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
  ```
- After changing code: `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build [service]`
- **NEVER run `docker compose down -v`** — this destroys HSM keys and audit data
- Check health: `docker compose ps` — all services should show `(healthy)`

## AGCS Standard

Vargate implements the Agent Governance Certification Standard (AGCS v0.9). Key controls:
- AG-2.2: Merkle tree audit aggregation (Sprint 5)
- AG-2.3: Blockchain anchoring with inclusion proofs
- AG-2.8: Policy replay / decision replayability

When implementing features, reference AGCS controls where applicable.
