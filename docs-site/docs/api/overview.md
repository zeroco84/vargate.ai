# API Overview

The Vargate API is a RESTful JSON API. All endpoints are served under `https://vargate.ai/api/`.

---

## Interactive Documentation

For the full interactive reference with request/response schemas and a "Try it out" feature:

- **Swagger UI:** [vargate.ai/api/docs](https://vargate.ai/api/docs)
- **ReDoc:** [vargate.ai/api/redoc](https://vargate.ai/api/redoc)
- **OpenAPI JSON:** [vargate.ai/api/openapi.json](https://vargate.ai/api/openapi.json)

---

## Authentication

Most endpoints require authentication via `X-API-Key` header or `Authorization: Bearer <token>`. See [Authentication](../auth.md) for details.

---

## Endpoint Groups

### Tool Calls (1 endpoint)

The core proxy endpoint. Submit agent tool calls for governance evaluation.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/mcp/tools/call` | [Submit a governed tool call](tool-calls.md) |

### Auth (8 endpoints)

Signup, login, OAuth, sessions, and API key management.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/signup` | Email signup |
| `GET` | `/auth/verify-email` | Verify email address |
| `POST` | `/auth/login` | Login with email/password |
| `GET` | `/auth/github` | GitHub OAuth redirect |
| `GET` | `/auth/github/callback` | GitHub OAuth callback |
| `POST` | `/auth/session` | Create JWT session |
| `POST` | `/api-keys/rotate` | Rotate API key |
| `GET` | `/auth/me` | Current user info |

### Tenants (7 endpoints)

Tenant management, settings, and public dashboards.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/tenants` | Create tenant (admin) |
| `GET` | `/tenants` | List tenants (admin) |
| `GET` | `/tenants/{id}` | Get tenant details |
| `PATCH` | `/dashboard/settings` | Update tenant settings |
| `GET` | `/dashboard/public/{slug}` | Public dashboard |
| `GET` | `/transparency` | Public transparency stats |
| `GET` | `/transparency/{tenant_id}` | Tenant transparency |

### Approval Queue (4 endpoints)

Human-in-the-loop approval workflow.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/approvals` | [List pending actions](approvals.md) |
| `GET` | `/approvals/history` | Past approval decisions |
| `POST` | `/approve/{action_id}` | Approve an action |
| `POST` | `/reject/{action_id}` | Reject an action |

### Audit (10+ endpoints)

Audit trail, hash chain, replay, and GDPR erasure.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/audit/log` | [Query audit records](audit.md) |
| `GET` | `/audit/verify` | Verify hash chain integrity |
| `POST` | `/audit/erase/{subject_id}` | GDPR erasure |
| `GET` | `/audit/erase/{subject_id}/verify` | Verify erasure |
| `POST` | `/audit/replay` | Replay a decision |
| `POST` | `/audit/replay-bulk` | Bulk replay |
| `GET` | `/audit/subjects` | List PII subjects |

### Blockchain & Merkle (10+ endpoints)

Blockchain anchoring and Merkle tree proofs.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/anchor/trigger` | [Manual anchor](blockchain.md) |
| `GET` | `/anchor/verify` | Verify on-chain anchor |
| `GET` | `/anchor/status` | Multi-chain status |
| `GET` | `/audit/merkle/roots` | List Merkle trees |
| `GET` | `/audit/merkle/proof/{hash}` | Inclusion proof |
| `GET` | `/audit/merkle/consistency/{n}/{m}` | Consistency proof |
| `GET` | `/compliance/export/{tenant_id}` | Compliance package |

### Credentials Vault (6 endpoints)

HSM-backed credential storage for agent-blind execution.

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/credentials/register` | [Register a credential](credentials.md) |
| `GET` | `/credentials` | List credentials |
| `DELETE` | `/credentials/{tool_id}/{name}` | Remove credential |
| `GET` | `/credentials/{tool_id}/status` | Credential status |
| `GET` | `/credentials/access-log` | Access history |

### Policy (2 endpoints)

Policy rules and templates.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/policy/rules` | Current policy rules |
| `GET` | `/policy/templates` | Available templates |

### System (3 endpoints)

Health, monitoring, and operations.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Gateway health check |
| `POST` | `/backup` | Trigger backup |
| `GET` | `/metrics` | Prometheus metrics |

---

## Rate Limiting

Requests are rate-limited per tenant (configurable `rate_limit_rps` and `rate_limit_burst`). Auth endpoints have additional per-IP rate limits. When exceeded, you'll receive HTTP 429:

```json
{
  "error": "rate_limit_exceeded",
  "tenant_id": "your-tenant-id",
  "rate_limit_rps": 10,
  "rate_limit_burst": 20
}
```
