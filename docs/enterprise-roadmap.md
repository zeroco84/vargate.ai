# Vargate Enterprise Roadmap

Last updated: 2026-04-08

---

## Tier 1 (Available Now — Open Source)

| Feature | AGCS Control | Status |
|---------|-------------|--------|
| Policy-based action evaluation (OPA/Rego, two-pass) | AG-1.1 | Shipped |
| Hash-chained audit trail (per-tenant, tamper-evident) | AG-1.2 | Shipped |
| Action identification (UUID v4) | AG-1.3 | Shipped |
| Agent identification (id, type, version) | AG-1.4 | Shipped |
| Decision transparency (public dashboards, transparency API) | AG-1.5 | Shipped |
| Human approval workflow (queue, approve, reject) | AG-1.6 | Shipped |
| Rate limiting (per-tenant + per-IP) | AG-1.7 | Shipped |
| Per-tenant isolation (hash chains, Redis, queries) | AG-1.8 | Shipped |
| Credential brokering (agent-blind HSM execution) | AG-1.9 | Shipped |
| Behavioral analysis (anomaly scoring, two-pass eval) | AG-1.10 | Shipped |
| PII detection + crypto-shredding (GDPR erasure) | AG-1.11 | Shipped |
| Merkle tree audit aggregation (hourly, per-tenant) | AG-2.2 | Shipped |
| Blockchain anchoring — Polygon + Ethereum | AG-2.3/2.6 | Shipped |
| Decision replayability | AG-2.8 | Shipped |
| Policy template library (5 templates) | AG-1.1 | Shipped |
| Webhook notifications (HMAC-SHA256 signed) | AG-2.7 | Shipped |
| Configurable failure modes (fail-closed/open/queue) | — | Shipped |
| Compliance artifact export (JSON + PDF) | AG-2.8 | Shipped |
| Prometheus monitoring + Grafana dashboards | — | Shipped |
| CLI tool (vargate-cli) | — | Shipped |
| OpenAPI 3.1 interactive docs | — | Shipped |

---

## Tier 2 (Enterprise — Planned)

### SSO / SAML Integration

| | |
|---|---|
| **AGCS** | AG-1.x (access control) |
| **Effort** | 2 sprints |
| **Prerequisites** | None |
| **Priority** | High |

Enterprise SSO via SAML 2.0 / OIDC. Replace current GitHub OAuth + email signup with enterprise IdP integration (Okta, Azure AD, Google Workspace). Enables centralized user management, MFA enforcement, and session policy alignment with corporate identity infrastructure.

### FIPS 140-2 Level 3 HSM

| | |
|---|---|
| **AGCS** | AG-3.4 |
| **Effort** | 1 sprint |
| **Prerequisites** | Hardware HSM or AWS CloudHSM |
| **Priority** | High (required for Tier 3) |

Replace SoftHSM2 with a FIPS-certified hardware HSM for credential storage and blockchain transaction signing. HSM signer abstraction already implemented (`gateway/blockchain_client.py` line 58). Required for AGCS Tier 3 certification. Candidate hardware: Thales Luna, AWS CloudHSM, Azure Dedicated HSM.

### TEE Attestation (Trusted Execution Environment)

| | |
|---|---|
| **AGCS** | AG-3.x |
| **Effort** | 2 sprints |
| **Prerequisites** | Intel SGX / AMD SEV capable hardware |
| **Priority** | Medium |

Run the gateway inside a TEE with remote attestation. Proves to auditors that the gateway code hasn't been tampered with at runtime. Produces attestation quotes that can be independently verified. Critical for highest-assurance deployments (government, defense, financial infrastructure).

### Multi-Region Deployment

| | |
|---|---|
| **AGCS** | AG-2.x (data residency) |
| **Effort** | 3 sprints |
| **Prerequisites** | Multi-region infrastructure |
| **Priority** | Medium |

Deploy gateway instances in multiple regions with data residency controls. Ensures EU tenant data stays in EU regions. Requires: region-aware tenant routing, cross-region Merkle tree synchronization, region-specific blockchain anchoring. Required for strict GDPR compliance in multi-national deployments.

### Per-Tenant Policy Customization

| | |
|---|---|
| **AGCS** | AG-1.1 |
| **Effort** | 1 sprint |
| **Prerequisites** | Policy template library (Sprint 7 — done) |
| **Priority** | High |

Allow tenants to write custom Rego policies beyond the 5 templates. Includes: policy sandbox with syntax validation, dry-run testing against historical actions, version-controlled policy history, and rollback capability. Builds on the existing parameterized template system.

### Compliance Dashboard

| | |
|---|---|
| **AGCS** | AG-2.8 |
| **Effort** | 2 sprints |
| **Prerequisites** | Compliance export (Sprint 8 — done) |
| **Priority** | Medium |

Interactive React dashboard showing real-time AGCS compliance status, control-by-control. Visual evidence mapping with drill-down to specific audit records, Merkle proofs, and blockchain anchors. One-click PDF/JSON export. Timeline view of compliance drift. Builds on the compliance artifact generator.

### Audit Log Streaming (SIEM Integration)

| | |
|---|---|
| **AGCS** | AG-2.2 |
| **Effort** | 1 sprint |
| **Prerequisites** | Webhook support (Sprint 7 — done) |
| **Priority** | High |

Real-time streaming of audit events to SIEM systems via configurable sinks. Supported targets: Splunk (HEC), Datadog, Elasticsearch, AWS CloudWatch, Azure Sentinel. Implements batching, retry, and backpressure. Extends the existing webhook infrastructure with higher-throughput delivery.

### RBAC (Role-Based Access Control)

| | |
|---|---|
| **AGCS** | AG-1.x |
| **Effort** | 2 sprints |
| **Prerequisites** | SSO integration |
| **Priority** | Medium |

Fine-grained roles within a tenant: Admin, Approver, Viewer, Agent Operator. Controls who can approve actions, view audit logs, modify policies, and manage credentials. Audit trail includes actor identity for all administrative operations.

### AGCS Certification Registry

| | |
|---|---|
| **AGCS** | — |
| **Effort** | 3-4 sprints |
| **Prerequisites** | Multi-org support, assessor auth |
| **Priority** | Low (future) |

Public registry for AGCS assessment results. Organizations submit self-assessments or third-party attestations, anchored on blockchain. Enables enterprise buyers to verify vendor compliance. See `docs/agcs-compliance/registry-design.md` for full design.

---

## Tier 3 (Future — Research)

### Formal Verification of Policy

| | |
|---|---|
| **AGCS** | AG-3.x |
| **Effort** | Research phase |

Formal methods (model checking, theorem proving) applied to Rego policies to prove safety properties. Example: "This policy can never allow an action that transfers more than $10,000 without human approval." Requires academic partnership.

### Federated Governance

| | |
|---|---|
| **AGCS** | AG-3.x |
| **Effort** | Research phase |

Multiple organizations share governance infrastructure while maintaining independent policy and audit trails. Cross-org Merkle tree linking for supply-chain governance. Enables "my agent called your agent" audit scenarios.

### Zero-Knowledge Compliance Proofs

| | |
|---|---|
| **AGCS** | AG-3.x |
| **Effort** | Research phase |

Prove compliance without revealing the underlying audit data. ZK proofs that demonstrate: "All actions in this period were evaluated against policy, and none violated critical controls" — without exposing action details. Enables compliance verification for classified or highly sensitive operations.
