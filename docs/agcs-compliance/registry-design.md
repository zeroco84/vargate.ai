# AGCS Certification Registry — Design Document

Version: 0.1 (Draft)
Status: Design Only — Not Implemented
Estimated Effort: 3-4 sprints
Author: Vargate Engineering

---

## 1. Purpose

A certification registry where organizations publish their AGCS assessment results, enabling enterprise buyers to verify that a vendor's AI agent governance meets the standard. The registry serves as a public trust anchor: "This organization has been assessed against AGCS v0.9, Tier 2, and passed."

The registry is blockchain-anchored — assessment attestations are hashed and anchored on-chain, making them tamper-evident and independently verifiable without trusting the registry operator.

---

## 2. Data Model

### Organization

```
Organization {
  id:           UUID
  name:         string          -- "Acme Corp"
  domain:       string          -- "acme.com"
  contact:      string          -- "compliance@acme.com"
  website:      string          -- "https://acme.com"
  created_at:   datetime
  verified:     boolean         -- domain ownership verified
}
```

### Assessment

```
Assessment {
  id:               UUID
  organization_id:  UUID (FK → Organization)
  agcs_version:     string          -- "0.9"
  tier:             integer         -- 1, 2, or 3
  assessment_date:  date
  expiry_date:      date            -- typically 12 months
  assessor_type:    enum            -- "self" | "third_party" | "continuous"
  assessor_name:    string          -- "Vargate Automated" or "Deloitte"
  status:           enum            -- "pass" | "partial" | "fail" | "expired"
  evidence_hash:    string          -- SHA-256 of the compliance export bundle
  anchor_tx_hash:   string          -- blockchain tx anchoring the evidence hash
  anchor_chain:     string          -- "polygon" | "ethereum"
  notes:            text
  created_at:       datetime
}
```

### ControlResult

```
ControlResult {
  id:               UUID
  assessment_id:    UUID (FK → Assessment)
  control_id:       string          -- "AG-1.1", "AG-2.3", etc.
  control_name:     string          -- "Policy-Based Action Evaluation"
  status:           enum            -- "pass" | "partial" | "fail" | "not_applicable"
  evidence_hash:    string          -- SHA-256 hash of supporting evidence
  evidence_url:     string          -- optional link to public evidence
  notes:            text
}
```

### Verification

```
Verification {
  id:                   UUID
  assessment_id:        UUID (FK → Assessment)
  verifier:             string          -- "Jane Smith, Deloitte"
  verifier_org:         string          -- "Deloitte"
  verification_date:    date
  result:               enum            -- "confirmed" | "disputed" | "inconclusive"
  attestation_hash:     string          -- SHA-256 of verifier's signed attestation
  anchor_tx_hash:       string          -- blockchain tx for the attestation
  notes:                text
}
```

---

## 3. API Surface

### Submit an Assessment

```
POST /registry/assessments
Content-Type: application/json
Authorization: Bearer <org_token>

{
  "organization_id": "...",
  "agcs_version": "0.9",
  "tier": 2,
  "assessor_type": "self",
  "evidence_hash": "sha256:abc123...",
  "control_results": [
    {"control_id": "AG-1.1", "status": "pass", "evidence_hash": "sha256:..."},
    {"control_id": "AG-1.2", "status": "pass", "evidence_hash": "sha256:..."},
    ...
  ]
}

Response: 201 Created
{
  "assessment_id": "...",
  "status": "pass",
  "anchor_tx_hash": "0x...",
  "registry_url": "https://registry.agcs.org/assessments/..."
}
```

### Retrieve Assessment History

```
GET /registry/assessments/{org_id}
Response: 200
{
  "organization": {"name": "Acme Corp", "domain": "acme.com"},
  "assessments": [
    {
      "id": "...",
      "tier": 2,
      "status": "pass",
      "date": "2026-04-08",
      "expiry": "2027-04-08",
      "anchor_tx_hash": "0x..."
    }
  ]
}
```

### Verify an Assessment

```
GET /registry/verify/{assessment_id}
Response: 200
{
  "assessment_id": "...",
  "organization": "Acme Corp",
  "tier": 2,
  "status": "pass",
  "evidence_hash": "sha256:abc123...",
  "on_chain_hash": "sha256:abc123...",
  "hashes_match": true,
  "anchor_tx_hash": "0x...",
  "anchor_chain": "polygon",
  "explorer_url": "https://polygonscan.com/tx/0x...",
  "verified": true
}
```

### Search Compliant Organizations

```
GET /registry/search?tier=2&status=pass&agcs_version=0.9
Response: 200
{
  "results": [
    {
      "organization": "Acme Corp",
      "domain": "acme.com",
      "tier": 2,
      "status": "pass",
      "assessment_date": "2026-04-08",
      "expiry_date": "2027-04-08"
    }
  ],
  "total": 42
}
```

---

## 4. Assessor Workflow

### Self-Assessment

1. Organization runs Vargate's automated compliance checks (or uses the compliance export endpoint).
2. The compliance export bundle is hashed (SHA-256).
3. Organization submits assessment with evidence hash via `POST /registry/assessments`.
4. Registry anchors the evidence hash on-chain.
5. Assessment is publicly visible with status and anchor reference.

### Third-Party Assessment

1. Organization engages a qualified assessor (audit firm, consultancy).
2. Assessor reviews the compliance export bundle, interviews staff, examines infrastructure.
3. Assessor submits attestation via the registry API with their credentials.
4. Attestation is anchored on-chain separately from the self-assessment.
5. Assessment status updated to reflect third-party verification.

### Continuous Assessment

1. Organization configures automated periodic re-assessment (e.g., monthly).
2. Compliance export is regenerated automatically.
3. Delta between current and previous assessment is computed.
4. If all controls still pass, assessment is renewed automatically.
5. If any control degrades, alert is sent and status updated to "partial".
6. Continuous assessments show a timeline of compliance status.

---

## 5. Trust Model

- **Self-assessments** are labeled as such. They demonstrate intent and process but carry lower assurance.
- **Third-party assessments** carry higher assurance. The assessor's identity and organization are recorded.
- **Blockchain anchoring** ensures assessment data cannot be modified after submission.
- **Evidence hashes** allow independent verification: anyone with the compliance export bundle can hash it and compare against the on-chain record.
- **Expiry dates** prevent stale assessments from being used as current evidence.

---

## 6. Implementation Notes

- **Estimated effort:** 3-4 sprints
- **Dependencies:**
  - Multi-organization account support (separate from tenant multi-tenancy)
  - Assessor authentication and credentialing
  - Blockchain-anchored attestation (extends existing anchor infrastructure)
  - Public-facing registry UI
- **Infrastructure:** Separate service from the governance proxy. Could share blockchain infrastructure.
- **Standards alignment:** Registry design should be reviewed against ISO 27001 audit trail requirements and SOC 2 trust service criteria.

---

## 7. Open Questions

1. Should the registry be operated by Vargate, by a neutral third party, or as a DAO?
2. What are the minimum qualifications for a third-party assessor?
3. Should evidence bundles be stored on-registry or just hashed?
4. How to handle assessment disputes?
5. Fee structure: free for self-assessment, paid for third-party attestation?
