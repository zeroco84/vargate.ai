# Audit Trail

Every governance decision is recorded in a hash-chained audit log. The chain is tamper-evident: each record's hash includes the previous record's hash. If any record is modified, the chain breaks.

---

## Hash Chain Model

```
Record 1: hash = SHA256(action_data + GENESIS)
Record 2: hash = SHA256(action_data + Record_1.hash)
Record 3: hash = SHA256(action_data + Record_2.hash)
...
```

Each tenant has an independent hash chain starting from GENESIS. One tenant's chain never includes another tenant's records.

---

## Endpoints

### Query Audit Log

```
GET /audit/log?limit=20
```

Returns recent audit records for your tenant.

**Query parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `limit` | integer | 20 | Number of records (max 1000) |

**Response:**

```json
{
  "records": [
    {
      "id": 42,
      "action_id": "550e8400-...",
      "agent_id": "my-agent-v1",
      "tool": "http",
      "method": "GET",
      "decision": "allow",
      "violations": [],
      "severity": "none",
      "record_hash": "a1b2c3...",
      "prev_hash": "d4e5f6...",
      "requested_at": "2026-04-08T10:00:00Z",
      "bundle_revision": "v1.0.0-1234567890"
    }
  ]
}
```

### Verify Chain Integrity

```
GET /audit/verify
```

Walks the entire chain and verifies each link. Returns:

```json
{
  "valid": true,
  "record_count": 847
}
```

If the chain is broken:

```json
{
  "valid": false,
  "record_count": 847,
  "failed_at_action_id": "550e8400-...",
  "reason": "hash_mismatch"
}
```

### Decision Replay

```
POST /audit/replay
Content-Type: application/json
```

Replay a historical decision against the current policy. Useful for drift detection — checking whether today's policy would make the same decision.

```json
{
  "action_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Response:

```json
{
  "original_decision": "allow",
  "replay_decision": "allow",
  "consistent": true
}
```

### Bulk Replay

```
POST /audit/replay-bulk
Content-Type: application/json
```

Replay multiple actions at once:

```json
{
  "action_ids": ["550e8400-...", "660f9511-...", "770a0622-..."]
}
```

---

## GDPR Erasure (Crypto-Shredding)

Vargate automatically detects PII in action parameters. PII fields are encrypted with per-subject HSM keys before storage.

### Erase Subject Data

```
POST /audit/erase/{subject_id}
```

Destroys the HSM encryption key for the given subject. All ciphertext for that subject becomes irrecoverable. The audit records remain (preserving chain integrity), but the PII content is cryptographically destroyed.

!!! danger "Irreversible"
    Erasure cannot be undone. The HSM key is permanently destroyed.

```json
{
  "status": "erased",
  "subject_id": "user-123",
  "records_affected": 15
}
```

### Verify Erasure

```
GET /audit/erase/{subject_id}/verify
```

Confirms the HSM key no longer exists:

```json
{
  "erased": true,
  "key_exists": false
}
```

### List PII Subjects

```
GET /audit/subjects
```

Returns all subjects with PII in the audit trail, useful for GDPR inventory.
