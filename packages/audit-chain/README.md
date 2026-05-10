# vargate-audit-chain

Shared per-tenant hash-chain and Merkle-aggregator primitives used by both
**Vargate Pro** (autonomous-agent action audit log) and **Vargate Telemetry**
(human Claude usage records). The package is **Apache 2.0** so it can be
consumed by Telemetry's BSL-1.1-licensed product without licensing
friction (more-permissive into more-restrictive is the legal direction;
the reverse is not).

## Why this exists

Both Pro and Telemetry need a per-tenant hash chain over their audit /
telemetry records, plus a Merkle aggregator for periodic anchoring to a
public ledger. The math is identical for both products; the storage
shape is not. Keeping the math in one Apache-licensed package means:

- Pro and Telemetry share crypto primitives. Bug fixes in one apply to
  the other.
- Auditors review the chain math once, not twice.
- Each product owns its own table-shaped bookkeeping (Pro's
  `audit_log`, Telemetry's `telemetry_records`) and only delegates the
  tenant-bound hash math to this package.

This is the **two chains per tenant, shared primitives** model — the
honest architecture given that Pro's audit_log and Telemetry's
telemetry_records have intrinsically different schemas. ADR-001 in the
parent repo's `docs/adr/` covers the rationale.

## Public API

```python
from vargate_audit_chain import (
    GENESIS_HASH,            # the literal "GENESIS" prev_hash for the first record
    GENESIS_ROOT,            # the Merkle empty-tree sentinel hash
    compute_record_hash,     # generic, tenant-bound: (tenant_id, canonical_bytes, prev_hash) -> hex
    verify_record_chain,     # generic verifier over Iterator[ChainRecord]
    ChainRecord,             # frozen dataclass: (canonical_bytes, prev_hash, record_hash)
    VerifyResult,            # frozen dataclass: (valid, record_count, failure_reason, failed_at_index)
    MerkleTree,              # binary Merkle tree over hex SHA-256 leaves (RFC 6962)
)
```

### `compute_record_hash(tenant_id, canonical_bytes, prev_hash) -> str`

Returns a SHA-256 hex digest binding the record to a tenant.

The digest is computed over a length-prefixed concatenation of
`tenant_id`, `canonical_bytes`, and `prev_hash`. Length prefixing means a
record from tenant A cannot collide with — or be replayed into — tenant
B's chain. Two records with the same `canonical_bytes` and `prev_hash`
but different `tenant_id` produce different hashes by construction.

**Determinism:** identical inputs always produce identical output.

### `verify_record_chain(tenant_id, records: Iterator[ChainRecord]) -> VerifyResult`

Walks a chain in order, checking at each step:

1. The record's `prev_hash` matches the running expected previous hash
   (starts at `GENESIS_HASH`).
2. Recomputing `compute_record_hash(tenant_id, record.canonical_bytes,
   record.prev_hash)` matches the record's stored `record_hash`.

Accepts any iterable of `ChainRecord` (dataclass) — callers can `yield`
records as they read them from a database, without materializing the
full chain in memory.

`VerifyResult.valid` is `True` only if every record passes both checks.
On failure, `failure_reason` and `failed_at_index` localize the problem.

### `MerkleTree(leaves: list[str])`

Binary Merkle tree following RFC 6962 conventions (Certificate
Transparency–compatible). Bitcoin-style odd-leaf padding (duplicate the
last leaf). Pure code, no I/O.

## What is *not* in this package

- **Storage.** Database reads, table schemas, write paths, and ID
  sequencing all stay in the consuming codebase. The package operates
  on `(canonical_bytes, prev_hash) → record_hash` and nothing else.
- **`chain_seq` advancement.** Sequence numbers are the caller's
  responsibility. Pro relies on `audit_log`'s auto-increment `id` for
  ordering; Telemetry uses an explicit `chain_seq` column on
  `telemetry_records`. Both work, both are out of scope for this
  package.
- **Ledger anchoring.** Submitting Merkle roots to Sepolia, Polygon, or
  any other chain is the consuming product's job.

## Installing

This package lives at `packages/audit-chain/` inside the
`vargate-proxy` repository. Two ways to consume it:

**Inside Pro (same repo):** the gateway Dockerfile installs it via
`pip install /opt/audit-chain` after copying the package source into
the build context. See `gateway/Dockerfile`.

**Outside this repo (e.g., Ogma's `vargate-telemetry`):** install via
Git+SSH from `vargate.ai`:

```toml
# in vargate-telemetry/pyproject.toml
dependencies = [
    "vargate-audit-chain @ git+ssh://git@github.com/zeroco84/vargate.ai.git@<sha>#subdirectory=packages/audit-chain",
]
```

Consumers pin to a specific SHA for reproducible builds; bump the
pinned commit deliberately when picking up upstream changes.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE).
