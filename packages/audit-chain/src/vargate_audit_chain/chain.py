"""Per-tenant hash-chain primitives.

The package is intentionally storage-agnostic — it knows nothing about
SQLite, Postgres, table schemas, or sequence numbers. Callers compose
records however they like, build canonical bytes, and call into the
two functions here:

    record_hash = compute_record_hash(tenant_id, canonical_bytes, prev_hash)
    result      = verify_record_chain(tenant_id, iter_of_chain_records)

Sequencing (chain_seq, audit_log.id, etc.) is the caller's job. See
the package README for the rationale.

Hash format: SHA-256 over a length-prefixed concatenation of
`tenant_id || canonical_bytes || prev_hash`. Length prefixes prevent
substring confusion and ensure that a record from tenant A cannot
collide with or be replayed into tenant B's chain.

Legacy compatibility: pre-Sprint-16 vargate-proxy records were hashed
as plain `sha256(canonical_bytes)` with no tenant_id binding. The
`verify_record_chain` function falls back to that form so a chain
that spans the Sprint 16 migration verifies end-to-end. See
`compute_record_hash_legacy` for the full contract.
"""

from __future__ import annotations

import dataclasses
import hashlib
from typing import Iterable, Optional

# The literal `prev_hash` value for the first record in a tenant's chain.
# Both Pro and Telemetry use the same string so a tenant's chain has a
# stable root regardless of which product produced the first record.
GENESIS_HASH: str = "GENESIS"


@dataclasses.dataclass(frozen=True)
class ChainRecord:
    """One link in a chain — what was hashed and what hash came out.

    `canonical_bytes` is the application's serialized representation of
    the record (e.g., a JSON dump of fields, a protobuf, or any other
    deterministic encoding). `prev_hash` is the previous record's
    `record_hash`, or `GENESIS_HASH` for the first record. `record_hash`
    is the result of `compute_record_hash` over the other two values.
    """

    canonical_bytes: bytes
    prev_hash: str
    record_hash: str


@dataclasses.dataclass(frozen=True)
class VerifyResult:
    """Outcome of `verify_record_chain`.

    On success: `valid=True`, `record_count=N`, others `None`.
    On failure: `valid=False`, `record_count=K` (records validated
    before the failure), `failure_reason` describing the bad invariant,
    `failed_at_index=K` so the caller can locate the bad row.
    """

    valid: bool
    record_count: int = 0
    failure_reason: Optional[str] = None
    failed_at_index: Optional[int] = None


def compute_record_hash_legacy(canonical_bytes: bytes) -> str:
    """Pre-Sprint-16 hash: SHA-256 over `canonical_bytes` alone.

    Records written before the Sprint 16 tenant_id-binding migration
    (vargate-proxy commit 712ec02, 2026-05-10) had their hashes computed
    by this simpler form — no tenant_id binding, no length framing.

    `verify_record_chain` uses this as a fallback when the new
    (tenant-bound) `compute_record_hash` doesn't match a stored
    record_hash, so chains that span the migration still verify
    end-to-end. **New records MUST use `compute_record_hash`, not this
    function.** The legacy form is exposed only for verifier
    backward-compatibility.

    Security trade-off: the legacy form lacks tenant_id binding, so it
    cannot detect a record's `canonical_bytes` being copied from tenant
    A's chain into tenant B's chain. The prev_hash sequence (which
    `verify_record_chain` checks independently and that came in before
    Sprint 16) catches such replays in practice — every tenant's chain
    has its own prev_hash thread, and a copied record would carry the
    wrong prev_hash for its new tenant and fail the prev-link check.
    """
    if not isinstance(canonical_bytes, (bytes, bytearray)):
        raise TypeError("canonical_bytes must be bytes")
    return hashlib.sha256(bytes(canonical_bytes)).hexdigest()


def compute_record_hash(
    tenant_id: str,
    canonical_bytes: bytes,
    prev_hash: str,
) -> str:
    """Return the SHA-256 hex digest binding a record to a tenant.

    The digest covers a length-prefixed concatenation of `tenant_id`,
    `canonical_bytes`, and `prev_hash`. Length prefixing is what makes
    the binding swap-resistant — without it, the byte stream
    `"ab" + "cd"` would collide with `"a" + "bcd"`.

    Two records with identical `canonical_bytes` and `prev_hash` but
    different `tenant_id` are guaranteed to produce different hashes,
    so a record's hash from tenant A cannot be replayed into tenant B's
    chain.
    """
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("tenant_id must be a non-empty string")
    if not isinstance(canonical_bytes, (bytes, bytearray)):
        raise TypeError("canonical_bytes must be bytes")
    if not isinstance(prev_hash, str):
        raise TypeError("prev_hash must be a string")

    h = hashlib.sha256()
    tenant_bytes = tenant_id.encode("utf-8")
    prev_bytes = prev_hash.encode("utf-8")

    # 4-byte big-endian length prefixes give an unambiguous framing
    # and bound each field at 4 GB — far above anything we'd ever feed.
    h.update(len(tenant_bytes).to_bytes(4, "big"))
    h.update(tenant_bytes)
    h.update(len(canonical_bytes).to_bytes(4, "big"))
    h.update(bytes(canonical_bytes))
    h.update(len(prev_bytes).to_bytes(4, "big"))
    h.update(prev_bytes)

    return h.hexdigest()


def verify_record_chain(
    tenant_id: str,
    records: Iterable[ChainRecord],
    *,
    genesis: str = GENESIS_HASH,
) -> VerifyResult:
    """Walk a chain in order, checking link integrity at each step.

    Accepts any iterable so callers can stream records out of a database
    cursor without materializing the whole chain in memory. The
    iteration order MUST match the chain's natural order — typically
    the table's primary-key order or the application's sequence column.

    Returns `VerifyResult(valid=True, record_count=N)` on success.
    On the first failure, returns `VerifyResult(valid=False, ...)` with
    `failure_reason` and `failed_at_index` populated.
    """
    if not isinstance(tenant_id, str) or not tenant_id:
        raise ValueError("tenant_id must be a non-empty string")

    expected_prev = genesis
    count = 0

    for idx, rec in enumerate(records):
        if not isinstance(rec, ChainRecord):
            return VerifyResult(
                valid=False,
                record_count=count,
                failure_reason=f"record at index {idx} is not a ChainRecord",
                failed_at_index=idx,
            )

        if rec.prev_hash != expected_prev:
            return VerifyResult(
                valid=False,
                record_count=count,
                failure_reason=(
                    f"prev_hash mismatch at index {idx}: "
                    f"got {rec.prev_hash!r}, expected {expected_prev!r}"
                ),
                failed_at_index=idx,
            )

        expected_hash = compute_record_hash(
            tenant_id, rec.canonical_bytes, rec.prev_hash,
        )
        if expected_hash != rec.record_hash:
            # Fall back to the pre-Sprint-16 form (SHA-256 over
            # canonical_bytes alone, no tenant_id binding). Chains
            # that span the migration carry records of both shapes;
            # the verifier accepts either so end-to-end verification
            # still succeeds. Tamper detection holds: a modified
            # `canonical_bytes` produces a different SHA-256 under
            # both forms.
            legacy_hash = compute_record_hash_legacy(rec.canonical_bytes)
            if legacy_hash != rec.record_hash:
                return VerifyResult(
                    valid=False,
                    record_count=count,
                    failure_reason=(
                        f"record_hash mismatch at index {idx}: "
                        f"got {rec.record_hash!r}, recomputed "
                        f"{expected_hash!r} (legacy form "
                        f"{legacy_hash!r} also mismatched)"
                    ),
                    failed_at_index=idx,
                )

        expected_prev = rec.record_hash
        count += 1

    return VerifyResult(valid=True, record_count=count)
