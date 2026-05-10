"""Unit tests for vargate_audit_chain.chain — pure-function coverage."""

from __future__ import annotations

import pytest

from vargate_audit_chain import (
    GENESIS_HASH,
    ChainRecord,
    compute_record_hash,
    verify_record_chain,
)


# --- compute_record_hash ----------------------------------------------------


def test_compute_record_hash_is_deterministic() -> None:
    """Same inputs -> same output, every time."""
    h1 = compute_record_hash("tenant-A", b"payload", "GENESIS")
    h2 = compute_record_hash("tenant-A", b"payload", "GENESIS")
    assert h1 == h2
    # SHA-256 hex digest is 64 chars
    assert len(h1) == 64
    assert all(c in "0123456789abcdef" for c in h1)


def test_record_hash_binds_tenant_id() -> None:
    """Same canonical_bytes + prev_hash, different tenant_ids -> different hashes.

    This is the *defining* property of the tenant-bound primitive: a
    record's hash from tenant A cannot collide with or be replayed into
    tenant B's chain.
    """
    canonical = b"some canonical record bytes"
    prev = "abc123"

    h_a = compute_record_hash("tenant-A", canonical, prev)
    h_b = compute_record_hash("tenant-B", canonical, prev)

    assert h_a != h_b, (
        "tenant_id binding broken: same canonical_bytes + prev_hash "
        "produce same hash for different tenants"
    )


def test_record_hash_changes_on_canonical_bytes() -> None:
    """Different canonical_bytes for the same tenant -> different hashes."""
    h1 = compute_record_hash("t", b"payload one", "p")
    h2 = compute_record_hash("t", b"payload two", "p")
    assert h1 != h2


def test_record_hash_changes_on_prev_hash() -> None:
    """Different prev_hash for the same tenant + bytes -> different hashes."""
    h1 = compute_record_hash("t", b"x", "prev-1")
    h2 = compute_record_hash("t", b"x", "prev-2")
    assert h1 != h2


def test_compute_record_hash_length_prefixing_swap_resistant() -> None:
    """Length prefixing means concatenation can't collide across boundaries."""
    # Without length prefixing, ("ab", "cd") and ("a", "bcd") would
    # produce the same hash if naively concatenated. With length prefixing
    # they cannot.
    h_split_a = compute_record_hash("ab", b"cd", "x")
    h_split_b = compute_record_hash("a", b"bcd", "x")
    assert h_split_a != h_split_b


def test_compute_record_hash_rejects_empty_tenant() -> None:
    with pytest.raises(ValueError):
        compute_record_hash("", b"payload", "GENESIS")


def test_compute_record_hash_rejects_non_bytes_canonical() -> None:
    with pytest.raises(TypeError):
        compute_record_hash("t", "not bytes", "GENESIS")  # type: ignore[arg-type]


def test_compute_record_hash_accepts_bytearray() -> None:
    """bytearray and bytes should produce the same hash for equal contents."""
    h_bytes = compute_record_hash("t", b"payload", "p")
    h_ba = compute_record_hash("t", bytearray(b"payload"), "p")
    assert h_bytes == h_ba


# --- verify_record_chain ----------------------------------------------------


def _build_chain(tenant_id: str, payloads: list[bytes]) -> list[ChainRecord]:
    """Build a valid chain of ChainRecords for testing."""
    records = []
    prev = GENESIS_HASH
    for payload in payloads:
        rh = compute_record_hash(tenant_id, payload, prev)
        records.append(
            ChainRecord(
                canonical_bytes=payload,
                prev_hash=prev,
                record_hash=rh,
            )
        )
        prev = rh
    return records


def test_verify_empty_chain_is_valid() -> None:
    result = verify_record_chain("t", iter([]))
    assert result.valid is True
    assert result.record_count == 0


def test_verify_single_record_chain_valid() -> None:
    chain = _build_chain("t", [b"only record"])
    result = verify_record_chain("t", iter(chain))
    assert result.valid is True
    assert result.record_count == 1


def test_verify_multi_record_chain_valid() -> None:
    chain = _build_chain("t", [b"a", b"b", b"c", b"d"])
    result = verify_record_chain("t", iter(chain))
    assert result.valid is True
    assert result.record_count == 4
    assert result.failure_reason is None


def test_verify_detects_prev_hash_mismatch() -> None:
    """A broken prev_hash link is caught at the wrong record."""
    chain = _build_chain("t", [b"a", b"b", b"c"])
    # Tamper: change record 1's prev_hash so it doesn't match record 0's hash.
    bad = list(chain)
    bad[1] = ChainRecord(
        canonical_bytes=bad[1].canonical_bytes,
        prev_hash="WRONG_PREV",
        record_hash=bad[1].record_hash,
    )
    result = verify_record_chain("t", iter(bad))
    assert result.valid is False
    assert result.failed_at_index == 1
    assert "prev_hash mismatch" in (result.failure_reason or "")


def test_verify_detects_record_hash_mismatch() -> None:
    """A tampered record_hash is caught even if prev_hash chain looks valid."""
    chain = _build_chain("t", [b"a", b"b"])
    # Tamper: change record 0's stored record_hash without changing canonical.
    bad = [
        ChainRecord(
            canonical_bytes=chain[0].canonical_bytes,
            prev_hash=chain[0].prev_hash,
            record_hash="0" * 64,  # plausible-looking but wrong hex
        ),
        chain[1],
    ]
    result = verify_record_chain("t", iter(bad))
    assert result.valid is False
    assert result.failed_at_index == 0
    assert "record_hash mismatch" in (result.failure_reason or "")


def test_verify_detects_cross_tenant_replay() -> None:
    """Records valid under tenant A do NOT verify under tenant B.

    This is the operational consequence of `compute_record_hash`'s
    tenant_id binding: even a perfectly self-consistent chain from
    tenant A fails verification when fed in under tenant B's id.
    """
    a_chain = _build_chain("tenant-A", [b"x", b"y"])
    result = verify_record_chain("tenant-B", iter(a_chain))
    assert result.valid is False
    assert result.failed_at_index == 0
    # The first record's record_hash was computed under tenant-A but
    # the verifier recomputes under tenant-B and gets a different value.
    assert "record_hash mismatch" in (result.failure_reason or "")


def test_verify_accepts_iterator_streaming() -> None:
    """The verifier consumes from an iterator without materializing the chain."""
    chain = _build_chain("t", [b"a", b"b", b"c"])

    def streaming_source():
        for rec in chain:
            yield rec

    result = verify_record_chain("t", streaming_source())
    assert result.valid is True
    assert result.record_count == 3
