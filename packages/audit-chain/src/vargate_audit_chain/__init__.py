"""Vargate audit-chain primitives — shared between Pro and Telemetry.

Public surface:

    from vargate_audit_chain import (
        GENESIS_HASH,            # "GENESIS" — the prev_hash for the first record
        GENESIS_ROOT,            # Merkle empty-tree sentinel hash
        compute_record_hash,     # tenant-bound SHA-256 over canonical bytes
        verify_record_chain,     # generic chain verifier over an iterator
        ChainRecord,             # frozen dataclass for verify input
        VerifyResult,            # frozen dataclass for verify output
        MerkleTree,              # RFC 6962-style binary Merkle tree
    )
"""

from vargate_audit_chain.chain import (
    GENESIS_HASH,
    ChainRecord,
    VerifyResult,
    compute_record_hash,
    verify_record_chain,
)
from vargate_audit_chain.merkle import GENESIS_ROOT, MerkleTree

__all__ = [
    "ChainRecord",
    "GENESIS_HASH",
    "GENESIS_ROOT",
    "MerkleTree",
    "VerifyResult",
    "compute_record_hash",
    "verify_record_chain",
]

__version__ = "0.1.0"
