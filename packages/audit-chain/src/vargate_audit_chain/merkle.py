"""Binary Merkle tree over SHA-256 (RFC 6962 / Certificate Transparency).

Pure code, no I/O. Bitcoin-style odd-leaf padding (duplicate the last
leaf to keep tree levels even).

Moved here from `gateway/merkle.py` in vargate-proxy so both Pro and
Telemetry can build trees without depending on each other's storage.
"""

from __future__ import annotations

import hashlib
from typing import List

# Canonical root for an empty tree — deterministic sentinel value.
# Anchored callers (Pro, Telemetry) use this when no records yet exist.
GENESIS_ROOT: str = hashlib.sha256(b"VARGATE_GENESIS").hexdigest()


def _hash_pair(left_hex: str, right_hex: str) -> str:
    """SHA-256 of (left_bytes || right_bytes) returned as lowercase hex."""
    left_bytes = bytes.fromhex(left_hex)
    right_bytes = bytes.fromhex(right_hex)
    return hashlib.sha256(left_bytes + right_bytes).hexdigest()


class MerkleTree:
    """Binary Merkle tree over SHA-256 leaf hashes.

    Bitcoin-style: odd leaf count is padded by duplicating the last leaf.
    Leaves are passed in already-hashed form (lowercase hex SHA-256, no
    `0x` prefix) so the caller controls the leaf-hash function.
    """

    def __init__(self, leaves: List[str]):
        """
        Args:
            leaves: list of lowercase hex SHA-256 hashes (no 0x prefix).
        """
        self._leaves: List[str] = list(leaves)
        self._levels: List[List[str]] = []
        self._build()

    def _build(self) -> None:
        """Construct all levels of the Merkle tree bottom-up."""
        if not self._leaves:
            self._levels = []
            return

        current = list(self._leaves)
        if len(current) % 2 == 1:
            current.append(current[-1])

        self._levels = [current]

        while len(current) > 1:
            next_level: List[str] = []
            for i in range(0, len(current), 2):
                next_level.append(_hash_pair(current[i], current[i + 1]))
            if len(next_level) > 1 and len(next_level) % 2 == 1:
                next_level.append(next_level[-1])
            current = next_level
            self._levels.append(current)

    @property
    def root(self) -> str:
        if not self._levels:
            return GENESIS_ROOT
        return self._levels[-1][0]

    @property
    def leaf_count(self) -> int:
        return len(self._leaves)

    @property
    def height(self) -> int:
        return len(self._levels)

    def get_proof(self, index: int) -> List[dict]:
        """Inclusion proof for the leaf at the given index.

        Returns:
            list of `{"sibling": hex_hash, "position": "left"|"right"}`
            where position indicates the sibling's position relative to
            the node being proved.
        """
        if index < 0 or index >= len(self._leaves):
            raise IndexError(
                f"Leaf index {index} out of range "
                f"(0..{len(self._leaves) - 1})"
            )

        proof: List[dict] = []
        idx = index

        for level in self._levels[:-1]:
            if idx % 2 == 0:
                sibling_idx = idx + 1
                sibling_pos = "right"
            else:
                sibling_idx = idx - 1
                sibling_pos = "left"

            if sibling_idx < len(level):
                proof.append(
                    {
                        "sibling": level[sibling_idx],
                        "position": sibling_pos,
                    }
                )

            idx = idx // 2

        return proof

    @staticmethod
    def verify_proof(leaf: str, proof: List[dict], root: str) -> bool:
        """Verify a Merkle inclusion proof."""
        current = leaf
        for step in proof:
            sibling = step["sibling"]
            if step["position"] == "left":
                current = _hash_pair(sibling, current)
            else:
                current = _hash_pair(current, sibling)
        return current == root
