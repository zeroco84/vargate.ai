"""
Vargate Merkle Tree Implementation
Binary Merkle tree over audit record SHA-256 hashes.
Supports inclusion proofs (AG-2.3) for O(log n) verification of any record.

Worked example for leaves ["aaa...", "bbb...", "ccc..."]:
  With 3 leaves, pad to 4 by duplicating last: ["aaa", "bbb", "ccc", "ccc"]
  Level 0 (leaves): [aaa, bbb, ccc, ccc]
  Level 1: [H(aaa+bbb), H(ccc+ccc)]
  Level 2 (root): [H(H(aaa+bbb) + H(ccc+ccc))]

  Proof for index 1 (bbb):
    sibling=aaa, position=left   (aaa is to the left of bbb)
    sibling=H(ccc+ccc), position=right  (right subtree hash)
  Verify: H(aaa + bbb) -> H(H(aaa+bbb) + H(ccc+ccc)) == root ✓
"""

import hashlib
import sqlite3


# Canonical root for an empty tree — deterministic sentinel value
GENESIS_ROOT = hashlib.sha256(b"VARGATE_GENESIS").hexdigest()


def _hash_pair(left_hex: str, right_hex: str) -> str:
    """Hash two hex-encoded values together: SHA-256(left_bytes + right_bytes)."""
    left_bytes = bytes.fromhex(left_hex)
    right_bytes = bytes.fromhex(right_hex)
    return hashlib.sha256(left_bytes + right_bytes).hexdigest()


class MerkleTree:
    """
    Binary Merkle tree over SHA-256 leaf hashes.
    Bitcoin-style: odd leaf count is padded by duplicating the last leaf.
    """

    def __init__(self, leaves: list[str]):
        """
        Args:
            leaves: list of lowercase hex SHA-256 hashes (no 0x prefix).
        """
        self._leaves = list(leaves)  # copy
        self._levels: list[list[str]] = []
        self._build()

    def _build(self):
        """Construct all levels of the Merkle tree bottom-up."""
        if not self._leaves:
            self._levels = []
            return

        # Level 0 = leaves (with padding if odd)
        current = list(self._leaves)
        if len(current) % 2 == 1:
            current.append(current[-1])  # duplicate last leaf

        self._levels = [current]

        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                next_level.append(_hash_pair(current[i], current[i + 1]))
            # Pad odd intermediate levels too
            if len(next_level) > 1 and len(next_level) % 2 == 1:
                next_level.append(next_level[-1])
            current = next_level
            self._levels.append(current)

    @property
    def root(self) -> str:
        """Return the Merkle root as a lowercase hex string."""
        if not self._levels:
            return GENESIS_ROOT
        return self._levels[-1][0]

    @property
    def leaf_count(self) -> int:
        """Number of original leaves (before padding)."""
        return len(self._leaves)

    def get_proof(self, index: int) -> list[dict]:
        """
        Get an inclusion proof for the leaf at the given index.

        Returns:
            list of {"sibling": hex_hash, "position": "left"|"right"}
            where position indicates the sibling's position relative to the
            node being proved (i.e., if sibling is "left", it goes on the left
            side when hashing).
        """
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"Leaf index {index} out of range (0..{len(self._leaves) - 1})")

        proof = []
        idx = index

        for level in self._levels[:-1]:  # skip root level
            if idx % 2 == 0:
                # Node is left child, sibling is right
                sibling_idx = idx + 1
                sibling_pos = "right"
            else:
                # Node is right child, sibling is left
                sibling_idx = idx - 1
                sibling_pos = "left"

            if sibling_idx < len(level):
                proof.append({
                    "sibling": level[sibling_idx],
                    "position": sibling_pos,
                })

            idx = idx // 2  # move to parent

        return proof

    @staticmethod
    def verify_proof(leaf: str, proof: list[dict], root: str) -> bool:
        """
        Verify a Merkle inclusion proof.

        Args:
            leaf: the hex hash of the leaf to verify
            proof: list of {"sibling": hex, "position": "left"|"right"}
            root: expected Merkle root hex hash

        Returns:
            True if the proof is valid.
        """
        current = leaf
        for step in proof:
            sibling = step["sibling"]
            if step["position"] == "left":
                current = _hash_pair(sibling, current)
            else:
                current = _hash_pair(current, sibling)
        return current == root

    @staticmethod
    def from_db(conn: sqlite3.Connection) -> "MerkleTree":
        """
        Build a MerkleTree from all record_hash values in the audit_log table,
        ordered by id ASC.
        """
        rows = conn.execute(
            "SELECT record_hash FROM audit_log WHERE erasure_status = 'active' OR erasure_status IS NULL ORDER BY id ASC"
        ).fetchall()
        leaves = [row[0] if isinstance(row, tuple) else row["record_hash"] for row in rows]
        return MerkleTree(leaves)
