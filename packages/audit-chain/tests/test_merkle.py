"""Unit tests for vargate_audit_chain.merkle — pure Merkle code only.

The DB-coupled helpers (build_hourly_trees, get_inclusion_proof,
get_consistency_proof, verify_merkle_chain) live in Pro's gateway/merkle.py
and are tested against Pro's audit_log table by Pro's integration suite.
"""

from __future__ import annotations

import hashlib

import pytest

from vargate_audit_chain import GENESIS_ROOT, MerkleTree


def _h(data: bytes) -> str:
    """Helper: SHA-256 hex of bytes."""
    return hashlib.sha256(data).hexdigest()


def test_empty_tree_returns_genesis_root() -> None:
    tree = MerkleTree([])
    assert tree.root == GENESIS_ROOT
    assert tree.leaf_count == 0
    assert tree.height == 0


def test_single_leaf_root_is_padded_pair_of_self() -> None:
    """One leaf -> tree pads by duplicating it; root is hash(leaf || leaf)."""
    leaf = _h(b"only")
    tree = MerkleTree([leaf])
    expected_root = hashlib.sha256(
        bytes.fromhex(leaf) + bytes.fromhex(leaf)
    ).hexdigest()
    assert tree.root == expected_root
    assert tree.leaf_count == 1


def test_two_leaves_root_is_hash_of_pair() -> None:
    a = _h(b"a")
    b = _h(b"b")
    tree = MerkleTree([a, b])
    expected_root = hashlib.sha256(
        bytes.fromhex(a) + bytes.fromhex(b)
    ).hexdigest()
    assert tree.root == expected_root


def test_four_leaves_balanced_tree() -> None:
    leaves = [_h(b"a"), _h(b"b"), _h(b"c"), _h(b"d")]
    tree = MerkleTree(leaves)
    assert tree.leaf_count == 4
    # height = level0 (4 leaves) + level1 (2) + level2 (1 root) = 3
    assert tree.height == 3


def test_proof_verifies_for_every_leaf() -> None:
    """Every leaf gets a proof that verifies against the root."""
    leaves = [_h(f"leaf-{i}".encode()) for i in range(8)]
    tree = MerkleTree(leaves)

    for idx in range(len(leaves)):
        proof = tree.get_proof(idx)
        assert MerkleTree.verify_proof(leaves[idx], proof, tree.root)


def test_proof_fails_for_wrong_leaf() -> None:
    leaves = [_h(f"leaf-{i}".encode()) for i in range(4)]
    tree = MerkleTree(leaves)
    proof = tree.get_proof(0)
    # Try verifying with a different leaf - should fail.
    wrong_leaf = _h(b"not-in-tree")
    assert not MerkleTree.verify_proof(wrong_leaf, proof, tree.root)


def test_proof_fails_against_wrong_root() -> None:
    leaves = [_h(f"leaf-{i}".encode()) for i in range(4)]
    tree = MerkleTree(leaves)
    proof = tree.get_proof(0)
    assert not MerkleTree.verify_proof(leaves[0], proof, "0" * 64)


def test_get_proof_rejects_out_of_range() -> None:
    tree = MerkleTree([_h(b"a"), _h(b"b")])
    with pytest.raises(IndexError):
        tree.get_proof(5)
    with pytest.raises(IndexError):
        tree.get_proof(-1)


def test_odd_leaves_pad_by_duplicating_last() -> None:
    """3 leaves should produce the same root as [a, b, c, c]."""
    a, b, c = _h(b"a"), _h(b"b"), _h(b"c")
    tree3 = MerkleTree([a, b, c])
    tree4 = MerkleTree([a, b, c, c])
    assert tree3.root == tree4.root


def test_genesis_root_is_deterministic() -> None:
    """GENESIS_ROOT is a stable, well-known sentinel."""
    expected = hashlib.sha256(b"VARGATE_GENESIS").hexdigest()
    assert GENESIS_ROOT == expected
