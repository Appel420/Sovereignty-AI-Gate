"""
Tests: sovereignty_core.audit.merkle — SCAR Merkle tree builder.

Covers:
    - single-entry tree (root == leaf hash)
    - multi-entry trees (power-of-two and odd counts)
    - order-sensitivity of the root
    - content-sensitivity of the root
    - inclusion proof generation and verification
    - tampered proof detection
    - empty-log rejection
    - AuditLedger bridge (build_merkle_from_audit_ledger)
    - canonicalization is deterministic
"""
from __future__ import annotations

import pytest

from sia.audit.ledger import AuditLedger
from sovereignty_core.audit.merkle import (
    MerkleError,
    MerkleTree,
    build_merkle_from_audit_ledger,
    build_merkle_from_scarlog,
    canonicalize,
    generate_proof,
    hash_entry,
    hash_pair,
    verify_merkle_proof,
)


# ── Fixtures ─────────────────────────────────────────────────────────────────


def _entry(n: int) -> dict:
    return {
        "timestamp": f"2026-07-14T00:00:0{n}Z",
        "event": "MEMORY_APPEND",
        "actor": f"device_key_{n}",
        "payload_hash": "a" * 64,
        "sequence": n,
    }


def _scarlog(count: int) -> list[dict]:
    return [_entry(i) for i in range(count)]


# ── Canonicalization ─────────────────────────────────────────────────────────


def test_canonicalize_is_deterministic():
    entry = _entry(0)
    assert canonicalize(entry) == canonicalize(entry)


def test_canonicalize_sorts_keys():
    e1 = {"b": 2, "a": 1}
    e2 = {"a": 1, "b": 2}
    assert canonicalize(e1) == canonicalize(e2)


def test_hash_entry_is_64_hex_chars():
    h = hash_entry(_entry(0))
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_hash_entry_is_deterministic():
    assert hash_entry(_entry(0)) == hash_entry(_entry(0))


def test_hash_entry_differs_for_different_entries():
    assert hash_entry(_entry(0)) != hash_entry(_entry(1))


def test_hash_pair_is_64_hex_chars():
    h = hash_pair("a" * 64, "b" * 64)
    assert len(h) == 64


def test_hash_pair_is_not_commutative():
    h1 = hash_pair("a" * 64, "b" * 64)
    h2 = hash_pair("b" * 64, "a" * 64)
    assert h1 != h2


# ── Empty log ────────────────────────────────────────────────────────────────


def test_empty_scarlog_raises():
    with pytest.raises(MerkleError, match="empty"):
        build_merkle_from_scarlog([])


# ── Single-entry tree ────────────────────────────────────────────────────────


def test_single_entry_root_equals_leaf():
    log = _scarlog(1)
    tree = build_merkle_from_scarlog(log)
    assert tree.root == tree.leaves[0]
    assert len(tree.leaves) == 1
    assert len(tree.levels) == 1


# ── Two-entry tree ───────────────────────────────────────────────────────────


def test_two_entry_tree_structure():
    tree = build_merkle_from_scarlog(_scarlog(2))
    assert len(tree.leaves) == 2
    assert len(tree.levels) == 2  # leaves + root
    assert tree.root == hash_pair(tree.leaves[0], tree.leaves[1])


# ── Power-of-two tree ────────────────────────────────────────────────────────


def test_four_entry_tree():
    tree = build_merkle_from_scarlog(_scarlog(4))
    assert len(tree.leaves) == 4
    assert len(tree.levels) == 3  # leaves, mid, root


# ── Odd-count tree (duplication of last leaf) ────────────────────────────────


def test_odd_entry_tree_three():
    tree = build_merkle_from_scarlog(_scarlog(3))
    assert len(tree.leaves) == 3
    # level 1 should be [pair(0,1), pair(2,2)]
    expected_mid_0 = hash_pair(tree.leaves[0], tree.leaves[1])
    expected_mid_1 = hash_pair(tree.leaves[2], tree.leaves[2])
    assert tree.levels[1][0] == expected_mid_0
    assert tree.levels[1][1] == expected_mid_1
    assert tree.root == hash_pair(expected_mid_0, expected_mid_1)


def test_odd_entry_tree_five():
    tree = build_merkle_from_scarlog(_scarlog(5))
    assert tree.root == build_merkle_from_scarlog(_scarlog(5)).root  # deterministic


# ── Root is order-sensitive ──────────────────────────────────────────────────


def test_root_is_order_sensitive():
    log = _scarlog(4)
    tree_asc = build_merkle_from_scarlog(log)
    tree_rev = build_merkle_from_scarlog(list(reversed(log)))
    assert tree_asc.root != tree_rev.root


# ── Root is content-sensitive ────────────────────────────────────────────────


def test_root_changes_on_entry_tamper():
    log = _scarlog(4)
    tree_original = build_merkle_from_scarlog(log)
    tampered = [dict(e) for e in log]
    tampered[2]["actor"] = "INJECTED"
    tree_tampered = build_merkle_from_scarlog(tampered)
    assert tree_original.root != tree_tampered.root


# ── MerkleTree is immutable ──────────────────────────────────────────────────


def test_merkle_tree_is_frozen():
    tree = build_merkle_from_scarlog(_scarlog(2))
    with pytest.raises((AttributeError, TypeError)):
        tree.root = "hacked"  # type: ignore[misc]


# ── Proof: single-entry ───────────────────────────────────────────────────────


def test_proof_single_entry():
    tree = build_merkle_from_scarlog(_scarlog(1))
    proof = generate_proof(tree, 0)
    assert proof.leaf_hash == tree.leaves[0]
    assert proof.root == tree.root
    assert proof.siblings == []
    assert verify_merkle_proof(proof) is True


# ── Proof: every leaf of a 4-entry tree ──────────────────────────────────────


@pytest.mark.parametrize("idx", range(4))
def test_proof_four_entry_all_leaves(idx: int):
    tree = build_merkle_from_scarlog(_scarlog(4))
    proof = generate_proof(tree, idx)
    assert verify_merkle_proof(proof) is True


# ── Proof: every leaf of a 5-entry (odd) tree ───────────────────────────────


@pytest.mark.parametrize("idx", range(5))
def test_proof_five_entry_all_leaves(idx: int):
    tree = build_merkle_from_scarlog(_scarlog(5))
    proof = generate_proof(tree, idx)
    assert verify_merkle_proof(proof) is True


# ── Proof: tampered leaf hash is rejected ────────────────────────────────────


def test_proof_tampered_leaf_rejected():
    tree = build_merkle_from_scarlog(_scarlog(4))
    proof = generate_proof(tree, 1)
    bad_proof = type(proof)(
        leaf_hash="0" * 64,
        siblings=proof.siblings,
        root=proof.root,
    )
    assert verify_merkle_proof(bad_proof) is False


# ── Proof: wrong root is rejected ───────────────────────────────────────────


def test_proof_wrong_root_rejected():
    tree = build_merkle_from_scarlog(_scarlog(4))
    proof = generate_proof(tree, 0)
    bad_proof = type(proof)(
        leaf_hash=proof.leaf_hash,
        siblings=proof.siblings,
        root="f" * 64,
    )
    assert verify_merkle_proof(bad_proof) is False


# ── Proof: out-of-range index ─────────────────────────────────────────────────


def test_proof_out_of_range_raises():
    tree = build_merkle_from_scarlog(_scarlog(3))
    with pytest.raises(IndexError):
        generate_proof(tree, 99)

    with pytest.raises(IndexError):
        generate_proof(tree, -1)


# ── AuditLedger bridge ───────────────────────────────────────────────────────


def test_build_from_audit_ledger_matches_dict_path():
    ledger = AuditLedger()
    ledger.append("scar.memory_append", {"payload_hash": "a" * 64}, actor_id="device:1")
    ledger.append("scar.delegation_issued", {"token_id": "tok-1"}, actor_id="device:1")

    tree_ledger = build_merkle_from_audit_ledger(ledger)
    entries_as_dicts = [e.to_dict() for e in ledger.all_entries()]
    tree_dict = build_merkle_from_scarlog(entries_as_dicts)

    assert tree_ledger.root == tree_dict.root
    assert tree_ledger.leaves == tree_dict.leaves


def test_build_from_empty_audit_ledger_raises():
    with pytest.raises(MerkleError, match="empty"):
        build_merkle_from_audit_ledger(AuditLedger())


def test_audit_ledger_bridge_proof_verifies():
    ledger = AuditLedger()
    for i in range(5):
        ledger.append(f"scar.event_{i}", {"seq": i}, actor_id="device:x")

    tree = build_merkle_from_audit_ledger(ledger)
    for i in range(5):
        assert verify_merkle_proof(generate_proof(tree, i)) is True


# ── Algorithm field ──────────────────────────────────────────────────────────


def test_tree_algorithm_field():
    tree = build_merkle_from_scarlog(_scarlog(2))
    assert tree.algorithm == "SHA-256"
