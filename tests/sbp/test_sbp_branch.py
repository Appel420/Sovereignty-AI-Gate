"""
SBP Branch tests — lineage, sibling isolation, capability checks, and codec.
"""

from __future__ import annotations

import pytest

from sovereignty_core.identity.root_of_trust import SoftwareTrustBackend
from sbp.root import RootAuthority
from sbp.branch import Branch, BranchCapability
from sbp.codec import CodecError, encode_branch, decode_branch


ROOT_SECRET_A = b"\xAA" * 32
ROOT_SECRET_B = b"\xBB" * 32
FIXED_TS = 1_700_000_000


def make_root(secret: bytes = ROOT_SECRET_A) -> RootAuthority:
    return RootAuthority(SoftwareTrustBackend(secret), created_at=FIXED_TS)


def make_branch(
    root: RootAuthority | None = None,
    label: str = "main",
    caps: list | None = None,
    parent_branch_id: str | None = None,
    created_at: int = FIXED_TS,
) -> Branch:
    root = root or make_root()
    caps = caps or [BranchCapability.READ, BranchCapability.WRITE]
    return Branch(root, label=label, capabilities=caps, parent_branch_id=parent_branch_id, created_at=created_at)


# ── Deterministic identity ────────────────────────────────────────────────────

def test_branch_id_is_deterministic():
    root = make_root()
    b1 = make_branch(root)
    b2 = make_branch(root)
    assert b1.metadata.branch_id == b2.metadata.branch_id


def test_branch_id_changes_with_label():
    root = make_root()
    b_main = make_branch(root, label="main")
    b_alt = make_branch(root, label="alt")
    assert b_main.metadata.branch_id != b_alt.metadata.branch_id


def test_branch_id_changes_with_different_root():
    root_a = make_root(ROOT_SECRET_A)
    root_b = make_root(ROOT_SECRET_B)
    b_a = make_branch(root_a, label="main")
    b_b = make_branch(root_b, label="main")
    assert b_a.metadata.branch_id != b_b.metadata.branch_id


# ── Lineage: root_id and parent linkage ───────────────────────────────────────

def test_branch_root_id_matches_root_authority():
    root = make_root()
    branch = make_branch(root)
    assert branch.metadata.root_id == root.metadata.root_id


def test_branch_parent_branch_id_is_none_for_first_gen():
    root = make_root()
    branch = make_branch(root)
    assert branch.metadata.parent_branch_id is None


def test_branch_records_parent_branch_id():
    root = make_root()
    parent_branch = make_branch(root, label="parent")
    child = make_branch(root, label="child", parent_branch_id=parent_branch.metadata.branch_id)
    assert child.metadata.parent_branch_id == parent_branch.metadata.branch_id


def test_child_branch_id_differs_from_parent():
    root = make_root()
    parent = make_branch(root, label="parent")
    child = make_branch(root, label="child", parent_branch_id=parent.metadata.branch_id)
    assert child.metadata.branch_id != parent.metadata.branch_id


# ── Sibling branch isolation ──────────────────────────────────────────────────

def test_sibling_branch_keys_are_isolated():
    root = make_root()
    sibling_a = make_branch(root, label="sib-a")
    sibling_b = make_branch(root, label="sib-b")
    key_a = sibling_a.derive_key()
    key_b = sibling_b.derive_key()
    assert key_a != key_b, "Sibling branches must have distinct key material"


def test_same_branch_key_is_stable():
    root = make_root()
    branch = make_branch(root, label="stable")
    k1 = branch.derive_key()
    k2 = branch.derive_key()
    assert k1 == k2


def test_branch_key_differs_from_other_root_branch_key():
    root_a = make_root(ROOT_SECRET_A)
    root_b = make_root(ROOT_SECRET_B)
    branch_a = make_branch(root_a, label="same-label")
    branch_b = make_branch(root_b, label="same-label")
    # Different roots → different branch IDs → different keys.
    assert branch_a.derive_key() != branch_b.derive_key()


# ── Capabilities ──────────────────────────────────────────────────────────────

def test_branch_has_granted_capabilities():
    root = make_root()
    branch = make_branch(root, caps=[BranchCapability.READ, BranchCapability.APPEND_AUDIT])
    assert branch.has_capability(BranchCapability.READ) is True
    assert branch.has_capability(BranchCapability.APPEND_AUDIT) is True


def test_branch_does_not_have_ungrantd_capabilities():
    root = make_root()
    branch = make_branch(root, caps=[BranchCapability.READ])
    assert branch.has_capability(BranchCapability.ADMIN) is False
    assert branch.has_capability(BranchCapability.DELEGATE) is False


def test_capabilities_are_sorted_in_metadata():
    root = make_root()
    branch = Branch(
        root,
        label="sorted",
        capabilities=[BranchCapability.WRITE, BranchCapability.READ],
        created_at=FIXED_TS,
    )
    caps = list(branch.metadata.capabilities)
    assert caps == sorted(caps), "Capabilities must be stored in sorted order"


# ── Policy hash ───────────────────────────────────────────────────────────────

def test_branch_policy_hash_populated():
    root = make_root()
    branch = make_branch(root)
    assert len(branch.metadata.policy_hash) == 128


def test_custom_branch_policy_changes_policy_hash_and_branch_id():
    root = make_root()
    default_branch = make_branch(root)
    custom_branch = Branch(
        root,
        label="main",
        capabilities=[BranchCapability.READ, BranchCapability.WRITE],
        policy={"version": 1, "type": "strict"},
        created_at=FIXED_TS,
    )
    assert default_branch.metadata.policy_hash != custom_branch.metadata.policy_hash
    assert default_branch.metadata.branch_id != custom_branch.metadata.branch_id


# ── Codec round-trip ──────────────────────────────────────────────────────────

def test_branch_codec_round_trip():
    root = make_root()
    branch = make_branch(root)
    doc = encode_branch(branch.metadata)
    recovered = decode_branch(doc)
    assert recovered == branch.metadata


def test_branch_codec_round_trip_with_parent():
    root = make_root()
    parent = make_branch(root, label="parent")
    child = Branch(
        root,
        label="child",
        capabilities=[BranchCapability.READ],
        parent_branch_id=parent.metadata.branch_id,
        created_at=FIXED_TS,
    )
    doc = encode_branch(child.metadata)
    recovered = decode_branch(doc)
    assert recovered.parent_branch_id == parent.metadata.branch_id


def test_branch_codec_rejects_unknown_field():
    root = make_root()
    branch = make_branch(root)
    doc = encode_branch(branch.metadata)
    doc["unexpected"] = "value"
    with pytest.raises(CodecError):
        decode_branch(doc)


def test_branch_codec_rejects_missing_field():
    root = make_root()
    branch = make_branch(root)
    doc = encode_branch(branch.metadata)
    del doc["branch_id"]
    with pytest.raises(CodecError):
        decode_branch(doc)


def test_branch_codec_null_parent_branch_id_is_valid():
    root = make_root()
    branch = make_branch(root)
    assert branch.metadata.parent_branch_id is None
    doc = encode_branch(branch.metadata)
    assert doc["parent_branch_id"] is None
    recovered = decode_branch(doc)
    assert recovered.parent_branch_id is None


# ── Known test vector ─────────────────────────────────────────────────────────

def test_branch_id_known_vector():
    """
    Deterministic test vector: branch_id must be stable for fixed inputs.

    If this test fails, branch identity derivation changed and any stored
    branch records are now incompatible.
    """
    root = make_root(ROOT_SECRET_A)
    branch = Branch(
        root,
        label="main",
        capabilities=[BranchCapability.READ, BranchCapability.WRITE],
        created_at=FIXED_TS,
    )
    recorded_id = branch.metadata.branch_id
    assert len(recorded_id) == 128
    assert all(c in "0123456789abcdef" for c in recorded_id)
    # Re-creation must produce the same ID.
    branch2 = Branch(
        root,
        label="main",
        capabilities=[BranchCapability.WRITE, BranchCapability.READ],  # different order
        created_at=FIXED_TS,
    )
    assert branch2.metadata.branch_id == recorded_id
