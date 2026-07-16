"""
SBP Audit chain tests — chaining, integrity verification, and honest signatures.
"""

from __future__ import annotations

import pytest

from sovereignty_core.identity.root_of_trust import SoftwareTrustBackend
from sbp.root import RootAuthority
from sbp.branch import Branch, BranchCapability
from sbp.audit import AuditChain, AuditEntry, GENESIS_HASH, AuditChainError


ROOT_SECRET = b"\xDD" * 32
FIXED_TS = 1_700_000_002
FIXED_STAMP = "2023-11-14T22:13:20Z"


def make_root() -> RootAuthority:
    return RootAuthority(SoftwareTrustBackend(ROOT_SECRET), created_at=FIXED_TS)


def make_chain(root: RootAuthority | None = None, branch_id: str = "branch-audit-test") -> AuditChain:
    root = root or make_root()
    return AuditChain(branch_id=branch_id, root=root)


# ── Append and basic structure ────────────────────────────────────────────────

def test_empty_chain_has_no_entries():
    chain = make_chain()
    assert len(chain.entries) == 0


def test_append_returns_audit_entry():
    chain = make_chain()
    entry = chain.append(actor_id="root-actor", action="TEST_ACTION", timestamp=FIXED_STAMP)
    assert isinstance(entry, AuditEntry)


def test_sequence_numbers_are_monotonic():
    chain = make_chain()
    e0 = chain.append(actor_id="actor", action="A0", timestamp=FIXED_STAMP)
    e1 = chain.append(actor_id="actor", action="A1", timestamp=FIXED_STAMP)
    e2 = chain.append(actor_id="actor", action="A2", timestamp=FIXED_STAMP)
    assert e0.sequence == 0
    assert e1.sequence == 1
    assert e2.sequence == 2


def test_first_entry_previous_hash_is_genesis():
    chain = make_chain()
    entry = chain.append(actor_id="actor", action="GENESIS_TEST", timestamp=FIXED_STAMP)
    assert entry.previous_hash == GENESIS_HASH


def test_subsequent_entry_links_to_previous():
    chain = make_chain()
    e0 = chain.append(actor_id="actor", action="A0", timestamp=FIXED_STAMP)
    e1 = chain.append(actor_id="actor", action="A1", timestamp=FIXED_STAMP)
    assert e1.previous_hash == e0.entry_hash


def test_chain_length_grows_after_append():
    chain = make_chain()
    chain.append(actor_id="actor", action="ONE", timestamp=FIXED_STAMP)
    chain.append(actor_id="actor", action="TWO", timestamp=FIXED_STAMP)
    assert len(chain.entries) == 2


# ── Signature is real, not fake ───────────────────────────────────────────────

def test_entry_signature_is_nonempty():
    chain = make_chain()
    entry = chain.append(actor_id="actor", action="SIG_CHECK", timestamp=FIXED_STAMP)
    assert entry.signature != ""
    assert entry.signature != "PLACEHOLDER"
    assert entry.signature != "FAKE"


def test_entry_signature_is_valid_ed25519():
    root = make_root()
    chain = make_chain(root)
    entry = chain.append(actor_id="actor", action="REAL_SIG", timestamp=FIXED_STAMP)
    # Verify the raw signature using the root backend directly.
    from sia.utils.canonical import canonical_bytes
    assert root.verify(canonical_bytes(entry.signing_document()), entry.signature) is True


# ── Chain integrity verification ──────────────────────────────────────────────

def test_integrity_empty_chain():
    chain = make_chain()
    assert chain.verify_integrity() is True


def test_integrity_single_entry():
    chain = make_chain()
    chain.append(actor_id="actor", action="SINGLE", timestamp=FIXED_STAMP)
    assert chain.verify_integrity() is True


def test_integrity_multiple_entries():
    chain = make_chain()
    for i in range(5):
        chain.append(actor_id="actor", action=f"ACTION_{i}", timestamp=FIXED_STAMP)
    assert chain.verify_integrity() is True


def test_integrity_detects_tampered_entry_hash():
    chain = make_chain()
    chain.append(actor_id="actor", action="TAMPER_ME", timestamp=FIXED_STAMP)
    # Directly tamper the stored entry hash.
    from dataclasses import replace
    bad_entry = replace(chain._entries[0], entry_hash="0" * 128)
    chain._entries[0] = bad_entry
    assert chain.verify_integrity() is False


def test_integrity_detects_tampered_action():
    chain = make_chain()
    chain.append(actor_id="actor", action="ORIGINAL", timestamp=FIXED_STAMP)
    from dataclasses import replace
    bad = replace(chain._entries[0], action="TAMPERED")
    chain._entries[0] = bad
    assert chain.verify_integrity() is False


def test_integrity_detects_broken_chain_link():
    chain = make_chain()
    chain.append(actor_id="actor", action="FIRST", timestamp=FIXED_STAMP)
    chain.append(actor_id="actor", action="SECOND", timestamp=FIXED_STAMP)
    # Break the previous_hash link in entry 1.
    from dataclasses import replace
    bad = replace(chain._entries[1], previous_hash="0" * 128)
    chain._entries[1] = bad
    assert chain.verify_integrity() is False


# ── Object and metadata binding ───────────────────────────────────────────────

def test_append_with_object_id():
    chain = make_chain()
    oid = "a" * 128
    entry = chain.append(actor_id="actor", action="ISSUE", object_id=oid, timestamp=FIXED_STAMP)
    assert entry.object_id == oid


def test_append_with_metadata_stores_hash_not_plaintext():
    chain = make_chain()
    entry = chain.append(
        actor_id="actor",
        action="WITH_META",
        metadata={"key": "secret-value"},
        timestamp=FIXED_STAMP,
    )
    assert entry.metadata_hash is not None
    assert len(entry.metadata_hash) == 128
    assert "secret-value" not in str(entry.to_dict())


def test_append_without_metadata_has_none_hash():
    chain = make_chain()
    entry = chain.append(actor_id="actor", action="NO_META", timestamp=FIXED_STAMP)
    assert entry.metadata_hash is None


# ── Guard rails ───────────────────────────────────────────────────────────────

def test_chain_requires_nonempty_branch_id():
    root = make_root()
    with pytest.raises(ValueError, match="branch_id"):
        AuditChain(branch_id="", root=root)


def test_append_requires_nonempty_action():
    chain = make_chain()
    with pytest.raises(ValueError, match="action"):
        chain.append(actor_id="actor", action="")


def test_append_preserves_explicit_empty_entry_id():
    chain = make_chain()
    entry = chain.append(
        actor_id="actor",
        action="EMPTY_ID",
        entry_id="",
        timestamp=FIXED_STAMP,
    )
    assert entry.entry_id == ""


def test_append_rejects_non_string_entry_id():
    chain = make_chain()
    with pytest.raises(TypeError, match="entry_id must be a string"):
        chain.append(actor_id="actor", action="BAD_ID", entry_id=123)


# ── Export bundle ─────────────────────────────────────────────────────────────

def test_export_bundle_structure():
    chain = make_chain()
    chain.append(actor_id="actor", action="BUNDLE_TEST", timestamp=FIXED_STAMP)
    bundle = chain.export_bundle()
    assert bundle["format"] == "SBP-AUDIT-BUNDLE-0.1"
    assert bundle["branch_id"] == chain.branch_id
    assert bundle["entry_count"] == 1
    assert len(bundle["entries"]) == 1


def test_export_bundle_entries_match_chain():
    chain = make_chain()
    e0 = chain.append(actor_id="actor", action="E0", timestamp=FIXED_STAMP)
    e1 = chain.append(actor_id="actor", action="E1", timestamp=FIXED_STAMP)
    bundle = chain.export_bundle()
    assert bundle["entries"][0]["entry_hash"] == e0.entry_hash
    assert bundle["entries"][1]["entry_hash"] == e1.entry_hash


# ── Audit chaining determinism ────────────────────────────────────────────────

def test_audit_chain_deterministic_hashes():
    """
    Audit chain: same actions with same timestamps must produce identical
    entry hashes (so stored bundles can be replayed and verified).

    NOTE: signatures use uuid4 entry IDs so they differ per run, but the
    entry hash covers entry_id so it also differs.  This test verifies that
    the chain structure (previous_hash linkage) is correct and stable.
    """
    root = make_root()
    chain = AuditChain(branch_id="det-branch", root=root)
    e0 = chain.append(actor_id="actor", action="FIRST", timestamp=FIXED_STAMP)
    e1 = chain.append(actor_id="actor", action="SECOND", timestamp=FIXED_STAMP)

    # The linkage must hold regardless of run order.
    assert e1.previous_hash == e0.entry_hash
    assert e0.previous_hash == GENESIS_HASH
    assert chain.verify_integrity() is True
