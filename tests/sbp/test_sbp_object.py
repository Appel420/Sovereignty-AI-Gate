"""
SBP Object manifest and envelope tests.
"""

from __future__ import annotations

import hashlib
import pytest

from sovereignty_core.identity.root_of_trust import SoftwareTrustBackend
from sbp.root import RootAuthority
from sbp.branch import Branch, BranchCapability
from sbp.object import ObjectManifest, ObjectEnvelope, seal_manifest, unseal_manifest


ROOT_SECRET = b"\xCC" * 32
FIXED_TS = 1_700_000_001


def make_root() -> RootAuthority:
    return RootAuthority(SoftwareTrustBackend(ROOT_SECRET), created_at=FIXED_TS)


def make_branch(root: RootAuthority | None = None) -> Branch:
    root = root or make_root()
    return Branch(
        root,
        label="object-branch",
        capabilities=[BranchCapability.ISSUE_OBJECT, BranchCapability.READ],
        created_at=FIXED_TS,
    )


CONTENT = b"hello sovereign object"
CONTENT_HASH = hashlib.sha3_512(CONTENT).hexdigest()


# ── ObjectManifest creation ───────────────────────────────────────────────────

def test_manifest_object_id_is_deterministic():
    branch = make_branch()
    m1 = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    m2 = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    assert m1.object_id == m2.object_id


def test_manifest_object_id_changes_with_content_hash():
    branch = make_branch()
    m1 = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    other_hash = hashlib.sha3_512(b"other content").hexdigest()
    m2 = ObjectManifest.create(branch=branch, content_hash=other_hash, created_at=FIXED_TS)
    assert m1.object_id != m2.object_id


def test_manifest_branch_id_matches_branch():
    branch = make_branch()
    manifest = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    assert manifest.branch_id == branch.metadata.branch_id


def test_manifest_owner_id_matches_branch_owner():
    branch = make_branch()
    manifest = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    assert manifest.owner_id == branch.metadata.owner_id


def test_manifest_encryption_algorithm_is_aes_256_gcm():
    branch = make_branch()
    manifest = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    assert manifest.encryption_algorithm == "AES-256-GCM"


def test_manifest_object_id_is_128_hex_chars():
    branch = make_branch()
    manifest = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    assert len(manifest.object_id) == 128
    assert all(c in "0123456789abcdef" for c in manifest.object_id)


def test_manifest_to_dict_round_trip():
    branch = make_branch()
    manifest = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    doc = manifest.to_dict()
    assert doc["object_id"] == manifest.object_id
    assert doc["branch_id"] == manifest.branch_id
    assert doc["content_hash"] == manifest.content_hash
    assert doc["owner_id"] == manifest.owner_id
    assert doc["encryption_algorithm"] == "AES-256-GCM"


# ── ObjectEnvelope seal / unseal ──────────────────────────────────────────────

def test_seal_and_unseal_round_trip():
    branch = make_branch()
    manifest = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    envelope = seal_manifest(manifest, branch)
    recovered = unseal_manifest(envelope, branch)
    assert recovered == manifest


def test_envelope_object_id_matches_manifest():
    branch = make_branch()
    manifest = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    envelope = seal_manifest(manifest, branch)
    assert envelope.object_id == manifest.object_id


def test_envelope_branch_id_matches_manifest():
    branch = make_branch()
    manifest = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    envelope = seal_manifest(manifest, branch)
    assert envelope.branch_id == manifest.branch_id


def test_envelope_nonce_is_unique_per_seal():
    branch = make_branch()
    manifest = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    env1 = seal_manifest(manifest, branch)
    env2 = seal_manifest(manifest, branch)
    assert env1.nonce_hex != env2.nonce_hex, "Each seal must use a fresh nonce"


def test_unseal_fails_with_wrong_branch():
    root = make_root()
    branch_a = Branch(root, label="branch-a", capabilities=[BranchCapability.ISSUE_OBJECT], created_at=FIXED_TS)
    branch_b = Branch(root, label="branch-b", capabilities=[BranchCapability.ISSUE_OBJECT], created_at=FIXED_TS)
    manifest = ObjectManifest.create(branch=branch_a, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    envelope = seal_manifest(manifest, branch_a)
    with pytest.raises(ValueError, match="decryption failed"):
        unseal_manifest(envelope, branch_b)


def test_unseal_fails_with_tampered_ciphertext():
    branch = make_branch()
    manifest = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    envelope = seal_manifest(manifest, branch)
    # Flip a byte in the ciphertext hex.
    ct = bytearray(bytes.fromhex(envelope.ciphertext_hex))
    ct[0] ^= 0xFF
    tampered = ObjectEnvelope(
        object_id=envelope.object_id,
        branch_id=envelope.branch_id,
        nonce_hex=envelope.nonce_hex,
        ciphertext_hex=ct.hex(),
        encryption_algorithm=envelope.encryption_algorithm,
        created_at=envelope.created_at,
    )
    with pytest.raises(ValueError, match="decryption failed"):
        unseal_manifest(tampered, branch)


def test_envelope_to_dict_contains_no_plaintext_content_hash():
    """The envelope dict must not contain the plaintext content hash."""
    branch = make_branch()
    manifest = ObjectManifest.create(branch=branch, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    envelope = seal_manifest(manifest, branch)
    doc = envelope.to_dict()
    assert CONTENT_HASH not in str(doc)


# ── Cross-branch object isolation ─────────────────────────────────────────────

def test_objects_in_different_branches_have_different_ids():
    root = make_root()
    branch_a = Branch(root, label="branch-a", capabilities=[BranchCapability.ISSUE_OBJECT], created_at=FIXED_TS)
    branch_b = Branch(root, label="branch-b", capabilities=[BranchCapability.ISSUE_OBJECT], created_at=FIXED_TS)
    m_a = ObjectManifest.create(branch=branch_a, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    m_b = ObjectManifest.create(branch=branch_b, content_hash=CONTENT_HASH, created_at=FIXED_TS)
    assert m_a.object_id != m_b.object_id
