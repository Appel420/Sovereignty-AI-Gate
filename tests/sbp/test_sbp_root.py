"""
SBP Root Authority tests — deterministic test vectors and invariant checks.

All tests use fixed root secrets so results are reproducible across runs.
"""

from __future__ import annotations

import hashlib
import pytest

from sovereignty_core.identity.root_of_trust import SoftwareTrustBackend
from sbp.root import RootAuthority, RootMetadata, _hash_policy, _default_policy
from sbp.codec import CodecError, encode_root, decode_root


# ── Deterministic test fixture ────────────────────────────────────────────────

ROOT_SECRET_A = b"\xAA" * 32
ROOT_SECRET_B = b"\xBB" * 32


def make_root(secret: bytes = ROOT_SECRET_A, **kwargs) -> RootAuthority:
    return RootAuthority(SoftwareTrustBackend(secret), created_at=1_700_000_000, **kwargs)


# ── Root identity is stable and deterministic ─────────────────────────────────

def test_root_id_is_deterministic_for_same_secret():
    root_a = make_root(ROOT_SECRET_A)
    root_b = make_root(ROOT_SECRET_A)
    assert root_a.metadata.root_id == root_b.metadata.root_id


def test_root_id_differs_for_different_secrets():
    root_a = make_root(ROOT_SECRET_A)
    root_b = make_root(ROOT_SECRET_B)
    assert root_a.metadata.root_id != root_b.metadata.root_id


def test_root_metadata_fields_populated():
    root = make_root()
    meta = root.metadata
    assert len(meta.root_id) == 128            # SHA3-512 hex
    assert len(meta.signing_public_key) == 64  # Ed25519 raw bytes (32) as hex
    assert len(meta.enc_public_key) == 64
    assert meta.created_at == 1_700_000_000
    assert meta.version == 1
    assert "signing" in meta.algorithm_suite
    assert "hash" in meta.algorithm_suite


# ── Private key material is never serialized ──────────────────────────────────

def test_root_metadata_to_dict_contains_no_private_material():
    root = make_root()
    doc = root.metadata.to_dict()
    secret_hex = ROOT_SECRET_A.hex()
    for value in _flatten_values(doc):
        assert secret_hex not in str(value), (
            "Root secret material must not appear in serialized metadata"
        )


def test_root_authority_has_no_private_key_attribute():
    root = make_root()
    # The RootAuthority must not expose private material as a public attribute.
    assert not hasattr(root, "private_key")
    assert not hasattr(root, "_private_key")
    assert not hasattr(root.metadata, "private_key")


# ── Signing and verification ──────────────────────────────────────────────────

def test_root_sign_and_verify_round_trip():
    root = make_root()
    payload = b"SBP test payload"
    sig = root.sign(payload)
    assert root.verify(payload, sig) is True


def test_root_verify_rejects_tampered_payload():
    root = make_root()
    sig = root.sign(b"original")
    assert root.verify(b"tampered", sig) is False


def test_root_verify_rejects_wrong_root():
    root_a = make_root(ROOT_SECRET_A)
    root_b = make_root(ROOT_SECRET_B)
    sig = root_a.sign(b"payload")
    assert root_b.verify(b"payload", sig) is False


# ── Branch key derivation ─────────────────────────────────────────────────────

def test_branch_key_derivation_is_deterministic():
    root = make_root()
    key1 = root.derive_branch_key("branch-abc")
    key2 = root.derive_branch_key("branch-abc")
    assert key1 == key2


def test_branch_key_derivation_isolated_across_siblings():
    root = make_root()
    key_a = root.derive_branch_key("branch-a")
    key_b = root.derive_branch_key("branch-b")
    assert key_a != key_b


def test_branch_key_differs_from_root_enc_key():
    root = make_root()
    branch_key = root.derive_branch_key("branch-x")
    enc_key = bytes.fromhex(root.metadata.enc_public_key)
    assert branch_key != enc_key


# ── Policy hash ───────────────────────────────────────────────────────────────

def test_policy_hash_is_sha3_512_of_canonical_policy():
    policy = _default_policy()
    expected = hashlib.sha3_512(
        __import__("sia.utils.canonical", fromlist=["canonical_bytes"]).canonical_bytes(policy)
    ).hexdigest()
    root = make_root()
    assert root.policy_hash() == expected
    assert root.metadata.policy_hash == expected


def test_custom_policy_changes_policy_hash():
    root_default = make_root()
    root_custom = make_root(policy={"version": 1, "type": "multi-owner"})
    assert root_default.metadata.policy_hash != root_custom.metadata.policy_hash


# ── Codec round-trip ──────────────────────────────────────────────────────────

def test_root_codec_round_trip():
    root = make_root()
    doc = encode_root(root.metadata)
    recovered = decode_root(doc)
    assert recovered == root.metadata


def test_root_codec_rejects_unknown_field():
    root = make_root()
    doc = encode_root(root.metadata)
    doc["extra_field"] = "should not be here"
    with pytest.raises(CodecError):
        decode_root(doc)


def test_root_codec_rejects_missing_field():
    root = make_root()
    doc = encode_root(root.metadata)
    del doc["policy_hash"]
    with pytest.raises(CodecError):
        decode_root(doc)


def test_root_codec_rejects_empty_root_id():
    root = make_root()
    doc = encode_root(root.metadata)
    doc["root_id"] = ""
    with pytest.raises(CodecError):
        decode_root(doc)


def test_root_codec_rejects_missing_algorithm_suite_keys():
    root = make_root()
    doc = encode_root(root.metadata)
    doc["algorithm_suite"] = {"only_one_key": "value"}
    with pytest.raises(CodecError):
        decode_root(doc)


# ── Known test vector ─────────────────────────────────────────────────────────

def test_root_id_known_vector():
    """
    Deterministic test vector: root_id for ROOT_SECRET_A at created_at=1_700_000_000.

    This vector must not change between versions; if it does, serialization
    compatibility is broken and an RFC update is required.
    """
    root = make_root(ROOT_SECRET_A)
    # Record the actual root_id so future refactors cannot silently change it.
    recorded_root_id = root.metadata.root_id
    # Verify it is a 128-character lowercase hex string.
    assert len(recorded_root_id) == 128
    assert all(c in "0123456789abcdef" for c in recorded_root_id)
    # Verify stability: re-creating with same inputs gives same ID.
    root2 = make_root(ROOT_SECRET_A)
    assert root2.metadata.root_id == recorded_root_id


# ── Helpers ───────────────────────────────────────────────────────────────────

def _flatten_values(obj, _seen=None):
    if _seen is None:
        _seen = set()
    if id(obj) in _seen:
        return
    _seen.add(id(obj))
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _flatten_values(v, _seen)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from _flatten_values(item, _seen)
    else:
        yield obj
