from __future__ import annotations

import json
from pathlib import Path

import pytest

from sovereignty_core.identity.root_of_trust import SoftwareTrustBackend
from sia.utils.canonical import canonical_bytes, canonical_json
from sbp.audit import AuditChain, AuditEntry
from sbp.branch import Branch
from sbp.codec import decode_branch, decode_root, encode_branch, encode_root, CodecError
from sbp.object import ObjectEnvelope, ObjectManifest, seal_manifest, unseal_manifest
from sbp.root import RootAuthority


REPO_ROOT = Path(__file__).resolve().parents[2]
VECTORS_ROOT = REPO_ROOT / "vectors"
FIXTURE_PATHS = [
    "root/creation.json",
    "root/signing.json",
    "root/policy_hash.json",
    "branch/derivation.json",
    "branch/lineage.json",
    "branch/isolation.json",
    "object/manifest.json",
    "object/seal.json",
    "object/unseal.json",
    "object/failure_cases.json",
    "audit/genesis.json",
    "audit/append.json",
    "audit/verification.json",
    "codec/canonical.json",
    "codec/invalid_schema.json",
]


def _fixture(path: str) -> dict:
    return json.loads((VECTORS_ROOT / path).read_text(encoding="utf-8"))


def _make_root(secret_hex: str, *, created_at: int, policy: dict | None = None) -> RootAuthority:
    return RootAuthority(
        SoftwareTrustBackend(bytes.fromhex(secret_hex)),
        created_at=created_at,
        policy=policy,
    )


def _make_branch(root: RootAuthority, data: dict, *, parent_branch_id: str | None = None) -> Branch:
    return Branch(
        root,
        label=data["label"],
        capabilities=data["capabilities"],
        parent_branch_id=parent_branch_id if parent_branch_id is not None else data.get("parent_branch_id"),
        created_at=data["created_at"],
        policy=data.get("policy"),
    )


def _manifest_from_dict(data: dict) -> ObjectManifest:
    return ObjectManifest(
        version=data["version"],
        object_id=data["object_id"],
        branch_id=data["branch_id"],
        content_hash=data["content_hash"],
        owner_id=data["owner_id"],
        encryption_algorithm=data["encryption_algorithm"],
        created_at=data["created_at"],
        metadata=data["metadata"],
    )


def _envelope_from_dict(data: dict) -> ObjectEnvelope:
    return ObjectEnvelope(
        version=data["version"],
        object_id=data["object_id"],
        branch_id=data["branch_id"],
        nonce_hex=data["nonce_hex"],
        ciphertext_hex=data["ciphertext_hex"],
        encryption_algorithm=data["encryption_algorithm"],
        created_at=data["created_at"],
    )


def _entry_from_dict(data: dict) -> AuditEntry:
    return AuditEntry(
        sequence=data["sequence"],
        entry_id=data["entry_id"],
        timestamp=data["timestamp"],
        branch_id=data["branch_id"],
        actor_id=data["actor_id"],
        action=data["action"],
        object_id=data["object_id"],
        metadata_hash=data["metadata_hash"],
        previous_hash=data["previous_hash"],
        signature=data["signature"],
        entry_hash=data["entry_hash"],
    )


def test_fixture_inventory_is_exact():
    assert sorted(path.relative_to(VECTORS_ROOT).as_posix() for path in VECTORS_ROOT.rglob("*.json")) == sorted(FIXTURE_PATHS)


def test_root_creation_vector():
    vector = _fixture("root/creation.json")
    root = _make_root(
        vector["inputs"]["root_secret_hex"],
        created_at=vector["inputs"]["created_at"],
        policy=vector["inputs"]["policy"],
    )

    assert encode_root(root.metadata) == vector["expected"]["metadata"]
    assert canonical_json(encode_root(root.metadata)) == vector["expected"]["canonical_json"]
    assert canonical_bytes(encode_root(root.metadata)).hex() == vector["expected"]["canonical_bytes_hex"]
    assert decode_root(vector["expected"]["metadata"]) == root.metadata


def test_root_signing_vector():
    vector = _fixture("root/signing.json")
    root = _make_root(vector["inputs"]["root_secret_hex"], created_at=vector["inputs"]["created_at"])
    wrong_root = _make_root(vector["inputs"]["wrong_root_secret_hex"], created_at=vector["inputs"]["created_at"])
    payload = vector["inputs"]["payload_utf8"].encode("utf-8")
    tampered = vector["inputs"]["tampered_payload_utf8"].encode("utf-8")

    signature = root.sign(payload)

    assert signature == vector["expected"]["signature_hex"]
    assert root.verify(payload, signature) is vector["expected"]["verify_ok"]
    assert root.verify(tampered, signature) is vector["expected"]["verify_tampered_ok"]
    assert wrong_root.verify(payload, signature) is vector["expected"]["verify_wrong_root_ok"]


def test_root_policy_hash_vector():
    vector = _fixture("root/policy_hash.json")
    default_root = _make_root(
        vector["inputs"]["root_secret_hex"],
        created_at=vector["inputs"]["created_at"],
        policy=vector["inputs"]["default_policy"],
    )
    custom_root = _make_root(
        vector["inputs"]["root_secret_hex"],
        created_at=vector["inputs"]["created_at"],
        policy=vector["inputs"]["custom_policy"],
    )

    assert default_root.metadata.policy_hash == vector["expected"]["default_policy_hash"]
    assert custom_root.metadata.policy_hash == vector["expected"]["custom_policy_hash"]
    assert (default_root.metadata.policy_hash != custom_root.metadata.policy_hash) is vector["expected"]["hashes_differ"]


def test_branch_derivation_vector():
    vector = _fixture("branch/derivation.json")
    root = _make_root(vector["inputs"]["root_secret_hex"], created_at=vector["inputs"]["root_created_at"])
    branch = _make_branch(root, vector["inputs"])

    assert encode_branch(branch.metadata) == vector["expected"]["metadata"]
    assert branch.derive_key().hex() == vector["expected"]["derived_key_hex"]
    assert canonical_json(encode_branch(branch.metadata)) == vector["expected"]["canonical_json"]
    assert canonical_bytes(encode_branch(branch.metadata)).hex() == vector["expected"]["canonical_bytes_hex"]
    assert decode_branch(vector["expected"]["metadata"]) == branch.metadata


def test_branch_lineage_vector():
    vector = _fixture("branch/lineage.json")
    root = _make_root(vector["inputs"]["root_secret_hex"], created_at=vector["inputs"]["root_created_at"])
    parent = _make_branch(root, vector["inputs"]["parent"])
    child = _make_branch(root, vector["inputs"]["child"], parent_branch_id=parent.metadata.branch_id)

    assert encode_branch(parent.metadata) == vector["expected"]["parent_metadata"]
    assert encode_branch(child.metadata) == vector["expected"]["child_metadata"]
    assert child.metadata.parent_branch_id == parent.metadata.branch_id
    assert parent.derive_key().hex() == vector["expected"]["parent_key_hex"]
    assert child.derive_key().hex() == vector["expected"]["child_key_hex"]
    assert child.metadata.branch_id != parent.metadata.branch_id


def test_branch_isolation_vector():
    vector = _fixture("branch/isolation.json")
    root_a = _make_root(vector["inputs"]["root_a_secret_hex"], created_at=vector["inputs"]["root_created_at"])
    root_b = _make_root(vector["inputs"]["root_b_secret_hex"], created_at=vector["inputs"]["root_created_at"])
    sibling_a = _make_branch(root_a, vector["inputs"]["sibling_a"])
    sibling_b = _make_branch(root_a, vector["inputs"]["sibling_b"])
    other_root = _make_branch(root_b, vector["inputs"]["other_root_same_label"])

    assert sibling_a.metadata.branch_id == vector["expected"]["sibling_a_branch_id"]
    assert sibling_b.metadata.branch_id == vector["expected"]["sibling_b_branch_id"]
    assert other_root.metadata.branch_id == vector["expected"]["other_root_branch_id"]
    assert sibling_a.derive_key().hex() == vector["expected"]["sibling_a_key_hex"]
    assert sibling_b.derive_key().hex() == vector["expected"]["sibling_b_key_hex"]
    assert other_root.derive_key().hex() == vector["expected"]["other_root_key_hex"]
    assert sibling_a.derive_key() != sibling_b.derive_key()
    assert sibling_a.derive_key() != other_root.derive_key()


def test_object_manifest_vector():
    vector = _fixture("object/manifest.json")
    root = _make_root(vector["inputs"]["root_secret_hex"], created_at=vector["inputs"]["root_created_at"])
    branch = _make_branch(root, vector["inputs"]["branch"])
    manifest = ObjectManifest.create(
        branch=branch,
        content_hash=vector["inputs"]["content_hash"],
        metadata=vector["inputs"]["metadata"],
        created_at=vector["inputs"]["created_at"],
    )

    assert manifest.to_dict() == vector["expected"]["manifest"]
    assert branch.derive_key().hex() == vector["expected"]["branch_key_hex"]
    assert canonical_json(manifest.to_dict()) == vector["expected"]["canonical_json"]
    assert canonical_bytes(manifest.to_dict()).hex() == vector["expected"]["canonical_bytes_hex"]


def test_object_seal_and_unseal_vectors():
    seal_vector = _fixture("object/seal.json")
    unseal_vector = _fixture("object/unseal.json")
    root = _make_root(seal_vector["inputs"]["root_secret_hex"], created_at=seal_vector["inputs"]["root_created_at"])
    branch = _make_branch(root, seal_vector["inputs"]["branch"])
    manifest = _manifest_from_dict(seal_vector["inputs"]["manifest"])

    envelope = seal_manifest(
        manifest,
        branch,
        nonce=bytes.fromhex(seal_vector["inputs"]["fixed_nonce_hex"]),
    )

    assert envelope.to_dict() == seal_vector["expected"]["envelope"]
    recovered = unseal_manifest(_envelope_from_dict(unseal_vector["inputs"]["envelope"]), branch)
    assert canonical_json(recovered.to_dict()) == canonical_json(unseal_vector["expected"]["manifest"])
    assert recovered.object_id == unseal_vector["expected"]["manifest"]["object_id"]
    assert recovered.branch_id == unseal_vector["expected"]["manifest"]["branch_id"]


def test_object_failure_vectors():
    vector = _fixture("object/failure_cases.json")
    root = _make_root(vector["inputs"]["root_secret_hex"], created_at=vector["inputs"]["root_created_at"])
    correct_branch = _make_branch(root, vector["inputs"]["correct_branch"])
    wrong_branch = _make_branch(root, vector["inputs"]["wrong_branch"])
    valid_envelope = _envelope_from_dict(vector["inputs"]["valid_envelope"])
    tampered_envelope = _envelope_from_dict(vector["inputs"]["tampered_envelope"])

    with pytest.raises(ValueError, match=vector["expected"]["wrong_branch_error_contains"]):
        unseal_manifest(valid_envelope, wrong_branch)
    with pytest.raises(ValueError, match=vector["expected"]["tamper_error_contains"]):
        unseal_manifest(tampered_envelope, correct_branch)


def test_audit_genesis_vector():
    vector = _fixture("audit/genesis.json")
    root = _make_root(vector["inputs"]["root_secret_hex"], created_at=vector["inputs"]["root_created_at"])
    chain = AuditChain(branch_id=vector["inputs"]["branch_id"], root=root)

    entry = chain.append(
        actor_id=vector["inputs"]["actor_id"],
        action=vector["inputs"]["action"],
        timestamp=vector["inputs"]["timestamp"],
        entry_id=vector["inputs"]["entry_id"],
    )

    assert entry.to_dict() == vector["expected"]["entry"]
    assert chain.export_bundle() == vector["expected"]["bundle"]
    assert chain.verify_integrity() is True


def test_audit_append_vector():
    vector = _fixture("audit/append.json")
    root = _make_root(vector["inputs"]["root_secret_hex"], created_at=vector["inputs"]["root_created_at"])
    chain = AuditChain(branch_id=vector["inputs"]["branch_id"], root=root)

    for item in vector["inputs"]["entries"]:
        chain.append(
            actor_id=item["actor_id"],
            action=item["action"],
            object_id=item["object_id"],
            metadata=item["metadata"],
            timestamp=item["timestamp"],
            entry_id=item["entry_id"],
        )

    assert [entry.to_dict() for entry in chain.entries] == vector["expected"]["entries"]
    assert chain.export_bundle() == vector["expected"]["bundle"]
    assert chain.verify_integrity() is True


def test_audit_verification_vector():
    vector = _fixture("audit/verification.json")
    root = _make_root(vector["inputs"]["root_secret_hex"], created_at=vector["inputs"]["root_created_at"])
    valid_chain = AuditChain(branch_id=vector["inputs"]["branch_id"], root=root)
    valid_chain._entries = [_entry_from_dict(entry) for entry in vector["inputs"]["entries"]]
    assert valid_chain.verify_integrity() is vector["expected"]["verify_ok"]

    tampered_action_chain = AuditChain(branch_id=vector["inputs"]["branch_id"], root=root)
    tampered_action_chain._entries = [
        _entry_from_dict(vector["inputs"]["tampered_action_entry"]),
        _entry_from_dict(vector["inputs"]["entries"][1]),
    ]
    assert tampered_action_chain.verify_integrity() is vector["expected"]["verify_tampered_action_ok"]

    tampered_link_chain = AuditChain(branch_id=vector["inputs"]["branch_id"], root=root)
    tampered_link_chain._entries = [
        _entry_from_dict(vector["inputs"]["entries"][0]),
        _entry_from_dict(vector["inputs"]["tampered_link_entry"]),
    ]
    assert tampered_link_chain.verify_integrity() is vector["expected"]["verify_tampered_link_ok"]


def test_codec_canonical_vector():
    vector = _fixture("codec/canonical.json")

    assert canonical_json(vector["inputs"]["canonical_payload"]) == vector["expected"]["canonical_payload_json"]
    assert canonical_bytes(vector["inputs"]["canonical_payload"]).hex() == vector["expected"]["canonical_payload_bytes_hex"]
    assert "café" in vector["expected"]["canonical_payload_json"]
    assert canonical_json(vector["inputs"]["root_metadata"]) == vector["expected"]["root_canonical_json"]
    assert canonical_bytes(vector["inputs"]["root_metadata"]).hex() == vector["expected"]["root_canonical_bytes_hex"]
    assert canonical_json(vector["inputs"]["branch_metadata"]) == vector["expected"]["branch_canonical_json"]
    assert canonical_bytes(vector["inputs"]["branch_metadata"]).hex() == vector["expected"]["branch_canonical_bytes_hex"]


def test_codec_invalid_schema_vector():
    vector = _fixture("codec/invalid_schema.json")

    with pytest.raises(CodecError) as root_error:
        decode_root(vector["inputs"]["root_with_unknown_field"])
    assert vector["expected"]["root_error_contains"] in str(root_error.value)
    with pytest.raises(CodecError) as branch_error:
        decode_branch(vector["inputs"]["branch_missing_required_field"])
    assert vector["expected"]["branch_error_contains"] in str(branch_error.value)
