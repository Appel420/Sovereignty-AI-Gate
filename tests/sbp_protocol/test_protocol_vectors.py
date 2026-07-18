"""SBP v0.2 offline protocol conformance runners."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sovereignty_core.identity.root_of_trust import SoftwareTrustBackend
from sbp.audit import AuditChain
from sbp.branch import Branch, BranchCapability
from sbp.object import ObjectManifest, seal_manifest
from sbp.protocol import (
    AuthorityExchange,
    CapabilityOffer,
    ProtocolError,
    ReplicationRecord,
    create_authority_exchange,
    create_delegation,
    negotiate_capabilities,
    resolve_replication_conflict,
    verify_authority_exchange,
    verify_delegation,
)
from sbp.root import RootAuthority

ROOT_SECRET = b"\x11" * 32
ROOT_SECRET_OTHER = b"\x22" * 32
VECTORS = Path(__file__).parent / "vectors"


def vector(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def root(secret: bytes = ROOT_SECRET) -> RootAuthority:
    return RootAuthority(SoftwareTrustBackend(secret), created_at=1_700_000_000)


def branch(authority: RootAuthority) -> Branch:
    return Branch(
        authority,
        label="protocol-main",
        capabilities=[BranchCapability.READ, BranchCapability.WRITE, BranchCapability.DELEGATE],
        created_at=1_700_000_001,
    )


def test_vector_inventory_is_closed() -> None:
    expected = {
        "capability_negotiation.json",
        "authority_exchange.json",
        "delegation.json",
        "branch_creation.json",
        "audit_event.json",
        "replication.json",
    }
    assert {path.name for path in VECTORS.glob("*.json")} == expected


def test_capability_negotiation_vector() -> None:
    data = vector("capability_negotiation.json")
    local = CapabilityOffer(**data["local"])
    remote = CapabilityOffer(**data["remote"])
    assert negotiate_capabilities(local, remote) == tuple(data["expected"]["intersection"])


def test_capability_negotiation_rejects_duplicates_and_version_mismatch() -> None:
    data = vector("capability_negotiation.json")
    with pytest.raises(ProtocolError):
        CapabilityOffer(**{**data["local"], "capabilities": ["audit", "audit"]})
    with pytest.raises(ProtocolError):
        negotiate_capabilities(
            CapabilityOffer(**data["local"]),
            CapabilityOffer(**{**data["remote"], "version": "9.0.0"}),
        )


def test_authority_exchange_vector_is_signed_and_canonical() -> None:
    data = vector("authority_exchange.json")
    authority = root()
    record = create_authority_exchange(
        authority,
        exchange_id=data["inputs"]["exchange_id"],
        peer_id=data["inputs"]["peer_id"],
        capabilities=data["inputs"]["capabilities"],
    )
    assert record.to_dict()["root_id"] == authority.metadata.root_id
    assert verify_authority_exchange(record)
    assert record.to_dict()["signature"] != data["expected"]["tampered_signature"]
    tampered = AuthorityExchange(**{**record.to_dict(), "peer_id": "peer:tampered"})
    assert not verify_authority_exchange(tampered)


def test_delegation_vector_enforces_scope_and_expiry() -> None:
    data = vector("delegation.json")
    authority = root()
    record = create_delegation(
        authority,
        delegation_id=data["inputs"]["delegation_id"],
        grantee_id=data["inputs"]["grantee_id"],
        branch_id=data["inputs"]["branch_id"],
        capabilities=data["inputs"]["capabilities"],
        parent_capabilities=data["inputs"]["parent_capabilities"],
        expires_at=data["inputs"]["expires_at"],
    )
    assert verify_delegation(record, authority, required_capability="READ", now=100)
    assert not verify_delegation(record, authority, required_capability="ADMIN", now=100)
    assert not verify_delegation(record, authority, required_capability="READ", now=201)
    with pytest.raises(ProtocolError):
        create_delegation(
            authority,
            delegation_id="out-of-scope",
            grantee_id="peer:b",
            branch_id="branch:a",
            capabilities=["ADMIN"],
            parent_capabilities=["READ"],
        )


def test_branch_creation_vector_preserves_lineage() -> None:
    data = vector("branch_creation.json")
    authority = root()
    parent = Branch(
        authority,
        label=data["parent"]["label"],
        capabilities=data["parent"]["capabilities"],
        created_at=data["parent"]["created_at"],
    )
    child = Branch(
        authority,
        label=data["child"]["label"],
        capabilities=data["child"]["capabilities"],
        parent_branch_id=parent.metadata.branch_id,
        created_at=data["child"]["created_at"],
    )
    assert child.metadata.parent_branch_id == parent.metadata.branch_id
    assert child.metadata.branch_id != parent.metadata.branch_id
    assert child.metadata.root_id == authority.metadata.root_id


def test_audit_event_vector_is_signed_and_linked() -> None:
    data = vector("audit_event.json")
    authority = root()
    chain = AuditChain(branch_id=data["inputs"]["branch_id"], root=authority)
    first = chain.append(**data["inputs"]["first"])
    second = chain.append(**data["inputs"]["second"])
    assert first.previous_hash == "0" * 128
    assert second.previous_hash == first.entry_hash
    assert chain.verify_integrity()
    chain._entries[1] = type(second)(**{**second.to_dict(), "action": "TAMPERED"})
    assert not chain.verify_integrity()


def test_replication_vector_is_encrypted_and_conflict_resolution_is_stable() -> None:
    data = vector("replication.json")
    authority = root()
    b = branch(authority)
    manifest = ObjectManifest.create(
        branch=b,
        content_hash=data["inputs"]["content_hash"],
        created_at=data["inputs"]["created_at"],
    )
    envelope = seal_manifest(manifest, b, nonce=bytes.fromhex(data["inputs"]["nonce_hex"]))
    left = ReplicationRecord.from_envelope(
        envelope, source_root_id=authority.metadata.root_id, replica_id="replica:a"
    )
    right = ReplicationRecord.from_envelope(
        envelope, source_root_id=authority.metadata.root_id, replica_id="replica:b"
    )
    assert "ciphertext_hex" in left.envelope
    assert "signing_public_key" not in left.to_dict()
    assert resolve_replication_conflict(left, right).replica_id == "replica:a"
    with pytest.raises(ProtocolError):
        resolve_replication_conflict(left, ReplicationRecord(
            object_id="different", branch_id=left.branch_id, envelope=left.envelope,
            source_root_id=left.source_root_id, replica_id="replica:c",
        ))


def test_replication_does_not_transfer_authority() -> None:
    authority = root()
    other = root(ROOT_SECRET_OTHER)
    b = branch(authority)
    manifest = ObjectManifest.create(branch=b, content_hash="a" * 128, created_at=1_700_000_001)
    record = ReplicationRecord.from_envelope(
        seal_manifest(manifest, b, nonce=b"\x01" * 12),
        source_root_id=authority.metadata.root_id,
        replica_id="replica:offline",
    )
    assert record.source_root_id == authority.metadata.root_id
    assert record.source_root_id != other.metadata.root_id
