"""Tests for the device-signed sovereign SCAR audit ledger."""

from __future__ import annotations

from dataclasses import replace

import pytest

from sovereignty_core.audit.ledger import (
    GENESIS_EVENT_HASH,
    SCARActor,
    SCARLedger,
    SCARLedgerError,
    assert_scar_invariants,
)
from sovereignty_core.audit.merkle import verify_merkle_proof
from sovereignty_core.identity.root_of_trust import RootOfTrust, SoftwareTrustBackend
from sovereignty_core.permissions.capability import CapabilityScope, CapabilityToken
from sovereignty_core.vault.memory_chain import (
    MemoryChain,
    MemoryClassification,
    MemoryProvenance,
)


def _trust() -> RootOfTrust:
    return RootOfTrust(SoftwareTrustBackend(b"\x05" * 32))


def _ledger() -> SCARLedger:
    return SCARLedger(identity_id="human-1", root_of_trust=_trust())


def _token() -> CapabilityToken:
    return CapabilityToken.create(
        provider_id="provider:copilot",
        owner_identity="human-1",
        scopes=[CapabilityScope.READ_CONTEXT_WINDOW],
        issuer_device="device-1",
        signature="capability-signature",
        ttl_seconds=60,
    )


def test_append_event_is_device_signed_and_chained():
    ledger = _ledger()
    first = ledger.append_event("IDENTITY_CREATED", actor=SCARActor.HUMAN)
    second = ledger.append_event("DEVICE_BOUND", actor=SCARActor.DEVICE)

    assert first.previous_event_hash == GENESIS_EVENT_HASH
    assert second.previous_event_hash == first.event_hash
    assert first.sequence == 0
    assert second.sequence == 1
    assert first.signature
    assert ledger.verify_integrity() is True


def test_integrity_detects_tampered_event_metadata():
    ledger = _ledger()
    event = ledger.append_event("MEMORY_CHANGE", actor=SCARActor.HUMAN)
    ledger._events[0] = replace(event, metadata={"injected": True})

    assert ledger.verify_integrity() is False


def test_integrity_detects_broken_event_chain():
    ledger = _ledger()
    ledger.append_event("FIRST", actor=SCARActor.HUMAN)
    second = ledger.append_event("SECOND", actor=SCARActor.HUMAN)
    ledger._events[1] = replace(second, previous_event_hash="f" * 64)

    assert ledger.verify_integrity() is False


def test_record_memory_change_references_block_hash_without_plaintext():
    ledger = _ledger()
    chain = MemoryChain()
    block = chain.append(
        classification=MemoryClassification.USER_CONFIRMED,
        content={"sensitive": "never export this"},
        provenance=MemoryProvenance(
            owner_identity="human-1",
            source_type="human",
            source_id="human-1",
        ),
    )

    event = ledger.record_memory_change(block)

    assert event.actor is SCARActor.HUMAN
    assert event.memory_hash == block.block_hash
    assert "sensitive" not in event.metadata
    assert ledger.verify_integrity() is True


def test_record_memory_change_rejects_other_identity():
    ledger = _ledger()
    block = MemoryChain().append(
        classification=MemoryClassification.USER_CONFIRMED,
        content="irrelevant",
        provenance=MemoryProvenance(
            owner_identity="human-2",
            source_type="human",
            source_id="human-2",
        ),
    )

    with pytest.raises(SCARLedgerError, match="identity"):
        ledger.record_memory_change(block)


def test_record_capability_issue_references_token_without_signature():
    ledger = _ledger()
    token = _token()

    event = ledger.record_capability_issue(token)

    assert event.capability_id == token.token_id
    assert event.actor is SCARActor.HUMAN
    assert event.metadata["provider_id"] == token.provider_id
    assert "signature" not in event.metadata


def test_provider_access_requires_active_capability():
    ledger = _ledger()
    token = _token()
    token.revoke(revoked_at=1)

    with pytest.raises(SCARLedgerError, match="active capability"):
        ledger.record_provider_access(token)


def test_provider_events_require_capability_provenance():
    with pytest.raises(SCARLedgerError, match="capability provenance"):
        _ledger().append_event("PROVIDER_EVENT", actor=SCARActor.PROVIDER)


def test_provider_access_carries_capability_and_memory_hash():
    ledger = _ledger()
    token = _token()

    event = ledger.record_provider_access(token, memory_hash="a" * 64)

    assert event.actor is SCARActor.PROVIDER
    assert event.capability_id == token.token_id
    assert event.memory_hash == "a" * 64


def test_merkle_attestation_binds_current_identity_device_and_root():
    ledger = _ledger()
    ledger.append_event("MEMORY_CHANGE", actor=SCARActor.HUMAN)
    ledger.append_event("CAPABILITY_ISSUED", actor=SCARActor.HUMAN)

    attestation = ledger.attest_merkle_root(created_at="2026-07-14T00:00:00Z")

    assert attestation.root_hash == ledger.get_merkle_root().root
    assert attestation.entry_count == 2
    assert attestation.version == 1
    assert attestation.signature_algorithm == "Ed25519"
    assert attestation.identity_id == "human-1"
    assert attestation.device_id == ledger.device_id
    assert ledger.verify_attestation(attestation) is True


def test_attestation_rejected_after_log_changes():
    ledger = _ledger()
    ledger.append_event("FIRST", actor=SCARActor.HUMAN)
    attestation = ledger.attest_merkle_root()
    ledger.append_event("SECOND", actor=SCARActor.HUMAN)

    assert ledger.verify_attestation(attestation) is False


def test_attestation_rejects_tampered_signature():
    ledger = _ledger()
    ledger.append_event("FIRST", actor=SCARActor.HUMAN)
    attestation = ledger.attest_merkle_root()

    assert ledger.verify_attestation(replace(attestation, signature="0" * 64)) is False


def test_empty_ledger_cannot_get_merkle_root():
    with pytest.raises(SCARLedgerError, match="empty"):
        _ledger().get_merkle_root()


def test_export_bundle_contains_public_evidence_only():
    ledger = _ledger()
    ledger.append_event(
        "MEMORY_CHANGE",
        actor=SCARActor.HUMAN,
        memory_hash="a" * 64,
    )

    bundle = ledger.export_audit_bundle()

    assert bundle["format"] == "SAMA-SCAR-AUDIT-BUNDLE-1"
    assert bundle["identity_id"] == "human-1"
    assert bundle["merkle_root"] == ledger.get_merkle_root().root
    assert bundle["attestation"]["root_hash"] == bundle["merkle_root"]
    assert "_root_secret" not in str(bundle)


def test_export_empty_ledger_contains_no_attestation():
    bundle = _ledger().export_audit_bundle()

    assert bundle["entries"] == []
    assert "attestation" not in bundle


def test_merkle_proof_exports_one_event_without_exposing_the_ledger():
    ledger = _ledger()
    ledger.append_event("FIRST", actor=SCARActor.HUMAN)
    event = ledger.append_event("SECOND", actor=SCARActor.HUMAN)

    proof = ledger.prove_event(event.sequence)

    assert proof.root == ledger.get_merkle_root().root
    assert verify_merkle_proof(proof) is True


def test_integrity_detects_sequence_tampering():
    ledger = _ledger()
    event = ledger.append_event("FIRST", actor=SCARActor.HUMAN)
    ledger._events[0] = replace(event, sequence=1)

    assert ledger.verify_integrity() is False


def test_assert_scar_invariants_accepts_valid_ledger():
    ledger = _ledger()
    ledger.append_event("FIRST", actor=SCARActor.HUMAN)

    assert_scar_invariants(ledger)


def test_event_metadata_is_immutable_and_export_is_detached():
    ledger = _ledger()
    event = ledger.append_event(
        "FIRST", actor=SCARActor.HUMAN, metadata={"nested": {"value": "original"}}
    )
    exported = event.to_dict()
    exported["metadata"]["nested"]["value"] = "tampered"

    with pytest.raises(TypeError):
        event.metadata["nested"] = {}
    with pytest.raises(TypeError):
        event.metadata["nested"]["value"] = "tampered"
    assert event.to_dict()["metadata"]["nested"]["value"] == "original"
