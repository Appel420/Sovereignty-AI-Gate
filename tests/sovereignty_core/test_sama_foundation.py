from __future__ import annotations

from dataclasses import replace

import pytest

from sovereignty_core.identity.identity import DeviceBinding, HumanIdentity
from sovereignty_core.identity.root_of_trust import RootOfTrust, SoftwareTrustBackend
from sovereignty_core.permissions.capability import CapabilityScope, CapabilityToken
from sovereignty_core.permissions.consent import ConsentStatus, ConsentRecord
from sovereignty_core.vault.memory_chain import (
    MemoryChain,
    MemoryClassification,
    MemoryProvenance,
)


def test_modules_import_cleanly():
    identity = HumanIdentity.create(
        identity_id="human-1",
        display_name="Alice",
        public_identity_key="pub-1",
    )
    assert identity.provider is None
    assert identity.authority_source.value == "ROOT_OF_TRUST"


def test_root_of_trust_identity_is_deterministic_for_same_backend_secret():
    secret = b"\x01" * 32
    trust_a = RootOfTrust(SoftwareTrustBackend(secret))
    trust_b = RootOfTrust(SoftwareTrustBackend(secret))

    assert trust_a.identity.identity_id == trust_b.identity.identity_id
    assert trust_a.derive_identity_key() != trust_a.derive_vault_key()


def test_root_of_trust_sign_and_verify_round_trip():
    trust = RootOfTrust(SoftwareTrustBackend(b"\x02" * 32))
    payload = b"hello sovereignty"
    signed = trust.sign(payload)

    assert trust.verify(payload, signed) is True
    assert trust.verify(b"tampered", signed) is False


def test_human_identity_device_binding_round_trip():
    identity = HumanIdentity.create(
        identity_id="human-1",
        display_name="Alice",
        public_identity_key="pub-1",
    )
    binding = DeviceBinding(device_id="device-1", root_identity_id="root-1", bound_at=1)
    identity.bind_device(binding)

    assert identity.is_device_trusted("device-1") is True
    assert identity.deactivate_device("device-1") is True
    assert identity.is_device_trusted("device-1") is False


def test_capability_token_enforces_least_privilege_and_revocation():
    unsigned = CapabilityToken.create(
        provider_id="provider:claude",
        owner_identity="human-1",
        scopes=[CapabilityScope.READ_CONTEXT_WINDOW],
        issuer_device="device-1",
        signature="sig-1",
        ttl_seconds=60,
    )

    assert unsigned.allows(CapabilityScope.READ_CONTEXT_WINDOW) is True
    unsigned.revoke(revocation_id="rev-1", revoked_at=10)
    assert unsigned.is_active(now=10) is False
    assert unsigned.revocation_id == "rev-1"


def test_capability_token_rejects_forbidden_scope():
    with pytest.raises(ValueError):
        CapabilityToken.create(
            provider_id="provider:claude",
            owner_identity="human-1",
            scopes=[CapabilityScope.ROOT_ACCESS],
            issuer_device="device-1",
            signature="sig-1",
            ttl_seconds=60,
        )


def test_capability_signature_hook_can_use_root_of_trust():
    trust = RootOfTrust(SoftwareTrustBackend(b"\x03" * 32))
    provisional = CapabilityToken.create(
        provider_id="provider:copilot",
        owner_identity="human-1",
        scopes=[CapabilityScope.APPEND_MEMORY_SUGGESTION],
        issuer_device="device-1",
        signature="placeholder",
        ttl_seconds=60,
    )
    signed = replace(
        provisional,
        signature=trust.sign(provisional.signing_payload()).signature,
    )

    assert signed.verify_signature(trust.verify_signature) is True


def test_consent_record_tracks_revocation():
    consent = ConsentRecord.grant(
        owner_identity="human-1",
        grantee_id="provider:claude",
        scopes=["READ_CONTEXT_WINDOW"],
        purpose="summarization",
        issuer_device="device-1",
    )

    assert consent.current_status() is ConsentStatus.ACTIVE
    assert consent.allows("READ_CONTEXT_WINDOW") is True
    consent.revoke("user withdrew approval", revoked_at=5)
    assert consent.current_status() is ConsentStatus.REVOKED
    assert consent.allows("READ_CONTEXT_WINDOW", now=5) is False


def test_memory_chain_validates_hash_chain_and_signature():
    trust = RootOfTrust(SoftwareTrustBackend(b"\x04" * 32))
    chain = MemoryChain()
    provenance = MemoryProvenance(
        owner_identity="human-1",
        source_type="provider",
        source_id="provider:claude",
        issuer_device="device-1",
    )

    chain.append(
        classification=MemoryClassification.USER_CONFIRMED,
        content={"message": "confirmed"},
        provenance=provenance,
        signer=trust.identity.identity_id,
        sign_payload=lambda payload: trust.sign(payload).signature,
    )
    chain.append(
        classification=MemoryClassification.AI_SUGGESTED,
        content={"message": "suggested"},
        provenance=provenance,
        signer=trust.identity.identity_id,
        sign_payload=lambda payload: trust.sign(payload).signature,
    )

    assert chain.validate(trust.verify_signature) is True

    tampered = replace(chain.blocks[1], content={"message": "tampered"})
    chain._blocks[1] = tampered
    assert chain.validate(trust.verify_signature) is False
