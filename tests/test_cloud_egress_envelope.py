from __future__ import annotations

import json

import pytest

from sia.egress import CloudEgressEnvelope, EgressEnvelopeError


def test_portable_json_round_trip():
    envelope = CloudEgressEnvelope.seal(
        b"owner-controlled cloud payload",
        passphrase="correct horse battery staple",
        recipient_id="storage:owner-archive",
        content_type="application/sia-record",
        created="2026-01-01T00:00:00Z",
    )

    received = CloudEgressEnvelope.from_dict(json.loads(envelope.to_json()))

    assert received.open(
        passphrase="correct horse battery staple",
        recipient_id="storage:owner-archive",
    ) == b"owner-controlled cloud payload"
    assert b"owner-controlled cloud payload" not in envelope.to_json().encode()


def test_wrong_passphrase_or_recipient_fails_closed():
    envelope = CloudEgressEnvelope.seal(
        b"private", passphrase="shared secret", recipient_id="device:one"
    )

    with pytest.raises(EgressEnvelopeError):
        envelope.open(passphrase="wrong secret", recipient_id="device:one")
    with pytest.raises(EgressEnvelopeError):
        envelope.open(passphrase="shared secret", recipient_id="device:two")


def test_tampered_authenticated_metadata_fails_closed():
    envelope = CloudEgressEnvelope.seal(
        b"private", passphrase="shared secret", recipient_id="device:one"
    )
    tampered = CloudEgressEnvelope(
        **{**envelope.to_dict(), "content_type": "text/plain"}
    )

    with pytest.raises(EgressEnvelopeError):
        tampered.open(passphrase="shared secret", recipient_id="device:one")


def test_rejects_unknown_or_malformed_envelope():
    with pytest.raises(EgressEnvelopeError):
        CloudEgressEnvelope.from_dict({"schema": "unknown"})


def test_envelope_id_tracks_tampering():
    envelope = CloudEgressEnvelope.seal(
        b"private", passphrase="shared secret", recipient_id="vault:archive"
    )
    tampered = {**envelope.to_dict(), "created": "2026-01-01T00:00:00Z"}

    with pytest.raises(EgressEnvelopeError, match="identifier"):
        CloudEgressEnvelope.from_dict(tampered)


def test_expired_envelope_fails_closed():
    envelope = CloudEgressEnvelope.seal(
        b"private",
        passphrase="shared secret",
        recipient_id="vault:archive",
        created="2025-01-01T00:00:00Z",
        expires="2025-01-02T00:00:00Z",
    )

    with pytest.raises(EgressEnvelopeError, match="expired"):
        envelope.open(passphrase="shared secret", recipient_id="vault:archive")


def test_recipient_namespace_is_required():
    with pytest.raises(ValueError, match="registered namespace"):
        CloudEgressEnvelope.seal(
            b"private", passphrase="shared secret", recipient_id="recipient:one"
        )


def test_sia_ep_0001_interoperability_vector():
    vector = {
        "ciphertext": "fQBjRpHNUQBTSknN3tskfusjcTr2RjBYBR-bcPWQaqbr2pWUHzBk",
        "content_type": "application/sia-test",
        "created": "2026-01-01T00:00:00Z",
        "envelope_id": (
            "0b5042d2935884f1d663239cd1af4ed022404835e9854e1453ad73175dbb1045"
        ),
        "expires": "2026-12-31T23:59:59Z",
        "kdf": "argon2id",
        "kdf_params": {"iterations": 3, "lanes": 4, "length": 32, "memory_cost": 65536},
        "nonce": "EBESExQVFhcYGRob",
        "recipient_id": "storage:test-vector",
        "salt": "AAECAwQFBgcICQoLDA0ODw==",
        "schema": "sia.cloud-egress.v1",
        "suite": "SIA-E1",
    }

    envelope = CloudEgressEnvelope.from_dict(vector)

    assert envelope.open(
        passphrase="correct horse battery staple",
        recipient_id="storage:test-vector",
    ) == b"SIA-EP-0001 test vector"
