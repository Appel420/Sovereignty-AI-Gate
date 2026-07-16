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
    )

    received = CloudEgressEnvelope.from_dict(json.loads(envelope.to_json()))

    assert received.open(
        passphrase="correct horse battery staple",
        recipient_id="storage:owner-archive",
    ) == b"owner-controlled cloud payload"
    assert b"owner-controlled cloud payload" not in envelope.to_json().encode()


def test_wrong_passphrase_or_recipient_fails_closed():
    envelope = CloudEgressEnvelope.seal(
        b"private", passphrase="shared secret", recipient_id="recipient:one"
    )

    with pytest.raises(EgressEnvelopeError):
        envelope.open(passphrase="wrong secret", recipient_id="recipient:one")
    with pytest.raises(EgressEnvelopeError):
        envelope.open(passphrase="shared secret", recipient_id="recipient:two")


def test_tampered_authenticated_metadata_fails_closed():
    envelope = CloudEgressEnvelope.seal(
        b"private", passphrase="shared secret", recipient_id="recipient:one"
    )
    tampered = CloudEgressEnvelope(
        **{**envelope.to_dict(), "content_type": "text/plain"}
    )

    with pytest.raises(EgressEnvelopeError):
        tampered.open(passphrase="shared secret", recipient_id="recipient:one")


def test_rejects_unknown_or_malformed_envelope():
    with pytest.raises(EgressEnvelopeError):
        CloudEgressEnvelope.from_dict({"schema": "unknown"})
