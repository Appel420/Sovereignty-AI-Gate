"""Fail-closed tests for the Gate.one verification core."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

from gateone.enclave.tpm_attestation import TPMQuote, TPMQuoteVerifier, TPMVerification
from gateone.evidence.scar import SCARGateOneEvidenceRecorder
from gateone.verifier.attestation import (
    AttestationEnvelope,
    AttestationVerification,
    AttestationVerifier,
)
from gateone.verifier.policy import AuthorityOutcome, AuthorityPolicy
from gateone.verifier.pqc import MLDSA87Verifier, PQCVerification
from gateone.verifier.service import GateOneAuthority
from sovereignty_core.audit.scar import SCARLedger
from sovereignty_core.identity.root_of_trust import RootOfTrust, SoftwareTrustBackend


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _quote() -> TPMQuote:
    return TPMQuote(
        quoted_b64=_b64(b"quote"),
        signature_b64=_b64(b"signature"),
        ak_public_b64=_b64(b"ak-public"),
        pcr_values_b64=_b64(b"pcr-values"),
        pcr_selection="sha256:0,1",
    )


def _envelope(*, nonce: str = "challenge", issued_at: str | None = None) -> AttestationEnvelope:
    return AttestationEnvelope(
        identity_id="human-1",
        nonce=nonce,
        issued_at=issued_at or datetime.now(timezone.utc).isoformat(),
        payload={"identity_id": "human-1", "operation": "tool.execute"},
        signature_b64=_b64(b"signature"),
        public_key_b64=_b64(b"public-key"),
        trusted_ak_hash=hashlib.sha3_512(b"ak-public").hexdigest(),
        tpm_quote=_quote(),
    )


def test_mldsa_verifier_rejects_malformed_base64_without_a_backend():
    result = MLDSA87Verifier().verify(
        payload=b"payload",
        signature_b64="not-base64",
        public_key_b64=_b64(b"public-key"),
    )

    assert result.verified is False
    assert result.reason_code == "PQC_ENCODING_INVALID"


def test_tpm_verifier_quarantines_when_the_real_verifier_is_unavailable():
    result = TPMQuoteVerifier(executable="gateone-missing-tpm2-checkquote").verify(
        _quote(),
        nonce="challenge",
        trusted_ak_hash=hashlib.sha3_512(b"ak-public").hexdigest(),
    )

    assert result.verified is False
    assert result.available is False
    assert result.reason_code == "TPM_VERIFIER_UNAVAILABLE"


def test_envelope_rejects_nonce_mismatch_before_crypto_or_hardware_verification():
    verification = AttestationVerifier().verify(_envelope(), expected_nonce="other")

    assert verification.reason_code == "NONCE_MISMATCH"
    assert verification.pqc.reason_code == "PQC_NOT_ATTEMPTED"
    assert verification.tpm.reason_code == "TPM_NOT_ATTEMPTED"


def test_envelope_rejects_stale_attestation_before_crypto_or_hardware_verification():
    stale = (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()
    verification = AttestationVerifier().verify(_envelope(issued_at=stale), expected_nonce="challenge")

    assert verification.reason_code == "FRESHNESS_FAILED"
    assert verification.pqc.reason_code == "PQC_NOT_ATTEMPTED"


def test_unavailable_pqc_backend_produces_quarantine_not_allow():
    verification = AttestationVerifier().verify(_envelope(), expected_nonce="challenge")
    decision = AuthorityPolicy().decide(verification)

    assert verification.pqc.verified is False
    assert verification.pqc.available is False
    assert decision.outcome is AuthorityOutcome.QUARANTINE
    assert decision.reason_code == "PQC_BACKEND_UNAVAILABLE"


def test_policy_allows_only_when_pqc_and_tpm_are_both_verified():
    verification = AttestationVerification(
        canonical_payload=b"payload",
        pqc=PQCVerification(True, True, "PQC_VERIFIED", "verified"),
        tpm=TPMVerification(True, True, "TPM_QUOTE_VERIFIED", "verified"),
        reason_code="TPM_QUOTE_VERIFIED",
        reason="verified",
    )

    decision = AuthorityPolicy().decide(verification)

    assert decision.outcome is AuthorityOutcome.ALLOW
    assert decision.reason_code == "ATTESTATION_VERIFIED"


def test_gateone_emits_signed_scar_evidence_after_quarantine_decision():
    root = RootOfTrust(SoftwareTrustBackend(b"\x01" * 32))
    ledger = SCARLedger(identity_id="human-1", root_of_trust=root)
    authority = GateOneAuthority(
        attestation_verifier=AttestationVerifier(),
        policy=AuthorityPolicy(),
        evidence_recorder=SCARGateOneEvidenceRecorder(ledger),
    )

    result = authority.verify(_envelope(), expected_nonce="challenge")

    assert result.decision.outcome is AuthorityOutcome.QUARANTINE
    assert result.evidence.event_type == "GATEONE_VERIFICATION"
    assert result.evidence.metadata["decision"] == "quarantine"
    assert "challenge" not in str(result.evidence.to_dict())
    assert ledger.verify_integrity() is True
