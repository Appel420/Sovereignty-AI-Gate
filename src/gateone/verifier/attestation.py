"""Canonical envelope validation for Gate.one's verification chain."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from gateone.enclave.tpm_attestation import TPMQuote, TPMQuoteVerifier, TPMVerification
from gateone.verifier.pqc import MLDSA87Verifier, PQCVerification
from sia.utils.canonical import canonical_bytes


@dataclass(frozen=True)
class AttestationEnvelope:
    """The complete signed and TPM-attested input accepted by Gate.one."""

    identity_id: str
    nonce: str
    issued_at: str
    payload: dict[str, Any]
    signature_b64: str
    public_key_b64: str
    trusted_ak_hash: str
    tpm_quote: TPMQuote


@dataclass(frozen=True)
class AttestationVerification:
    """Cryptographic and hardware verification outcomes for one envelope."""

    canonical_payload: bytes | None
    pqc: PQCVerification
    tpm: TPMVerification
    reason_code: str
    reason: str


class AttestationVerifier:
    """Validate canonical payload binding, freshness, ML-DSA-87, and TPM evidence."""

    def __init__(
        self,
        *,
        pqc_verifier: MLDSA87Verifier | None = None,
        tpm_verifier: TPMQuoteVerifier | None = None,
        max_age: timedelta = timedelta(minutes=5),
        max_future_skew: timedelta = timedelta(seconds=30),
    ) -> None:
        self._pqc_verifier = pqc_verifier or MLDSA87Verifier()
        self._tpm_verifier = tpm_verifier or TPMQuoteVerifier()
        self._max_age = max_age
        self._max_future_skew = max_future_skew

    def verify(
        self, envelope: AttestationEnvelope, *, expected_nonce: str, now: datetime | None = None
    ) -> AttestationVerification:
        """Run the fixed verification order and stop before any authority decision."""
        invalid = self._validate(envelope, expected_nonce, now or datetime.now(timezone.utc))
        if invalid is not None:
            return invalid

        payload = canonical_bytes(envelope.payload)
        pqc = self._pqc_verifier.verify(
            payload=payload,
            signature_b64=envelope.signature_b64,
            public_key_b64=envelope.public_key_b64,
        )
        if not pqc.verified:
            return AttestationVerification(payload, pqc, self._not_attempted_tpm(), pqc.reason_code, pqc.reason)

        tpm = self._tpm_verifier.verify(
            envelope.tpm_quote,
            nonce=envelope.nonce,
            trusted_ak_hash=envelope.trusted_ak_hash,
        )
        return AttestationVerification(payload, pqc, tpm, tpm.reason_code, tpm.reason)

    def _validate(
        self, envelope: AttestationEnvelope, expected_nonce: str, now: datetime
    ) -> AttestationVerification | None:
        if not expected_nonce or envelope.nonce != expected_nonce:
            return self._invalid("NONCE_MISMATCH", "Attestation nonce does not match the issued challenge.")
        if not envelope.identity_id or not envelope.trusted_ak_hash:
            return self._invalid("IDENTITY_BINDING_MISSING", "Identity and trusted TPM key binding are required.")
        if envelope.payload.get("identity_id") != envelope.identity_id:
            return self._invalid("IDENTITY_BINDING_INVALID", "Payload identity is not bound to the envelope identity.")
        try:
            issued_at = datetime.fromisoformat(envelope.issued_at.replace("Z", "+00:00"))
            if issued_at.tzinfo is None:
                raise ValueError("timestamp lacks timezone")
        except (AttributeError, ValueError) as exc:
            return self._invalid("FRESHNESS_INVALID", f"Attestation timestamp is invalid: {exc}")
        issued_at = issued_at.astimezone(timezone.utc)
        if issued_at < now - self._max_age or issued_at > now + self._max_future_skew:
            return self._invalid("FRESHNESS_FAILED", "Attestation timestamp is outside the accepted freshness window.")
        try:
            canonical_bytes(envelope.payload)
        except (TypeError, ValueError) as exc:
            return self._invalid("PAYLOAD_INVALID", f"Payload cannot be canonicalized: {exc}")
        return None

    @staticmethod
    def _not_attempted_tpm() -> TPMVerification:
        return TPMVerification(False, False, "TPM_NOT_ATTEMPTED", "TPM verification was not attempted.")

    def _invalid(self, reason_code: str, reason: str) -> AttestationVerification:
        unavailable = PQCVerification(False, False, "PQC_NOT_ATTEMPTED", "PQC verification was not attempted.")
        return AttestationVerification(None, unavailable, self._not_attempted_tpm(), reason_code, reason)
