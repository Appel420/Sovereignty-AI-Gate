"""Fail-closed authority policy for verified Gate.one attestations."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from gateone.verifier.attestation import AttestationVerification


class AuthorityOutcome(StrEnum):
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    DENY = "deny"


@dataclass(frozen=True)
class AuthorityDecision:
    """The final authority outcome after cryptographic verification."""

    outcome: AuthorityOutcome
    reason_code: str
    reason: str


class AuthorityPolicy:
    """Allow only fully verified attestations; unavailable verifiers quarantine."""

    def decide(self, verification: AttestationVerification) -> AuthorityDecision:
        """Return a deterministic fail-closed authority decision."""
        if verification.pqc.verified and verification.tpm.verified:
            return AuthorityDecision(AuthorityOutcome.ALLOW, "ATTESTATION_VERIFIED", "Attestation verified.")
        if not verification.pqc.available or not verification.tpm.available:
            return AuthorityDecision(AuthorityOutcome.QUARANTINE, verification.reason_code, verification.reason)
        return AuthorityDecision(AuthorityOutcome.DENY, verification.reason_code, verification.reason)
