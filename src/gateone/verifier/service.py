"""Gate.one's core verification pipeline, independent of any HTTP transport."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from gateone.evidence.scar import GateOneEvidence
from gateone.verifier.attestation import (
    AttestationEnvelope,
    AttestationVerification,
    AttestationVerifier,
)
from gateone.verifier.policy import AuthorityDecision, AuthorityPolicy
from sovereignty_core.audit.scar import SCAREvent


class GateOneEvidenceRecorder(Protocol):
    """The minimal SCAR-compatible evidence boundary used by the core pipeline."""

    def record(self, evidence: GateOneEvidence) -> SCAREvent:
        """Append immutable evidence for the completed authority decision."""


@dataclass(frozen=True)
class GateOneVerificationResult:
    """The complete decision and immutable evidence generated for one challenge."""

    verification: AttestationVerification
    decision: AuthorityDecision
    evidence: SCAREvent


class GateOneAuthority:
    """Execute canonicalization, verification, decision, then evidence emission."""

    def __init__(
        self,
        *,
        attestation_verifier: AttestationVerifier,
        policy: AuthorityPolicy,
        evidence_recorder: GateOneEvidenceRecorder,
    ) -> None:
        self._attestation_verifier = attestation_verifier
        self._policy = policy
        self._evidence_recorder = evidence_recorder

    def verify(
        self, envelope: AttestationEnvelope, *, expected_nonce: str
    ) -> GateOneVerificationResult:
        """Complete the Gate.one core flow without opening any transport surface."""
        verification = self._attestation_verifier.verify(
            envelope, expected_nonce=expected_nonce
        )
        decision = self._policy.decide(verification)
        evidence = self._evidence_recorder.record(
            GateOneEvidence(
                identity_id=envelope.identity_id,
                decision=decision,
                nonce_hash=hashlib.sha3_512(expected_nonce.encode("utf-8")).hexdigest(),
                verification_codes=(
                    verification.reason_code,
                    verification.pqc.reason_code,
                    verification.tpm.reason_code,
                ),
            )
        )
        return GateOneVerificationResult(verification, decision, evidence)
