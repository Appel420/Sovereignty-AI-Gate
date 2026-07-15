"""SCAR-compatible immutable evidence for Gate.one authority decisions."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from gateone.verifier.policy import AuthorityDecision
from sovereignty_core.audit.scar import SCARActor, SCARLedger, SCAREvent


@dataclass(frozen=True)
class GateOneEvidence:
    """Public-safe verification metadata retained in the SCAR ledger."""

    identity_id: str
    decision: AuthorityDecision
    nonce_hash: str
    verification_codes: tuple[str, ...]


class SCARGateOneEvidenceRecorder:
    """Append a device-signed Gate.one verification event after each decision."""

    def __init__(self, ledger: SCARLedger) -> None:
        self._ledger = ledger

    def record(self, evidence: GateOneEvidence) -> SCAREvent:
        """Record non-secret evidence only; payloads, signatures, and quotes are excluded."""
        if evidence.identity_id != self._ledger.identity_id:
            raise ValueError("Gate.one evidence identity does not match the SCAR ledger.")
        metadata: dict[str, Any] = {
            "decision": evidence.decision.outcome.value,
            "reason_code": evidence.decision.reason_code,
            "nonce_hash": evidence.nonce_hash,
            "verification_codes": list(evidence.verification_codes),
        }
        return self._ledger.append_event(
            "GATEONE_VERIFICATION",
            actor=SCARActor.DEVICE,
            metadata=metadata,
        )
