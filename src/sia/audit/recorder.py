"""
Audit: recorder.

High-level helper that records well-typed authority events to an
AuditLedger with a consistent payload schema.
"""
from __future__ import annotations

from typing import Any

from sia.audit.ledger import AuditLedger


class AuditRecorder:
    """
    Wraps :class:`AuditLedger` with typed event helpers.

    All authority-related actions that must be auditable should flow
    through this recorder so that payloads have a consistent shape.
    """

    def __init__(self, ledger: AuditLedger) -> None:
        self._ledger = ledger

    @property
    def ledger(self) -> AuditLedger:
        return self._ledger

    # ── Authority events ──────────────────────────────────────────────────────

    def record_authority_init(self, actor_id: str, version: str) -> None:
        self._ledger.append(
            "authority.init",
            {"version": version},
            actor_id=actor_id,
        )

    def record_boundary_registered(
        self,
        actor_id: str,
        boundary_id: str,
        boundary_type: str,
        model_id: str,
    ) -> None:
        self._ledger.append(
            "boundary.registered",
            {
                "boundary_id": boundary_id,
                "boundary_type": boundary_type,
                "model_id": model_id,
            },
            actor_id=actor_id,
        )

    def record_delegation_issued(
        self, actor_id: str, token_id: str, grantee_id: str, scope: list[str]
    ) -> None:
        self._ledger.append(
            "delegation.issued",
            {"token_id": token_id, "grantee_id": grantee_id, "scope": scope},
            actor_id=actor_id,
        )

    def record_delegation_revoked(self, actor_id: str, token_id: str) -> None:
        self._ledger.append(
            "delegation.revoked",
            {"token_id": token_id},
            actor_id=actor_id,
        )

    def record_memory_access(
        self,
        actor_id: str,
        record_id: str,
        model_id: str,
        access_type: str,
    ) -> None:
        self._ledger.append(
            "memory.access",
            {
                "record_id": record_id,
                "model_id": model_id,
                "access_type": access_type,
            },
            actor_id=actor_id,
        )

    def record_export(self, actor_id: str, bundle_id: str) -> None:
        self._ledger.append(
            "export.created",
            {"bundle_id": bundle_id},
            actor_id=actor_id,
        )

    def record_import(self, actor_id: str, bundle_id: str) -> None:
        self._ledger.append(
            "import.loaded",
            {"bundle_id": bundle_id},
            actor_id=actor_id,
        )

    def record_conformance_result(
        self,
        actor_id: str,
        rfc: str,
        passed: bool,
        details: dict[str, Any] | None = None,
    ) -> None:
        self._ledger.append(
            "conformance.result",
            {"rfc": rfc, "passed": passed, "details": details or {}},
            actor_id=actor_id,
        )
