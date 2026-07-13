"""
Sovereign Authority — top-level orchestrator.

``SovereignAuthority`` ties together all SIA subsystems: boundary
registry, policy engine, delegation authorizer, memory, audit ledger,
import/export, and conformance harness.
"""
from __future__ import annotations

from typing import Any

from sia.audit.ledger import AuditLedger
from sia.audit.recorder import AuditRecorder
from sia.conformance.harness import ConformanceHarness
from sia.delegation.authorizer import DelegationAuthorizer
from sia.delegation.models import DelegationToken
from sia.errors.exceptions import NotInitializedError
from sia.export.models import ExportBundle
from sia.export.validator import validate_bundle
from sia.imports.loader import BundleLoader
from sia.imports.models import ImportBundle
from sia.memory.models import MemoryRecord
from sia.memory.validator import assert_read_access, validate_record
from sia.security.authority_policy import AuthorityPolicy
from sia.security.boundary_registry import BoundaryRegistry, BoundaryType
from sia.utils.hashing import sha256_object

__version__ = "0.1.0"


class SovereignAuthority:
    """
    Top-level Sovereignty AI Gate authority instance.

    This class is the single entry point for all authority operations.
    All actions are recorded to the audit ledger.

    Usage::

        sa = SovereignAuthority(owner_id="user:alice")
        sa.initialize()
        sa.register_boundary("b001", "model:gpt4", "creator", scope=["memory.read"])
    """

    def __init__(
        self,
        owner_id: str,
        policy: dict[str, Any] | None = None,
    ) -> None:
        self._owner_id = owner_id
        self._initialized = False
        self._registry = BoundaryRegistry()
        self._policy = AuthorityPolicy(
            policy or {"default": "deny", "rules": []}
        )
        self._delegations = DelegationAuthorizer()
        self._memory: dict[str, MemoryRecord] = {}
        self._ledger = AuditLedger()
        self._recorder = AuditRecorder(self._ledger)
        self._loader = BundleLoader()
        self._conformance = ConformanceHarness()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def initialize(self) -> None:
        """Mark the authority as initialized and write the init audit record."""
        self._initialized = True
        self._recorder.record_authority_init(
            actor_id=self._owner_id, version=__version__
        )

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise NotInitializedError()

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def owner_id(self) -> str:
        return self._owner_id

    @property
    def registry(self) -> BoundaryRegistry:
        return self._registry

    @property
    def ledger(self) -> AuditLedger:
        return self._ledger

    @property
    def conformance(self) -> ConformanceHarness:
        return self._conformance

    # ── Boundary management ───────────────────────────────────────────────────

    def register_boundary(
        self,
        boundary_id: str,
        model_id: str,
        boundary_type: BoundaryType,
        scope: list[str],
    ) -> None:
        """Register a model boundary and record the event."""
        self._require_initialized()
        self._registry.register(
            boundary_id=boundary_id,
            model_id=model_id,
            boundary_type=boundary_type,
            creator_id=self._owner_id,
            scope=scope,
        )
        self._recorder.record_boundary_registered(
            actor_id=self._owner_id,
            boundary_id=boundary_id,
            boundary_type=boundary_type,
            model_id=model_id,
        )

    # ── Delegation ────────────────────────────────────────────────────────────

    def issue_delegation(
        self,
        token: DelegationToken,
        parent_scope: list[str] | None = None,
    ) -> DelegationToken:
        """Issue a delegation token and record the event."""
        self._require_initialized()
        issued = self._delegations.issue(token, parent_scope=parent_scope)
        self._recorder.record_delegation_issued(
            actor_id=self._owner_id,
            token_id=issued.token_id,
            grantee_id=issued.grantee_id,
            scope=issued.scope,
        )
        return issued

    def revoke_delegation(self, token_id: str) -> None:
        """Revoke a delegation token and record the event."""
        self._require_initialized()
        self._delegations.revoke(token_id)
        self._recorder.record_delegation_revoked(
            actor_id=self._owner_id, token_id=token_id
        )

    # ── Memory ────────────────────────────────────────────────────────────────

    def store_memory(self, record: MemoryRecord) -> None:
        """Validate and store a memory record."""
        self._require_initialized()
        validate_record(record)
        self._memory[record.record_id] = record
        self._recorder.record_memory_access(
            actor_id=self._owner_id,
            record_id=record.record_id,
            model_id=record.model_id,
            access_type="write",
        )

    def read_memory(
        self, record_id: str, requesting_model_id: str
    ) -> MemoryRecord:
        """Read a memory record, enforcing consent rules."""
        self._require_initialized()
        record = self._memory[record_id]
        assert_read_access(record, requesting_model_id)
        self._recorder.record_memory_access(
            actor_id=requesting_model_id,
            record_id=record_id,
            model_id=record.model_id,
            access_type="read",
        )
        return record

    # ── Export / Import ───────────────────────────────────────────────────────

    def create_export(
        self,
        bundle_id: str,
        payload: dict[str, Any],
        payload_hash: str,
        signature: str,
    ) -> ExportBundle:
        """Build, validate, and record an export bundle."""
        self._require_initialized()
        bundle = ExportBundle(
            bundle_id=bundle_id,
            created_by=self._owner_id,
            payload=payload,
            payload_hash=payload_hash,
            signature=signature,
        )
        validate_bundle(bundle)
        self._recorder.record_export(
            actor_id=self._owner_id, bundle_id=bundle_id
        )
        return bundle

    def load_import(self, bundle: ImportBundle) -> None:
        """Validate and load an import bundle."""
        self._require_initialized()
        self._loader.load(bundle)
        self._recorder.record_import(
            actor_id=self._owner_id, bundle_id=bundle.bundle_id
        )

    # ── Policy ────────────────────────────────────────────────────────────────

    def enforce_policy(self, request: dict[str, Any]) -> None:
        """Enforce the authority policy for *request*."""
        self._require_initialized()
        self._policy.enforce(request)

    # ── Audit ─────────────────────────────────────────────────────────────────

    def verify_ledger(self) -> None:
        """Verify ledger chain integrity. Raises on tamper detection."""
        self._ledger.verify_chain()
