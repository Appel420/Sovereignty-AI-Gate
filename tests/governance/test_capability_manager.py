from __future__ import annotations

from sia.capability_manager import CapabilityManager
from sia.delegation.models import DelegationToken
from sia.audit.ledger import AuditLedger
from sia.audit.recorder import AuditRecorder


def test_capability_manager_issues_and_authorizes():
    ledger = AuditLedger()
    manager = CapabilityManager(
        owner_identity="user:alice",
        recorder=AuditRecorder(ledger),
    )

    grant = manager.issue(
        capability_id="cap-1",
        subject_id="agent:one",
        scope=["workspace.read"],
        resource_id="workspace:research",
    )

    decision = manager.authorize(
        capability_id=grant.capability_id,
        subject_id="agent:one",
        action="workspace.read",
        resource_id="workspace:research",
    )

    assert decision.allowed is True
    assert decision.reason_code == "AUTHORIZED"
    assert decision.evidence_sequence is not None
    assert ledger.verify_chain() is None


def test_capability_manager_rejects_subject_and_resource_mismatch():
    manager = CapabilityManager(owner_identity="user:alice")
    manager.issue(
        capability_id="cap-2",
        subject_id="agent:one",
        scope=["workspace.read"],
        resource_id="workspace:research",
    )

    subject = manager.authorize(
        capability_id="cap-2",
        subject_id="agent:two",
        action="workspace.read",
        resource_id="workspace:research",
    )
    resource = manager.authorize(
        capability_id="cap-2",
        subject_id="agent:one",
        action="workspace.read",
        resource_id="workspace:finance",
    )

    assert subject.reason_code == "SUBJECT_MISMATCH"
    assert resource.reason_code == "RESOURCE_MISMATCH"
    assert not subject.allowed and not resource.allowed


def test_capability_manager_rejects_child_scope_escalation():
    manager = CapabilityManager(owner_identity="user:alice")
    manager.issue(
        capability_id="cap-parent",
        subject_id="agent:one",
        scope=["workspace.read"],
    )

    try:
        manager.issue(
            capability_id="cap-child",
            subject_id="agent:two",
            scope=["workspace.write"],
            parent_capability_id="cap-parent",
        )
    except Exception as exc:
        assert "scope" in str(exc).lower()
    else:
        raise AssertionError("child scope escalation was accepted")


def test_capability_manager_revocation_denies_access():
    manager = CapabilityManager(owner_identity="user:alice")
    manager.issue(
        capability_id="cap-revoked",
        subject_id="agent:one",
        scope=["audit.read"],
    )
    manager.revoke("cap-revoked")

    decision = manager.authorize(
        capability_id="cap-revoked",
        subject_id="agent:one",
        action="audit.read",
    )

    assert decision.allowed is False
    assert decision.reason_code == "CAPABILITY_INACTIVE"
