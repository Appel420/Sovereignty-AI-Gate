"""
S-001B — Governed Tool Execution Backend: Conformance Tests.

These tests prove the full AuthorityGate → AuthorizationDecision →
ToolExecutionContext → PlaygroundExecutor.execute_authorized() flow and every
denial/rejection path mandated by S-001B.

Scope: S-001B only.  No S-002 identity/workspace fields are implemented.
"""
from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from sia import SovereignAuthority
from sia.authority_gate import IdentityContext, OperationRequest, ProtectedOperation
from sia.delegation.models import DelegationToken
from sia.tools import (
    ContextForgeryDenied,
    DirectExecutionDenied,
    PlaygroundExecutor,
    ToolCapability,
    ToolExecutionContext,
    ToolRegistry,
)
from sia.tools.audit import AuditLedger as ToolAuditLedger
from sia.tools.models import _issue_tool_execution_context


# ── Helpers ───────────────────────────────────────────────────────────────────


def make_authority(operation: ProtectedOperation = ProtectedOperation.EXECUTE_TOOL) -> SovereignAuthority:
    authority = SovereignAuthority(
        owner_id="user:alice",
        policy={
            "default": "deny",
            "rules": [
                {
                    "id": f"allow-{operation.value.lower()}",
                    "effect": "allow",
                    "match": {"operation": operation.value},
                }
            ],
        },
    )
    authority.initialize()
    return authority


def make_tool_capability(
    tool_name: str = "echo",
    expired: bool = False,
) -> ToolCapability:
    """ToolCapability — used by the executor to check allowed commands and expiry."""
    return ToolCapability(
        tool_id=f"local.shell.{tool_name}",
        allowed_commands=(tool_name,),
        max_runtime_seconds=5,
        owner="device-root",
        expires_at=(
            datetime.now(timezone.utc) - timedelta(seconds=1)
            if expired
            else datetime.now(timezone.utc) + timedelta(hours=1)
        ),
        signature="signed-capability",
    )


def make_execute_delegation(
    authority: SovereignAuthority,
    *,
    expired: bool = False,
) -> DelegationToken:
    """DelegationToken with scope 'tool.execute' — used by the AuthorityGate."""
    expires_at = (
        datetime.now(timezone.utc) - timedelta(seconds=1)
        if expired
        else datetime.now(timezone.utc) + timedelta(hours=1)
    )
    return DelegationToken(
        token_id="tok-execute-tool",
        grantor_id="user:alice",
        grantee_id="delegate:tool",
        scope=["tool.execute"],
        expires_at=expires_at.isoformat(),
    )


def make_executor(tmp_path=None) -> PlaygroundExecutor:
    registry = ToolRegistry()
    registry.register("echo", "/bin/echo")
    ledger = ToolAuditLedger(tmp_path / "tool-audit.jsonl") if tmp_path else None
    return PlaygroundExecutor(registry=registry, audit_ledger=ledger)


# ── 1. Direct execute() is denied ────────────────────────────────────────────


def test_direct_execute_denied():
    """PlaygroundExecutor.execute() must fail closed with DirectExecutionDenied."""
    executor = make_executor()
    with pytest.raises(DirectExecutionDenied, match="authority-issued"):
        executor.execute("echo", ["hello"], make_tool_capability())


def test_execute_authorized_with_non_context_denied():
    """execute_authorized() rejects anything that is not a ToolExecutionContext."""
    executor = make_executor()
    with pytest.raises(DirectExecutionDenied):
        executor.execute_authorized("not-a-context")  # type: ignore[arg-type]


# ── 2. Missing context denied ─────────────────────────────────────────────────


def test_missing_capability_denied(tmp_path):
    """EXECUTE_TOOL with no capability → MISSING_CAPABILITY, no tool execution."""
    authority = make_authority()
    executor = make_executor(tmp_path)

    decision, result = authority.execute_tool_authorized(
        authority.make_operation_request(
            ProtectedOperation.EXECUTE_TOOL,
            resource_id="echo",
        ),
        executor=executor,
        tool_name="echo",
        args=["hello"],
        capability=make_tool_capability(),
        input_hash="input-1",
    )

    assert decision.allowed is False
    assert decision.reason_code == "MISSING_CAPABILITY"
    assert result is None
    # Tool audit ledger must be empty — no subprocess was run
    assert executor.audit_ledger.read_all() == []


def test_missing_capability_emits_denied_evidence(tmp_path):
    """Authorization denial must emit a tool.operation.denied audit event."""
    authority = make_authority()
    executor = make_executor(tmp_path)

    authority.execute_tool_authorized(
        authority.make_operation_request(
            ProtectedOperation.EXECUTE_TOOL,
            resource_id="echo",
        ),
        executor=executor,
        tool_name="echo",
        args=["hello"],
        capability=make_tool_capability(),
    )

    tool_events = [
        e for e in authority.ledger.all_entries()
        if e.event_type == "tool.operation.denied"
    ]
    assert len(tool_events) == 1
    ev = tool_events[0]
    assert ev.payload["execution_status"] == "denied"
    assert ev.payload["tool_name"] == "echo"
    assert ev.payload["decision"] == "denied"


# ── 3. Caller-created / forged context denied ─────────────────────────────────


def test_forged_context_construction_denied():
    """ToolExecutionContext built without _AUTHORITY_TOKEN raises ContextForgeryDenied."""
    cap = make_tool_capability()
    with pytest.raises(ContextForgeryDenied, match="authority"):
        ToolExecutionContext(
            request_id="forged-req",
            authorization_id=None,
            identity_id="attacker",
            capability_id=None,
            tool_name="echo",
            operation="EXECUTE_TOOL",
            tool_capability=cap,
            args=("hello",),
            input_hash="",
            requester="",
            runtime_version="",
            issued_at="2026-01-01T00:00:00Z",
            _marker=None,  # wrong marker
        )


def test_forged_context_with_wrong_marker_denied():
    """A context with an arbitrary (non-sentinel) marker is rejected."""
    cap = make_tool_capability()
    with pytest.raises(ContextForgeryDenied):
        ToolExecutionContext(
            request_id="forged-req",
            authorization_id=None,
            identity_id="attacker",
            capability_id=None,
            tool_name="echo",
            operation="EXECUTE_TOOL",
            tool_capability=cap,
            args=("hello",),
            input_hash="",
            requester="",
            runtime_version="",
            issued_at="2026-01-01T00:00:00Z",
            _marker=object(),  # different object, not the sentinel
        )


# ── 4. Capability mismatch denied ─────────────────────────────────────────────


def test_capability_context_mismatch_denied(tmp_path):
    """Mismatched capability_id between decision and request → CAPABILITY_CONTEXT_MISMATCH."""
    from sia.authority_gate import AuthorizationDecision

    authority = make_authority()
    delegation = make_execute_delegation(authority)
    executor = make_executor(tmp_path)

    # Patch authorize_operation to return an allowed decision with a DIFFERENT capability_id
    patched_decision = AuthorizationDecision(
        allowed=True,
        operation="EXECUTE_TOOL",
        reason_code="AUTHORIZED",
        reason="patched",
        capability_id="cap-DIFFERENT-ID",
        policy_hash="ph",
        audit_required=True,
        evidence_sequence=99,
    )

    with patch.object(authority, "authorize_operation", return_value=patched_decision):
        mismatch_decision, mismatch_result = authority.execute_tool_authorized(
            authority.make_operation_request(
                ProtectedOperation.EXECUTE_TOOL,
                capability=delegation,
                resource_id="echo",
            ),
            executor=executor,
            tool_name="echo",
            args=["hello"],
            capability=make_tool_capability(),
        )

    assert mismatch_decision.allowed is False
    assert mismatch_decision.reason_code == "CAPABILITY_CONTEXT_MISMATCH"
    assert mismatch_result is None

    # Rejected evidence must be emitted
    rejected_events = [
        e for e in authority.ledger.all_entries()
        if e.event_type == "tool.operation.rejected"
    ]
    assert any(
        e.payload.get("failure_reason") == "CAPABILITY_CONTEXT_MISMATCH"
        for e in rejected_events
    )


# ── 5. Tool mismatch denied ───────────────────────────────────────────────────


def test_tool_not_in_allowed_commands_denied(tmp_path):
    """Execution denied when tool_name is not in capability.allowed_commands."""
    executor = make_executor(tmp_path)
    cap = make_tool_capability("echo")

    # Issue a valid context but request "ls" which is not in ("echo",)
    ctx = _issue_tool_execution_context(
        request_id="req-mismatch",
        authorization_id="auth-mismatch",
        identity_id="user:alice",
        capability_id="cap-test",
        tool_name="ls",  # not in allowed_commands
        operation="EXECUTE_TOOL",
        tool_capability=cap,
        args=("-la",),
        input_hash="",
        issued_at=datetime.now(timezone.utc).isoformat(),
    )
    from sia.tools.validator import CapabilityValidationError

    with pytest.raises(CapabilityValidationError, match="allowed_commands"):
        executor.execute_authorized(ctx)


# ── 6. Workspace / binding mismatch denied ────────────────────────────────────


def test_s002_fields_reserved_and_none():
    """S-002 fields on ToolExecutionContext must be None (not implemented)."""
    ctx = _issue_tool_execution_context(
        request_id="req-s002",
        authorization_id=None,
        identity_id="user:alice",
        capability_id=None,
        tool_name="echo",
        operation="EXECUTE_TOOL",
        tool_capability=make_tool_capability(),
        args=("hello",),
        issued_at=datetime.now(timezone.utc).isoformat(),
    )
    assert ctx.workspace_id is None
    assert ctx.binding_id is None
    assert ctx.branch is None
    assert ctx.task_id is None


# ── 7. Expired context denied ─────────────────────────────────────────────────


def test_expired_capability_denied_in_execute_authorized(tmp_path):
    """execute_authorized() must reject an expired ToolCapability."""
    executor = make_executor(tmp_path)
    expired_cap = make_tool_capability("echo", expired=True)
    ctx = _issue_tool_execution_context(
        request_id="req-expired",
        authorization_id="auth-expired",
        identity_id="user:alice",
        capability_id=None,
        tool_name="echo",
        operation="EXECUTE_TOOL",
        tool_capability=expired_cap,
        args=("hello",),
        issued_at=datetime.now(timezone.utc).isoformat(),
    )
    from sia.tools.validator import CapabilityValidationError

    with pytest.raises(CapabilityValidationError, match="expired"):
        executor.execute_authorized(ctx)


def test_expired_capability_denied_through_authority(tmp_path):
    """execute_tool_authorized with expired ToolCapability → fails in executor, failed evidence emitted."""
    authority = make_authority()
    delegation = make_execute_delegation(authority)
    executor = make_executor(tmp_path)

    expired_cap = make_tool_capability("echo", expired=True)

    with pytest.raises(Exception, match="expired"):
        authority.execute_tool_authorized(
            authority.make_operation_request(
                ProtectedOperation.EXECUTE_TOOL,
                capability=delegation,
                resource_id="echo",
            ),
            executor=executor,
            tool_name="echo",
            args=["hello"],
            capability=expired_cap,
        )

    # Failed evidence must be present
    failed_events = [
        e for e in authority.ledger.all_entries()
        if e.event_type == "tool.operation.failed"
    ]
    assert len(failed_events) >= 1


# ── 8. Valid authority-issued context executes ────────────────────────────────


def test_valid_authority_context_executes(tmp_path):
    """Full happy path: authority gate → context → execute_authorized → result."""
    authority = make_authority()
    delegation = make_execute_delegation(authority)
    executor = make_executor(tmp_path)

    decision, result = authority.execute_tool_authorized(
        authority.make_operation_request(
            ProtectedOperation.EXECUTE_TOOL,
            capability=delegation,
            resource_id="echo",
        ),
        executor=executor,
        tool_name="echo",
        args=["sovereignty"],
        capability=make_tool_capability("echo"),
        input_hash="input-ok",
        requester="user:alice",
        runtime_version="v1",
    )

    assert decision.allowed is True
    assert decision.reason_code == "AUTHORIZED"
    assert result is not None
    assert result.status == "success"
    assert "sovereignty" in result.stdout


# ── 9. Successful execution evidence ─────────────────────────────────────────


def test_successful_execution_emits_evidence(tmp_path):
    """Successful execution must emit started and completed tool.operation events."""
    authority = make_authority()
    delegation = make_execute_delegation(authority)
    executor = make_executor(tmp_path)

    authority.execute_tool_authorized(
        authority.make_operation_request(
            ProtectedOperation.EXECUTE_TOOL,
            capability=delegation,
            resource_id="echo",
        ),
        executor=executor,
        tool_name="echo",
        args=["evidence-test"],
        capability=make_tool_capability("echo"),
        input_hash="input-evidence",
    )

    all_entries = authority.ledger.all_entries()
    event_types = [e.event_type for e in all_entries]

    assert "tool.operation.started" in event_types
    assert "tool.operation.completed" in event_types

    started = next(e for e in all_entries if e.event_type == "tool.operation.started")
    completed = next(e for e in all_entries if e.event_type == "tool.operation.completed")

    assert started.payload["tool_name"] == "echo"
    assert started.payload["decision"] == "authorized"
    assert started.payload["execution_status"] == "started"

    assert completed.payload["tool_name"] == "echo"
    assert completed.payload["decision"] == "authorized"
    assert completed.payload["execution_status"] == "completed"

    # Both events must share the same request_id
    assert started.payload["request_id"] == completed.payload["request_id"]
    assert started.payload["identity_id"] == "user:alice"


# ── 10. Failed execution evidence ─────────────────────────────────────────────


def test_failed_execution_emits_evidence(tmp_path):
    """When the executor raises, tool.operation.failed must be emitted."""
    authority = make_authority()
    delegation = make_execute_delegation(authority)

    registry = ToolRegistry()
    registry.register("badsys", "/bin/echo")
    executor = PlaygroundExecutor(
        registry=registry,
        audit_ledger=ToolAuditLedger(tmp_path / "t.jsonl"),
    )

    # Use an expired capability so execute_authorized raises inside the try block
    expired_cap = make_tool_capability("badsys", expired=True)

    with pytest.raises(Exception):
        authority.execute_tool_authorized(
            authority.make_operation_request(
                ProtectedOperation.EXECUTE_TOOL,
                capability=delegation,
                resource_id="badsys",
            ),
            executor=executor,
            tool_name="badsys",
            args=["x"],
            capability=expired_cap,
        )

    failed_events = [
        e for e in authority.ledger.all_entries()
        if e.event_type == "tool.operation.failed"
    ]
    assert len(failed_events) >= 1
    ev = failed_events[0]
    assert ev.payload["execution_status"] == "failed"
    assert ev.payload["tool_name"] == "badsys"
    assert "failure_reason" in ev.payload


# ── 11. Authorization denial evidence ─────────────────────────────────────────


def test_authorization_denial_evidence(tmp_path):
    """No capability → MISSING_CAPABILITY denial → tool.operation.denied evidence."""
    authority = make_authority()
    executor = make_executor(tmp_path)

    # No capability → MISSING_CAPABILITY
    authority.execute_tool_authorized(
        authority.make_operation_request(
            ProtectedOperation.EXECUTE_TOOL,
            resource_id="echo",
        ),
        executor=executor,
        tool_name="echo",
        args=["x"],
        capability=make_tool_capability("echo"),
    )

    denied_events = [
        e for e in authority.ledger.all_entries()
        if e.event_type == "tool.operation.denied"
    ]
    assert len(denied_events) >= 1
    ev = denied_events[0]
    assert ev.payload["decision"] == "denied"
    assert ev.payload["execution_status"] == "denied"
    assert ev.payload["tool_name"] == "echo"
    assert ev.payload["identity_id"] == "user:alice"


# ── 12. Context fields are bound correctly ────────────────────────────────────


def test_context_binds_correct_fields(tmp_path):
    """ToolExecutionContext issued by authority must carry matching field values."""
    authority = make_authority()
    delegation = make_execute_delegation(authority)

    captured_ctx: list[ToolExecutionContext] = []

    class CapturingExecutor:
        audit_ledger = None

        def execute_authorized(self, ctx: ToolExecutionContext) -> None:
            captured_ctx.append(ctx)
            raise RuntimeError("capture-only")

    with pytest.raises(RuntimeError, match="capture-only"):
        authority.execute_tool_authorized(
            authority.make_operation_request(
                ProtectedOperation.EXECUTE_TOOL,
                capability=delegation,
                resource_id="echo",
            ),
            executor=CapturingExecutor(),
            tool_name="echo",
            args=["binding-test"],
            capability=make_tool_capability("echo"),
            input_hash="ih-bind",
            requester="user:alice",
            runtime_version="v42",
        )

    assert len(captured_ctx) == 1
    ctx = captured_ctx[0]
    assert isinstance(ctx, ToolExecutionContext)
    assert ctx.tool_name == "echo"
    assert ctx.operation == "EXECUTE_TOOL"
    assert ctx.args == ("binding-test",)
    assert ctx.input_hash == "ih-bind"
    assert ctx.requester == "user:alice"
    assert ctx.runtime_version == "v42"
    assert ctx.identity_id == "user:alice"
    assert ctx.capability_id == delegation.token_id
    # S-002 fields reserved
    assert ctx.workspace_id is None
    assert ctx.binding_id is None
    assert ctx.branch is None
    assert ctx.task_id is None
