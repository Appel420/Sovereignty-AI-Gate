from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.sia.tools import (
    AuditLedger,
    CapabilityValidationError,
    DirectExecutionDenied,
    PlaygroundExecutor,
    ToolCapability,
    ToolRegistry,
    ToolValidator,
)
from src.sia.tools.models import _issue_tool_execution_context
from src.sia.tools.registry import DuplicateToolRegistrationError


def make_capability(tool_name: str = "echo", expired: bool = False) -> ToolCapability:
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


def _make_ctx(
    tool_name: str = "echo",
    args: tuple[str, ...] = ("hello",),
    input_hash: str = "",
    runtime_version: str = "",
    capability: ToolCapability | None = None,
):
    """Helper: issue an authority-bound ToolExecutionContext for unit tests."""
    cap = capability or make_capability(tool_name)
    return _issue_tool_execution_context(
        request_id="req-test",
        authorization_id="auth-test",
        identity_id="user:test",
        capability_id="cap-test",
        tool_name=tool_name,
        operation="EXECUTE_TOOL",
        tool_capability=cap,
        args=args,
        input_hash=input_hash,
        runtime_version=runtime_version,
        issued_at=datetime.now(timezone.utc).isoformat(),
    )


def test_registry_denies_unregistered_tool():
    registry = ToolRegistry()
    with pytest.raises(PermissionError):
        registry.resolve("missing")


def test_registry_denies_duplicate_registration():
    registry = ToolRegistry()
    registry.register("echo", "/bin/echo")

    with pytest.raises(DuplicateToolRegistrationError):
        registry.register("echo", "/different/path")


def test_validator_denies_expired_capability():
    validator = ToolValidator()
    request = type("Req", (), {})()
    request.tool_name = "echo"
    request.args = ("hello",)
    request.input_hash = "abc"
    request.requester = "tester"
    request.capability = make_capability(expired=True)

    with pytest.raises(CapabilityValidationError):
        validator.validate(request)


def test_direct_execute_is_denied():
    """execute() must fail closed — direct execution without authority context is forbidden."""
    registry = ToolRegistry()
    registry.register("echo", "/bin/echo")
    executor = PlaygroundExecutor(registry=registry)

    with pytest.raises(DirectExecutionDenied):
        executor.execute("echo", ["hello"], make_capability("echo"))


def test_executor_success(tmp_path):
    registry = ToolRegistry()
    registry.register("echo", "/bin/echo")
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    executor = PlaygroundExecutor(registry=registry, audit_ledger=ledger)

    ctx = _make_ctx("echo", ("hello",), input_hash="in-123")
    result = executor.execute_authorized(ctx)

    assert result.status == "success"
    assert "hello" in result.stdout
    records = ledger.read_all()
    assert len(records) == 1
    assert records[0]["result"]["tool_name"] == "echo"


def test_audit_hash_is_written(tmp_path):
    registry = ToolRegistry()
    registry.register("echo", "/bin/echo")
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    executor = PlaygroundExecutor(registry=registry, audit_ledger=ledger)

    ctx = _make_ctx("echo", ("hello",), input_hash="in-456")
    executor.execute_authorized(ctx)

    records = ledger.read_all()
    assert "ledger_hash" in records[0]
    assert len(records[0]["ledger_hash"]) == 128


def test_execution_hash_is_deterministic_for_same_identity(tmp_path):
    registry = ToolRegistry()
    registry.register("echo", "/bin/echo")
    ledger = AuditLedger(tmp_path / "audit.jsonl")
    executor = PlaygroundExecutor(registry=registry, audit_ledger=ledger)

    ctx_one = _make_ctx("echo", ("hello",), input_hash="in-789", runtime_version="v1")
    ctx_two = _make_ctx("echo", ("hello",), input_hash="in-789", runtime_version="v1")
    result_one = executor.execute_authorized(ctx_one)
    result_two = executor.execute_authorized(ctx_two)

    assert result_one.execution_hash == result_two.execution_hash
