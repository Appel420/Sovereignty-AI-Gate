from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone
from typing import Sequence

from sia.utils.canonical import canonical_bytes

from .audit import AuditLedger
from .models import ToolCapability, ToolExecutionRequest, ToolExecutionResult
from .registry import ToolRegistry
from .validator import ToolValidator


class PlaygroundExecutor:
    """Capability-bound local execution for a gated playground.

    Execution is restricted to registered tools and produces auditable results,
    but it is intentionally not a sandbox.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        validator: ToolValidator | None = None,
        audit_ledger: AuditLedger | None = None,
    ) -> None:
        self.registry = registry
        self.validator = validator or ToolValidator()
        self.audit_ledger = audit_ledger

    def execute(
        self,
        tool_name: str,
        args: Sequence[str],
        capability: ToolCapability,
        input_hash: str = "",
        requester: str = "",
        runtime_version: str = "",
    ) -> ToolExecutionResult:
        request = ToolExecutionRequest(
            tool_name=tool_name,
            args=tuple(args),
            capability=capability,
            input_hash=input_hash,
            requester=requester,
        )
        self.validator.validate(request)

        executable = self.registry.resolve(tool_name)
        result = subprocess.run(
            [executable, *args],
            capture_output=True,
            text=True,
            timeout=capability.max_runtime_seconds,
            check=False,
        )

        timestamp = datetime.now(timezone.utc).isoformat()
        stdout_hash = hashlib.sha256(result.stdout.encode("utf-8")).hexdigest()
        stderr_hash = hashlib.sha256(result.stderr.encode("utf-8")).hexdigest()
        execution_hash = self._hash_execution(
            tool_name=tool_name,
            args=args,
            input_hash=input_hash,
            stdout_hash=stdout_hash,
            stderr_hash=stderr_hash,
            returncode=result.returncode,
            runtime_version=runtime_version,
        )
        signature = self._hash_signature(capability.signature, execution_hash)

        output = ToolExecutionResult(
            tool_name=tool_name,
            status="success" if result.returncode == 0 else "error",
            stdout=result.stdout,
            stderr=result.stderr,
            returncode=result.returncode,
            input_hash=input_hash,
            execution_hash=execution_hash,
            timestamp=timestamp,
            signature=signature,
        )

        if self.audit_ledger is not None:
            self.audit_ledger.record(request, output)

        return output

    def _hash_execution(
        self,
        *,
        tool_name: str,
        args: Sequence[str],
        input_hash: str,
        stdout_hash: str,
        stderr_hash: str,
        returncode: int,
        runtime_version: str,
    ) -> str:
        payload = {
            "tool_name": tool_name,
            "args": list(args),
            "input_hash": input_hash,
            "stdout_hash": stdout_hash,
            "stderr_hash": stderr_hash,
            "returncode": returncode,
            "runtime_version": runtime_version,
        }
        encoded = canonical_bytes(payload)
        return hashlib.sha256(encoded).hexdigest()

    def _hash_signature(self, capability_signature: str, execution_hash: str) -> str:
        payload = f"{capability_signature}:{execution_hash}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()
