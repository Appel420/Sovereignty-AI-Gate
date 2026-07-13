from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Tuple


@dataclass(frozen=True)
class ToolCapability:
    tool_id: str
    allowed_commands: Tuple[str, ...]
    max_runtime_seconds: int
    owner: str
    expires_at: datetime
    signature: str

    def is_expired(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        return current >= expires_at


@dataclass(frozen=True)
class ToolExecutionRequest:
    tool_name: str
    args: Tuple[str, ...]
    capability: ToolCapability
    input_hash: str
    requester: str = ""


@dataclass(frozen=True)
class ToolExecutionResult:
    tool_name: str
    status: str
    stdout: str
    stderr: str
    returncode: int
    input_hash: str
    execution_hash: str
    timestamp: str
    signature: str
