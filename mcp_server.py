#!/usr/bin/env python3
"""Local-first Model Context Protocol server for Sovereignty AI Studio."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from sia.mcp_authority import MCPAuthorityAdapter

PROTOCOL_VERSION = "2025-03-26"
VALID_MODES = frozenset({"offline", "hybrid", "online"})
REPOSITORY_ROOT = Path(__file__).resolve().parent


class SovereignMCPServer:
    """A bounded, credential-free MCP tool provider."""

    def __init__(
        self,
        workspace: Path | None = None,
        mode: str | None = None,
        authority_adapter: MCPAuthorityAdapter | None = None,
    ) -> None:
        requested_workspace = workspace or Path(
            os.environ.get("SG_MCP_WORKSPACE", REPOSITORY_ROOT)
        )
        self.workspace = requested_workspace.resolve()
        requested_mode = mode or os.environ.get("SG_MCP_MODE", "offline")
        self.mode = requested_mode if requested_mode in VALID_MODES else "offline"
        self.authority_adapter = authority_adapter or MCPAuthorityAdapter(
            workspace=self.workspace,
            mode=self.mode,
        )

    def handle(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one JSON-RPC request, returning None for notifications."""
        method = request.get("method")
        request_id = request.get("id")
        if not isinstance(method, str):
            return self._error(request_id, -32600, "Invalid Request")
        if request.get("jsonrpc") != "2.0":
            return self._error(request_id, -32600, "JSON-RPC version must be 2.0")
        if method == "notifications/initialized":
            return None
        if method == "initialize":
            return self._result(
                request_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "sovereignty-ai-studio",
                        "version": "1.0.0",
                    },
                },
            )
        if method == "tools/list":
            return self._result(request_id, {"tools": self.authority_adapter.tools()})
        if method == "tools/call":
            params = request.get("params", {})
            if not isinstance(params, dict):
                return self._error(request_id, -32602, "Invalid tool parameters")
            try:
                tool_result = self.authority_adapter.call_tool(request_id, params)
            except ValueError as error:
                return self._tool_error(request_id, str(error))
            return self._result(request_id, tool_result.to_mcp_result())
        return self._error(request_id, -32601, f"Method not found: {method}")

    @staticmethod
    def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @classmethod
    def _tool_error(cls, request_id: Any, message: str) -> dict[str, Any]:
        return cls._result(
            request_id, {"content": [{"type": "text", "text": message}], "isError": True}
        )

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def main() -> None:
    """Run the newline-delimited stdio MCP transport."""
    server = SovereignMCPServer()
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError("Request must be a JSON object")
            response = server.handle(request)
        except (json.JSONDecodeError, ValueError) as error:
            response = SovereignMCPServer._error(None, -32700, str(error))
        if response is not None:
            print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
