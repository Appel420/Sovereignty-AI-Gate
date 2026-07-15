#!/usr/bin/env python3
"""Local-first Model Context Protocol server for Sovereignty AI Studio."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "2025-03-26"
MAX_FILE_BYTES = 1_000_000
MAX_LIST_RESULTS = 200
VALID_MODES = frozenset({"offline", "hybrid", "online"})
SENSITIVE_SUFFIXES = frozenset({".env", ".key", ".pem", ".p12", ".pfx", ".token"})
REPOSITORY_ROOT = Path(__file__).resolve().parent


class SovereignMCPServer:
    """A bounded, credential-free MCP tool provider."""

    def __init__(self, workspace: Path | None = None, mode: str | None = None) -> None:
        requested_workspace = workspace or Path(
            os.environ.get("SG_MCP_WORKSPACE", REPOSITORY_ROOT)
        )
        self.workspace = requested_workspace.resolve()
        requested_mode = mode or os.environ.get("SG_MCP_MODE", "offline")
        self.mode = requested_mode if requested_mode in VALID_MODES else "offline"

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
            return self._result(request_id, {"tools": self._tools()})
        if method == "tools/call":
            params = request.get("params", {})
            if not isinstance(params, dict):
                return self._error(request_id, -32602, "Invalid tool parameters")
            return self._call_tool(request_id, params)
        return self._error(request_id, -32601, f"Method not found: {method}")

    def _tools(self) -> list[dict[str, Any]]:
        return [
            self._tool("sovereignty_status", "Report local server security boundaries.", {}),
            self._tool(
                "workspace_list",
                "List non-hidden, non-sensitive files in the local workspace.",
                {"path": {"type": "string", "description": "Optional relative directory."}},
            ),
            self._tool(
                "workspace_read",
                "Read a bounded UTF-8 text file from the local workspace.",
                {"path": {"type": "string", "description": "Required relative file path."}},
                required=["path"],
            ),
            self._tool(
                "workspace_analyze",
                "Produce read-only syntax and whitespace diagnostics for a workspace file.",
                {"path": {"type": "string", "description": "Required relative file path."}},
                required=["path"],
            ),
            self._tool(
                "workspace_repo_status",
                "Report bounded repository status without exposing shell access.",
                {},
            ),
        ]

    @staticmethod
    def _tool(
        name: str, description: str, properties: dict[str, Any], required: list[str] | None = None
    ) -> dict[str, Any]:
        schema: dict[str, Any] = {
            "type": "object",
            "properties": properties,
            "additionalProperties": False,
        }
        if required:
            schema["required"] = required
        return {"name": name, "description": description, "inputSchema": schema}

    def _call_tool(self, request_id: Any, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return self._error(request_id, -32602, "Tool name and arguments must be valid")
        allowed_arguments = {
            "sovereignty_status": set(),
            "workspace_list": {"path"},
            "workspace_read": {"path"},
            "workspace_analyze": {"path"},
            "workspace_repo_status": set(),
        }
        if name not in allowed_arguments:
            return self._error(request_id, -32602, f"Unknown tool: {name}")
        if set(arguments) - allowed_arguments[name]:
            return self._tool_error(request_id, "Unsupported tool arguments")
        try:
            if name == "sovereignty_status":
                payload: dict[str, Any] = {
                    "mode": self.mode,
                    "workspace": str(self.workspace),
                    "network": "disabled by this MCP server",
                    "credentials": "not accepted, stored, or transmitted",
                }
            elif name == "workspace_list":
                payload = self._list_workspace(arguments.get("path", ""))
            elif name == "workspace_read":
                payload = self._read_workspace(arguments.get("path"))
            elif name == "workspace_analyze":
                payload = self._analyze_workspace(arguments.get("path"))
            else:
                payload = self._repo_status()
        except (OSError, UnicodeDecodeError, ValueError) as error:
            return self._tool_error(request_id, str(error))
        return self._result(
            request_id,
            {"content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}]},
        )

    def _resolve_workspace_path(self, relative_path: Any) -> Path:
        if not isinstance(relative_path, str) or not relative_path:
            raise ValueError("A non-empty relative path is required")
        candidate = (self.workspace / relative_path).resolve()
        try:
            candidate.relative_to(self.workspace)
        except ValueError as error:
            raise ValueError("Path must remain within the configured workspace") from error
        if self._is_restricted(candidate):
            raise ValueError("Hidden and sensitive files cannot be accessed")
        return candidate

    def _is_restricted(self, path: Path) -> bool:
        relative = path.relative_to(self.workspace)
        return any(
            part.startswith(".") for part in relative.parts if part not in {".", ".."}
        ) or path.suffix.lower() in SENSITIVE_SUFFIXES

    def _list_workspace(self, relative_path: Any) -> dict[str, Any]:
        directory = self.workspace if relative_path == "" else self._resolve_workspace_path(relative_path)
        if not directory.is_dir():
            raise ValueError("Path is not a directory")
        files: list[str] = []
        for item in directory.rglob("*"):
            if len(files) >= MAX_LIST_RESULTS:
                break
            resolved = item.resolve()
            if item.is_file() and resolved.is_relative_to(self.workspace) and not self._is_restricted(resolved):
                files.append(str(resolved.relative_to(self.workspace)))
        return {"files": sorted(files), "truncated": len(files) == MAX_LIST_RESULTS}

    def _read_workspace(self, relative_path: Any) -> dict[str, str]:
        file_path = self._resolve_workspace_path(relative_path)
        if not file_path.is_file():
            raise ValueError("Path is not a file")
        if file_path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"File exceeds {MAX_FILE_BYTES} byte read limit")
        return {"path": str(file_path.relative_to(self.workspace)), "content": file_path.read_text("utf-8")}

    def _analyze_workspace(self, relative_path: Any) -> dict[str, Any]:
        file_path = self._resolve_workspace_path(relative_path)
        if not file_path.is_file():
            raise ValueError("Path is not a file")
        if file_path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"File exceeds {MAX_FILE_BYTES} byte read limit")
        content = file_path.read_text("utf-8")
        diagnostics = [
            {"rule": "trailing-whitespace", "line": line_number}
            for line_number, line in enumerate(content.splitlines(), start=1)
            if line.rstrip() != line
        ]
        if file_path.suffix == ".py":
            try:
                ast.parse(content, filename=str(file_path))
            except SyntaxError as error:
                diagnostics.insert(
                    0,
                    {"rule": "syntax-error", "line": error.lineno or 1, "message": error.msg},
                )
        return {
            "path": str(file_path.relative_to(self.workspace)),
            "diagnostics": diagnostics,
            "writeAccess": "disabled; review and apply fixes explicitly in the agent branch",
        }

    def _repo_status(self) -> dict[str, Any]:
        status = {
            "branch": "unknown",
            "commit": "unknown",
            "staged_count": 0,
            "unstaged_count": 0,
            "untracked_count": 0,
            "clean": True,
            "workspace": str(self.workspace),
            "shell_access": "disabled; repository status is read-only",
        }
        try:
            result = subprocess.run(
                ["git", "status", "--porcelain=v1", "--branch"],
                cwd=self.workspace,
                capture_output=True,
                check=True,
                text=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return status
        for line in result.stdout.splitlines():
            if line.startswith("## "):
                status["branch"] = line[3:].split("...", maxsplit=1)[0] or "unknown"
            elif line.startswith("?? "):
                status["untracked_count"] += 1
            else:
                status["staged_count"] += int(line[0] != " ")
                status["unstaged_count"] += int(line[1] != " ")
        try:
            status["commit"] = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.workspace,
                capture_output=True,
                check=True,
                text=True,
                timeout=5,
            ).stdout.strip()
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        status["clean"] = not any(
            status[key] for key in ("staged_count", "unstaged_count", "untracked_count")
        )
        return status

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
