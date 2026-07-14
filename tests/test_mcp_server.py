import json
import tempfile
from pathlib import Path

from mcp_server import PROTOCOL_VERSION, SovereignMCPServer


def call_tool(server: SovereignMCPServer, name: str, arguments: dict | None = None) -> dict:
    response = server.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}}}
    )
    assert response is not None
    return response


def tool_text(server: SovereignMCPServer, name: str, arguments: dict | None = None) -> dict:
    response = call_tool(server, name, arguments)
    return json.loads(response["result"]["content"][0]["text"])


def test_status_and_initialize_are_local_first() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        server = SovereignMCPServer(workspace=Path(temporary_directory))
        response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert response is not None
        assert response["result"]["protocolVersion"] == PROTOCOL_VERSION
        assert tool_text(server, "sovereignty_status")["network"] == "disabled by this MCP server"


def test_workspace_tools_restrict_sensitive_files_and_path_escape() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        workspace = Path(temporary_directory)
        (workspace / "notes.txt").write_text("local data", encoding="utf-8")
        (workspace / ".env").write_text("TOKEN=private", encoding="utf-8")
        (workspace / "private.pem").write_text("private", encoding="utf-8")
        server = SovereignMCPServer(workspace=workspace)

        assert tool_text(server, "workspace_list")["files"] == ["notes.txt"]
        assert tool_text(server, "workspace_read", {"path": "notes.txt"})["content"] == "local data"
        for path in (".env", "private.pem", "../etc/passwd"):
            assert call_tool(server, "workspace_read", {"path": path})["result"]["isError"]


def test_analysis_is_read_only_and_reports_diagnostics() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        workspace = Path(temporary_directory)
        (workspace / "broken.py").write_text("def bad(:  \n", encoding="utf-8")
        result = tool_text(SovereignMCPServer(workspace=workspace), "workspace_analyze", {"path": "broken.py"})

        assert result["diagnostics"][0]["rule"] == "syntax-error"
        assert any(item["rule"] == "trailing-whitespace" for item in result["diagnostics"])
        assert result["writeAccess"].startswith("disabled")


def test_repo_status_is_read_only_and_has_safe_defaults() -> None:
    with tempfile.TemporaryDirectory() as temporary_directory:
        result = tool_text(SovereignMCPServer(workspace=Path(temporary_directory)), "workspace_repo_status")

        assert result["clean"] is True
        assert result["shell_access"].startswith("disabled")
