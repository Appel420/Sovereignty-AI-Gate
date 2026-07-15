import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from mcp_server import PROTOCOL_VERSION, SovereignMCPServer
from sia import ProtectedOperation, SovereignAuthority
from sia.mcp_authority import MAX_FILE_BYTES, MCPAuthorityAdapter, WorkspaceExecutor


def call_tool(
    server: SovereignMCPServer,
    name: str,
    arguments: dict | None = None,
    **extra_params: object,
) -> dict:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}, **extra_params},
        }
    )
    assert response is not None
    return response


def tool_text(
    server: SovereignMCPServer,
    name: str,
    arguments: dict | None = None,
    **extra_params: object,
) -> dict:
    response = call_tool(server, name, arguments, **extra_params)
    return json.loads(response["result"]["content"][0]["text"])


def make_server(
    workspace: Path,
    *,
    policy: dict | None = None,
    workspace_executor: WorkspaceExecutor | None = None,
) -> tuple[SovereignMCPServer, SovereignAuthority]:
    authority = SovereignAuthority(
        owner_id="user:alice",
        policy=policy or {"default": "deny", "rules": []},
    )
    authority.initialize()
    adapter = MCPAuthorityAdapter(
        workspace=workspace,
        mode="offline",
        authority=authority,
        workspace_executor=workspace_executor,
    )
    return SovereignMCPServer(workspace=workspace, authority_adapter=adapter), authority


def identity_payload(authority: SovereignAuthority) -> dict:
    identity = authority.identity_context()
    return {
        "identity_id": identity.identity_id,
        "device_id": identity.device_id,
        "verified": identity.verified,
        "metadata": dict(identity.metadata),
    }


def capability_payload(
    authority: SovereignAuthority,
    *,
    capability_id: str,
    scopes: list[str],
    expires_at: str | int | None = None,
    revoked: bool = False,
) -> dict:
    return {
        "capability_id": capability_id,
        "owner_identity": authority.owner_id,
        "scopes": scopes,
        "expires_at": expires_at
        if expires_at is not None
        else int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
        "revoked": revoked,
        "issuer_device": authority.identity_context().device_id,
    }


def allow_policy(*operations: ProtectedOperation) -> dict:
    return {
        "default": "deny",
        "rules": [
            {
                "id": f"allow-{operation.value.lower()}",
                "effect": "allow",
                "match": {"operation": operation.value},
            }
            for operation in operations
        ],
    }


def last_mcp_event(authority: SovereignAuthority):
    event = authority.ledger.tail(1)[0]
    assert event.event_type == "mcp.operation"
    return event


class SpyExecutor(WorkspaceExecutor):
    def __init__(self, workspace: Path) -> None:
        super().__init__(workspace)
        self.called = False

    def execute(self, tool_name: str, arguments: dict[str, object]) -> dict[str, object]:
        self.called = True
        return super().execute(tool_name, arguments)


def test_status_initialize_and_tool_surface_are_local_first(tmp_path: Path) -> None:
    server, _authority = make_server(tmp_path)

    response = server.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize"})

    assert response is not None
    assert response["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert tool_text(server, "sovereignty_status")["network"] == "disabled by this MCP server"
    listed_tools = server.handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert listed_tools is not None
    assert [tool["name"] for tool in listed_tools["result"]["tools"]] == [
        "sovereignty_status",
        "workspace_list",
        "workspace_read",
        "workspace_analyze",
        "workspace_repo_status",
    ]


def test_workspace_tools_require_identity_and_do_not_execute_directly(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("local data", encoding="utf-8")
    spy_executor = SpyExecutor(tmp_path)
    server, authority = make_server(tmp_path, workspace_executor=spy_executor)

    denied = tool_text(
        server,
        "workspace_read",
        {"path": "notes.txt"},
        capability=capability_payload(
            authority,
            capability_id="cap-anon",
            scopes=["workspace.read"],
        ),
    )

    assert call_tool(
        server,
        "workspace_read",
        {"path": "notes.txt"},
        capability=capability_payload(
            authority,
            capability_id="cap-anon",
            scopes=["workspace.read"],
        ),
    )["result"]["isError"]
    assert denied["decision"] == "NO_IDENTITY"
    assert denied["result"] == "denied"
    assert spy_executor.called is False


def test_workspace_tools_deny_missing_and_expired_capabilities(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("local data", encoding="utf-8")
    server, authority = make_server(tmp_path)
    identity = identity_payload(authority)

    missing = tool_text(
        server,
        "workspace_read",
        {"path": "notes.txt"},
        identity=identity,
    )
    expired = tool_text(
        server,
        "workspace_read",
        {"path": "notes.txt"},
        identity=identity,
        capability=capability_payload(
            authority,
            capability_id="cap-expired",
            scopes=["workspace.read"],
            expires_at=int((datetime.now(timezone.utc) - timedelta(seconds=1)).timestamp()),
        ),
    )

    assert missing["decision"] == "MISSING_CAPABILITY"
    assert missing["result"] == "denied"
    assert expired["decision"] == "EXPIRED_CAPABILITY"
    assert expired["result"] == "denied"


def test_workspace_policy_denial_is_recorded(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("local data", encoding="utf-8")
    server, authority = make_server(tmp_path)

    denial = tool_text(
        server,
        "workspace_read",
        {"path": "notes.txt"},
        identity=identity_payload(authority),
        capability=capability_payload(
            authority,
            capability_id="cap-policy",
            scopes=["workspace.read"],
        ),
    )

    event = last_mcp_event(authority)
    assert denial["decision"] == "POLICY_DENIED"
    assert event.payload["request_id"] == 1
    assert event.payload["operation"] == ProtectedOperation.WORKSPACE_READ.value
    assert event.payload["identity_id"] == authority.owner_id
    assert event.payload["capability_id"] == "cap-policy"
    assert event.payload["result"] == "denied"
    assert event.payload["failure_reason"] == denial["failure_reason"]
    assert event.timestamp


def test_workspace_read_succeeds_after_authorization_and_records_evidence(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("local data", encoding="utf-8")
    server, authority = make_server(
        tmp_path,
        policy=allow_policy(ProtectedOperation.WORKSPACE_READ),
    )

    result = tool_text(
        server,
        "workspace_read",
        {"path": "notes.txt"},
        identity=identity_payload(authority),
        capability=capability_payload(
            authority,
            capability_id="cap-read",
            scopes=["workspace.read"],
        ),
    )

    event = last_mcp_event(authority)
    assert result == {"path": "notes.txt", "content": "local data"}
    assert event.payload["decision"] == "AUTHORIZED"
    assert event.payload["result"] == "success"
    assert event.payload["failure_reason"] is None


def test_workspace_execution_failures_are_rejected_and_recorded(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("local data", encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=private", encoding="utf-8")
    (tmp_path / "huge.txt").write_text("x" * (MAX_FILE_BYTES + 1), encoding="utf-8")
    server, authority = make_server(
        tmp_path,
        policy=allow_policy(ProtectedOperation.WORKSPACE_READ),
    )
    auth = {
        "identity": identity_payload(authority),
        "capability": capability_payload(
            authority,
            capability_id="cap-read",
            scopes=["workspace.read"],
        ),
    }

    hidden = tool_text(server, "workspace_read", {"path": ".env"}, **auth)
    traversal = tool_text(server, "workspace_read", {"path": "../etc/passwd"}, **auth)
    oversized = tool_text(server, "workspace_read", {"path": "huge.txt"}, **auth)

    assert hidden["result"] == "error"
    assert hidden["failure_reason"] == "Hidden and sensitive files cannot be accessed"
    assert traversal["failure_reason"] == "Path must remain within the configured workspace"
    assert oversized["failure_reason"] == f"File exceeds {MAX_FILE_BYTES} byte read limit"
    assert last_mcp_event(authority).payload["result"] == "error"


def test_workspace_analyze_is_governed_read_only_and_audited(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text("def bad(:  \n", encoding="utf-8")
    server, authority = make_server(
        tmp_path,
        policy=allow_policy(ProtectedOperation.WORKSPACE_ANALYZE),
    )

    result = tool_text(
        server,
        "workspace_analyze",
        {"path": "broken.py"},
        identity=identity_payload(authority),
        capability=capability_payload(
            authority,
            capability_id="cap-analyze",
            scopes=["workspace.analyze"],
        ),
    )

    event = last_mcp_event(authority)
    assert result["diagnostics"][0]["rule"] == "syntax-error"
    assert any(item["rule"] == "trailing-whitespace" for item in result["diagnostics"])
    assert result["writeAccess"].startswith("disabled")
    assert event.payload["operation"] == ProtectedOperation.WORKSPACE_ANALYZE.value
    assert event.payload["result"] == "success"


def test_workspace_repo_status_is_governed_and_shell_free(tmp_path: Path) -> None:
    server, authority = make_server(
        tmp_path,
        policy=allow_policy(ProtectedOperation.WORKSPACE_REPO_STATUS),
    )

    result = tool_text(
        server,
        "workspace_repo_status",
        identity=identity_payload(authority),
        capability=capability_payload(
            authority,
            capability_id="cap-status",
            scopes=["workspace.repo_status"],
        ),
    )

    event = last_mcp_event(authority)
    assert result["clean"] is True
    assert result["shell_access"].startswith("disabled")
    assert result["status_source"] == "filesystem"
    assert event.payload["operation"] == ProtectedOperation.WORKSPACE_REPO_STATUS.value
    assert event.payload["result"] == "success"
