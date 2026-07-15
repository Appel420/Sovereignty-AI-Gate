# PR-001 Design Notes — Governed MCP Entry Point

## Scope

PR-001 governs privileged MCP `tools/call` workspace operations without changing provider flows, dashboard code, deployment assets, or unrelated authority paths.

## MCPAuthorityAdapter

`MCPAuthorityAdapter` is the single translation layer between JSON-RPC MCP requests and the existing Sovereignty AI Gate authority pipeline.

Responsibilities:

- expose the canonical MCP tool surface
- validate MCP tool names and argument shapes
- translate governed workspace tools into canonical `ProtectedOperation` values
- construct `OperationRequest` values using supplied identity and capability context
- invoke `AuthorityGate` through `SovereignAuthority.authorize_operation()`
- return structured denial and execution-failure outcomes
- record MCP evidence with the existing audit recorder

`mcp_server.py` remains protocol-only: request parsing, protocol dispatch, and adapter delegation.

## Canonical MCP tool surface

- `sovereignty_status`
- `workspace_list`
- `workspace_read`
- `workspace_analyze`
- `workspace_repo_status`

Only the workspace-prefixed tools are privileged and governed.

## MCP to OperationRequest mapping

| MCP tool | ProtectedOperation | Resource id |
|---|---|---|
| `workspace_list` | `WORKSPACE_LIST` | requested relative path or `.` |
| `workspace_read` | `WORKSPACE_READ` | requested relative path |
| `workspace_analyze` | `WORKSPACE_ANALYZE` | requested relative path |
| `workspace_repo_status` | `WORKSPACE_REPO_STATUS` | `.` |

Identity is supplied as an `IdentityContext`-compatible object.
Capability and optional parent capability are supplied as `CapabilityRecord`-compatible objects.

## Authorization flow

```text
mcp_server.py
    ↓
MCPAuthorityAdapter
    ↓
OperationRequest
    ↓
AuthorityGate
    ↓
AuthorizationDecision
    ↓
WorkspaceExecutor
    ↓
AuditRecorder
```

- `initialize`, `tools/list`, and notifications remain protocol operations.
- Denied workspace requests fail closed before the workspace executor runs.
- Approved requests execute only after `AuthorizationDecision.allowed` is true.
- Workspace execution remains read-only and filesystem-bounded.

## Evidence model

Every governed MCP workspace request appends `mcp.operation` evidence with:

- `request_id`
- `operation`
- `identity_id`
- `capability_id`
- `policy_hash`
- `decision`
- `result`
- `failure_reason`

The append-only audit ledger entry timestamp remains the canonical event timestamp.

## Workspace safety model

`WorkspaceExecutor` owns filesystem behavior only:

- workspace confinement
- path traversal prevention
- hidden and sensitive file rejection
- bounded file reads
- read-only diagnostics
- shell-free repository status
- no networking

## Test plan

Focused MCP tests cover:

- anonymous request denial
- missing capability denial
- expired capability denial
- policy denial evidence
- successful authorized read evidence
- path traversal rejection
- hidden file rejection
- oversized file rejection
- unauthorized execution bypass prevention
- authorized `workspace_analyze`
- authorized `workspace_repo_status`
