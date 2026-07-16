# S-004 — Governed GitHub Deployment Skill

**Status:** DESIGN ONLY  
**Authorization:** NOT AUTHORIZED FOR IMPLEMENTATION  
**Dependency:** S-001B completion and acceptance  
**Merge:** Manual pull request review only

## 1. Purpose

`sovereignty-github-pusher` is a proposed high-trust execution skill for governed GitHub repository operations. It may create or deploy verified sovereign code artifacts only through the governed skill runtime.

This document records the architecture boundary. It does not authorize implementation, connector activation, repository deployment, or merge activity.

## 2. Ownership boundary

The skill must not directly own GitHub authority.

```text
Skill
  ↓
SkillRuntime / Executor
  ↓
AuthorityGate
  ↓
Capability issuance or denial
  ↓
Registered GitHub connector
  ↓
Evidence plane
```

The GitHub connector is a governed dependency, not a hidden execution path.

## 3. Proposed manifest

```yaml
name: sovereignty-github-pusher
version: "1.0.0"
owner: "Appel420"
trust_level: "sovereign-core"
description: "Governed GitHub deployment capability for verified sovereign code artifacts."
requires:
  - identity-authority
  - authority-gate
  - scar-log
  - code-validator
  - pqc-attestation
  - github-connector
provides:
  - github repository management
  - governed code deployment
  - commit attestation tracking
permissions:
  memory_read: gated
  memory_write: consent_required
  network_access: github_only
  file_write: local_only
  repository_write: gated
  repository_create: approval_required
audit_events:
  - SKILL_ACTIVATED
  - REPOSITORY_CREATED
  - FILE_PUSHED
  - COMMIT_CREATED
  - PUSH_FAILED
  - SKILL_DENIED
aliases:
  - github-push
  - sovereignty-push
  - push-repml
  - fix-ecosystem
```

The manifest is a design proposal and is not an implementation artifact yet.

## 4. AuthorityGate request

GitHub operations must enter the authority path as an `OperationRequest`:

```python
request = OperationRequest(
    operation="github_push",
    actor=identity_context,
    target="sovereignty-github-pusher",
    capability="repository.write",
    context_hash=context_hash,
    reason="user_requested_push",
    metadata={
        "repo": "sovereignty-one-core",
        "branch": "main",
        "artifact_type": "REPML",
        "verification_required": True,
    },
)
```

The expected decision path is:

```text
OperationRequest
    ↓
Identity check
    ↓
Capability check
    ↓
Repository policy
    ↓
Code validation
    ↓
PQC/SCAR attestation
    ↓
GitHub operation
```

A denial must fail closed and emit auditable evidence. The skill must not invoke a connector before authorization is granted.

## 5. Pre-push validation

Before invoking the GitHub connector, the runtime must complete the applicable validation steps:

```text
SkillExecutor
    ↓
CodeValidator
    ├── placeholder and fake implementation checks
    ├── accidental secret detection
    ├── dependency audit
    ├── test-status verification
    └── manifest validation
    ↓
PQC/SCAR attestation where required
    ↓
GitHub connector
```

The exact validator and attestation implementations remain subject to the later S-004 implementation plan.

## 6. Evidence

Every GitHub operation must produce canonical evidence in the Evidence Plane. The event should include authorization linkage in addition to repository and artifact details:

```json
{
  "event": "GITHUB_PUSH",
  "request_id": "...",
  "authorization_id": "...",
  "skill": "sovereignty-github-pusher",
  "identity_id": "...",
  "repo": "sovereignty-one-core",
  "branch": "main",
  "files": [
    "core/repml.js",
    "index.html"
  ],
  "commit_sha": "...",
  "artifact_hash": "...",
  "pqc_signature": "...",
  "scar_entry": "...",
  "decision": "ALLOW",
  "timestamp": "..."
}
```

Denials and failures must also be recorded with an appropriate reason and execution status.

## 7. Human-visible execution boundary

Before any repository mutation, the runtime must expose a readable preflight containing at least:

```text
execution_id
identity
repository
workspace
base branch
target branch
allowed scope
forbidden scope
requested tools
network policy
approval requirement
```

The actual operation must match the approved plan. Scope deviation must block the operation and record evidence for human review.

No hidden connector, background push, implicit repository permission, or silent cloud fallback is permitted.

## 8. Security and sovereignty constraints

- Use only registered GitHub connectors through `SkillRuntime`.
- Require explicit authority for repository writes.
- Require separate approval for repository creation.
- Restrict network access to the approved GitHub connector.
- Keep private keys local; never transmit raw private keys.
- Preserve user control over data sharing, workspace access, repository mutation, external communication, and merges.
- Do not use fake cryptography, placeholder security claims, or random stand-ins for security functionality.
- Do not merge automatically; manual pull request review is required.

## 9. Scope and dependency status

This artifact does not authorize:

- implementation of the skill;
- GitHub connector activation;
- repository creation or deployment;
- CI/CD integration;
- provider or MCP changes;
- S-002 identity or workspace implementation;
- changes to the active S-001B implementation scope.

Dependency ordering:

```text
S-001B — Governed Tool Execution Backend
    ↓
S-002 — Skill Registry and Manifest Enforcement
    ↓
S-003 — Connector Governance Layer
    ↓
S-004 — Governed GitHub Deployment Skill
```

S-004 remains a future consumer of the governed execution primitives, not a dependency that modifies S-001B.
