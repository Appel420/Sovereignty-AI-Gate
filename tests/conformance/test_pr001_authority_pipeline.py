from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sia import LocalMockProvider, ProtectedOperation, SovereignAuthority
from sia.authority_gate import AuthorizedContextPacket, IdentityContext, OperationRequest
from sia.delegation.models import DelegationToken
from sia.memory.models import MemoryRecord
from sia.tools import PlaygroundExecutor, ToolCapability, ToolRegistry
from sia.tools.audit import AuditLedger as ToolAuditLedger
from sia.utils.hashing import sha256_object
from sovereignty_core.permissions.capability import CapabilityScope, CapabilityToken


def make_authority(operation: ProtectedOperation) -> SovereignAuthority:
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


def make_delegation(
    scope: list[str],
    *,
    grantee_id: str = "delegate:test",
    expires_at: datetime | None = None,
    parent_id: str | None = None,
) -> DelegationToken:
    return DelegationToken(
        token_id=f"tok-{grantee_id}-{len(scope)}",
        grantor_id="user:alice",
        grantee_id=grantee_id,
        scope=scope,
        expires_at=(expires_at or (datetime.now(timezone.utc) + timedelta(hours=1))).isoformat(),
        parent_id=parent_id,
    )


def make_tool_capability() -> ToolCapability:
    return ToolCapability(
        tool_id="local.shell.echo",
        allowed_commands=("echo",),
        max_runtime_seconds=5,
        owner="device-root",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        signature="signed-capability",
    )


def test_no_identity_denied_and_audited():
    authority = make_authority(ProtectedOperation.READ_MEMORY)
    request = OperationRequest(
        operation=ProtectedOperation.READ_MEMORY,
        identity=None,
        capability=make_delegation(["memory.read"]),
    )

    decision = authority.authorize_operation(request)

    assert decision.allowed is False
    assert decision.reason_code == "NO_IDENTITY"
    event = authority.authority_evidence.ledger.events[-1]
    assert event.metadata["allowed"] is False
    assert event.metadata["reason_code"] == "NO_IDENTITY"


def test_invalid_identity_denied_and_audited():
    authority = make_authority(ProtectedOperation.READ_MEMORY)
    request = OperationRequest(
        operation=ProtectedOperation.READ_MEMORY,
        identity=IdentityContext(
            identity_id="user:mallory",
            device_id=authority.identity_context().device_id,
            verified=True,
        ),
        capability=make_delegation(["memory.read"]),
    )

    decision = authority.authorize_operation(request)

    assert decision.allowed is False
    assert decision.reason_code == "INVALID_IDENTITY"
    event = authority.authority_evidence.ledger.events[-1]
    assert event.metadata["reason_code"] == "INVALID_IDENTITY"


def test_missing_capability_denied_and_audited():
    authority = make_authority(ProtectedOperation.WRITE_MEMORY)
    record = MemoryRecord(record_id="mem-001", model_id="model:gpt4", content={"text": "hello"})

    decision = authority.store_memory_authorized(
        authority.make_operation_request(
            ProtectedOperation.WRITE_MEMORY,
            resource_id=record.record_id,
            model_id=record.model_id,
        ),
        record,
    )

    assert decision.allowed is False
    assert decision.reason_code == "MISSING_CAPABILITY"
    assert len(authority.ledger) == 1
    assert len(authority.vault.chain.blocks) == 0


def test_expired_capability_denied():
    authority = make_authority(ProtectedOperation.READ_MEMORY)
    expired = make_delegation(
        ["memory.read"],
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    decision = authority.authorize_operation(
        authority.make_operation_request(
            ProtectedOperation.READ_MEMORY,
            capability=expired,
            resource_id="mem-expired",
        )
    )

    assert decision.allowed is False
    assert decision.reason_code == "EXPIRED_CAPABILITY"


def test_child_capability_cannot_exceed_parent_scope():
    authority = make_authority(ProtectedOperation.WRITE_MEMORY)
    parent = make_delegation(["memory.read"], grantee_id="delegate:parent")
    child = make_delegation(
        ["memory.write"],
        grantee_id="delegate:child",
        parent_id=parent.token_id,
    )

    decision = authority.authorize_operation(
        authority.make_operation_request(
            ProtectedOperation.WRITE_MEMORY,
            capability=child,
            parent_capability=parent,
            resource_id="mem-child",
        )
    )

    assert decision.allowed is False
    assert decision.reason_code == "CHILD_SCOPE_EXCEEDED"


def test_policy_rejection_denied_and_audited():
    authority = SovereignAuthority(
        owner_id="user:alice",
        policy={"default": "deny", "rules": []},
    )
    authority.initialize()
    capability = CapabilityToken.create(
        provider_id="provider:copilot",
        owner_identity="user:alice",
        scopes=[CapabilityScope.READ_CONTEXT_WINDOW],
        issuer_device=authority.identity_context().device_id or "device-1",
        signature="sig-1",
        ttl_seconds=60,
    )

    decision = authority.authorize_operation(
        authority.make_operation_request(
            ProtectedOperation.READ_MEMORY,
            capability=capability,
            resource_id="mem-policy",
        )
    )

    assert decision.allowed is False
    assert decision.reason_code == "POLICY_DENIED"
    event = authority.authority_evidence.ledger.events[-1]
    assert event.metadata["reason_code"] == "POLICY_DENIED"


def test_approved_action_audited():
    authority = make_authority(ProtectedOperation.READ_MEMORY)
    capability = CapabilityToken.create(
        provider_id="provider:copilot",
        owner_identity="user:alice",
        scopes=[CapabilityScope.READ_CONTEXT_WINDOW],
        issuer_device=authority.identity_context().device_id or "device-1",
        signature="sig-2",
        ttl_seconds=60,
    )

    decision = authority.authorize_operation(
        authority.make_operation_request(
            ProtectedOperation.READ_MEMORY,
            capability=capability,
            resource_id="mem-approved",
        )
    )

    assert decision.allowed is True
    assert decision.reason_code == "AUTHORIZED"
    assert decision.capability_id == capability.token_id
    assert decision.audit_required is True
    event = authority.authority_evidence.ledger.events[-1]
    assert event.metadata["allowed"] is True
    assert event.capability_id == capability.token_id
    assert event.metadata["policy_hash"] == decision.policy_hash


def test_export_requires_the_gate():
    authority = make_authority(ProtectedOperation.EXPORT_ARCHIVE)
    payload = {"boundaries": [], "version": "0.1.0"}

    decision, bundle = authority.create_export_authorized(
        authority.make_operation_request(
            ProtectedOperation.EXPORT_ARCHIVE,
            resource_id="exp-001",
        ),
        "exp-001",
        payload,
        sha256_object(payload),
        "a" * 128,
    )

    assert decision.allowed is False
    assert decision.reason_code == "MISSING_CAPABILITY"
    assert bundle is None


def test_tool_execution_requires_the_gate(tmp_path):
    authority = make_authority(ProtectedOperation.EXECUTE_TOOL)
    registry = ToolRegistry()
    registry.register("echo", "/bin/echo")
    audit = ToolAuditLedger(tmp_path / "tool-audit.jsonl")
    executor = PlaygroundExecutor(registry=registry, audit_ledger=audit)

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
    assert audit.read_all() == []


def test_provider_execution_requires_an_authorized_context_packet():
    provider = LocalMockProvider()
    packet = AuthorizedContextPacket(
        packet_id="pkt-1",
        provider_id=provider.provider_id,
        owner_identity="user:alice",
        capability_id="cap-1",
        operation=ProtectedOperation.CALL_PROVIDER.value,
        policy_hash="hash-1",
        memory_context=(),
        authorized=False,
    )

    with pytest.raises(ValueError, match="authorized context packet"):
        provider.execute(packet)


def test_provider_receives_no_vault_or_keys():
    authority = make_authority(ProtectedOperation.CALL_PROVIDER)
    provider = LocalMockProvider()
    record = MemoryRecord(
        record_id="mem-provider",
        model_id="model:gpt4",
        content={"text": "approved context"},
    )
    authority.store_memory(record)
    capability = make_delegation(["provider.call"], grantee_id=provider.provider_id)

    decision, response = authority.call_provider_authorized(
        authority.make_operation_request(
            ProtectedOperation.CALL_PROVIDER,
            capability=capability,
            provider_id=provider.provider_id,
            resource_id=record.record_id,
        ),
        provider=provider,
        record_ids=[record.record_id],
    )

    assert decision.allowed is True
    assert response == {
        "provider_id": "local.mock",
        "status": "ok",
        "authorized": True,
        "proof": f"local.mock:CALL_PROVIDER:{capability.token_id}:1",
    }
    assert provider.last_packet is not None
    payload = provider.last_packet.to_dict()
    assert "vault" not in payload
    assert "keys" not in payload
    assert "identity_secret" not in payload
    assert payload["memory_context"] == [
        {
            "record_id": "mem-provider",
            "model_id": "model:gpt4",
            "content": {"text": "approved context"},
        }
    ]


def test_provider_lifecycle_is_authority_owned_and_sequenced():
    authority = make_authority(ProtectedOperation.CALL_PROVIDER)
    provider = LocalMockProvider()
    capability = make_delegation(["provider.call"], grantee_id=provider.provider_id)

    decision, response = authority.call_provider_authorized(
        authority.make_operation_request(
            ProtectedOperation.CALL_PROVIDER,
            capability=capability,
            provider_id=provider.provider_id,
        ),
        provider=provider,
    )

    assert decision.allowed is True
    assert response is not None
    events = [
        entry for entry in authority.ledger.all_entries()
        if entry.event_type.startswith("provider.")
    ]
    assert [event.event_type for event in events] == [
        "provider.requested",
        "provider.approved",
        "provider.completed",
    ]
    assert [event.payload["authority_sequence"] for event in events] == [2, 3, 4]
    assert len({event.payload["correlation_id"] for event in events}) == 1
    assert all(event.payload["provider_id"] == provider.provider_id for event in events)


def test_denied_provider_call_records_authority_failure():
    authority = make_authority(ProtectedOperation.CALL_PROVIDER)
    provider = LocalMockProvider()

    decision, response = authority.call_provider_authorized(
        authority.make_operation_request(
            ProtectedOperation.CALL_PROVIDER,
            provider_id=provider.provider_id,
        ),
        provider=provider,
    )

    assert decision.allowed is False
    assert response is None
    event = authority.ledger.tail(1)[0]
    assert event.event_type == "provider.failed"
    assert event.payload["authority_sequence"] == 1
    assert event.payload["error_category"] == "authorization"
    assert event.payload["error_code"] == "MISSING_CAPABILITY"


def test_audit_chain_verifies():
    authority = make_authority(ProtectedOperation.WRITE_MEMORY)
    denied = authority.authorize_operation(
        authority.make_operation_request(
            ProtectedOperation.WRITE_MEMORY,
            resource_id="mem-denied",
        )
    )
    granted_capability = make_delegation(["memory.write"])
    granted = authority.store_memory_authorized(
        authority.make_operation_request(
            ProtectedOperation.WRITE_MEMORY,
            capability=granted_capability,
            resource_id="mem-granted",
            model_id="model:gpt4",
        ),
        MemoryRecord(
            record_id="mem-granted",
            model_id="model:gpt4",
            content={"text": "stored"},
        ),
    )

    assert denied.allowed is False
    assert granted.allowed is True
    assert authority.verify_authority_evidence() is True


# ── DEV-HMAC-SHA256 / hardware_backed guards (RFC-0021) ──────────────────────


def test_identity_context_hardware_backed_false_for_software_authority():
    """
    SovereignAuthority backed by SoftwareTrustBackend must produce
    IdentityContext with hardware_backed=False.

    This ensures production gates can detect and reject software-backed
    identities when hardware attestation is required.
    """
    authority = make_authority(ProtectedOperation.EXECUTE_TOOL)
    context = authority._identity.identity_context()
    assert context.hardware_backed is False, (
        "Software-backed authority must expose hardware_backed=False "
        "so production gates can enforce hardware attestation requirements."
    )


def test_evidence_bundle_carries_dev_mode_label(capsys):
    """
    When using SoftwareTrustBackend, the exported audit bundle must include
    a dev_mode=True label and a signing_algorithm field per RFC-0021.
    """
    authority = make_authority(ProtectedOperation.EXECUTE_TOOL)
    capability = make_delegation(["tool.execute"])
    authority.authorize_operation(
        authority.make_operation_request(
            ProtectedOperation.EXECUTE_TOOL,
            capability=capability,
            resource_id="tool:test",
        )
    )
    bundle = authority._authority_evidence.export_bundle()
    assert bundle.get("dev_mode") is True, (
        "Audit bundles from software-backed authority must declare dev_mode=True"
    )
    assert bundle.get("signing_algorithm") == "DEV-HMAC-SHA256", (
        "Audit bundle must declare the actual signing algorithm"
    )
    assert "[DEV]" in bundle.get("dev_warning", ""), (
        "Audit bundle must include a human-readable [DEV] warning"
    )
