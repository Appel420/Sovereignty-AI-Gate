"""Offline SBP v0.2 protocol contracts.

These contracts define canonical, signed records without introducing a
transport.  Implementations may carry the records over any local or remote
medium, but verification and conflict handling are transport-independent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from sia.utils.canonical import canonical_bytes
from sbp.object import ObjectEnvelope
from sbp.root import RootAuthority

PROTOCOL_NAME = "SBP"
PROTOCOL_VERSION = "0.2.0"
SUITE_ID = "SBP-INTEROP-0.2/Ed25519-SHA3-512-AES-256-GCM"


class ProtocolError(ValueError):
    """Raised when an SBP protocol record is invalid."""


def _require_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class CapabilityOffer:
    """Canonical capability offer exchanged by two SBP peers."""

    peer_id: str
    protocol: str
    version: str
    capabilities: tuple[str, ...]
    suite: str = SUITE_ID

    def __post_init__(self) -> None:
        _require_string(self.peer_id, "peer_id")
        if self.protocol != PROTOCOL_NAME or self.version != PROTOCOL_VERSION:
            raise ProtocolError("unsupported SBP protocol version")
        caps = tuple(_require_string(c, "capability") for c in self.capabilities)
        object.__setattr__(self, "capabilities", caps)
        if len(set(self.capabilities)) != len(self.capabilities):
            raise ProtocolError("capabilities must be unique")
        if tuple(sorted(self.capabilities)) != self.capabilities:
            raise ProtocolError("capabilities must be sorted")
        _require_string(self.suite, "suite")

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol,
            "version": self.version,
            "suite": self.suite,
            "peer_id": self.peer_id,
            "capabilities": list(self.capabilities),
        }


def negotiate_capabilities(
    local: CapabilityOffer, remote: CapabilityOffer
) -> tuple[str, ...]:
    """Return the deterministic intersection of two compatible offers."""
    if local.protocol != remote.protocol or local.version != remote.version:
        raise ProtocolError("capability negotiation version mismatch")
    if local.suite != remote.suite:
        raise ProtocolError("capability negotiation suite mismatch")
    return tuple(sorted(set(local.capabilities) & set(remote.capabilities)))


@dataclass(frozen=True)
class AuthorityExchange:
    """A signed statement binding a peer identity to its public root record."""

    exchange_id: str
    peer_id: str
    root_id: str
    signing_public_key: str
    capabilities: tuple[str, ...]
    signature: str
    version: int = 1

    def signing_document(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "exchange_id": self.exchange_id,
            "peer_id": self.peer_id,
            "root_id": self.root_id,
            "signing_public_key": self.signing_public_key,
            "capabilities": list(self.capabilities),
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.signing_document(), "signature": self.signature}


def create_authority_exchange(
    root: RootAuthority,
    *,
    exchange_id: str,
    peer_id: str,
    capabilities: list[str],
) -> AuthorityExchange:
    exchange_id = _require_string(exchange_id, "exchange_id")
    peer_id = _require_string(peer_id, "peer_id")
    caps = tuple(sorted(set(_require_string(c, "capability") for c in capabilities)))
    record = AuthorityExchange(
        exchange_id=exchange_id,
        peer_id=peer_id,
        root_id=root.metadata.root_id,
        signing_public_key=root.metadata.signing_public_key,
        capabilities=caps,
        signature="",
    )
    signature = root.sign(canonical_bytes(record.signing_document()))
    return AuthorityExchange(**{**record.signing_document(), "signature": signature})


def verify_authority_exchange(record: AuthorityExchange) -> bool:
    """Verify the exchange signature using the advertised Ed25519 key."""
    import hashlib
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        exchange_id = _require_string(record.exchange_id, "exchange_id")
        peer_id = _require_string(record.peer_id, "peer_id")
        root_id = _require_string(record.root_id, "root_id")
        signing_public_key = _require_string(record.signing_public_key, "signing_public_key")
        signature = _require_string(record.signature, "signature")

        signing_key_bytes = bytes.fromhex(signing_public_key)
        expected_root_id = hashlib.sha3_512(
            b"SBP_ROOT_SIGNING_IDENTITY:" + signing_key_bytes
        ).hexdigest()
        if root_id != expected_root_id:
            return False

        caps = tuple(_require_string(c, "capability") for c in record.capabilities)
        if len(set(caps)) != len(caps) or tuple(sorted(caps)) != caps:
            return False

        signing_doc = {
            "version": record.version,
            "exchange_id": exchange_id,
            "peer_id": peer_id,
            "root_id": root_id,
            "signing_public_key": signing_public_key,
            "capabilities": list(caps),
        }

        key = Ed25519PublicKey.from_public_bytes(signing_key_bytes)
        key.verify(bytes.fromhex(signature), canonical_bytes(signing_doc))
        return True
    except (ProtocolError, InvalidSignature, ValueError, TypeError):
        return False


@dataclass(frozen=True)
class Delegation:
    """A narrowly scoped, root-signed capability delegation."""

    delegation_id: str
    grantor_id: str
    grantee_id: str
    branch_id: str
    capabilities: tuple[str, ...]
    expires_at: int | None
    signature: str
    version: int = 1

    def signing_document(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "delegation_id": self.delegation_id,
            "grantor_id": self.grantor_id,
            "grantee_id": self.grantee_id,
            "branch_id": self.branch_id,
            "capabilities": list(self.capabilities),
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.signing_document(), "signature": self.signature}


def create_delegation(
    root: RootAuthority,
    *,
    delegation_id: str,
    grantee_id: str,
    branch_id: str,
    capabilities: list[str],
    parent_capabilities: list[str] | None = None,
    expires_at: int | None = None,
) -> Delegation:
    delegation_id = _require_string(delegation_id, "delegation_id")
    grantee_id = _require_string(grantee_id, "grantee_id")
    branch_id = _require_string(branch_id, "branch_id")

    caps = tuple(sorted(set(_require_string(c, "capability") for c in capabilities)))
    if parent_capabilities is not None:
        parent_caps = set(
            _require_string(c, "parent_capability") for c in parent_capabilities
        )
        if not set(caps).issubset(parent_caps):
            raise ProtocolError("delegation exceeds parent capabilities")

    record = Delegation(
        delegation_id=delegation_id,
        grantor_id=root.metadata.root_id,
        grantee_id=grantee_id,
        branch_id=branch_id,
        capabilities=caps,
        expires_at=expires_at,
        signature="",
    )
    signature = root.sign(canonical_bytes(record.signing_document()))
    return Delegation(**{**record.signing_document(), "signature": signature})


def verify_delegation(
    delegation: Delegation,
    root: RootAuthority,
    *,
    required_capability: str | None = None,
    now: int | None = None,
) -> bool:
    try:
        if delegation.grantor_id != root.metadata.root_id:
            return False

        caps = tuple(_require_string(c, "capability") for c in delegation.capabilities)
        if len(set(caps)) != len(caps) or tuple(sorted(caps)) != caps:
            return False

        if delegation.expires_at is not None and now is not None and now >= delegation.expires_at:
            return False
        if required_capability is not None and required_capability not in caps:
            return False

        signing_doc = {
            "version": delegation.version,
            "delegation_id": _require_string(delegation.delegation_id, "delegation_id"),
            "grantor_id": delegation.grantor_id,
            "grantee_id": _require_string(delegation.grantee_id, "grantee_id"),
            "branch_id": _require_string(delegation.branch_id, "branch_id"),
            "capabilities": list(caps),
            "expires_at": delegation.expires_at,
        }
        return root.verify(canonical_bytes(signing_doc), delegation.signature)
    except (ProtocolError, TypeError, ValueError):
        return False


@dataclass(frozen=True)
class ReplicationRecord:
    """An encrypted object replica; it never contains authority material."""

    object_id: str
    branch_id: str
    envelope: dict[str, Any]
    source_root_id: str
    replica_id: str
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "object_id": self.object_id,
            "branch_id": self.branch_id,
            "envelope": dict(self.envelope),
            "source_root_id": self.source_root_id,
            "replica_id": self.replica_id,
        }

    @classmethod
    def from_envelope(
        cls, envelope: ObjectEnvelope, *, source_root_id: str, replica_id: str
    ) -> "ReplicationRecord":
        if (
            not envelope.object_id
            or not envelope.branch_id
            or not envelope.ciphertext_hex
            or not envelope.nonce_hex
        ):
            raise ProtocolError("replication requires an encrypted envelope")
        _require_string(source_root_id, "source_root_id")
        _require_string(replica_id, "replica_id")
        return cls(
            object_id=envelope.object_id,
            branch_id=envelope.branch_id,
            envelope=envelope.to_dict(),
            source_root_id=source_root_id,
            replica_id=replica_id,
        )


def resolve_replication_conflict(
    left: ReplicationRecord, right: ReplicationRecord
) -> ReplicationRecord:
    """Choose a stable winner without granting the replica authority."""
    if left.object_id != right.object_id or left.branch_id != right.branch_id:
        raise ProtocolError("replication conflict records must share object and branch")
    return min(
        (left, right),
        key=lambda record: (record.replica_id, canonical_bytes(record.to_dict())),
    )
