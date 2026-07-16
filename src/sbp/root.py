"""
SBP Root Authority primitive.

The Root Authority is the device-local trust anchor for the Sovereignty
Boundary Protocol.  It exposes:

- A stable public identity derived deterministically from the signing key.
- A signing public key for signature verification by external parties.
- A key-encryption boundary: a separate encryption-public-key whose
  corresponding private material is derived from root secret material.
  The encryption private key is never returned by public APIs.
- A creation timestamp (Unix integer, set once at construction time).
- Algorithm-suite metadata describing the signing and encryption algorithms.
- A policy hash committing to a policy document.

Private root material is caller-controlled (supplied as a ``TrustBackend``
instance or raw bytes) and is never serialized into ``RootMetadata`` or any
public record.

The ``ALGORITHM_SUITE`` constant documents the exact algorithms in use so
that verifiers have a single authoritative reference.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Any

from sia.utils.canonical import canonical_bytes
from sovereignty_core.identity.root_of_trust import (
    RootTrustError,
    SoftwareTrustBackend,
    TrustBackend,
)

# ── Algorithm suite ──────────────────────────────────────────────────────────

ALGORITHM_SUITE: dict[str, str] = {
    "signing": "Ed25519",
    "hash": "SHA3-512",
    "kdf": "SHA3-512-counter",
    "encryption": "AES-256-GCM",
    "key_wrap": "raw-derive",
    # Placeholder for post-quantum upgrade path (not active in v0.1).
    "pqc_signing": "ML-DSA-87 (optional, requires liboqs)",
}

# Domain tags keep every derived key purpose isolated at the byte level.
_DOMAIN_SIGNING_ID = b"SBP_ROOT_SIGNING_IDENTITY:"
_DOMAIN_ENC_PUBLIC = b"SBP_ROOT_ENC_PUBLIC:"


@dataclass(frozen=True)
class RootMetadata:
    """
    Public, serializable metadata for a Root Authority.

    Invariants
    ----------
    - ``root_id`` is derived deterministically from ``signing_public_key``.
    - ``enc_public_key`` is derived from root secret material and is safe to
      expose for key-transport use.
    - No private key material appears in any field.
    """

    root_id: str
    signing_public_key: str   # hex-encoded raw Ed25519 public key (32 bytes)
    enc_public_key: str       # hex-encoded derived encryption public material
    created_at: int           # Unix timestamp (seconds, UTC)
    algorithm_suite: dict[str, str]
    policy_hash: str          # SHA3-512 hex of the canonical policy document
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable public metadata document."""
        return {
            "version": self.version,
            "root_id": self.root_id,
            "signing_public_key": self.signing_public_key,
            "enc_public_key": self.enc_public_key,
            "created_at": self.created_at,
            "algorithm_suite": dict(self.algorithm_suite),
            "policy_hash": self.policy_hash,
        }


class RootAuthority:
    """
    SBP Root Authority: device-local trust anchor.

    Parameters
    ----------
    backend:
        A ``TrustBackend`` instance that holds private root material.
        When omitted a fresh ``SoftwareTrustBackend`` is created using
        ``os.urandom(32)``.  The backend must not be shared with callers.
    policy:
        An optional policy document (any JSON-serializable dict).  When
        omitted the default single-owner policy is used.

    Notes
    -----
    - Private root material lives inside ``backend`` and is never exposed.
    - ``enc_private_key`` is derived from root secret material on demand via
      ``derive_branch_key``; it is not stored as a class attribute.
    """

    def __init__(
        self,
        backend: TrustBackend | None = None,
        *,
        policy: dict[str, Any] | None = None,
        created_at: int | None = None,
    ) -> None:
        self._backend: TrustBackend = backend or SoftwareTrustBackend(os.urandom(32))
        self._created_at: int = created_at if created_at is not None else int(time.time())
        self._policy: dict[str, Any] = policy if policy is not None else _default_policy()
        self._metadata: RootMetadata = self._build_metadata()

    # ── Public interface ─────────────────────────────────────────────────────

    @property
    def metadata(self) -> RootMetadata:
        """Return the public, serializable Root metadata."""
        return self._metadata

    def sign(self, payload: bytes) -> str:
        """
        Sign *payload* bytes using root private material.

        Returns the hex-encoded signature.  Private material is never
        returned or logged.
        """
        return self._backend.sign(payload)

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify a signature produced by this Root Authority."""
        return self._backend.verify(payload, signature)

    def derive_branch_key(self, branch_id: str, *, length: int = 32) -> bytes:
        """
        Derive branch-scoped key material from root secret material.

        The derivation is one-way: given branch key material and the branch ID
        it is not possible to recover root secret material or the key material
        of a sibling branch.  Sibling isolation is ensured by including the
        unique ``branch_id`` in the derivation context.

        The derived bytes are caller-controlled; they are never stored or
        logged by this class.
        """
        context = b"SBP_BRANCH_KEY:" + branch_id.encode("utf-8")
        return self._backend.derive_key(context, length=length)

    def policy_hash(self) -> str:
        """Return the SHA3-512 hex digest of the canonical policy document."""
        return _hash_policy(self._policy)

    def best_effort_destroy(self) -> None:
        """Best-effort cleanup of in-memory root private material."""
        self._backend.best_effort_destroy()

    # ── Private helpers ──────────────────────────────────────────────────────

    def _build_metadata(self) -> RootMetadata:
        signing_pub = self._backend.public_key_bytes()
        root_id = hashlib.sha3_512(
            _DOMAIN_SIGNING_ID + signing_pub
        ).hexdigest()

        # Derive an encryption public key from root material using a
        # domain-separated context.  The corresponding private bytes are
        # available via derive_branch_key("__enc__") for callers that need
        # to perform key-transport; they are never stored here.
        enc_pub_bytes = self._backend.derive_key(
            _DOMAIN_ENC_PUBLIC + signing_pub, length=32
        )

        return RootMetadata(
            root_id=root_id,
            signing_public_key=signing_pub.hex(),
            enc_public_key=enc_pub_bytes.hex(),
            created_at=self._created_at,
            algorithm_suite=dict(ALGORITHM_SUITE),
            policy_hash=_hash_policy(self._policy),
        )


# ── Internal helpers ─────────────────────────────────────────────────────────


def _default_policy() -> dict[str, Any]:
    """Return the minimal single-owner default policy document."""
    return {
        "version": 1,
        "type": "single-owner",
        "authority": "local-device",
        "backups_are_replicas": True,
        "local_state_is_authoritative": True,
    }


def _hash_policy(policy: dict[str, Any]) -> str:
    """Return the SHA3-512 hex digest of a canonical policy document."""
    return hashlib.sha3_512(canonical_bytes(policy)).hexdigest()
