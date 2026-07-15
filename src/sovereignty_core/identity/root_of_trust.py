"""
Root-of-trust abstractions for the Sovereign AI Memory Architecture.

The root layer defines the stable contract that higher SAMA layers depend
on. It does not pretend to be a production cryptographic implementation.
Production deployments should supply platform-backed adapters that keep
root material inside a secure device boundary.

Development cryptography:
  SoftwareTrustBackend uses DEV-HMAC-SHA256 (HMAC-SHA256 over a session
  secret). This profile is development-only. It MUST NOT be used in
  production authority paths. A visible [DEV] warning is emitted to stderr
  whenever this backend is instantiated, per RFC-0021.
"""

from __future__ import annotations

import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import hmac
import secrets
import time


class RootTrustError(RuntimeError):
    """Raised when a root-of-trust operation cannot be completed."""


class DevelopmentSigner:
    """
    Deterministic development-only integrity helper.

    WARNING:
    This is not a public-key signature scheme. It exists only for local
    testing and interface validation. Production backends must use secure
    platform signing APIs or modern signature algorithms such as Ed25519.
    """

    @staticmethod
    def sign(secret: bytes, payload: bytes) -> str:
        return hmac.new(secret, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def verify(secret: bytes, payload: bytes, signature: str) -> bool:
        expected = DevelopmentSigner.sign(secret, payload)
        return hmac.compare_digest(expected, signature)


class TrustBackend(ABC):
    """
    Stable backend contract for device-rooted trust material.

    Higher layers depend on this interface rather than platform-specific
    hardware APIs.
    """

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Return a stable identifier for the backend implementation."""

    @property
    @abstractmethod
    def hardware_backed(self) -> bool:
        """Return whether the backend is backed by secure hardware."""

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """
        Return the signing algorithm identifier for this backend.

        Development backends return ``"DEV-HMAC-SHA256"``.
        Production backends return a standard identifier such as
        ``"Ed25519"`` or ``"ML-DSA-87"``.
        """

    @abstractmethod
    def public_key_bytes(self) -> bytes:
        """Return public root material that is safe to expose."""

    @abstractmethod
    def sign(self, payload: bytes) -> str:
        """Sign payload bytes without exposing root material."""

    @abstractmethod
    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify a signature produced by this backend."""

    @abstractmethod
    def derive_key(self, context: bytes, *, length: int = 32) -> bytes:
        """Derive deterministic key material for a scoped local purpose."""

    @abstractmethod
    def best_effort_destroy(self) -> None:
        """
        Best-effort cleanup of in-memory authority material.

        Python cannot guarantee secure erasure; hardware adapters may offer
        stronger deletion semantics.
        """


class SoftwareTrustBackend(TrustBackend):
    """
    Development backend that stores root material in process memory.

    This backend is intentionally explicit and human-readable. It is suitable
    for local testing only and must not be treated as a hardware root.

    [DEV] WARNING: This backend uses DEV-HMAC-SHA256, which is not a
    public-key scheme and provides no hardware-backed attestation. It MUST
    NOT be used in production authority paths. A warning is printed to
    stderr on instantiation.
    """

    _DEV_ALGORITHM = "DEV-HMAC-SHA256"

    def __init__(self, root_secret: bytes | None = None) -> None:
        self._root_secret = root_secret or secrets.token_bytes(32)
        print(
            "[DEV] SoftwareTrustBackend activated — algorithm: DEV-HMAC-SHA256. "
            "This backend is development-only and MUST NOT be used in production "
            "authority paths. Replace with a hardware-backed TrustBackend for "
            "production deployments.",
            file=sys.stderr,
        )

    @property
    def backend_name(self) -> str:
        return "software"

    @property
    def hardware_backed(self) -> bool:
        return False

    @property
    def algorithm(self) -> str:
        return self._DEV_ALGORITHM

    def public_key_bytes(self) -> bytes:
        return hashlib.sha256(b"SAMA_ROOT_PUBLIC:" + self._root_secret).digest()

    def sign(self, payload: bytes) -> str:
        return DevelopmentSigner.sign(self._root_secret, payload)

    def verify(self, payload: bytes, signature: str) -> bool:
        return DevelopmentSigner.verify(self._root_secret, payload, signature)

    def derive_key(self, context: bytes, *, length: int = 32) -> bytes:
        if length <= 0:
            raise RootTrustError("Derived key length must be positive")

        output = bytearray()
        counter = 0
        while len(output) < length:
            block = hashlib.sha256(
                b"SAMA_DERIVE:" + counter.to_bytes(4, "big") + context + self._root_secret
            ).digest()
            output.extend(block)
            counter += 1
        return bytes(output[:length])

    def best_effort_destroy(self) -> None:
        self._root_secret = b""


@dataclass(frozen=True)
class DeviceIdentity:
    """Public device identity derived deterministically from root authority."""

    identity_id: str
    public_key: str
    backend_name: str
    hardware_backed: bool
    created_at: int
    version: int = 1


@dataclass(frozen=True)
class SignedObject:
    """Signature envelope for sovereignty objects."""

    payload_hash: str
    signature: str
    signer: str
    timestamp: int
    algorithm: str = "DEV-HMAC-SHA256"


class RootOfTrust:
    """
    Stable SAMA contract for device-rooted authority.

    Responsibilities:
    - expose public device identity
    - derive deterministic local-only authority material
    - sign sovereignty objects without exposing private root material
    """

    def __init__(self, backend: TrustBackend | None = None) -> None:
        self._backend = backend or SoftwareTrustBackend()
        self._identity = self._create_identity()

    @property
    def backend(self) -> TrustBackend:
        """Return the configured root backend."""

        return self._backend

    @property
    def identity(self) -> DeviceIdentity:
        """Return the public device identity."""

        return self._identity

    def _create_identity(self) -> DeviceIdentity:
        public_material = self._backend.public_key_bytes()
        identity_id = hashlib.sha256(b"SAMA_IDENTITY:" + public_material).hexdigest()
        return DeviceIdentity(
            identity_id=identity_id,
            public_key=public_material.hex(),
            backend_name=self._backend.backend_name,
            hardware_backed=self._backend.hardware_backed,
            created_at=int(time.time()),
        )

    def derive_identity_key(self) -> bytes:
        """Derive local identity-scoped key material."""

        return self._backend.derive_key(b"SAMA_IDENTITY_KEY", length=32)

    def derive_vault_key(self) -> bytes:
        """
        Derive local vault key material.

        Vault key material remains separate from identity key material and
        must never be exposed to providers.
        """

        return self._backend.derive_key(b"SAMA_VAULT_KEY", length=32)

    def sign(self, payload: bytes) -> SignedObject:
        """Sign payload bytes using the configured backend."""

        payload_hash = hashlib.sha256(payload).hexdigest()
        signature = self._backend.sign(payload)
        return SignedObject(
            payload_hash=payload_hash,
            signature=signature,
            signer=self.identity.identity_id,
            timestamp=int(time.time()),
            algorithm=self._backend.algorithm,
        )

    def verify(self, payload: bytes, signed: SignedObject) -> bool:
        """Verify payload integrity and backend signature."""

        expected_hash = hashlib.sha256(payload).hexdigest()
        if expected_hash != signed.payload_hash:
            return False
        return self._backend.verify(payload, signed.signature)

    def verify_signature(self, payload: bytes, signature: str) -> bool:
        """Verification hook for higher-layer signed objects."""

        return self._backend.verify(payload, signature)

    def export_public_identity(self) -> dict[str, object]:
        """Return a serializable public-only identity document."""

        return {
            "identity_id": self.identity.identity_id,
            "public_key": self.identity.public_key,
            "backend_name": self.identity.backend_name,
            "hardware_backed": self.identity.hardware_backed,
            "created_at": self.identity.created_at,
            "version": self.identity.version,
        }

    def best_effort_destroy(self) -> None:
        """Best-effort cleanup of local authority material."""

        self._backend.best_effort_destroy()
