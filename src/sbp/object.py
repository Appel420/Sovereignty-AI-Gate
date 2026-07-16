"""
SBP encrypted object manifest and envelope.

An object manifest binds an object's identity to its branch, content hash,
encryption metadata, and authorization/ownership metadata.  The manifest
itself is plaintext; the envelope wraps the manifest under AES-256-GCM
authenticated encryption using branch-scoped key material.

Design notes
------------
- ``ObjectManifest`` is a public, signed description of an object.
  It never contains plaintext object content.
- ``ObjectEnvelope`` is the AES-256-GCM–encrypted form of a canonical
  manifest.  The ciphertext, nonce, and tag are stored as hex strings so
  the envelope can be serialized to JSON.
- Encryption uses the ``cryptography`` library (already a project dependency)
  with a 96-bit nonce from ``os.urandom``.
- The envelope ``object_id`` is the SHA3-512 of the canonical manifest bytes,
  making it both a stable reference and an integrity commitment.
- Authorization metadata (owner_id, branch_id) is bound inside the manifest
  and therefore inside the authenticated ciphertext.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from sia.utils.canonical import canonical_bytes
from sbp.branch import Branch


# ── Object manifest ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ObjectManifest:
    """
    Public description of an SBP-managed object.

    Fields
    ------
    object_id:
        SHA3-512 hex of the canonical manifest dict (computed at creation).
    branch_id:
        The branch this object belongs to.
    content_hash:
        SHA3-512 hex of the raw object content (caller-supplied).
    owner_id:
        The root authority owner of this object.
    encryption_algorithm:
        The algorithm used to encrypt the object content.
    created_at:
        Unix timestamp (seconds, UTC).
    metadata:
        Optional additional authorization or descriptive metadata.
    """

    object_id: str
    branch_id: str
    content_hash: str
    owner_id: str
    encryption_algorithm: str
    created_at: int
    metadata: dict[str, Any]
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Return the canonical serializable manifest document."""
        return {
            "version": self.version,
            "object_id": self.object_id,
            "branch_id": self.branch_id,
            "content_hash": self.content_hash,
            "owner_id": self.owner_id,
            "encryption_algorithm": self.encryption_algorithm,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def create(
        cls,
        *,
        branch: Branch,
        content_hash: str,
        metadata: dict[str, Any] | None = None,
        created_at: int | None = None,
    ) -> "ObjectManifest":
        """
        Create a manifest for an object in the given branch.

        The ``object_id`` is computed deterministically from the manifest
        fields, so two manifests with identical inputs produce the same ID.
        """
        ts = created_at if created_at is not None else int(time.time())
        branch_meta = branch.metadata

        # Compute object_id from the core identity fields (without object_id
        # itself to avoid circularity).
        identity_doc = {
            "branch_id": branch_meta.branch_id,
            "content_hash": content_hash,
            "owner_id": branch_meta.owner_id,
            "encryption_algorithm": "AES-256-GCM",
            "created_at": ts,
            "metadata": dict(metadata or {}),
            "version": 1,
        }
        object_id = hashlib.sha3_512(
            b"SBP_OBJECT_ID:" + canonical_bytes(identity_doc)
        ).hexdigest()

        return cls(
            object_id=object_id,
            branch_id=branch_meta.branch_id,
            content_hash=content_hash,
            owner_id=branch_meta.owner_id,
            encryption_algorithm="AES-256-GCM",
            created_at=ts,
            metadata=dict(metadata or {}),
        )


# ── Object envelope ───────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ObjectEnvelope:
    """
    AES-256-GCM–encrypted SBP object envelope.

    The manifest is authenticated and encrypted under branch-scoped key
    material.  The nonce, ciphertext, and tag are stored as hex strings.

    Fields
    ------
    object_id:
        Copied from the enclosed manifest for index purposes.
    branch_id:
        Copied from the manifest.
    nonce_hex:
        Hex-encoded 96-bit AES-GCM nonce (12 bytes).
    ciphertext_hex:
        Hex-encoded AES-GCM ciphertext (includes the 16-byte GCM tag).
    encryption_algorithm:
        ``"AES-256-GCM"`` for this version.
    created_at:
        Unix timestamp.
    version:
        Envelope schema version (``1`` for SBP v0.1).
    """

    object_id: str
    branch_id: str
    nonce_hex: str
    ciphertext_hex: str
    encryption_algorithm: str
    created_at: int
    version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Return the canonical serializable envelope document."""
        return {
            "version": self.version,
            "object_id": self.object_id,
            "branch_id": self.branch_id,
            "nonce_hex": self.nonce_hex,
            "ciphertext_hex": self.ciphertext_hex,
            "encryption_algorithm": self.encryption_algorithm,
            "created_at": self.created_at,
        }


def seal_manifest(
    manifest: ObjectManifest,
    branch: Branch,
    *,
    nonce: bytes | None = None,
) -> ObjectEnvelope:
    """
    Encrypt *manifest* under branch-scoped key material.

    Returns an ``ObjectEnvelope`` containing the AES-256-GCM ciphertext.
    The plaintext canonical manifest bytes are authenticated but not stored
    in the envelope.

    The branch key is derived on demand via ``branch.derive_key()``; it is
    not stored by this function.

    When ``nonce`` is omitted, a fresh cryptographically random 96-bit nonce
    is generated.  The optional ``nonce`` parameter exists only for frozen
    interoperability vectors and deterministic tests; production callers
    should rely on the default random nonce generation.
    """
    key = branch.derive_key(length=32)
    if nonce is None:
        nonce = os.urandom(12)
    elif not isinstance(nonce, bytes):
        raise TypeError("seal_manifest nonce must be bytes")
    else:
        nonce = bytes(nonce)
    if len(nonce) != 12:
        raise ValueError("seal_manifest nonce must be exactly 12 bytes")
    plaintext = canonical_bytes(manifest.to_dict())
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return ObjectEnvelope(
        object_id=manifest.object_id,
        branch_id=manifest.branch_id,
        nonce_hex=nonce.hex(),
        ciphertext_hex=ciphertext.hex(),
        encryption_algorithm="AES-256-GCM",
        created_at=manifest.created_at,
    )


def unseal_manifest(envelope: ObjectEnvelope, branch: Branch) -> ObjectManifest:
    """
    Decrypt an ``ObjectEnvelope`` using branch-scoped key material.

    Raises ``ValueError`` if authentication fails (wrong branch or tampered
    ciphertext).
    """
    import json

    key = branch.derive_key(length=32)
    nonce = bytes.fromhex(envelope.nonce_hex)
    ciphertext = bytes.fromhex(envelope.ciphertext_hex)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError(
            "ObjectEnvelope decryption failed: authentication error or wrong branch key"
        ) from exc
    raw = json.loads(plaintext.decode("utf-8"))
    parent = raw.get("metadata")
    return ObjectManifest(
        version=int(raw["version"]),
        object_id=str(raw["object_id"]),
        branch_id=str(raw["branch_id"]),
        content_hash=str(raw["content_hash"]),
        owner_id=str(raw["owner_id"]),
        encryption_algorithm=str(raw["encryption_algorithm"]),
        created_at=int(raw["created_at"]),
        metadata=dict(parent) if isinstance(parent, dict) else {},
    )
