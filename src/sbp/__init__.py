"""
Sovereignty Boundary Protocol (SBP) — Reference v0.1

This package provides the foundational protocol primitives for the SBP:

- Root Authority: device-rooted trust anchor with stable public identity,
  signing key, key-encryption boundary, and policy hash.  Private root
  material is caller-controlled and never serialized into public records.
- Branch: cryptographic namespace derived from Root; carries deterministic
  identity, parent lineage, owner, capabilities, and branch-scoped keys.
- Object manifest: encrypted object envelope binding object identity to a
  Branch, content hash, encryption metadata, and ownership metadata.
- Audit entry: append-only, hash-chained, device-signed audit record for
  later Merkle verification.
- Codec: canonical serialization and strict validation for Root and Branch
  records, rejecting unknown or malformed fields.

Design constraints
------------------
- Device-first / offline-first by default.
- No network calls or cloud dependencies in the core primitives.
- Private root material is never serialized or returned by public APIs.
- All signatures are real (Ed25519 via the existing TrustBackend contract).
- Reuses ``sia.utils.canonical`` and ``sovereignty_core.identity.root_of_trust``
  rather than duplicating cryptographic utilities.
"""

from sbp.root import RootAuthority, RootMetadata
from sbp.branch import Branch, BranchMetadata
from sbp.object import ObjectManifest, ObjectEnvelope
from sbp.audit import AuditEntry, AuditChain
from sbp.codec import CodecError, encode_root, decode_root, encode_branch, decode_branch

__all__ = [
    "AuditChain",
    "AuditEntry",
    "Branch",
    "BranchMetadata",
    "CodecError",
    "ObjectEnvelope",
    "ObjectManifest",
    "RootAuthority",
    "RootMetadata",
    "decode_branch",
    "decode_root",
    "encode_branch",
    "encode_root",
]
__version__ = "0.1.0"
