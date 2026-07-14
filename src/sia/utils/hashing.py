"""
Utility: deterministic hashing helpers.

All hashes used inside SIA are SHA-256. The helpers here produce
hex-encoded strings by default (lowercase, 64 characters).
"""
from __future__ import annotations

import hashlib
from typing import Any

from sia.utils.canonical import canonical_bytes

HASH_ALGORITHM = "sha256"
DEFAULT_DOMAIN = "SIA_ARTIFACT"


def sha256_bytes(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of *data*."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def canonical_hash(obj: Any, *, domain: str = DEFAULT_DOMAIN) -> str:
    """Hash canonical bytes with optional domain separation."""
    domain_bytes = domain.encode("utf-8")
    payload_bytes = canonical_bytes(obj)
    return sha256_hex(domain_bytes + b"\x00" + payload_bytes)


def sha256_object(obj: Any) -> str:
    """Return the hex-encoded SHA-256 digest of canonical bytes for *obj*."""
    return canonical_hash(obj)


def chain_hash(previous_hash: str, entry: Any, *, domain: str = DEFAULT_DOMAIN) -> str:
    """Compute the chained hash for an audit ledger entry."""
    prev_bytes = previous_hash.encode("utf-8")
    entry_bytes = canonical_bytes(entry)
    return sha256_hex(domain.encode("utf-8") + b"\x00" + prev_bytes + b"\x00" + entry_bytes)
