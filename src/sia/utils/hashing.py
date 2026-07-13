"""
Utility: deterministic hashing helpers.

All hashes used inside SIA are SHA-256. The helpers here produce
hex-encoded strings by default (lowercase, 64 characters).
"""
from __future__ import annotations

import hashlib
from typing import Any

from sia.utils.canonical import canonical_json


def sha256_bytes(data: bytes) -> bytes:
    """Return the raw 32-byte SHA-256 digest of *data*."""
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def sha256_object(obj: Any) -> str:
    """
    Return the hex-encoded SHA-256 digest of the canonical JSON
    representation of *obj*.
    """
    return sha256_hex(canonical_json(obj))


def chain_hash(previous_hash: str, entry: Any) -> str:
    """
    Compute the chained hash for an audit ledger entry.

    ``H_n = SHA256(H_{n-1} || canonical_json(entry))``
    """
    prev_bytes = previous_hash.encode("utf-8")
    entry_bytes = canonical_json(entry)
    return sha256_hex(prev_bytes + entry_bytes)
