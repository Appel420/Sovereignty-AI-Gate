"""
Utility: canonical JSON serialization for deterministic hashing.

All objects that enter the audit ledger or are signed must be
serialized with `canonical_json()` to ensure byte-for-byte
reproducibility across platforms.
"""
from __future__ import annotations

import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """
    Serialize *obj* to a canonical UTF-8 JSON byte string.

    Rules:
    - Keys are sorted lexicographically (recursive).
    - No extra whitespace.
    - Unicode characters are NOT escaped (ensure_ascii=False).
    - The result is UTF-8 encoded.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def canonical_dict(obj: Any) -> Any:
    """
    Return a new object with all dict keys sorted recursively.
    Useful for normalising objects before comparison.
    """
    if isinstance(obj, dict):
        return {k: canonical_dict(v) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [canonical_dict(i) for i in obj]
    return obj
