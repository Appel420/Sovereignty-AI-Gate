"""
SBP canonical serialization and validation codec.

The codec provides strict encode/decode round-trips for ``RootMetadata`` and
``BranchMetadata`` records.  Unknown fields in deserialized dictionaries are
rejected so that the record type remains a closed schema.  Malformed or
missing required fields raise ``CodecError``.

Canonical encoding uses ``sia.utils.canonical.canonical_bytes`` to ensure
byte-for-byte reproducibility across platforms.
"""

from __future__ import annotations

from typing import Any

from sia.utils.canonical import canonical_bytes, canonical_json
from sbp.root import RootMetadata, ALGORITHM_SUITE
from sbp.branch import BranchMetadata


class CodecError(ValueError):
    """Raised when a record fails schema validation or codec round-trip."""


# ── Root Authority codec ──────────────────────────────────────────────────────

# Exact set of top-level keys permitted in a serialized RootMetadata document.
_ROOT_REQUIRED: frozenset[str] = frozenset({
    "version",
    "root_id",
    "signing_public_key",
    "enc_public_key",
    "created_at",
    "algorithm_suite",
    "policy_hash",
})


def encode_root(meta: RootMetadata) -> dict[str, Any]:
    """
    Encode a ``RootMetadata`` to a validated canonical dictionary.

    The returned dict contains only the fields defined in the closed schema.
    """
    doc = meta.to_dict()
    _validate_root_doc(doc)
    return doc


def encode_root_bytes(meta: RootMetadata) -> bytes:
    """Return canonical UTF-8 JSON bytes for a ``RootMetadata`` record."""
    return canonical_bytes(encode_root(meta))


def decode_root(doc: dict[str, Any]) -> RootMetadata:
    """
    Decode and validate a ``RootMetadata`` from a raw dictionary.

    Raises ``CodecError`` if required fields are missing, unknown fields are
    present, or field types are wrong.
    """
    _validate_root_doc(doc)
    try:
        return RootMetadata(
            version=int(doc["version"]),
            root_id=str(doc["root_id"]),
            signing_public_key=str(doc["signing_public_key"]),
            enc_public_key=str(doc["enc_public_key"]),
            created_at=int(doc["created_at"]),
            algorithm_suite=dict(doc["algorithm_suite"]),
            policy_hash=str(doc["policy_hash"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CodecError(f"Malformed RootMetadata record: {exc}") from exc


# ── Branch codec ──────────────────────────────────────────────────────────────

_BRANCH_REQUIRED: frozenset[str] = frozenset({
    "version",
    "branch_id",
    "root_id",
    "parent_branch_id",
    "owner_id",
    "capabilities",
    "policy_hash",
    "created_at",
    "label",
})


def encode_branch(meta: BranchMetadata) -> dict[str, Any]:
    """
    Encode a ``BranchMetadata`` to a validated canonical dictionary.

    The returned dict contains only the fields defined in the closed schema.
    """
    doc = meta.to_dict()
    _validate_branch_doc(doc)
    return doc


def encode_branch_bytes(meta: BranchMetadata) -> bytes:
    """Return canonical UTF-8 JSON bytes for a ``BranchMetadata`` record."""
    return canonical_bytes(encode_branch(meta))


def decode_branch(doc: dict[str, Any]) -> BranchMetadata:
    """
    Decode and validate a ``BranchMetadata`` from a raw dictionary.

    Raises ``CodecError`` if required fields are missing, unknown fields are
    present, or field types are wrong.
    """
    _validate_branch_doc(doc)
    try:
        parent = doc["parent_branch_id"]
        if parent is not None:
            parent = str(parent)
        return BranchMetadata(
            version=int(doc["version"]),
            branch_id=str(doc["branch_id"]),
            root_id=str(doc["root_id"]),
            parent_branch_id=parent,
            owner_id=str(doc["owner_id"]),
            capabilities=tuple(sorted(str(c) for c in doc["capabilities"])),
            policy_hash=str(doc["policy_hash"]),
            created_at=int(doc["created_at"]),
            label=str(doc["label"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CodecError(f"Malformed BranchMetadata record: {exc}") from exc


# ── Validation helpers ────────────────────────────────────────────────────────


def _validate_root_doc(doc: dict[str, Any]) -> None:
    """Raise ``CodecError`` if *doc* does not match the Root schema."""
    _check_exact_keys(doc, _ROOT_REQUIRED, "RootMetadata")
    _require_nonempty_str(doc, "root_id", "RootMetadata")
    _require_nonempty_str(doc, "signing_public_key", "RootMetadata")
    _require_nonempty_str(doc, "enc_public_key", "RootMetadata")
    _require_nonempty_str(doc, "policy_hash", "RootMetadata")
    _require_positive_int(doc, "created_at", "RootMetadata")
    _require_positive_int(doc, "version", "RootMetadata")
    if not isinstance(doc.get("algorithm_suite"), dict):
        raise CodecError("RootMetadata.algorithm_suite must be a dict")
    # Require at least the signing and hash algorithm entries.
    suite = doc["algorithm_suite"]
    for key in ("signing", "hash"):
        if key not in suite:
            raise CodecError(
                f"RootMetadata.algorithm_suite is missing required key '{key}'"
            )


def _validate_branch_doc(doc: dict[str, Any]) -> None:
    """Raise ``CodecError`` if *doc* does not match the Branch schema."""
    _check_exact_keys(doc, _BRANCH_REQUIRED, "BranchMetadata")
    _require_nonempty_str(doc, "branch_id", "BranchMetadata")
    _require_nonempty_str(doc, "root_id", "BranchMetadata")
    _require_nonempty_str(doc, "owner_id", "BranchMetadata")
    _require_nonempty_str(doc, "policy_hash", "BranchMetadata")
    _require_nonempty_str(doc, "label", "BranchMetadata")
    _require_positive_int(doc, "created_at", "BranchMetadata")
    _require_positive_int(doc, "version", "BranchMetadata")
    if not isinstance(doc.get("capabilities"), list):
        raise CodecError("BranchMetadata.capabilities must be a list")
    parent = doc.get("parent_branch_id")
    if parent is not None and not isinstance(parent, str):
        raise CodecError("BranchMetadata.parent_branch_id must be a string or null")


def _check_exact_keys(
    doc: dict[str, Any], required: frozenset[str], record_type: str
) -> None:
    """Raise ``CodecError`` on missing or extra keys."""
    present = frozenset(doc.keys())
    missing = required - present
    unknown = present - required
    if missing:
        raise CodecError(
            f"{record_type} is missing required fields: {sorted(missing)}"
        )
    if unknown:
        raise CodecError(
            f"{record_type} contains unknown fields: {sorted(unknown)}"
        )


def _require_nonempty_str(doc: dict[str, Any], key: str, record_type: str) -> None:
    value = doc.get(key)
    if not isinstance(value, str) or not value:
        raise CodecError(f"{record_type}.{key} must be a non-empty string")


def _require_positive_int(doc: dict[str, Any], key: str, record_type: str) -> None:
    value = doc.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise CodecError(f"{record_type}.{key} must be a positive integer")
