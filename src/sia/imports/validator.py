"""
Imports: validator.

Validates ImportBundle objects per RFC-0019 before they are loaded
into the local authority state.
"""
from __future__ import annotations

from sia.errors import codes
from sia.errors.exceptions import ImportError as SIAImportError
from sia.imports.models import ImportBundle, SUPPORTED_VERSIONS
from sia.utils.hashing import sha256_object

REQUIRED_FIELDS = {
    "bundle_id", "created_by", "payload", "payload_hash",
    "signature", "schema_version", "created_at",
}


def validate_import(bundle: ImportBundle) -> None:
    """
    Validate an ImportBundle's structure and payload hash integrity.

    Does NOT verify the cryptographic signature; that step requires
    the signer's public key and is handled by the loader.

    Raises:
        SIAImportError: if any validation check fails.
    """
    d = bundle.to_dict()

    missing = REQUIRED_FIELDS - d.keys()
    if missing:
        raise SIAImportError(
            codes.E_IMPORT_SCHEMA_INVALID,
            f"Missing required import fields: {missing}",
        )

    if d["schema_version"] not in SUPPORTED_VERSIONS:
        raise SIAImportError(
            codes.E_IMPORT_VERSION_UNSUPPORTED,
            f"Unsupported import schema version '{d['schema_version']}'.",
        )

    for field_name in ("bundle_id", "created_by", "payload_hash", "signature"):
        if not isinstance(d[field_name], str) or not d[field_name]:
            raise SIAImportError(
                codes.E_IMPORT_SCHEMA_INVALID,
                f"'{field_name}' must be a non-empty string.",
            )

    expected_hash = sha256_object(d["payload"])
    if d["payload_hash"] != expected_hash:
        raise SIAImportError(
            codes.E_IMPORT_SCHEMA_INVALID,
            f"payload_hash mismatch: expected {expected_hash}.",
        )
