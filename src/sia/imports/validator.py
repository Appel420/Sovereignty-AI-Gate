"""
Imports: validator.

Validate canonical RFC-0019 import payloads.
"""
from __future__ import annotations

from sia.errors import codes
from sia.errors.exceptions import AuthorityFailure
from sia.errors.exceptions import ImportError as SIAImportError
from sia.imports.models import SUPPORTED_VERSIONS, ImportBundle
from sia.utils.hashing import sha256_object


REQUIRED_FIELDS = {"ledger_version", "ledger_hash", "records"}


def validate_import(bundle: ImportBundle) -> None:
    """Validate an :class:`ImportBundle` against RFC-0019 rules.

    Raises :class:`sia.errors.exceptions.ImportError` with an appropriate
    error code when validation fails.
    """
    if bundle.schema_version not in SUPPORTED_VERSIONS:
        raise SIAImportError(
            code=codes.E_IMPORT_VERSION_UNSUPPORTED,
            message=f"schema version {bundle.schema_version!r} is not supported",
        )
    actual_hash = sha256_object(bundle.payload)
    if actual_hash != bundle.payload_hash:
        raise SIAImportError(
            code=codes.E_IMPORT_SCHEMA_INVALID,
            message="payload hash does not match bundle contents",
        )


def validate_import_payload(payload: dict) -> None:
    missing = REQUIRED_FIELDS - payload.keys()
    if missing:
        raise AuthorityFailure(
            rfc="RFC-0019",
            code="sia.error.import.payload_schema_invalid",
            message="required import fields missing",
        )
    if not isinstance(payload["records"], list):
        raise AuthorityFailure(
            rfc="RFC-0019",
            code="sia.error.import.records_invalid",
            message="records must be ordered list",
        )
    for record in payload["records"]:
        if not isinstance(record, dict):
            raise AuthorityFailure(
                rfc="RFC-0019",
                code="sia.error.import.record_invalid",
                message="record must be object",
            )
