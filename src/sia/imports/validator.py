"""
Imports: validator.

Validate canonical RFC-0019 import payloads.
"""
from __future__ import annotations

from sia.errors import codes
from sia.errors.exceptions import AuthorityFailure


REQUIRED_FIELDS = {"ledger_version", "ledger_hash", "records"}


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
