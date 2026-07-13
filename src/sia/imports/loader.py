"""
Imports: loader.

RFC-0019 canonical import loader.
"""
from __future__ import annotations

import json

from sia.errors.exceptions import AuthorityFailure
from sia.export.models import ExportBundle
from sia.export.validator import validate_bundle
from sia.imports.models import ImportedLedger
from sia.imports.validator import validate_import_payload


def import_ledger(envelope) -> ImportedLedger:
    if type(envelope) is not ExportBundle:
        raise AuthorityFailure(
            rfc="RFC-0019",
            code="sia.error.import.invalid_envelope_type",
            message="canonical ExportBundle required",
        )

    validate_bundle(envelope)
    decoded = json.loads(json.dumps(envelope.payload))
    validate_import_payload(decoded)

    return ImportedLedger(
        ledger_version=decoded["ledger_version"],
        ledger_hash=decoded["ledger_hash"],
        records=tuple(decoded["records"]),
    )
