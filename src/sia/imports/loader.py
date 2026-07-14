"""
Imports: loader.

RFC-0019 canonical import loader.
"""
from __future__ import annotations

import json

from sia.errors import codes
from sia.errors.exceptions import AuthorityFailure
from sia.errors.exceptions import ImportError as SIAImportError
from sia.export.models import ExportBundle
from sia.export.validator import validate_bundle
from sia.imports.models import ImportBundle, ImportedLedger
from sia.imports.validator import validate_import_payload


class BundleLoader:
    """In-memory store for validated RFC-0019 import bundles."""

    def __init__(self) -> None:
        self._bundles: dict[str, ImportBundle] = {}

    def load(self, bundle: ImportBundle) -> None:
        """Record *bundle* in the loader.

        Raises :class:`sia.errors.exceptions.ImportError` with
        :data:`sia.errors.codes.E_IMPORT_DUPLICATE` if a bundle with the
        same ``bundle_id`` has already been loaded.
        """
        if bundle.bundle_id in self._bundles:
            raise SIAImportError(
                code=codes.E_IMPORT_DUPLICATE,
                message=f"bundle {bundle.bundle_id!r} already imported",
            )
        self._bundles[bundle.bundle_id] = bundle

    def list_bundles(self) -> list[ImportBundle]:
        """Return all loaded bundles in insertion order."""
        return list(self._bundles.values())


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
