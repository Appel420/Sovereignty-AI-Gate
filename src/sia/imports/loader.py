"""
Imports: loader.

Loads a validated ImportBundle into the local authority state.
Duplicate bundles (same bundle_id) are rejected.
"""
from __future__ import annotations

from sia.errors import codes
from sia.errors.exceptions import ImportError as SIAImportError
from sia.imports.models import ImportBundle
from sia.imports.validator import validate_import


class BundleLoader:
    """
    Manages the set of imported authority bundles.

    Before loading, each bundle is validated by :func:`validate_import`.
    Duplicate bundle IDs are rejected with E_IMPORT_DUPLICATE.
    """

    def __init__(self) -> None:
        self._loaded: dict[str, ImportBundle] = {}

    def load(self, bundle: ImportBundle) -> None:
        """
        Validate and load *bundle* into the local registry.

        Raises:
            SIAImportError: on validation failure or duplicate.
        """
        validate_import(bundle)
        if bundle.bundle_id in self._loaded:
            raise SIAImportError(
                codes.E_IMPORT_DUPLICATE,
                f"Bundle '{bundle.bundle_id}' has already been imported.",
            )
        self._loaded[bundle.bundle_id] = bundle

    def get(self, bundle_id: str) -> ImportBundle:
        """Return the loaded bundle with *bundle_id*."""
        try:
            return self._loaded[bundle_id]
        except KeyError:
            raise SIAImportError(
                codes.E_IMPORT_LOAD_FAILED,
                f"Bundle '{bundle_id}' is not loaded.",
            )

    def list_bundles(self) -> list[ImportBundle]:
        return list(self._loaded.values())

    def __len__(self) -> int:
        return len(self._loaded)
