"""
Imports: data models.

RFC-0019 canonical import model.
Imported ledgers are evidence only: they can reconstruct state,
but they cannot create authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


IMPORT_SCHEMA_VERSION = "1.0"
SUPPORTED_VERSIONS = {"1.0"}


@dataclass(frozen=True)
class ImportedLedger:
    ledger_version: str
    ledger_hash: str
    records: tuple[dict[str, Any], ...]
    schema_version: str = IMPORT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "ledger_version": self.ledger_version,
            "ledger_hash": self.ledger_hash,
            "records": list(self.records),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImportedLedger":
        return cls(
            ledger_version=data["ledger_version"],
            ledger_hash=data["ledger_hash"],
            records=tuple(data["records"]),
            schema_version=data.get("schema_version", IMPORT_SCHEMA_VERSION),
        )
