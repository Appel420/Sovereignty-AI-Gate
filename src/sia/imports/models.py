"""
Imports: data models.

An ImportBundle is the inbound representation of an ExportBundle
received from a remote sovereign operator.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

IMPORT_SCHEMA_VERSION = "1.0"
SUPPORTED_VERSIONS = {"1.0"}


@dataclass
class ImportBundle:
    """
    Inbound authority bundle awaiting validation and loading.

    Fields mirror ExportBundle but carry the additional ``imported_at``
    timestamp added by the local system at load time.
    """

    bundle_id: str
    created_by: str
    payload: dict[str, Any]
    payload_hash: str
    signature: str
    created_at: str
    imported_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    schema_version: str = IMPORT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "bundle_id": self.bundle_id,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "imported_at": self.imported_at,
            "payload": self.payload,
            "payload_hash": self.payload_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ImportBundle":
        return cls(
            bundle_id=data["bundle_id"],
            created_by=data["created_by"],
            payload=data["payload"],
            payload_hash=data["payload_hash"],
            signature=data["signature"],
            created_at=data.get("created_at", ""),
            imported_at=data.get("imported_at", ""),
            schema_version=data.get("schema_version", IMPORT_SCHEMA_VERSION),
        )
