"""
Security: boundary registry.

The boundary registry maintains the set of active model boundaries.
Each boundary has an immutable creator field; no delegation chain may
change it (E_REGISTRY_CREATOR_LOCKED). Boundaries cannot be converted
from one type to another after registration (E_REGISTRY_CONVERSION_DENIED).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from sia.errors.exceptions import (
    CreatorLockedError,
    RegistryDuplicateError,
    RegistryNotFoundError,
)
from sia.errors import codes
from sia.errors.exceptions import SIAError

BoundaryType = Literal["creator", "transformer", "reader", "delegate"]


@dataclass
class BoundaryRecord:
    """Immutable record describing a registered model boundary."""

    boundary_id: str
    model_id: str
    boundary_type: BoundaryType
    creator_id: str  # always the original registering user; never changes
    scope: list[str]
    registered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    active: bool = True

    def to_dict(self) -> dict:
        return {
            "boundary_id": self.boundary_id,
            "model_id": self.model_id,
            "boundary_type": self.boundary_type,
            "creator_id": self.creator_id,
            "scope": self.scope,
            "registered_at": self.registered_at,
            "active": self.active,
        }


class BoundaryRegistry:
    """
    Registry of model authority boundaries.

    Invariants:
    - ``boundary_id`` values are unique.
    - ``creator_id`` is set at registration and never modified.
    - ``boundary_type`` cannot be changed after registration.
    """

    def __init__(self) -> None:
        self._records: dict[str, BoundaryRecord] = {}

    # ── Registration ──────────────────────────────────────────────────────────

    def register(
        self,
        boundary_id: str,
        model_id: str,
        boundary_type: BoundaryType,
        creator_id: str,
        scope: list[str],
    ) -> BoundaryRecord:
        """Register a new boundary. Raises ``RegistryDuplicateError`` if the
        ``boundary_id`` is already registered."""
        if boundary_id in self._records:
            raise RegistryDuplicateError(
                f"Boundary '{boundary_id}' is already registered."
            )
        record = BoundaryRecord(
            boundary_id=boundary_id,
            model_id=model_id,
            boundary_type=boundary_type,
            creator_id=creator_id,
            scope=list(scope),
        )
        self._records[boundary_id] = record
        return record

    # ── Lookup ────────────────────────────────────────────────────────────────

    def get(self, boundary_id: str) -> BoundaryRecord:
        """Return the boundary record for *boundary_id*.
        Raises ``RegistryNotFoundError`` if not found."""
        try:
            return self._records[boundary_id]
        except KeyError:
            raise RegistryNotFoundError(
                f"Boundary '{boundary_id}' not found in registry."
            )

    def list_active(self) -> list[BoundaryRecord]:
        """Return all active boundary records."""
        return [r for r in self._records.values() if r.active]

    def list_for_model(self, model_id: str) -> list[BoundaryRecord]:
        """Return all active boundaries for a given model."""
        return [
            r for r in self._records.values()
            if r.model_id == model_id and r.active
        ]

    # ── Mutation ──────────────────────────────────────────────────────────────

    def deactivate(self, boundary_id: str) -> None:
        """Mark a boundary as inactive."""
        record = self.get(boundary_id)
        record.active = False

    def update_scope(self, boundary_id: str, scope: list[str]) -> None:
        """Replace the scope list of an existing boundary.
        The creator_id and boundary_type are immutable."""
        record = self.get(boundary_id)
        record.scope = list(scope)

    def assert_no_conversion(
        self, boundary_id: str, requested_type: BoundaryType
    ) -> None:
        """
        Assert that converting *boundary_id* to *requested_type* is not
        permitted. Always raises ``SIAError`` with E_REGISTRY_CONVERSION_DENIED.
        """
        record = self.get(boundary_id)
        if record.boundary_type != requested_type:
            raise SIAError(
                codes.E_REGISTRY_CONVERSION_DENIED,
                f"Cannot convert boundary '{boundary_id}' from "
                f"'{record.boundary_type}' to '{requested_type}'.",
            )

    def assert_creator_locked(self, boundary_id: str, new_creator: str) -> None:
        """
        Assert that the creator field of *boundary_id* cannot be changed.
        Always raises ``CreatorLockedError`` if *new_creator* differs.
        """
        record = self.get(boundary_id)
        if record.creator_id != new_creator:
            raise CreatorLockedError(
                f"Boundary '{boundary_id}' creator is locked to "
                f"'{record.creator_id}'."
            )

    # ── Serialization ─────────────────────────────────────────────────────────

    def snapshot(self) -> list[dict]:
        """Return a serializable snapshot of all records."""
        return [r.to_dict() for r in self._records.values()]

    def __len__(self) -> int:
        return len(self._records)
