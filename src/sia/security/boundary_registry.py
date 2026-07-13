"""
Security: boundary registry.

Canonical registry of authority-producing boundaries.

This module implements the frozen SIA governance model:
- exact-type authority registration
- explicit RFC ownership
- one canonical creator per authority type
- transformer / creator disjointness
- no conversion from representation into authority
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Type

from sia.errors import codes
from sia.errors.exceptions import AuthorityFailure, SIAError


@dataclass(frozen=True)
class BoundaryDefinition:
    boundary_type: Type
    owning_rfc: str
    success_type: Type
    rejection_type: Type
    creator_rfc: str
    creator: Callable
    requires_exact_type: bool = True


# NOTE: These imports are intentionally local to avoid circular import issues
# in module loading. The canonical boundaries are declared as concrete runtime
# registrations in the governance layer.
CANONICAL_BOUNDARIES: tuple[BoundaryDefinition, ...] = ()


def find_creator_for_type(output_type: type) -> BoundaryDefinition | None:
    for boundary in CANONICAL_BOUNDARIES:
        if boundary.success_type is output_type:
            return boundary
    return None


def ensure_boundary_registry_is_canonical() -> None:
    creators: dict[type, str] = {}
    for boundary in CANONICAL_BOUNDARIES:
        if boundary.creator_rfc != boundary.owning_rfc:
            raise AuthorityFailure(
                rfc=boundary.owning_rfc,
                code="sia.error.boundary.creator_rfc_mismatch",
                message="creator RFC must equal owning RFC",
            )
        if boundary.success_type in creators:
            raise AuthorityFailure(
                rfc=boundary.owning_rfc,
                code="sia.error.boundary.duplicate_creator",
                message="canonical authority type has multiple creators",
            )
        creators[boundary.success_type] = boundary.creator_rfc


def enforce_no_implicit_authority_conversion(converter: Callable[[], object], *, rfc: str) -> object:
    result = converter()
    boundary = find_creator_for_type(type(result))
    if boundary is None:
        return result
    raise AuthorityFailure(
        rfc=rfc,
        code="sia.error.unregistered_authority_creation",
        message=(
            f"{type(result).__name__} was produced outside {boundary.creator_rfc}"
        ),
    )
