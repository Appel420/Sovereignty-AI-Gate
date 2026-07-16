"""
Security: boundary registry tests for the canonical authority model.
"""
from __future__ import annotations

from sia.errors.exceptions import AuthorityFailure
from sia.security.boundary_registry import (
    CANONICAL_BOUNDARIES,
    BoundaryDefinition,
    ensure_boundary_registry_is_canonical,
    find_creator_for_type,
)


class _AuthorityA:
    pass


class _AuthorityB:
    pass


def test_registry_is_canonical():
    ensure_boundary_registry_is_canonical()


def test_find_creator_for_type_returns_boundary_or_none():
    assert find_creator_for_type(_AuthorityA) is None


def test_creator_rfc_must_match_owning_rfc(monkeypatch):
    monkeypatch.setattr(
        "sia.security.boundary_registry.CANONICAL_BOUNDARIES",
        (
            BoundaryDefinition(
                boundary_type=_AuthorityA,
                owning_rfc="RFC-0001",
                success_type=_AuthorityA,
                rejection_type=_AuthorityB,
                creator_rfc="RFC-0002",
                creator=lambda: _AuthorityA(),
            ),
        ),
    )
    try:
        ensure_boundary_registry_is_canonical()
        assert False, "expected AuthorityFailure"
    except AuthorityFailure as exc:
        assert exc.code == "sia.error.boundary.creator_rfc_mismatch"
