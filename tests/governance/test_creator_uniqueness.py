"""
Governance: creator uniqueness tests.

Each boundary has exactly one creator, set at registration, that
can never be changed.
"""
import pytest
from sia.security.boundary_registry import BoundaryRegistry
from sia.errors.exceptions import CreatorLockedError


@pytest.fixture
def registry():
    r = BoundaryRegistry()
    r.register("b001", "model:m", "creator", "user:alice", [])
    return r


def test_creator_is_set_at_registration(registry):
    record = registry.get("b001")
    assert record.creator_id == "user:alice"


def test_creator_cannot_be_changed(registry):
    with pytest.raises(CreatorLockedError):
        registry.assert_creator_locked("b001", "user:mallory")


def test_creator_same_value_passes(registry):
    registry.assert_creator_locked("b001", "user:alice")  # must not raise


def test_multiple_boundaries_different_creators():
    r = BoundaryRegistry()
    r.register("ba", "model:ma", "creator", "user:alice", [])
    r.register("bb", "model:mb", "creator", "user:bob", [])
    assert r.get("ba").creator_id == "user:alice"
    assert r.get("bb").creator_id == "user:bob"


def test_scope_update_does_not_change_creator(registry):
    registry.update_scope("b001", ["a", "b"])
    assert registry.get("b001").creator_id == "user:alice"
