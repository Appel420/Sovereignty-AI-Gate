"""
Governance: boundary registry tests.
"""
import pytest
from sia.security.boundary_registry import BoundaryRegistry
from sia.errors.exceptions import RegistryDuplicateError, RegistryNotFoundError


@pytest.fixture
def registry():
    return BoundaryRegistry()


def test_register_and_get(registry):
    registry.register("b001", "model:m", "creator", "user:alice", ["*"])
    record = registry.get("b001")
    assert record.boundary_id == "b001"


def test_register_duplicate_raises(registry):
    registry.register("b001", "model:m", "creator", "user:alice", [])
    with pytest.raises(RegistryDuplicateError):
        registry.register("b001", "model:m2", "reader", "user:alice", [])


def test_not_found_raises(registry):
    with pytest.raises(RegistryNotFoundError):
        registry.get("missing")


def test_deactivate(registry):
    registry.register("b002", "model:m", "creator", "user:alice", [])
    registry.deactivate("b002")
    assert registry.get("b002").active is False


def test_list_active_excludes_inactive(registry):
    registry.register("b003", "model:m", "creator", "user:alice", [])
    registry.register("b004", "model:n", "reader", "user:alice", [])
    registry.deactivate("b003")
    active = registry.list_active()
    ids = [r.boundary_id for r in active]
    assert "b003" not in ids
    assert "b004" in ids


def test_snapshot(registry):
    registry.register("b005", "model:m", "creator", "user:alice", ["a"])
    snap = registry.snapshot()
    assert len(snap) == 1
    assert snap[0]["boundary_id"] == "b005"


def test_registry_len(registry):
    assert len(registry) == 0
    registry.register("b006", "model:m", "creator", "user:alice", [])
    assert len(registry) == 1
