"""
Authority boundary conformance tests.

Tests that authority boundaries enforce isolation between models
and that the no-conversion rule is enforced.
"""
import pytest
from sia import SovereignAuthority
from sia.errors import codes
from sia.errors.exceptions import SIAError, RegistryNotFoundError


@pytest.fixture
def sa():
    authority = SovereignAuthority(owner_id="user:alice")
    authority.initialize()
    return authority


def test_boundary_not_found_raises(sa):
    with pytest.raises(RegistryNotFoundError):
        sa.registry.get("nonexistent")


def test_boundary_scope_stored(sa):
    sa.register_boundary("b-scope", "model:m", "creator", scope=["a", "b"])
    record = sa.registry.get("b-scope")
    assert "a" in record.scope
    assert "b" in record.scope


def test_boundary_scope_update(sa):
    sa.register_boundary("b-upd", "model:m", "creator", scope=["a"])
    sa.registry.update_scope("b-upd", ["a", "b", "c"])
    record = sa.registry.get("b-upd")
    assert record.scope == ["a", "b", "c"]


def test_boundary_no_conversion(sa):
    sa.register_boundary("b-conv", "model:m", "creator", scope=[])
    with pytest.raises(SIAError) as exc_info:
        sa.registry.assert_no_conversion("b-conv", "transformer")
    assert exc_info.value.code == codes.E_REGISTRY_CONVERSION_DENIED


def test_boundary_creator_locked(sa):
    sa.register_boundary("b-lock", "model:m", "creator", scope=[])
    from sia.errors.exceptions import CreatorLockedError
    with pytest.raises(CreatorLockedError):
        sa.registry.assert_creator_locked("b-lock", "user:mallory")


def test_boundary_list_for_model(sa):
    sa.register_boundary("b-m1a", "model:target", "creator", scope=[])
    sa.register_boundary("b-m1b", "model:target", "reader", scope=[])
    sa.register_boundary("b-m2", "model:other", "creator", scope=[])
    result = sa.registry.list_for_model("model:target")
    assert len(result) == 2
    assert all(r.model_id == "model:target" for r in result)
