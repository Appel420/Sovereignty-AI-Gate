"""
Governance: transformer isolation tests.

A 'transformer' boundary type must remain isolated and cannot be
elevated to 'creator' or 'reader'.
"""
import pytest
from sia.security.boundary_registry import BoundaryRegistry
from sia.errors.exceptions import SIAError
from sia.errors import codes


@pytest.fixture
def registry():
    r = BoundaryRegistry()
    r.register("bt", "model:transformer", "transformer", "user:alice", ["transform.*"])
    return r


def test_transformer_type_preserved(registry):
    record = registry.get("bt")
    assert record.boundary_type == "transformer"


def test_transformer_no_conversion_to_creator(registry):
    with pytest.raises(SIAError) as exc_info:
        registry.assert_no_conversion("bt", "creator")
    assert exc_info.value.code == codes.E_REGISTRY_CONVERSION_DENIED


def test_transformer_no_conversion_to_reader(registry):
    with pytest.raises(SIAError) as exc_info:
        registry.assert_no_conversion("bt", "reader")
    assert exc_info.value.code == codes.E_REGISTRY_CONVERSION_DENIED


def test_transformer_same_type_passes(registry):
    registry.assert_no_conversion("bt", "transformer")  # must not raise


def test_transformer_scope_update_allowed(registry):
    registry.update_scope("bt", ["transform.text", "transform.image"])
    record = registry.get("bt")
    assert "transform.text" in record.scope
    assert record.boundary_type == "transformer"
