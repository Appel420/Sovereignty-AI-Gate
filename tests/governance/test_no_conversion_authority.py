"""
Governance: no-conversion-authority tests.

No delegation chain may grant the authority to convert a boundary
type. The registry enforces this unconditionally.
"""
import pytest
from sia.security.boundary_registry import BoundaryRegistry
from sia.errors.exceptions import SIAError
from sia.errors import codes


def test_no_conversion_from_creator_to_transformer():
    r = BoundaryRegistry()
    r.register("b1", "model:m", "creator", "user:alice", [])
    with pytest.raises(SIAError) as exc_info:
        r.assert_no_conversion("b1", "transformer")
    assert exc_info.value.code == codes.E_REGISTRY_CONVERSION_DENIED


def test_no_conversion_from_reader_to_creator():
    r = BoundaryRegistry()
    r.register("b2", "model:m", "reader", "user:alice", [])
    with pytest.raises(SIAError) as exc_info:
        r.assert_no_conversion("b2", "creator")
    assert exc_info.value.code == codes.E_REGISTRY_CONVERSION_DENIED


def test_no_conversion_from_delegate_to_creator():
    r = BoundaryRegistry()
    r.register("b3", "model:m", "delegate", "user:alice", [])
    with pytest.raises(SIAError) as exc_info:
        r.assert_no_conversion("b3", "creator")
    assert exc_info.value.code == codes.E_REGISTRY_CONVERSION_DENIED


def test_same_type_allowed():
    r = BoundaryRegistry()
    r.register("b4", "model:m", "creator", "user:alice", [])
    r.assert_no_conversion("b4", "creator")  # must not raise


def test_conversion_error_message_contains_boundary_id():
    r = BoundaryRegistry()
    r.register("b5", "model:m", "creator", "user:alice", [])
    with pytest.raises(SIAError) as exc_info:
        r.assert_no_conversion("b5", "transformer")
    assert "b5" in str(exc_info.value)
