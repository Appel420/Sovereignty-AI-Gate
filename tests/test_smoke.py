"""
Smoke test — verify core imports and basic initialization.
"""
import pytest
from sia import SovereignAuthority


def test_import():
    """The package imports without error."""
    assert SovereignAuthority is not None


def test_initialize():
    """SovereignAuthority initializes and records init event."""
    sa = SovereignAuthority(owner_id="user:test")
    sa.initialize()
    assert len(sa.ledger) == 1
    entry = sa.ledger.all_entries()[0]
    assert entry.event_type == "authority.init"


def test_ledger_integrity_after_init():
    sa = SovereignAuthority(owner_id="user:test")
    sa.initialize()
    sa.verify_ledger()  # should not raise


def test_not_initialized_raises():
    sa = SovereignAuthority(owner_id="user:test")
    from sia.errors.exceptions import NotInitializedError
    with pytest.raises(NotInitializedError):
        sa.register_boundary("b001", "model:x", "creator", scope=[])
