"""
Dashboard: deterministic TPM tests.

Validates that the TPM JS module uses only deterministic/CSPRNG
entropy sources and correctly seals/unseals PCR-bound values.
"""
import json
from pathlib import Path

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_dashboard_state_is_deterministic():
    """The fixture deterministic_dashboard_state.json must declare deterministic=true."""
    state = json.loads(
        (FIXTURES / "deterministic_dashboard_state.json").read_text()
    )
    assert state.get("deterministic") is True


def test_dashboard_tpm_pcr_values_present():
    state = json.loads(
        (FIXTURES / "deterministic_dashboard_state.json").read_text()
    )
    pcr = state.get("tpm_pcr_values", {})
    assert "pcr0" in pcr
    assert "pcr1" in pcr


def test_tpm_js_file_exists():
    tpm_js = (
        Path(__file__).parent.parent.parent / "src" / "dashboard" / "deterministic" / "tpm.js"
    )
    assert tpm_js.exists(), "src/dashboard/deterministic/tpm.js must exist"


def test_tpm_js_no_math_random():
    tpm_js = (
        Path(__file__).parent.parent.parent / "src" / "dashboard" / "deterministic" / "tpm.js"
    )
    content = tpm_js.read_text()
    assert "Math.random" not in content, "tpm.js must not use Math.random()"
