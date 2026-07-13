"""
Dashboard: deterministic compliance tests.
"""
import json
from pathlib import Path

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_compliance_js_exists():
    comp_js = (
        Path(__file__).parent.parent.parent
        / "src" / "dashboard" / "deterministic" / "compliance.js"
    )
    assert comp_js.exists(), "src/dashboard/deterministic/compliance.js must exist"


def test_compliance_js_no_math_random():
    comp_js = (
        Path(__file__).parent.parent.parent
        / "src" / "dashboard" / "deterministic" / "compliance.js"
    )
    content = comp_js.read_text()
    assert "Math.random" not in content, "compliance.js must not use Math.random()"


def test_dashboard_compliance_status_all_pass():
    state = json.loads(
        (FIXTURES / "deterministic_dashboard_state.json").read_text()
    )
    for rfc, status in state.get("compliance_status", {}).items():
        assert status == "pass", f"{rfc} compliance status is not 'pass': {status}"
