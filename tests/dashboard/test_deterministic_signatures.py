"""
Dashboard: deterministic signatures tests.
"""
from pathlib import Path


def test_signatures_js_exists():
    sig_js = (
        Path(__file__).parent.parent.parent
        / "src" / "dashboard" / "deterministic" / "signatures.js"
    )
    assert sig_js.exists(), "src/dashboard/deterministic/signatures.js must exist"


def test_signatures_js_no_math_random():
    sig_js = (
        Path(__file__).parent.parent.parent
        / "src" / "dashboard" / "deterministic" / "signatures.js"
    )
    content = sig_js.read_text()
    assert "Math.random" not in content, "signatures.js must not use Math.random()"


def test_signatures_js_uses_crypto():
    sig_js = (
        Path(__file__).parent.parent.parent
        / "src" / "dashboard" / "deterministic" / "signatures.js"
    )
    content = sig_js.read_text()
    assert "crypto" in content.lower(), "signatures.js must use the crypto API"
