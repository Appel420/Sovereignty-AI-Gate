from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> None:
    subprocess.run([sys.executable, *args], cwd=ROOT, check=True)


def test_cloud_dependency_inventory_is_machine_readable_and_scoped() -> None:
    inventory_path = ROOT / "docs/compliance/fedramp_phase4/cloud_dependency_inventory.json"
    payload = json.loads(inventory_path.read_text(encoding="utf-8"))
    items = payload["items"]
    assert payload["schema"] == "fedramp-phase4-cloud-dependency-inventory-v1"
    assert any(item["environment"] == "local/offline core" for item in items)
    assert any(item["environment"] == "optional cloud integration" for item in items)
    required_fields = {
        "owner",
        "purpose",
        "data_type",
        "trust_boundary",
        "authentication_method",
        "network_direction",
        "environment",
        "evidence_source",
    }
    for item in items:
        assert required_fields.issubset(item.keys())


def test_dependency_policy_check_passes() -> None:
    _run("scripts/check_dependency_policy.py")


def test_cloud_configuration_validation_passes() -> None:
    _run("scripts/validate_cloud_config.py")


def test_sbom_is_up_to_date() -> None:
    _run(
        "scripts/generate_sbom.py",
        "--check",
        "docs/compliance/fedramp_phase4/sbom.json",
    )
