#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
PACKAGE_JSON = ROOT / "package.json"
PACKAGE_LOCK = ROOT / "package-lock.json"
CONSTRAINTS = ROOT / "constraints" / "py312.txt"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _python_components() -> list[dict[str, str]]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    components: list[dict[str, str]] = []
    project = data.get("project", {})
    for section, deps in (
        ("runtime", project.get("dependencies", [])),
        ("optional", [d for group in project.get("optional-dependencies", {}).values() for d in group]),
    ):
        for dep in deps:
            name, version = dep.split("==", 1)
            components.append(
                {
                    "ecosystem": "pip",
                    "name": name,
                    "version": version,
                    "scope": section,
                    "source": "pyproject.toml",
                }
            )
    return components


def _npm_components() -> list[dict[str, str]]:
    package = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    lock = json.loads(PACKAGE_LOCK.read_text(encoding="utf-8"))
    components: list[dict[str, str]] = []
    root_meta = lock.get("packages", {}).get("", {})
    for section in ("dependencies", "devDependencies"):
        for name, version in package.get(section, {}).items():
            lock_section = root_meta.get(section, {})
            package_info = lock.get("packages", {}).get(f"node_modules/{name}", {})
            components.append(
                {
                    "ecosystem": "npm",
                    "name": name,
                    "version": version,
                    "scope": "runtime" if section == "dependencies" else "development",
                    "integrity": package_info.get("integrity", ""),
                    "lock_version": lock_section.get(name, ""),
                    "source": "package-lock.json",
                }
            )
    return components


def build_sbom() -> dict[str, object]:
    components = _python_components() + _npm_components()
    components.sort(key=lambda item: (item["ecosystem"], item["name"]))
    return {
        "schema": "Sovereignty-AI-Gate-SBOM-v1",
        "repository": "Appel420/Sovereignty-AI-Gate",
        "components": components,
        "verification": {
            "pyproject.toml.sha256": _sha256(PYPROJECT),
            "constraints/py312.txt.sha256": _sha256(CONSTRAINTS),
            "package.json.sha256": _sha256(PACKAGE_JSON),
            "package-lock.json.sha256": _sha256(PACKAGE_LOCK),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", type=Path)
    args = parser.parse_args()

    payload = build_sbom()
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"wrote {args.output}")
    if args.check:
        current = args.check.read_text(encoding="utf-8")
        if current != rendered:
            raise ValueError(f"SBOM is out of date: regenerate {args.check}")
        print(f"validated {args.check}")
    if not args.output and not args.check:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
