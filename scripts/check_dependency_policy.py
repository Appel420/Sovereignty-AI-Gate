#!/usr/bin/env python3
from __future__ import annotations

import ast
import json
import re
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = ROOT / "src"
PYPROJECT = ROOT / "pyproject.toml"
CONSTRAINTS = ROOT / "constraints" / "py312.txt"
PACKAGE_JSON = ROOT / "package.json"
PACKAGE_LOCK = ROOT / "package-lock.json"
PIN_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+$")
DIST_IMPORT_ALIASES = {
    "liboqs_python": {"oqs"},
}


def normalize_package_name(name: str) -> str:
    return name.strip().split("[", 1)[0].replace("-", "_").lower()


def parse_constraint_pins() -> set[str]:
    pins: set[str] = set()
    for line in CONSTRAINTS.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not PIN_PATTERN.match(stripped):
            raise ValueError(f"constraints entry must be exact-pinned: {stripped}")
        pins.add(normalize_package_name(stripped.split("==", 1)[0]))
    return pins


def assert_python_dependency_pins() -> set[str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = data.get("project", {})
    declared: set[str] = set()

    for dep in project.get("dependencies", []):
        if "==" not in dep:
            raise ValueError(f"project dependency must be exact pinned: {dep}")
        declared.add(normalize_package_name(dep.split("==", 1)[0]))
    for group in project.get("optional-dependencies", {}).values():
        for dep in group:
            if "==" not in dep:
                raise ValueError(f"optional dependency must be exact pinned: {dep}")
            declared.add(normalize_package_name(dep.split("==", 1)[0]))
    return declared


def expand_declared_import_names(declared: set[str]) -> set[str]:
    expanded = set(declared)
    for dist_name, aliases in DIST_IMPORT_ALIASES.items():
        if dist_name in declared:
            expanded.update(aliases)
    return expanded


def assert_npm_pins() -> None:
    package = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    lock = json.loads(PACKAGE_LOCK.read_text(encoding="utf-8"))

    for section in ("dependencies", "devDependencies"):
        deps = package.get(section, {})
        for name, version in deps.items():
            if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.]+)?", version):
                raise ValueError(f"{section} dependency must be exact pinned: {name}={version}")

    lock_root = lock.get("packages", {}).get("", {})
    for section in ("dependencies", "devDependencies"):
        deps = package.get(section, {})
        locked_deps = lock_root.get(section, {})
        for name, version in deps.items():
            if locked_deps.get(name) != version:
                raise ValueError(f"package-lock mismatch for {name}: {version} != {locked_deps.get(name)}")


def find_undeclared_imports(declared: set[str]) -> set[str]:
    stdlib = set(sys.stdlib_module_names)
    local_modules = {path.name for path in SRC_ROOT.iterdir() if path.is_dir()}
    undeclared: set[str] = set()
    allowed_imports = expand_declared_import_names(declared)

    for file_path in SRC_ROOT.rglob("*.py"):
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".", 1)[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level > 0 or not node.module:
                    continue
                names = [node.module.split(".", 1)[0]]
            else:
                continue
            for name in names:
                key = name.replace("-", "_").lower()
                if key in stdlib or key in local_modules:
                    continue
                if key not in allowed_imports:
                    undeclared.add(name)
    return undeclared


def main() -> int:
    declared = assert_python_dependency_pins()
    pins = parse_constraint_pins()
    missing_in_constraints = sorted(dep for dep in declared if dep not in pins)
    if missing_in_constraints:
        raise ValueError(
            "dependencies missing in constraints/py312.txt: "
            + ", ".join(missing_in_constraints)
        )
    undeclared = find_undeclared_imports(declared)
    if undeclared:
        raise ValueError(
            "source imports undeclared third-party modules: " + ", ".join(sorted(undeclared))
        )
    assert_npm_pins()
    print("dependency policy check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
