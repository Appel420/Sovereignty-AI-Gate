#!/usr/bin/env bash
# bootstrap.sh — Set up the development environment (offline-first).
# All dependencies are installed from local index or standard Python/npm
# registries. No proprietary cloud tooling required.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==> Sovereignty AI Gate — Bootstrap"
echo "    Root: ${ROOT}"

# ── Python ────────────────────────────────────────────────────────────────────
echo ""
echo "==> Setting up Python environment"
python3 -m venv "${ROOT}/.venv"
# shellcheck source=/dev/null
source "${ROOT}/.venv/bin/activate"
pip install --upgrade pip
pip install -c "${ROOT}/constraints/py312.txt" -e "${ROOT}[dev]"
echo "    Python environment ready."

# ── Node.js ───────────────────────────────────────────────────────────────────
echo ""
echo "==> Installing Node.js dependencies"
cd "${ROOT}"
npm install
echo "    Node.js dependencies installed."

echo ""
echo "==> Bootstrap complete."
echo "    Activate venv: source .venv/bin/activate"
echo "    Run tests:     bash scripts/run_tests.sh"
