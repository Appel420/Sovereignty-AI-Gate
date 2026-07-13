#!/usr/bin/env bash
# run_conformance.sh — Run only the conformance and governance tests.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==> Running conformance tests"
cd "${ROOT}"

if [ -f ".venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
fi

echo "--- Conformance ---"
pytest tests/conformance/ -v --tb=short

echo ""
echo "--- Governance ---"
pytest tests/governance/ -v --tb=short

echo ""
echo "==> Conformance checks complete."
