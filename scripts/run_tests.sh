#!/usr/bin/env bash
# run_tests.sh — Run the full Python test suite.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==> Running full test suite"
cd "${ROOT}"

if [ -f ".venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
fi

pytest --tb=short -q "$@"
echo ""
echo "==> Tests complete."
