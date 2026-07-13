#!/usr/bin/env bash
# build_release.sh — Build a release artifact.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

VERSION=$(python3 -c "import importlib.metadata; print(importlib.metadata.version('sovereignty-ai-gate'))" 2>/dev/null || echo "0.1.0")

echo "==> Building Sovereignty AI Gate release v${VERSION}"

cd "${ROOT}"

if [ -f ".venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
fi

# Run full test suite first
echo "--- Pre-release tests ---"
pytest --tb=short -q

# Build Python distribution
echo "--- Building Python distribution ---"
pip install --upgrade build
python -m build --outdir dist/

echo ""
echo "==> Release artifact built: dist/"
ls dist/
echo ""
echo "==> Build complete: v${VERSION}"
