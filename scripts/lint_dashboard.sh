#!/usr/bin/env bash
# lint_dashboard.sh — Check dashboard JS files for forbidden patterns.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DASHBOARD="${ROOT}/src/dashboard"

echo "==> Dashboard lint checks"

# Check for Math.random()
echo "--- Checking for Math.random() ---"
if grep -rn "Math\.random" "${DASHBOARD}/"; then
  echo "ERROR: Math.random() found — use crypto.getRandomValues() instead"
  exit 1
fi
echo "OK: No Math.random() found."

# Check for eval()
echo "--- Checking for eval() ---"
if grep -rn "[^a-zA-Z]eval(" "${DASHBOARD}/" --include="*.js"; then
  echo "ERROR: eval() found in dashboard JS"
  exit 1
fi
echo "OK: No eval() found."

echo ""
echo "==> Dashboard lint passed."
