#!/usr/bin/env bash
# SentinelFlow demo smoke test (Linux/macOS wrapper).
#
# Thin wrapper around the real cross-platform runner scripts/smoke.py, which
# drives the FULL core chain over real HTTP (never imports app services). It
# picks the best available Python (backend venv first), forwards every argument
# to smoke.py and propagates its exit code.
#
#   On PostgreSQL (Demo Mode) it asserts the complete chain incl. the durable
#   dispatch execution; on SQLite it proves the business chain through human
#   approval and asserts the execution step fails CLOSED. See smoke.py.
#
# Usage:
#   ./scripts/smoke.sh
#   ./scripts/smoke.sh --base-url http://127.0.0.1:8000 --token "$EXECUTION_TOKEN"
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE="$ROOT/scripts/smoke.py"

if [ ! -f "$SMOKE" ]; then
    echo "smoke.py not found at $SMOKE" >&2
    exit 2
fi

# Prefer the backend virtualenv (it has every dependency); fall back to a system
# interpreter. smoke.py is stdlib-only, so any Python 3.10+ works.
VENV_PY="$ROOT/backend/.venv/bin/python"
if [ -x "$VENV_PY" ]; then
    PY="$VENV_PY"
elif command -v python3 >/dev/null 2>&1; then
    PY="python3"
elif command -v python >/dev/null 2>&1; then
    PY="python"
else
    echo "No Python interpreter found. Install Python 3.10+ or run scripts/setup-dev.sh first." >&2
    exit 2
fi

exec "$PY" "$SMOKE" "$@"
