#!/usr/bin/env bash
# SentinelFlow native development setup (Linux/macOS).
#
# Mirrors scripts/setup-dev.ps1. Prepares a local, non-Docker dev environment:
# 1. checks Python / Node / npm (versions derived from the real project:
# Python >=3.10 [3.12 verified], Node >=20.19 [Vite 8], npm),
# 2. creates backend/.venv and installs backend requirements,
# 3. installs frontend dependencies (npm ci against package-lock.json),
# 4. creates .env from .env.example with a RANDOM local EXECUTION_TOKEN,
# 5. provisions the database and runs `alembic upgrade head`,
# 6. prints how to start the backend and frontend dev servers.
#
# Database choice (DATABASE=postgres|sqlite, default postgres):
# postgres : use the DATABASE_URL in .env (Demo Mode / production). Needs a
# reachable PostgreSQL; a clear note is printed if it is not.
# sqlite : provision a local SQLite file for core-chain dev. The full Demo
# chain's durable-dispatch execution step needs PostgreSQL/MVCC;
# SQLite runs the chain up to human approval and fails CLOSED at
# execution.
#
# Usage:
# ./scripts/setup-dev.sh
# DATABASE=sqlite ./scripts/setup-dev.sh
# SKIP_FRONTEND=1 WITH_DEV_DEPS=1 ./scripts/setup-dev.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"
DATABASE="${DATABASE:-postgres}"
SKIP_FRONTEND="${SKIP_FRONTEND:-0}"
WITH_DEV_DEPS="${WITH_DEV_DEPS:-0}"

step() { echo ""; echo "==> $1"; }
good() { echo "  [ok] $1"; }
note() { echo "  [--] $1"; }
bad()  { echo "  [!!] $1" >&2; }
rand_secret() {
    if command -v openssl >/dev/null 2>&1; then openssl rand -hex 32
    else python3 -c 'import secrets;print(secrets.token_hex(32))'; fi
}

echo "SentinelFlow native dev setup"
echo "repo: $ROOT"

# --- 1. Prerequisites ---------------------------------------------------------
step "Checking prerequisites"
PY=""
if command -v python3 >/dev/null 2>&1; then PY="python3"; elif command -v python >/dev/null 2>&1; then PY="python"; fi
if [ -z "$PY" ]; then bad "Python not found. Install Python 3.12 and re-run."; exit 1; fi
PV="$("$PY" --version 2>&1 | sed 's/Python //')"
PMAJ="$(printf '%s' "$PV" | cut -d. -f1)"; PMIN="$(printf '%s' "$PV" | cut -d. -f2)"
if [ "${PMAJ:-0}" -lt 3 ] || { [ "${PMAJ:-0}" -eq 3 ] && [ "${PMIN:-0}" -lt 10 ]; }; then
    bad "Python $PV is too old (need >=3.10; 3.12 recommended)."; exit 1
fi
good "Python $PV ($PY)"

if [ "$SKIP_FRONTEND" != "1" ]; then
    if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
        bad "Node/npm not found. Install Node 22 LTS or re-run with SKIP_FRONTEND=1."; exit 1
    fi
    NV="$(node --version 2>&1 | sed 's/^v//')"; NMAJ="$(printf '%s' "$NV" | cut -d. -f1)"; NMIN="$(printf '%s' "$NV" | cut -d. -f2)"
    NVER=$(( ${NMAJ:-0} * 100 + ${NMIN:-0} ))  # Vite 8 engines: ^20.19 || >=22.12 (Node 21 unsupported)
    if ! { { [ "$NVER" -ge 2019 ] && [ "$NVER" -lt 2100 ]; } || [ "$NVER" -ge 2212 ]; }; then bad "Node v$NV is too old (Vite 8 needs Node ^20.19 || >=22.12; 22 LTS recommended)."; exit 1; fi
    good "Node v$NV, npm $(npm --version 2>&1)"
fi

# --- 2. Backend virtualenv + deps --------------------------------------------
step "Creating backend virtualenv and installing dependencies"
VENV_PY="$BACKEND/.venv/bin/python"
if [ ! -x "$VENV_PY" ]; then
    "$PY" -m venv "$BACKEND/.venv"
    good "created backend/.venv"
else good "backend/.venv already exists"; fi
"$VENV_PY" -m pip install --upgrade pip --quiet
REQS=("requirements/base.lock")
[ "$WITH_DEV_DEPS" = "1" ] && REQS+=("requirements/dev.lock")
( cd "$BACKEND" && for r in "${REQS[@]}"; do "$VENV_PY" -m pip install -r "$r" --quiet && good "installed $r"; done )

# --- 3. .env ------------------------------------------------------------------
step "Initializing .env"
ENV_FILE="$ROOT/.env"; EXAMPLE="$ROOT/.env.example"
if [ -f "$ENV_FILE" ]; then
    good ".env already exists - leaving it untouched (idempotent)"
elif [ -f "$EXAMPLE" ]; then
    cp "$EXAMPLE" "$ENV_FILE"
    TOKEN="$(rand_secret)"
    # Inject a RANDOM local execution token (never a fixed/committed secret).
    if grep -Eq '^[[:space:]]*EXECUTION_TOKEN=' "$ENV_FILE"; then
        sed -i.bak -E "s|^[[:space:]]*EXECUTION_TOKEN=.*|EXECUTION_TOKEN=${TOKEN}|" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
    else
        echo "EXECUTION_TOKEN=${TOKEN}" >> "$ENV_FILE"
    fi
    good "created .env from .env.example (random EXECUTION_TOKEN generated)"
else
    bad ".env.example not found - cannot initialize .env"; exit 1
fi

# --- 4. Database + migration --------------------------------------------------
step "Provisioning database ($DATABASE) and running migrations"
if [ "$DATABASE" = "sqlite" ]; then
    SQLITE_URL="sqlite:///./sentinelflow_dev.db"
    if grep -Eq '^[[:space:]]*DATABASE_URL=' "$ENV_FILE"; then
        sed -i.bak -E "s|^[[:space:]]*DATABASE_URL=.*|DATABASE_URL=${SQLITE_URL}|" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
    else
        echo "DATABASE_URL=${SQLITE_URL}" >> "$ENV_FILE"
    fi
    note "DATABASE_URL set to a local SQLite file (core-chain dev only; execution needs PostgreSQL)"
fi
set +e
( cd "$BACKEND" && "$VENV_PY" -m alembic upgrade head 2>&1 | tail -n 3 )
MIG_RC=${PIPESTATUS[0]}
set -e
if [ "$MIG_RC" -eq 0 ]; then good "alembic upgrade head succeeded"
elif [ "$DATABASE" = "postgres" ]; then
    note "migration did not complete - is PostgreSQL running and DATABASE_URL correct?"
    note "tip: re-run with 'DATABASE=sqlite ./scripts/setup-dev.sh' for a zero-dependency local core-chain dev DB"
else bad "alembic upgrade head failed"; exit 1; fi

# --- 5. Frontend deps ---------------------------------------------------------
if [ "$SKIP_FRONTEND" != "1" ]; then
    step "Installing frontend dependencies (npm ci)"
    ( cd "$FRONTEND" && if [ -f package-lock.json ]; then npm ci --no-audit --no-fund 2>&1 | tail -n 3; else npm install --no-audit --no-fund 2>&1 | tail -n 3; fi )
    good "frontend dependencies installed"
fi

# --- 6. Next steps ------------------------------------------------------------
echo ""
echo "Setup complete. Start the dev servers:"
echo ""
echo "  Backend  (terminal 1):"
echo "    cd backend"
echo "    ./.venv/bin/python -m uvicorn app.main:app --reload --port 8000"
echo ""
if [ "$SKIP_FRONTEND" != "1" ]; then
    echo "  Frontend (terminal 2):"
    echo "    cd frontend"
    echo "    npm run dev     # opens http://localhost:5173"
    echo ""
fi
echo "  Then verify:  ./scripts/doctor.sh   and   ./scripts/smoke.sh"
echo ""
