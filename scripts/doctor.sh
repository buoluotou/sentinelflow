#!/usr/bin/env bash
# SentinelFlow doctor - one-shot environment & configuration diagnostics (Linux/macOS).
#
# Mirrors scripts/doctor.ps1. Checks everything a first-time user could trip
# over and prints a clear PASS / WARN / FAIL per item plus a summary. Run this
# BEFORE reading long troubleshooting docs.
#
# Covered: Python, Node, npm, Docker, Docker Compose, PostgreSQL, the ports
# SentinelFlow binds, the root .env, DATABASE_URL / AI_PROVIDER / execution &
# external-adapter configuration, the frontend API base URL, the Alembic
# migration head vs current, and (unless SKIP_HTTP=1) the live backend
# /health and /ready endpoints.
#
# Exit code: 0 when there is no FAIL, 1 when at least one FAIL was found. WARN
# never fails the run (Docker / PostgreSQL are optional per mode).
#
# Usage:
# ./scripts/doctor.sh
# BASE_URL=http://127.0.0.1:8000 SKIP_HTTP=1 ./scripts/doctor.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${BASE_URL:-${SF_BASE_URL:-http://127.0.0.1:8000}}"
BACKEND_PORT="${BACKEND_PORT:-8000}"
FRONTEND_PORT="${FRONTEND_PORT:-5173}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
SKIP_HTTP="${SKIP_HTTP:-0}"

NPASS=0; NWARN=0; NFAIL=0
if [ -t 1 ]; then
    C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_C=$'\033[36m'; C_0=$'\033[0m'
else
    C_G=""; C_Y=""; C_R=""; C_C=""; C_0=""
fi
ok()   { NPASS=$((NPASS+1)); printf '  %s[PASS]%s %s%s:%s %s\n' "$C_G" "$C_0" "$C_C" "$1" "$C_0" "$2"; }
warn() { NWARN=$((NWARN+1)); printf '  %s[WARN]%s %s%s:%s %s\n' "$C_Y" "$C_0" "$C_C" "$1" "$C_0" "$2"; }
fail() { NFAIL=$((NFAIL+1)); printf '  %s[FAIL]%s %s%s:%s %s\n' "$C_R" "$C_0" "$C_C" "$1" "$C_0" "$2"; }

# Read a KEY from a .env-style file (ignores comments), without printing secrets.
env_value() {
    local file="$1" key="$2"
    [ -f "$file" ] || return 0
    local line
    line="$(grep -E "^[[:space:]]*${key}=" "$file" | tail -n1 || true)"
    [ -n "$line" ] || return 0
    line="${line#*=}"
    line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")"
    printf '%s' "$line"
}
port_bound() {
    local port="$1"
    if command -v ss >/dev/null 2>&1; then ss -ltn 2>/dev/null | grep -Eq "[:.]${port}[[:space:]]" && return 0
    elif command -v netstat >/dev/null 2>&1; then netstat -ltn 2>/dev/null | grep -Eq "[:.]${port}[[:space:]]" && return 0
    elif command -v lsof >/dev/null 2>&1; then lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0
    fi
    return 1
}

echo ""
echo "SentinelFlow doctor"
echo "repo: $ROOT"
echo ""

# --- Interpreters & toolchains ------------------------------------------------
echo "Toolchain"
PY=""
if [ -x "$ROOT/backend/.venv/bin/python" ]; then PY="$ROOT/backend/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then PY="python3"
elif command -v python >/dev/null 2>&1; then PY="python"; fi
if [ -n "$PY" ]; then
    PV="$("$PY" --version 2>&1 | sed 's/Python //')"
    PMAJ="$(printf '%s' "$PV" | cut -d. -f1)"; PMIN="$(printf '%s' "$PV" | cut -d. -f2)"
    if [ "${PMAJ:-0}" -gt 3 ] || { [ "${PMAJ:-0}" -eq 3 ] && [ "${PMIN:-0}" -ge 10 ]; }; then
        ok "Python" "$PV ($PY) - >=3.10 required, 3.12 verified"
    else fail "Python" "$PV is too old - SentinelFlow needs >=3.10; 3.12 recommended"; fi
else fail "Python" "not found - install Python 3.12 or run scripts/setup-dev.sh"; fi

if command -v node >/dev/null 2>&1; then
    NV="$(node --version 2>&1 | sed 's/^v//')"; NMAJ="$(printf '%s' "$NV" | cut -d. -f1)"; NMIN="$(printf '%s' "$NV" | cut -d. -f2)"
    NVER=$(( ${NMAJ:-0} * 100 + ${NMIN:-0} ))  # Vite 8 engines: ^20.19 || >=22.12 (Node 21 unsupported)
    if { [ "$NVER" -ge 2019 ] && [ "$NVER" -lt 2100 ]; } || [ "$NVER" -ge 2212 ]; then ok "Node" "v$NV - satisfies Vite 8 (^20.19 || >=22.12); 22 LTS recommended"
    else fail "Node" "v$NV is too old - Vite 8 needs Node ^20.19 || >=22.12"; fi
else warn "Node" "not found - only needed for Native dev / frontend build (Docker quickstart builds it in-container)"; fi

if command -v npm >/dev/null 2>&1; then ok "npm" "$(npm --version 2>&1) (frontend uses package-lock.json)"
else warn "npm" "not found - needed for Native frontend dev; the Docker quickstart does not require it"; fi

if command -v docker >/dev/null 2>&1; then
    if DV="$(docker version --format '{{.Server.Version}}' 2>/dev/null)"; then ok "Docker" "engine $DV (daemon reachable)"
    else warn "Docker" "CLI present but the daemon is not reachable - start Docker; needed for the Docker quickstart only"; fi
    if CV="$(docker compose version 2>/dev/null)"; then ok "Docker Compose" "$(printf '%s' "$CV" | awk '{print $3}')"
    else warn "Docker Compose" "not available - the Docker quickstart needs 'docker compose' (v2 plugin)"; fi
else warn "Docker" "not found - the Docker quickstart is unavailable; use Native mode (scripts/setup-dev.sh)"; fi

# --- Database -----------------------------------------------------------------
echo ""
echo "Database"
if command -v psql >/dev/null 2>&1; then ok "PostgreSQL client" "$(psql --version 2>&1 | sed 's/psql (PostgreSQL) //') (psql on PATH)"
else warn "PostgreSQL client" "psql not on PATH - fine for the Docker quickstart (compose bundles PostgreSQL 16)"; fi
if port_bound "$POSTGRES_PORT"; then warn "Port $POSTGRES_PORT" "something is already listening - a local PostgreSQL? Demo Mode uses PostgreSQL; make sure DATABASE_URL matches it"
else ok "Port $POSTGRES_PORT" "free (compose will bind PostgreSQL here, or point DATABASE_URL at a remote one)"; fi

# --- Ports we bind ------------------------------------------------------------
echo ""
echo "Ports"
for pp in "$BACKEND_PORT backend" "$FRONTEND_PORT frontend"; do
    set -- $pp
    if port_bound "$1"; then warn "Port $1 ($2)" "already bound - if that is not SentinelFlow, set BACKEND_PORT/FRONTEND_PORT to a free port"
    else ok "Port $1 ($2)" "free"; fi
done

# --- Configuration ------------------------------------------------------------
echo ""
echo "Configuration"
ENV_FILE="$ROOT/.env"
if [ -f "$ENV_FILE" ]; then
    ok ".env" "present at repo root"
    DB_URL="$(env_value "$ENV_FILE" DATABASE_URL)"
    if [ -n "$DB_URL" ]; then
        SCHEME="${DB_URL%%://*}"
        case "$DB_URL" in
            *change_me*|*postgres:postgres*|*password=password*) warn "DATABASE_URL" "scheme=$SCHEME but it still contains a placeholder/weak credential - set a real one (value not printed)" ;;
            sqlite*) warn "DATABASE_URL" "sqlite - the full Demo chain (durable dispatch execution) needs PostgreSQL/MVCC; SQLite proves the chain up to approval only" ;;
            *) ok "DATABASE_URL" "scheme=$SCHEME (value not printed)" ;;
        esac
    else warn "DATABASE_URL" "not set in .env - the backend default is PostgreSQL; the Docker quickstart injects it"; fi

    AI="$(env_value "$ENV_FILE" AI_PROVIDER)"; ok "AI_PROVIDER" "${AI:-mock (default)}"
    EA="$(env_value "$ENV_FILE" EXECUTION_ADAPTER)"; ok "EXECUTION_ADAPTER" "${EA:-mock (default)}"
    ET="$(env_value "$ENV_FILE" EXECUTION_TOKEN)"; OP="$(env_value "$ENV_FILE" OPERATORS_JSON)"
    if [ -n "$ET" ] || [ -n "$OP" ]; then ok "Execution auth" "configured (EXECUTION_TOKEN/OPERATORS_JSON set - value not printed)"
    else warn "Execution auth" "EXECUTION_TOKEN/OPERATORS_JSON empty - every write/execute path returns 401; the quickstart generates a random local token"; fi

    for pair in "SHUFFLE_BASE_URL Shuffle" "WAZUH_BASE_URL Wazuh" "THEHIVE_BASE_URL TheHive"; do
        set -- $pair
        V="$(env_value "$ENV_FILE" "$1")"
        if [ -n "$V" ]; then warn "$2 (Integration Lab)" "ENABLED ($1 set) - LAB/EXPERIMENTAL, NOT production-certified"
        else ok "$2 (Integration Lab)" "disabled (default) - Demo Mode needs no external SOAR"; fi
    done
else
    warn ".env" "not found - copy .env.example to .env, or run scripts/quickstart.sh / scripts/setup-dev.sh which create it"
fi

VB="$(env_value "$ROOT/frontend/.env" VITE_API_BASE_URL)"
if [ -n "$VB" ]; then ok "VITE_API_BASE_URL" "'$VB' (frontend/.env) - the single authoritative API base"
else ok "VITE_API_BASE_URL" "unset - frontend uses same-origin relative /api (correct behind nginx / vite proxy)"; fi

# --- Migrations (hang-proof) --------------------------------------------------
echo ""
echo "Migrations"
TIMEOUT_BIN=""; command -v timeout >/dev/null 2>&1 && TIMEOUT_BIN="timeout 20"; command -v gtimeout >/dev/null 2>&1 && TIMEOUT_BIN="gtimeout 20"
if [ -f "$ROOT/backend/alembic.ini" ] && [ -n "$PY" ]; then
    HEAD_REV="$(cd "$ROOT/backend" && "$PY" -m alembic heads 2>/dev/null | grep -Eo '^[0-9A-Za-z_]+ \(head\)' | head -n1 | awk '{print $1}')"
    CUR_REV="$(cd "$ROOT/backend" && PGCONNECT_TIMEOUT=3 $TIMEOUT_BIN "$PY" -m alembic current 2>/dev/null | grep -Eo '^[0-9A-Za-z_]+' | head -n1 || true)"
    if [ -z "$CUR_REV" ]; then warn "Alembic current" "no current revision read (DATABASE_URL unreachable or DB not migrated) - head=${HEAD_REV:-unknown}"
    elif [ -n "$HEAD_REV" ] && [ "$CUR_REV" = "$HEAD_REV" ]; then ok "Alembic" "current == head ($HEAD_REV) - the reachable DB is migrated"
    elif [ -n "$HEAD_REV" ]; then warn "Alembic" "current=$CUR_REV but head=$HEAD_REV - run: (cd backend && alembic upgrade head)"
    else warn "Alembic" "could not resolve head (check backend/alembic.ini and DATABASE_URL)"; fi
else warn "Alembic" "backend/alembic.ini or Python missing - cannot check migration state"; fi

# --- Live backend -------------------------------------------------------------
echo ""
echo "Runtime"
if [ "$SKIP_HTTP" = "1" ]; then
    warn "Backend HTTP" "skipped (SKIP_HTTP=1)"
else
    HB="$(curl -fsS --noproxy '*' --max-time 4 "$BASE_URL/health" 2>/dev/null || true)"
    if [ -n "$HB" ]; then
        ok "GET /health" "200 - $BASE_URL is up"
        ok "Health body" "$(printf '%s' "$HB" | tr -d '\n')"
        if curl -fsS --noproxy '*' --max-time 4 "$BASE_URL/ready" >/dev/null 2>&1; then ok "GET /ready" "200 - database answers SELECT 1"
        else fail "GET /ready" "not ready (DB unreachable?)"; fi
    else
        warn "Backend HTTP" "no backend at $BASE_URL (not started) - run scripts/quickstart.sh (Docker) or scripts/setup-dev.sh (Native), then re-run doctor"
    fi
fi

# --- Summary ------------------------------------------------------------------
echo ""
echo "Summary: $NPASS PASS, $NWARN WARN, $NFAIL FAIL"
if [ "$NFAIL" -gt 0 ]; then echo "doctor: FAIL - resolve the FAIL items above, then re-run."; exit 1; fi
echo "doctor: PASS - no blocking issues (review any WARN for your chosen mode)."
exit 0
