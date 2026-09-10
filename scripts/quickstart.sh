#!/usr/bin/env bash
# SentinelFlow Docker Compose quickstart (Linux/macOS) - the recommended install path.
#
# Mirrors scripts/quickstart.ps1. One command from a fresh clone to a running Demo:
#   1. checks Docker + Docker Compose (v2) and that the daemon is reachable,
#   2. checks the ports SentinelFlow binds (5432 / 8000 / 5173 by default),
#   3. creates .env from .env.example and fills RANDOM local secrets
#      (POSTGRES_PASSWORD, EXECUTION_TOKEN) - never a fixed/committed secret,
#   4. validates the compose file (docker compose config),
#   5. brings up the stack in the enforced order
#      postgres(healthy) -> migrate(one-shot) -> backend -> frontend,
#   6. waits for the backend to become healthy,
#   7. runs the demo smoke test INSIDE the backend container (so the host
#      needs no Python/Node), and
#   8. prints the access URLs.
#
# DEFAULT = Demo Mode: AI_PROVIDER=mock, EXECUTION_ADAPTER=mock, every external
# system (Wazuh/Shuffle/TheHive) disabled. No real SOAR is contacted.
#
# Usage:
#   ./scripts/quickstart.sh
#   ./scripts/quickstart.sh --with-ollama   # AI Local Mode (adds Ollama)
#   ./scripts/quickstart.sh --down          # stop and remove the stack
set -euo pipefail

WITH_OLLAMA=0
REBUILD=0
DOWN=0
WAIT_SECONDS="${WAIT_SECONDS:-180}"
for arg in "$@"; do
    case "$arg" in
        --with-ollama) WITH_OLLAMA=1 ;;
        --rebuild)     REBUILD=1 ;;
        --down)        DOWN=1 ;;
        -h|--help)     sed -n '2,26p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg (see --help)" >&2; exit 2 ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() { echo ""; echo "==> $1"; }
good() { echo "  [ok] $1"; }
note() { echo "  [--] $1"; }
bad()  { echo "  [!!] $1" >&2; }

rand_secret() {
    # $1 = number of hex bytes
    if command -v openssl >/dev/null 2>&1; then openssl rand -hex "$1"
    else python3 -c "import secrets;print(secrets.token_hex($1))"; fi
}
get_env_key() {
    # $1 = file, $2 = key -> prints value (quotes/whitespace trimmed), empty if absent
    local file="$1" key="$2" line val
    [ -f "$file" ] || { printf ''; return 0; }
    line="$(grep -E "^[[:space:]]*${key}=" "$file" | tail -n1 || true)"
    [ -z "$line" ] && { printf ''; return 0; }
    val="${line#*=}"
    val="$(printf '%s' "$val" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//; s/^"(.*)"$/\1/; s/^'"'"'(.*)'"'"'$/\1/')"
    printf '%s' "$val"
}
set_env_key() {
    # $1 = file, $2 = key, $3 = value -> replaces the key in place, or appends it
    local file="$1" key="$2" val="$3" tmp
    tmp="$(mktemp)"
    awk -v key="$key" -v val="$val" '
        BEGIN { done=0 }
        { if ($0 ~ ("^[ \t]*" key "=")) { print key "=" val; done=1 } else { print $0 } }
        END { if (done==0) print key "=" val }
    ' "$file" > "$tmp"
    mv "$tmp" "$file"
}
port_bound() {
    # returns 0 (true) if something is already LISTENing on the port
    local port="$1"
    if command -v ss >/dev/null 2>&1; then
        ss -ltn 2>/dev/null | grep -Eq "[:.]${port}([[:space:]]|$)" && return 0 || return 1
    fi
    if command -v lsof >/dev/null 2>&1; then
        lsof -iTCP:"${port}" -sTCP:LISTEN -n -P >/dev/null 2>&1 && return 0 || return 1
    fi
    (exec 3<>"/dev/tcp/127.0.0.1/${port}") >/dev/null 2>&1
}

echo "SentinelFlow Docker quickstart"
echo "repo: $ROOT"

# --- Tear-down shortcut -------------------------------------------------------
if [ "$DOWN" = "1" ]; then
    step "Stopping and removing the stack"
    docker compose down
    good "stack removed (the pg-data volume is kept; add -v to 'docker compose down' to erase data)"
    exit 0
fi

# --- 1. Docker ----------------------------------------------------------------
step "Checking Docker"
if ! command -v docker >/dev/null 2>&1; then
    bad "Docker not found. Install Docker Engine (or Docker Desktop) and re-run, or use scripts/setup-dev.sh for Native mode."; exit 1
fi
if ! docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
    bad "the Docker daemon is not reachable. Start Docker and re-run."; exit 1
fi
good "Docker daemon reachable"
if ! docker compose version >/dev/null 2>&1; then
    bad "'docker compose' (v2) not available. Install the Compose plugin."; exit 1
fi
good "Docker Compose v2 available"

# --- 2. Ports -----------------------------------------------------------------
step "Checking ports"
ENV_FILE="$ROOT/.env"
pg_port="$(get_env_key "$ENV_FILE" POSTGRES_PORT)"; pg_port="${pg_port:-5432}"
be_port="$(get_env_key "$ENV_FILE" BACKEND_PORT)"; be_port="${be_port:-8000}"
fe_port="$(get_env_key "$ENV_FILE" FRONTEND_PORT)"; fe_port="${fe_port:-5173}"
check_port() {
    local port="$1" name="$2" varname="$3"
    if port_bound "$port"; then
        note "port ${port} (${name}) is already bound"
        note "  if that is not SentinelFlow, set ${varname}_PORT in .env to a free port and re-run"
    else
        good "port ${port} (${name}) free"
    fi
}
check_port "$pg_port" "PostgreSQL" "POSTGRES"
check_port "$be_port" "backend" "BACKEND"
check_port "$fe_port" "frontend" "FRONTEND"

# --- 3. .env + random local secrets ------------------------------------------
step "Preparing .env (Demo Mode defaults + random local secrets)"
if [ ! -f "$ENV_FILE" ]; then
    [ -f "$ROOT/.env.example" ] || { bad ".env.example not found"; exit 1; }
    cp "$ROOT/.env.example" "$ENV_FILE"
    good "created .env from .env.example"
else
    good ".env already exists (reusing it)"
fi
# Demo Mode is the default: never silently enable a real adapter.
[ -n "$(get_env_key "$ENV_FILE" AI_PROVIDER)" ]        || set_env_key "$ENV_FILE" AI_PROVIDER mock
[ -n "$(get_env_key "$ENV_FILE" EXECUTION_ADAPTER)" ]  || set_env_key "$ENV_FILE" EXECUTION_ADAPTER mock
# Mandatory random secrets (compose refuses an empty POSTGRES_PASSWORD).
pg_pass="$(get_env_key "$ENV_FILE" POSTGRES_PASSWORD)"
if [ -z "$pg_pass" ] || [ "$pg_pass" = "change_me" ]; then
    set_env_key "$ENV_FILE" POSTGRES_PASSWORD "$(rand_secret 24)"; good "generated a random POSTGRES_PASSWORD"
else
    good "POSTGRES_PASSWORD already set (kept)"
fi
exec_tok="$(get_env_key "$ENV_FILE" EXECUTION_TOKEN)"
if [ -z "$exec_tok" ] || [ "$exec_tok" = "change_me" ]; then
    set_env_key "$ENV_FILE" EXECUTION_TOKEN "$(rand_secret 32)"; good "generated a random EXECUTION_TOKEN"
else
    good "EXECUTION_TOKEN already set (kept)"
fi

# --- 4. Validate compose ------------------------------------------------------
step "Validating docker-compose.yml"
profile_args=()
[ "$WITH_OLLAMA" = "1" ] && profile_args=(--profile ollama)
if ! docker compose ${profile_args[@]+"${profile_args[@]}"} config >/dev/null 2>&1; then
    bad "docker compose config failed - fix .env / compose and re-run"; exit 1
fi
good "compose config is valid"

# --- 5. Bring up the stack ----------------------------------------------------
step "Building and starting the stack (first run downloads base images - this is the slow part)"
if ! docker compose ${profile_args[@]+"${profile_args[@]}"} up -d --build; then
    bad "docker compose up failed - see the output above (try: docker compose logs)"; exit 1
fi
good "stack started (postgres -> migrate -> backend -> frontend)"

# --- 6. Wait for backend healthy ---------------------------------------------
step "Waiting for the backend to become healthy (up to ${WAIT_SECONDS}s)"
deadline=$(( $(date +%s) + WAIT_SECONDS ))
healthy=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    # Resolve the container via compose SERVICE (never a fixed container_name)
    # so any COMPOSE_PROJECT_NAME / `-p <project>` works unchanged.
    cid="$(docker compose ps -q backend 2>/dev/null || true)"
    status=""
    if [ -n "$cid" ]; then
        status="$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || true)"
    fi
    if [ "$status" = "healthy" ]; then healthy=1; break; fi
    printf '.'
    sleep 3
done
echo ""
if [ "$healthy" = "1" ]; then good "backend is healthy (/ready answers 200)"
else note "backend not healthy yet - the smoke test below waits on /ready too; if it fails, run: docker compose logs backend"; fi

# --- 7. Smoke test (in-container; host needs no Python) -----------------------
step "Running the demo smoke test (inside the backend container over real HTTP)"
set +e
docker compose exec -T backend python - --base-url http://127.0.0.1:8000 --wait 60 < "$ROOT/scripts/smoke.py"
smoke_rc=$?
set -e
if [ "$smoke_rc" -eq 0 ]; then good "smoke test passed"
else bad "smoke test FAILED (exit $smoke_rc) - see docs/TROUBLESHOOTING.md and 'docker compose logs backend'"; fi

# --- 8. Access URLs -----------------------------------------------------------
echo ""
echo "SentinelFlow is up."
echo ""
echo "  Frontend (start here):  http://localhost:${fe_port}"
echo "  Backend API:            http://localhost:${be_port}/api/v1"
echo "  Interactive API docs:   http://localhost:${be_port}/docs"
echo ""
echo "  First run: open the Frontend - the smoke test already injected a sample alert over HTTP, so the Dashboard is live (not blank)."
echo "  Full alert storm (optional, needs Python 3.10+ on the host):"
echo "    python simulator/runner/run.py --repeat 30 --base-url http://localhost:${be_port}"
echo "  No host Python? POST alerts interactively from the API docs: http://localhost:${be_port}/docs"
echo "  Then follow the chain in the UI: Events -> Event detail (AI mock) -> Approval Queue -> Execute Console -> Execution Audit -> Observability."
echo ""
echo "  Useful commands:"
echo "    docker compose logs -f backend     # live backend logs"
echo "    docker compose ps                  # service health"
echo "    ./scripts/quickstart.sh --down     # stop and remove"
echo ""
exit "$smoke_rc"
