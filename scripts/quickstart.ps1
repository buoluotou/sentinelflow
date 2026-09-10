<#
.SYNOPSIS
    SentinelFlow Docker Compose quickstart (Windows) - the recommended install path.

.DESCRIPTION
    One command from a fresh clone to a running Demo:
      1. checks Docker + Docker Compose (v2) and that the daemon is reachable,
      2. checks the ports SentinelFlow binds (5432 / 8000 / 5173 by default),
      3. creates .env from .env.example and fills RANDOM local secrets
         (POSTGRES_PASSWORD, EXECUTION_TOKEN) - never a fixed/committed secret,
      4. validates the compose file (docker compose config),
      5. brings up the stack in the enforced order
         postgres(healthy) -> migrate(one-shot) -> backend -> frontend,
      6. waits for the backend to become healthy,
      7. runs the demo smoke test INSIDE the backend container (so the host
         needs no Python/Node), and
      8. prints the access URLs.

    DEFAULT = Demo Mode: AI_PROVIDER=mock, EXECUTION_ADAPTER=mock, every
    external system (Wazuh/Shuffle/TheHive) disabled. No real SOAR is contacted.

    -WithOllama additionally starts the optional `ollama` profile (AI Local
    Mode). Ollama is never required for the Demo.

.EXAMPLE
    ./scripts/quickstart.ps1
    ./scripts/quickstart.ps1 -WithOllama
    ./scripts/quickstart.ps1 -Down        # stop and remove the stack
#>
[CmdletBinding()]
param(
    [switch]$WithOllama,
    [switch]$Rebuild,
    [switch]$Down,
    [int]$WaitSeconds = 180
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Step($m) { Write-Host ""; Write-Host "==> $m" -ForegroundColor Cyan }
function Good($m) { Write-Host "  [ok] $m" -ForegroundColor Green }
function Note($m) { Write-Host "  [--] $m" -ForegroundColor Yellow }
function Bad($m) { Write-Host "  [!!] $m" -ForegroundColor Red }
function New-Secret([int]$Bytes = 32) {
    $b = [byte[]]::new($Bytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
    return ([Convert]::ToHexString($b)).ToLowerInvariant()
}
function Get-EnvKey([string]$Path, [string]$Key) {
    if (-not (Test-Path $Path)) { return $null }
    foreach ($line in Get-Content $Path) {
        $t = $line.Trim()
        if ($t.StartsWith("#")) { continue }
        if ($t.StartsWith("$Key=")) { return $t.Substring($Key.Length + 1).Trim().Trim('"').Trim("'") }
    }
    return $null
}
function Set-EnvKey([string]$Path, [string]$Key, [string]$Value) {
    $lines = if (Test-Path $Path) { Get-Content $Path } else { @() }
    $seen = $false
    $out = foreach ($l in $lines) {
        if ($l -match "^\s*$Key=") { $seen = $true; "$Key=$Value" } else { $l }
    }
    if (-not $seen) { $out += "$Key=$Value" }
    Set-Content -Path $Path -Value $out -Encoding utf8
}
function Test-Port([int]$Port) {
    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

Write-Host "SentinelFlow Docker quickstart" -ForegroundColor White
Write-Host "repo: $root" -ForegroundColor DarkGray

# --- Tear-down shortcut -------------------------------------------------------
if ($Down) {
    Step "Stopping and removing the stack"
    docker compose down
    Good "stack removed (the pg-data volume is kept; add -v to 'docker compose down' to erase data)"
    exit 0
}

# --- 1. Docker ----------------------------------------------------------------
Step "Checking Docker"
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Bad "Docker not found. Install Docker Desktop (Windows) and re-run, or use scripts/setup-dev.ps1 for Native mode."; exit 1
}
docker version --format "{{.Server.Version}}" *> $null
if ($LASTEXITCODE -ne 0) { Bad "the Docker daemon is not reachable. Start Docker Desktop and re-run."; exit 1 }
Good "Docker daemon reachable"
docker compose version *> $null
if ($LASTEXITCODE -ne 0) { Bad "'docker compose' (v2) not available. Update Docker Desktop."; exit 1 }
Good "Docker Compose v2 available"

# --- 2. Ports -----------------------------------------------------------------
Step "Checking ports"
$envFile = Join-Path $root ".env"
$pgPort = [int]($(if (Get-EnvKey $envFile "POSTGRES_PORT") { Get-EnvKey $envFile "POSTGRES_PORT" } else { 5432 }))
$bePort = [int]($(if (Get-EnvKey $envFile "BACKEND_PORT") { Get-EnvKey $envFile "BACKEND_PORT" } else { 8000 }))
$fePort = [int]($(if (Get-EnvKey $envFile "FRONTEND_PORT") { Get-EnvKey $envFile "FRONTEND_PORT" } else { 5173 }))
foreach ($p in @(@($pgPort, "PostgreSQL"), @($bePort, "backend"), @($fePort, "frontend"))) {
    if (Test-Port $p[0]) {
        Note ("port {0} ({1}) is already bound" -f $p[0], $p[1])
        Note ("  if that is not SentinelFlow, set {0}_PORT in .env to a free port and re-run" -f $(if ($p[1] -eq "PostgreSQL") { "POSTGRES" } elseif ($p[1] -eq "backend") { "BACKEND" } else { "FRONTEND" }))
    } else { Good ("port {0} ({1}) free" -f $p[0], $p[1]) }
}

# --- 3. .env + random local secrets ------------------------------------------
Step "Preparing .env (Demo Mode defaults + random local secrets)"
if (-not (Test-Path $envFile)) {
    if (-not (Test-Path (Join-Path $root ".env.example"))) { Bad ".env.example not found"; exit 1 }
    Copy-Item (Join-Path $root ".env.example") $envFile
    Good "created .env from .env.example"
} else { Good ".env already exists (reusing it)" }
# Demo Mode is the default: never silently enable a real adapter.
if (-not (Get-EnvKey $envFile "AI_PROVIDER")) { Set-EnvKey $envFile "AI_PROVIDER" "mock" }
if (-not (Get-EnvKey $envFile "EXECUTION_ADAPTER")) { Set-EnvKey $envFile "EXECUTION_ADAPTER" "mock" }
# Mandatory random secrets (compose refuses an empty POSTGRES_PASSWORD).
$pgPass = Get-EnvKey $envFile "POSTGRES_PASSWORD"
if (-not $pgPass -or $pgPass -match "change_me|^$") { Set-EnvKey $envFile "POSTGRES_PASSWORD" (New-Secret 24); Good "generated a random POSTGRES_PASSWORD" }
else { Good "POSTGRES_PASSWORD already set (kept)" }
$execTok = Get-EnvKey $envFile "EXECUTION_TOKEN"
if (-not $execTok -or $execTok -match "change_me|^$") { Set-EnvKey $envFile "EXECUTION_TOKEN" (New-Secret 32); Good "generated a random EXECUTION_TOKEN" }
else { Good "EXECUTION_TOKEN already set (kept)" }

# --- 4. Validate compose ------------------------------------------------------
Step "Validating docker-compose.yml"
$profileArgs = @(); if ($WithOllama) { $profileArgs = @("--profile", "ollama") }
docker compose @profileArgs config *> $null
if ($LASTEXITCODE -ne 0) { Bad "docker compose config failed - fix .env / compose and re-run"; exit 1 }
Good "compose config is valid"

# --- 5. Bring up the stack ----------------------------------------------------
Step "Building and starting the stack (first run downloads base images - this is the slow part)"
$upArgs = @("compose") + $profileArgs + @("up", "-d")
if ($Rebuild) { $upArgs += "--build" } else { $upArgs += "--build" }  # always build local images
docker @upArgs
if ($LASTEXITCODE -ne 0) { Bad "docker compose up failed - see the output above (try: docker compose logs)"; exit 1 }
Good "stack started (postgres -> migrate -> backend -> frontend)"

# --- 6. Wait for backend healthy ---------------------------------------------
Step "Waiting for the backend to become healthy (up to ${WaitSeconds}s)"
$deadline = (Get-Date).AddSeconds($WaitSeconds)
$healthy = $false
while ((Get-Date) -lt $deadline) {
    $status = (docker inspect -f "{{.State.Health.Status}}" sf-backend 2>$null)
    if ($status -eq "healthy") { $healthy = $true; break }
    Write-Host "." -NoNewline -ForegroundColor DarkGray
    Start-Sleep -Seconds 3
}
Write-Host ""
if ($healthy) { Good "backend is healthy (/ready answers 200)" }
else { Note "backend not healthy yet - the smoke test below waits on /ready too; if it fails, run: docker compose logs backend" }

# --- 7. Smoke test (in-container; host needs no Python) -----------------------
Step "Running the demo smoke test (inside the backend container over real HTTP)"
Get-Content (Join-Path $root "scripts\smoke.py") -Raw |
    docker compose exec -T backend python - --base-url http://127.0.0.1:8000 --wait 60
$smokeRc = $LASTEXITCODE
if ($smokeRc -eq 0) { Good "smoke test passed" } else { Bad "smoke test FAILED (exit $smokeRc) - see docs/TROUBLESHOOTING.md and 'docker compose logs backend'" }

# --- 8. Access URLs -----------------------------------------------------------
Write-Host ""
Write-Host "SentinelFlow is up." -ForegroundColor White
Write-Host ""
Write-Host ("  Frontend (start here):  http://localhost:{0}" -f $fePort) -ForegroundColor Green
Write-Host ("  Backend API:            http://localhost:{0}/api/v1" -f $bePort)
Write-Host ("  Interactive API docs:   http://localhost:{0}/docs" -f $bePort)
Write-Host ""
Write-Host "  First run: open the Frontend - the smoke test already injected a sample alert over HTTP, so the Dashboard is live (not blank)."
Write-Host "  Full alert storm (optional, needs Python 3.10+ on the host):"
Write-Host ("    python simulator/runner/run.py --repeat 30 --base-url http://localhost:{0}" -f $bePort)
Write-Host ("  No host Python? POST alerts interactively from the API docs: http://localhost:{0}/docs" -f $bePort)
Write-Host "  Then follow the chain in the UI: Events -> Event detail (AI mock) -> Approval Queue -> Execute Console -> Execution Audit -> Observability."
Write-Host ""
Write-Host "  Useful commands:" -ForegroundColor DarkGray
Write-Host "    docker compose logs -f backend     # live backend logs"
Write-Host "    docker compose ps                  # service health"
Write-Host "    ./scripts/quickstart.ps1 -Down     # stop and remove"
Write-Host ""
if ($smokeRc -ne 0) { exit $smokeRc }
exit 0
