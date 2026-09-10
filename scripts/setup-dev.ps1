<#
.SYNOPSIS
    SentinelFlow native development setup (Windows).

.DESCRIPTION
    Prepares a local, non-Docker development environment:
      1. checks Python / Node / npm (versions derived from the real project:
         Python >=3.10 [3.12 verified], Node >=20.19 [Vite 8], npm),
      2. creates backend\.venv and installs backend requirements,
      3. installs frontend dependencies (npm ci against package-lock.json),
      4. creates .env from .env.example with a RANDOM local EXECUTION_TOKEN
         (never a fixed/committed secret),
      5. provisions the database and runs `alembic upgrade head`,
      6. prints how to start the backend and frontend dev servers.

    Database choice (-Database):
      postgres (default) : use the DATABASE_URL in .env (Demo Mode / production).
                           Needs a reachable PostgreSQL; migration is attempted
                           and a clear WARN is printed if it is not reachable.
      sqlite             : provision a local SQLite file for core-chain dev.
                           NOTE: the full Demo chain's durable-dispatch execution
                           step needs PostgreSQL/MVCC; SQLite runs the chain up to
                           human approval and fails CLOSED at execution.

    This script never enables a real external adapter and never writes a fixed
    secret. Integration Lab (Wazuh/Shuffle/TheHive) stays disabled by default.

.EXAMPLE
    ./scripts/setup-dev.ps1
    ./scripts/setup-dev.ps1 -Database sqlite
#>
[CmdletBinding()]
param(
    [ValidateSet("postgres", "sqlite")]
    [string]$Database = "postgres",
    [switch]$SkipFrontend,
    [switch]$WithDevDeps
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"

function Step($m) { Write-Host ""; Write-Host "==> $m" -ForegroundColor Cyan }
function Good($m) { Write-Host "  [ok] $m" -ForegroundColor Green }
function Note($m) { Write-Host "  [--] $m" -ForegroundColor Yellow }
function Bad($m) { Write-Host "  [!!] $m" -ForegroundColor Red }
function New-Secret([int]$Bytes = 32) {
    $b = [byte[]]::new($Bytes)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($b)
    return ([Convert]::ToHexString($b)).ToLowerInvariant()
}

Write-Host "SentinelFlow native dev setup" -ForegroundColor White
Write-Host "repo: $root" -ForegroundColor DarkGray

# --- 1. Prerequisites ---------------------------------------------------------
Step "Checking prerequisites"
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if (-not $py) { Bad "Python not found. Install Python 3.12 from python.org and re-run."; exit 1 }
$pyExe = $py.Source
$pv = (& $pyExe --version 2>&1) -replace "Python ", ""
$pp = $pv.Split("."); if ([int]$pp[0] -lt 3 -or ([int]$pp[0] -eq 3 -and [int]$pp[1] -lt 10)) {
    Bad "Python $pv is too old (need >=3.10; 3.12 recommended)."; exit 1
}
Good "Python $pv ($pyExe)"

if (-not $SkipFrontend) {
    $node = Get-Command node -ErrorAction SilentlyContinue
    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if (-not $node -or -not $npm) { Bad "Node/npm not found. Install Node 22 LTS (nodejs.org) or re-run with -SkipFrontend."; exit 1 }
    $nv = (& node --version 2>&1) -replace "^v", ""
    $nver = ([int]$nv.Split(".")[0]) * 100 + ([int]$nv.Split(".")[1])  # Vite 8: ^20.19 || >=22.12 (Node 21 unsupported)
    if (-not ((($nver -ge 2019) -and ($nver -lt 2100)) -or ($nver -ge 2212))) { Bad "Node v$nv is too old (Vite 8 needs Node ^20.19 || >=22.12; 22 LTS recommended)."; exit 1 }
    Good "Node v$nv, npm $(& npm --version 2>&1)"
}

# --- 2. Backend virtualenv + deps --------------------------------------------
Step "Creating backend virtualenv and installing dependencies"
$venvPy = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) {
    & $pyExe -m venv (Join-Path $backend ".venv")
    if ($LASTEXITCODE -ne 0) { Bad "venv creation failed"; exit 1 }
    Good "created backend\.venv"
} else { Good "backend\.venv already exists" }
& $venvPy -m pip install --upgrade pip --quiet
$reqs = @("requirements\base.lock")
if ($WithDevDeps) { $reqs += "requirements\dev.lock" }
Push-Location $backend
foreach ($r in $reqs) {
    & $venvPy -m pip install -r $r --quiet
    if ($LASTEXITCODE -ne 0) { Pop-Location; Bad "pip install -r $r failed"; exit 1 }
    Good "installed $r"
}
Pop-Location

# --- 3. .env ------------------------------------------------------------------
Step "Initializing .env"
$envFile = Join-Path $root ".env"
$example = Join-Path $root ".env.example"
if (Test-Path $envFile) {
    Good ".env already exists - leaving it untouched (idempotent)"
} elseif (Test-Path $example) {
    Copy-Item $example $envFile
    # Inject a RANDOM local execution token so the write/execute paths work
    # out of the box; never a fixed/committed secret.
    $token = New-Secret 32
    $lines = Get-Content $envFile
    $out = foreach ($l in $lines) {
        if ($l -match '^\s*EXECUTION_TOKEN=') { "EXECUTION_TOKEN=$token" } else { $l }
    }
    Set-Content -Path $envFile -Value $out -Encoding utf8
    Good "created .env from .env.example (random EXECUTION_TOKEN generated)"
} else {
    Bad ".env.example not found - cannot initialize .env"; exit 1
}

# --- 4. Database + migration --------------------------------------------------
Step "Provisioning database ($Database) and running migrations"
if ($Database -eq "sqlite") {
    $sqlitePath = "sqlite:///./sentinelflow_dev.db"
    $lines = Get-Content $envFile
    $seen = $false
    $out = foreach ($l in $lines) {
        if ($l -match '^\s*DATABASE_URL=') { $seen = $true; "DATABASE_URL=$sqlitePath" } else { $l }
    }
    if (-not $seen) { $out += "DATABASE_URL=$sqlitePath" }
    Set-Content -Path $envFile -Value $out -Encoding utf8
    Note "DATABASE_URL set to a local SQLite file (core-chain dev only; execution needs PostgreSQL)"
}
$env:DATABASE_URL = $null  # let alembic read it from .env via Settings
Push-Location $backend
& $venvPy -m alembic upgrade head 2>&1 | Select-Object -Last 3
if ($LASTEXITCODE -eq 0) { Good "alembic upgrade head succeeded" }
else {
    if ($Database -eq "postgres") {
        Note "migration did not complete - is PostgreSQL running and DATABASE_URL correct?"
        Note "tip: re-run with '-Database sqlite' for a zero-dependency local core-chain dev DB"
    } else { Bad "alembic upgrade head failed"; Pop-Location; exit 1 }
}
Pop-Location

# --- 5. Frontend deps ---------------------------------------------------------
if (-not $SkipFrontend) {
    Step "Installing frontend dependencies (npm ci)"
    Push-Location $frontend
    if (Test-Path "package-lock.json") { & npm ci --no-audit --no-fund 2>&1 | Select-Object -Last 3 }
    else { & npm install --no-audit --no-fund 2>&1 | Select-Object -Last 3 }
    if ($LASTEXITCODE -eq 0) { Good "frontend dependencies installed" } else { Bad "npm install failed"; Pop-Location; exit 1 }
    Pop-Location
}

# --- 6. Next steps ------------------------------------------------------------
Write-Host ""
Write-Host "Setup complete. Start the dev servers:" -ForegroundColor White
Write-Host ""
Write-Host "  Backend  (terminal 1):" -ForegroundColor Gray
Write-Host "    cd backend"
Write-Host "    .\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000"
Write-Host ""
if (-not $SkipFrontend) {
    Write-Host "  Frontend (terminal 2):" -ForegroundColor Gray
    Write-Host "    cd frontend"
    Write-Host "    npm run dev     # opens http://localhost:5173"
    Write-Host ""
}
Write-Host "  Then verify:  ./scripts/doctor.ps1   and   ./scripts/smoke.ps1" -ForegroundColor Gray
Write-Host ""
exit 0
