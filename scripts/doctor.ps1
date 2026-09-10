<#
.SYNOPSIS
    SentinelFlow doctor - one-shot environment & configuration diagnostics (Windows).

.DESCRIPTION
    Checks everything a first-time user could trip over, in one pass, and prints
    a clear PASS / WARN / FAIL per item plus a summary. Run this BEFORE reading
    long troubleshooting docs.

    Covered: Python, Node, npm, Docker, Docker Compose, PostgreSQL, the ports
    SentinelFlow binds, the root .env, DATABASE_URL / AI_PROVIDER / execution &
    external-adapter configuration, the frontend API base URL, the Alembic
    migration head vs current, and (unless -SkipHttp) the live backend /health
    and /ready endpoints.

    Exit code: 0 when there is no FAIL, 1 when at least one FAIL was found.
    WARN never fails the run (Docker / PostgreSQL are optional depending on the
    mode you intend to use - see the guidance each WARN prints).

.EXAMPLE
    ./scripts/doctor.ps1
    ./scripts/doctor.ps1 -BaseUrl http://127.0.0.1:8000 -SkipHttp
#>
[CmdletBinding()]
param(
    [string]$BaseUrl = $(if ($env:SF_BASE_URL) { $env:SF_BASE_URL } else { "http://127.0.0.1:8000" }),
    [int]$BackendPort = 8000,
    [int]$FrontendPort = $(if ($env:FRONTEND_PORT) { [int]$env:FRONTEND_PORT } else { 5173 }),
    [int]$PostgresPort = 5432,
    [switch]$SkipHttp
)

$ErrorActionPreference = "SilentlyContinue"
$root = Split-Path -Parent $PSScriptRoot

$script:nPass = 0; $script:nWarn = 0; $script:nFail = 0
function Write-Check {
    param([string]$Level, [string]$Name, [string]$Detail)
    switch ($Level) {
        "PASS" { $script:nPass++; $color = "Green" }
        "WARN" { $script:nWarn++; $color = "Yellow" }
        "FAIL" { $script:nFail++; $color = "Red" }
        default { $color = "Gray" }
    }
    Write-Host ("  [{0}] " -f $Level) -ForegroundColor $color -NoNewline
    Write-Host ("{0}: " -f $Name) -NoNewline -ForegroundColor Cyan
    Write-Host $Detail
}
function OK($n, $d) { Write-Check "PASS" $n $d }
function Warn($n, $d) { Write-Check "WARN" $n $d }
function Fail($n, $d) { Write-Check "FAIL" $n $d }

function Get-EnvValue {
    param([string]$Path, [string]$Key)
    if (-not (Test-Path $Path)) { return $null }
    foreach ($line in Get-Content -Path $Path) {
        $t = $line.Trim()
        if ($t.StartsWith("#")) { continue }
        if ($t.StartsWith("$Key=")) {
            return $t.Substring($Key.Length + 1).Trim().Trim('"').Trim("'")
        }
    }
    return $null
}
function Test-Port {
    param([int]$Port)
    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

Write-Host ""
Write-Host "SentinelFlow doctor" -ForegroundColor White
Write-Host ("repo: {0}" -f $root) -ForegroundColor DarkGray
Write-Host ""

# --- Interpreters & toolchains ------------------------------------------------
Write-Host "Toolchain" -ForegroundColor White
$pyCmd = $null
foreach ($c in @((Join-Path $root "backend\.venv\Scripts\python.exe"), "python", "python3", "py")) {
    if ($c -like "*.exe") { if (Test-Path $c) { $pyCmd = $c; break } }
    elseif (Get-Command $c -ErrorAction SilentlyContinue) { $pyCmd = $c; break }
}
if ($pyCmd) {
    $pv = (& $pyCmd --version 2>&1) -replace "Python ", ""
    $parts = $pv.Split("."); $maj = [int]$parts[0]; $min = [int]$parts[1]
    if ($maj -gt 3 -or ($maj -eq 3 -and $min -ge 10)) { OK "Python" "$pv ($pyCmd) - >=3.10 required, 3.12 verified" }
    else { Fail "Python" "$pv is too old - SentinelFlow needs >=3.10 (dataclass slots); 3.12 recommended" }
} else { Fail "Python" "not found - install Python 3.12 or run scripts/setup-dev.ps1" }

$node = Get-Command node -ErrorAction SilentlyContinue
if ($node) {
    $nv = (& node --version 2>&1) -replace "^v", ""
    $nmaj = [int]$nv.Split(".")[0]
    if ($nmaj -ge 20) { OK "Node" "v$nv - >=20.19 required by Vite 8; 22 LTS recommended" }
    else { Fail "Node" "v$nv is too old - Vite 8 needs Node ^20.19 || >=22.12" }
} else { Warn "Node" "not found - only needed for Native dev / frontend build (Docker quickstart builds it in-container)" }

if (Get-Command npm -ErrorAction SilentlyContinue) { OK "npm" ((& npm --version 2>&1) + " (frontend uses package-lock.json)") }
else { Warn "npm" "not found - needed for Native frontend dev; the Docker quickstart does not require it" }

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($docker) {
    $dv = (& docker version --format "{{.Server.Version}}" 2>&1)
    if ($LASTEXITCODE -eq 0) { OK "Docker" "engine $dv (daemon reachable)" }
    else { Warn "Docker" "CLI present but the daemon is not reachable - start Docker Desktop; needed for the Docker quickstart only" }
    $compose = (& docker compose version 2>&1)
    if ($LASTEXITCODE -eq 0) { OK "Docker Compose" (($compose -split "\s+")[2]) }
    else { Warn "Docker Compose" "not available - the Docker quickstart needs 'docker compose' (v2 plugin)" }
} else { Warn "Docker" "not found - the Docker quickstart is unavailable; use Native mode (scripts/setup-dev.ps1)" }

# --- Database -----------------------------------------------------------------
Write-Host ""
Write-Host "Database" -ForegroundColor White
if (Get-Command psql -ErrorAction SilentlyContinue) {
    $pgv = (& psql --version 2>&1) -replace "psql \(PostgreSQL\) ", ""
    OK "PostgreSQL client" "$pgv (psql on PATH)"
} else { Warn "PostgreSQL client" "psql not on PATH - fine for the Docker quickstart (compose bundles PostgreSQL 16)" }
if (Test-Port $PostgresPort) { Warn "Port $PostgresPort" "something is already listening - a local PostgreSQL? Demo Mode uses PostgreSQL; make sure DATABASE_URL matches it" }
else { OK "Port $PostgresPort" "free (compose will bind PostgreSQL here, or point DATABASE_URL at a remote one)" }

# --- Ports we bind ------------------------------------------------------------
Write-Host ""
Write-Host "Ports" -ForegroundColor White
foreach ($p in @(@($BackendPort, "backend"), @($FrontendPort, "frontend"))) {
    if (Test-Port $p[0]) { Warn ("Port {0} ({1})" -f $p[0], $p[1]) "already bound - if that is not SentinelFlow, set BACKEND_PORT/FRONTEND_PORT to a free port" }
    else { OK ("Port {0} ({1})" -f $p[0], $p[1]) "free" }
}

# --- Configuration ------------------------------------------------------------
Write-Host ""
Write-Host "Configuration" -ForegroundColor White
$envFile = Join-Path $root ".env"
if (Test-Path $envFile) {
    OK ".env" "present at repo root"
    $dbUrl = Get-EnvValue $envFile "DATABASE_URL"
    if ($dbUrl) {
        $scheme = ($dbUrl -split "://")[0]
        if ($dbUrl -match "change_me|postgres:postgres|password=password") { Warn "DATABASE_URL" "scheme=$scheme but it still contains a placeholder/weak credential - set a real one (value not printed)" }
        elseif ($scheme -eq "sqlite") { Warn "DATABASE_URL" "sqlite - the full Demo chain (durable dispatch execution) needs PostgreSQL/MVCC; SQLite proves the chain up to approval only" }
        else { OK "DATABASE_URL" "scheme=$scheme (value not printed)" }
    } else { Warn "DATABASE_URL" "not set in .env - the backend default is PostgreSQL; the Docker quickstart injects it" }

    $aiProvider = Get-EnvValue $envFile "AI_PROVIDER"; if (-not $aiProvider) { $aiProvider = "mock (default)" }
    OK "AI_PROVIDER" $aiProvider
    $execAdapter = Get-EnvValue $envFile "EXECUTION_ADAPTER"; if (-not $execAdapter) { $execAdapter = "mock (default)" }
    OK "EXECUTION_ADAPTER" $execAdapter

    $execToken = Get-EnvValue $envFile "EXECUTION_TOKEN"
    $operators = Get-EnvValue $envFile "OPERATORS_JSON"
    if ($execToken -or $operators) { OK "Execution auth" "configured (EXECUTION_TOKEN/OPERATORS_JSON set - value not printed)" }
    else { Warn "Execution auth" "EXECUTION_TOKEN/OPERATORS_JSON empty - every write/execute path returns 401; the quickstart generates a random local token" }

    foreach ($pair in @(@("SHUFFLE_BASE_URL", "Shuffle"), @("WAZUH_BASE_URL", "Wazuh"), @("THEHIVE_BASE_URL", "TheHive"))) {
        $v = Get-EnvValue $envFile $pair[0]
        if ($v) { Warn ("{0} (Integration Lab)" -f $pair[1]) "ENABLED ($($pair[0]) set) - LAB/EXPERIMENTAL, NOT production-certified" }
        else { OK ("{0} (Integration Lab)" -f $pair[1]) "disabled (default) - Demo Mode needs no external SOAR" }
    }
} else {
    Warn ".env" "not found - copy .env.example to .env, or run scripts/quickstart.ps1 / scripts/setup-dev.ps1 which create it"
}

$feEnv = Join-Path $root "frontend\.env"
$viteBase = Get-EnvValue $feEnv "VITE_API_BASE_URL"
if ($viteBase) { OK "VITE_API_BASE_URL" "'$viteBase' (frontend/.env) - the single authoritative API base" }
else { OK "VITE_API_BASE_URL" "unset - frontend uses same-origin relative /api (correct behind nginx / vite proxy)" }

# --- Migrations (hang-proof) --------------------------------------------------
Write-Host ""
Write-Host "Migrations" -ForegroundColor White
$backendDir = Join-Path $root "backend"
if ((Test-Path (Join-Path $backendDir "alembic.ini")) -and $pyCmd) {
    Push-Location $backendDir
    # `alembic heads` only reads the script directory - no DB connection.
    $headOut = (& $pyCmd -m alembic heads 2>&1) -join "`n"
    $headRev = ([regex]::Match($headOut, "(?m)^([0-9A-Za-z_]+)\s*\(head\)")).Groups[1].Value
    Pop-Location
    # `alembic current` connects to the DB. Guard it with a short libpq connect
    # timeout AND a hard job timeout so an unreachable PostgreSQL can never hang
    # doctor (PGCONNECT_TIMEOUT is honored by psycopg3's bundled libpq).
    $curRev = $null; $timedOut = $false
    $job = Start-Job -ScriptBlock {
        param($py, $dir)
        Set-Location $dir
        $env:PGCONNECT_TIMEOUT = "3"
        (& $py -m alembic current 2>&1) -join "`n"
    } -ArgumentList $pyCmd, $backendDir
    if (Wait-Job $job -Timeout 20 | Out-Null) {
        $curOut = (Receive-Job $job) -join "`n"
        $curRev = ([regex]::Match($curOut, "(?m)^([0-9A-Za-z_]+)\s")).Groups[1].Value
    } else { Stop-Job $job; $timedOut = $true }
    Remove-Job $job -Force
    if ($timedOut) { Warn "Alembic current" "timed out reading migration state (DATABASE_URL unreachable?) - head=$headRev" }
    elseif ($headRev -and $curRev) {
        if ($curRev -eq $headRev) { OK "Alembic" "current == head ($headRev) - the reachable DB is migrated" }
        else { Warn "Alembic" "current=$curRev but head=$headRev - run: (cd backend; alembic upgrade head)" }
    } elseif ($headRev) { Warn "Alembic" "head=$headRev; no current revision read (DB not migrated yet or unreachable)" }
    else { Warn "Alembic" "could not resolve head (check backend/alembic.ini and DATABASE_URL)" }
} else { Warn "Alembic" "backend/alembic.ini or Python missing - cannot check migration state" }

# --- Live backend -------------------------------------------------------------
Write-Host ""
Write-Host "Runtime" -ForegroundColor White
if ($SkipHttp) {
    Warn "Backend HTTP" "skipped (-SkipHttp)"
} else {
    try {
        $req = [System.Net.HttpWebRequest]::Create("$($BaseUrl.TrimEnd('/'))/health")
        $req.Timeout = 4000; $req.Proxy = $null
        $resp = $req.GetResponse(); $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $bodyTxt = $reader.ReadToEnd(); $reader.Close(); $resp.Close()
        OK "GET /health" "200 - $BaseUrl is up"
        try {
            $j = $bodyTxt | ConvertFrom-Json
            OK "Health body" ("service={0} database={1} driver={2}" -f $j.service, $j.database, $j.database_driver)
        } catch { Warn "Health body" "non-JSON response" }
        try {
            $r2 = [System.Net.HttpWebRequest]::Create("$($BaseUrl.TrimEnd('/'))/ready"); $r2.Timeout = 4000; $r2.Proxy = $null
            $resp2 = $r2.GetResponse(); $resp2.Close(); OK "GET /ready" "200 - database answers SELECT 1"
        } catch { Fail "GET /ready" "not ready (DB unreachable?) - $($_.Exception.Message)" }
    } catch {
        Warn "Backend HTTP" "no backend at $BaseUrl (not started) - run scripts/quickstart.ps1 (Docker) or scripts/setup-dev.ps1 (Native), then re-run doctor"
    }
}

# --- Summary ------------------------------------------------------------------
Write-Host ""
Write-Host ("Summary: {0} PASS, {1} WARN, {2} FAIL" -f $script:nPass, $script:nWarn, $script:nFail) -ForegroundColor White
if ($script:nFail -gt 0) {
    Write-Host "doctor: FAIL - resolve the FAIL items above, then re-run." -ForegroundColor Red
    exit 1
}
Write-Host "doctor: PASS - no blocking issues (review any WARN for your chosen mode)." -ForegroundColor Green
exit 0
