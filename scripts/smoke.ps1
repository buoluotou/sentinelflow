<#
.SYNOPSIS
    SentinelFlow demo smoke test (Windows wrapper).

.DESCRIPTION
    Thin wrapper around the real cross-platform runner scripts/smoke.py, which
    drives the FULL core chain over real HTTP (never imports app services). It
    picks the best available Python (backend venv first), forwards every
    argument to smoke.py and propagates its exit code.

    On PostgreSQL (Demo Mode) it asserts the complete chain incl. the durable
    dispatch execution; on SQLite it proves the business chain through human
    approval and asserts the execution step fails CLOSED. See smoke.py.

.EXAMPLE
    ./scripts/smoke.ps1
    ./scripts/smoke.ps1 --base-url http://127.0.0.1:8000 --token $env:EXECUTION_TOKEN
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$smoke = Join-Path $root "scripts\smoke.py"

if (-not (Test-Path $smoke)) {
    Write-Error "smoke.py not found at $smoke"
    exit 2
}

# Prefer the backend virtualenv (it has every dependency); fall back to a
# system interpreter. smoke.py is stdlib-only, so any Python 3.10+ works.
$venvPy = Join-Path $root "backend\.venv\Scripts\python.exe"
$py = $null
foreach ($candidate in @($venvPy, "python", "python3", "py")) {
    if ($candidate -eq $venvPy) {
        if (Test-Path $venvPy) { $py = $venvPy; break }
    } elseif (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $py = $candidate; break
    }
}
if (-not $py) {
    Write-Error "No Python interpreter found. Install Python 3.10+ or run scripts/setup-dev.ps1 first."
    exit 2
}

& $py $smoke @Rest
exit $LASTEXITCODE
