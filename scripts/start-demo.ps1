<#
.SYNOPSIS
  Prepare and launch the full AO-SOC demo stack on Windows.

.DESCRIPTION
  One-shot demo bootstrap for local recordings and smoke tests (no Ollama, no Splunk).

  What this script does:
    1. Verifies Python 3 and Node.js/npm are available
    2. Installs orchestrator Python deps and backend/frontend npm packages (unless -SkipInstall)
    3. Starts the Aegis-Link broker (uvicorn :8500) in a new console window
    4. Starts the Express UI API (:4317) in a new console window
    5. Starts the Vite dashboard (:5173) in a new console window
    6. Loads demo alerts:
         - Default: batch seed (12 varied incidents via seed_demo_alert.py)
         - With -Live: real-time trickle via simulate_alerts.py in a fourth window

  After completion, open http://localhost:5173 — broker incidents show LIVE badges.

.PARAMETER Live
  Use live simulation (Option A) instead of instant batch seed (Option B).

.PARAMETER Count
  Number of alerts for batch seed (default: 12). Ignored when -Live is set.

.PARAMETER SkipInstall
  Skip pip/npm install steps (use when dependencies are already installed).

.PARAMETER Seed
  RNG seed for reproducible demo data (default: 42).

.PARAMETER SimInterval
  Seconds between alert batches in live mode (default: 10).

.PARAMETER SimDuration
  Total simulation duration in seconds (default: 120).

.EXAMPLE
  .\scripts\start-demo.ps1

.EXAMPLE
  .\scripts\start-demo.ps1 -Live -SimDuration 180

.NOTES
  Stop everything with: .\scripts\stop-demo.ps1
  Manual runbook: README.md "Demo usage"
#>

[CmdletBinding()]
param(
    [switch]$Live,
    [int]$Count = 12,
    [switch]$SkipInstall,
    [int]$Seed = 42,
    [double]$SimInterval = 10,
    [double]$SimDuration = 120
)

$ErrorActionPreference = 'Stop'

# --- Paths (script lives in repo/scripts/) ---
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir '..')).Path
$OrchestratorDir = Join-Path $RepoRoot 'orchestrator'
$BackendDir = Join-Path $RepoRoot 'backend'
$FrontendDir = Join-Path $RepoRoot 'frontend'
$PidFile = Join-Path $ScriptDir '.demo-pids.json'

$BrokerUrl = 'http://127.0.0.1:8500'
$ApiUrl = 'http://127.0.0.1:4317'
$DashboardUrl = 'http://localhost:5173'

# --- Helpers ---

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Test-CommandExists([string]$Name) {
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Wait-HttpOk {
    param(
        [string]$Url,
        [int]$TimeoutSec = 90,
        [string]$Label = $Url
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                Write-Host "    OK: $Label" -ForegroundColor Green
                return
            }
        } catch {
            # Broker/API still starting
        }
        Start-Sleep -Seconds 2
    }
    throw "Timed out after ${TimeoutSec}s waiting for $Label ($Url)"
}

function Start-DemoWindow {
    param(
        [string]$Title,
        [string]$WorkingDirectory,
        [string]$Command
    )
    # Separate console per service so demo logs stay visible (matches README manual flow).
    $proc = Start-Process -FilePath 'powershell.exe' -PassThru -ArgumentList @(
        '-NoExit',
        '-Command',
        "`$Host.UI.RawUI.WindowTitle = '$Title'; Set-Location '$WorkingDirectory'; $Command"
    )
    return $proc.Id
}

# --- 1. Prerequisites ---

Write-Step 'Checking prerequisites'

if (-not (Test-CommandExists 'python')) {
    throw 'Python not found on PATH. Install Python 3.11+ and re-run.'
}
if (-not (Test-CommandExists 'node')) {
    throw 'Node.js not found on PATH. Install Node 20+ and re-run.'
}
if (-not (Test-CommandExists 'npm')) {
    throw 'npm not found on PATH. Install Node.js (includes npm) and re-run.'
}

$pyVersion = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "    Python $pyVersion, Node $(& node -v)"

# --- 2. Install dependencies ---

if (-not $SkipInstall) {
    Write-Step 'Installing dependencies (use -SkipInstall to skip)'

    Write-Host '    pip install -r orchestrator/requirements.txt'
    Push-Location $OrchestratorDir
    & python -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { throw 'pip install failed for orchestrator' }
    Pop-Location

    foreach ($dir in @($BackendDir, $FrontendDir)) {
        Write-Host "    npm install in $dir"
        Push-Location $dir
        & npm install
        if ($LASTEXITCODE -ne 0) { throw "npm install failed in $dir" }
        Pop-Location
    }
} else {
    Write-Host '    Skipping install (-SkipInstall)' -ForegroundColor DarkGray
}

# --- 3. Start broker (must be first — backend merges live alerts from BROKER_URL) ---

Write-Step 'Starting Aegis-Link broker on port 8500'

$brokerCmd = "`$env:BROKER_PORT='8500'; python -m uvicorn soc_orchestrator:app --host 0.0.0.0 --port 8500"
$brokerPid = Start-DemoWindow -Title 'AO-SOC Broker' -WorkingDirectory $OrchestratorDir -Command $brokerCmd

Start-Sleep -Seconds 3
Wait-HttpOk -Url "$BrokerUrl/health" -Label 'Broker /health'

# --- 4. Start UI API ---

Write-Step 'Starting Express UI API on port 4317'

$apiCmd = "`$env:BROKER_URL='$BrokerUrl'; npm start"
$apiPid = Start-DemoWindow -Title 'AO-SOC API' -WorkingDirectory $BackendDir -Command $apiCmd

Start-Sleep -Seconds 2
Wait-HttpOk -Url "$ApiUrl/api/health" -Label 'UI API /api/health'

# --- 5. Start dashboard ---

Write-Step 'Starting Vite dashboard on port 5173'

$fePid = Start-DemoWindow -Title 'AO-SOC Dashboard' -WorkingDirectory $FrontendDir -Command 'npm run dev'

Start-Sleep -Seconds 4

# --- 6. Demo data ---

$simPid = $null

if ($Live) {
    Write-Step "Starting live alert simulation (${SimInterval}s interval, ${SimDuration}s duration)"

    $simArgs = @(
        'simulate_alerts.py',
        '--interval', $SimInterval,
        '--duration', $SimDuration,
        '--seed', $Seed
    )
    $simCmdLine = "python $($simArgs -join ' ')"
    $simPid = Start-DemoWindow -Title 'AO-SOC Simulator' -WorkingDirectory $OrchestratorDir -Command $simCmdLine
} else {
    Write-Step "Seeding $Count demo alerts (batch mode, resets prior demo data)"

    Push-Location $OrchestratorDir
    $seedArgs = @('seed_demo_alert.py', '--count', $Count, '--seed', $Seed)
    & python @seedArgs
    if ($LASTEXITCODE -ne 0) { throw 'seed_demo_alert.py failed' }
    Pop-Location
}

# --- 7. Save PIDs for stop-demo.ps1 ---

$meta = @{
    broker    = $brokerPid
    backend   = $apiPid
    frontend  = $fePid
    simulator = $simPid
    ports     = @(8500, 4317, 5173)
    mode      = if ($Live) { 'live' } else { 'batch' }
    startedAt = (Get-Date).ToString('o')
}
$meta | ConvertTo-Json | Set-Content -Path $PidFile -Encoding UTF8

# --- Done ---

Write-Host ''
Write-Host '========================================' -ForegroundColor Green
Write-Host ' AO-SOC demo stack is running' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor Green
Write-Host ''
Write-Host "  Dashboard:     $DashboardUrl"
Write-Host "  Live alerts:   $DashboardUrl/alerts"
Write-Host "  Broker health: $BrokerUrl/health"
Write-Host "  UI API:        $ApiUrl/api/summary"
Write-Host ''
Write-Host "  Mode:          $(if ($Live) { 'Live simulation' } else { "Batch seed ($Count alerts)" })"
Write-Host '  Stop all:      .\scripts\stop-demo.ps1'
Write-Host ''
Write-Host '  Broker/API/Dashboard run in separate PowerShell windows.' -ForegroundColor DarkGray
Write-Host '  Mock incidents are hidden while the broker is up (LIVE posture).' -ForegroundColor DarkGray
Write-Host ''
