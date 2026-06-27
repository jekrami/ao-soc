<#
.SYNOPSIS
  Stop AO-SOC demo processes started by start-demo.ps1.

.DESCRIPTION
  Terminates broker, UI API, frontend, and simulator processes recorded in
  scripts/.demo-pids.json. Falls back to killing listeners on ports 8500, 4317,
  and 5173 if the PID file is missing or stale.

.EXAMPLE
  .\scripts\stop-demo.ps1
#>

$ErrorActionPreference = 'SilentlyContinue'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = Join-Path $ScriptDir '.demo-pids.json'
$DemoPorts = @(8500, 4317, 5173)

function Stop-ProcessSafe([int]$ProcessId, [string]$Label) {
    if ($ProcessId -le 0) { return }
    $proc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    if ($proc) {
        Write-Host "  Stopping $Label (PID $ProcessId)..."
        Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
    }
}

function Stop-PortListeners([int]$Port) {
    # netstat works on all Windows versions; Get-NetTCPConnection needs admin on some builds.
    $lines = netstat -ano | Select-String ":\s*$Port\s"
    foreach ($line in $lines) {
        if ($line -match '\s+(\d+)\s*$') {
            $targetPid = [int]$Matches[1]
            if ($targetPid -gt 0 -and $targetPid -ne $PID) {
                Write-Host "  Stopping process on port $Port (PID $targetPid)..."
                Stop-Process -Id $targetPid -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Write-Host 'Stopping AO-SOC demo stack...' -ForegroundColor Cyan

if (Test-Path $PidFile) {
    try {
        $meta = Get-Content $PidFile -Raw | ConvertFrom-Json
        Stop-ProcessSafe -ProcessId $meta.broker -Label 'broker'
        Stop-ProcessSafe -ProcessId $meta.backend -Label 'UI API'
        Stop-ProcessSafe -ProcessId $meta.frontend -Label 'dashboard'
        if ($meta.simulator) {
            Stop-ProcessSafe -ProcessId $meta.simulator -Label 'simulator'
        }
    } catch {
        Write-Host '  Could not read PID file; falling back to port cleanup.' -ForegroundColor Yellow
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
} else {
    Write-Host '  No PID file found; cleaning ports 8500, 4317, 5173.' -ForegroundColor Yellow
}

foreach ($port in $DemoPorts) {
    Stop-PortListeners -Port $port
}

Write-Host 'Done.' -ForegroundColor Green
