# Trigger a test Splunk alert against the local broker (port 8500).
# Usage: .\trigger-alert.ps1

$uri = if ($env:BROKER_URL) { "$env:BROKER_URL/splunk-alert" } else { "http://127.0.0.1:8500/splunk-alert" }
$body = Get-Content -Raw -Path "$PSScriptRoot\sample-splunk-alert.json"

Invoke-RestMethod -Uri $uri -Method POST -ContentType "application/json" -Body $body
