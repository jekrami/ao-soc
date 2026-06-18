# Prints the SSH commit-signing public key and opens GitHub signing-key settings.
$keyPath = Join-Path $env:USERPROFILE '.ssh\id_rsa.pub'
if (-not (Test-Path $keyPath)) {
    Write-Error "No signing key at $keyPath"
    exit 1
}

Write-Host "`nGit signs commits with: $keyPath" -ForegroundColor Cyan
Write-Host "`nOn GitHub you MUST add this key with Key type: Signing key" -ForegroundColor Yellow
Write-Host "(Authentication keys do NOT verify commits — upload the same key again as Signing key)`n" -ForegroundColor Yellow
Get-Content $keyPath
Write-Host "`nFingerprint — must match on GitHub:" -ForegroundColor Cyan
ssh-keygen -lf $keyPath

try {
    Get-Content $keyPath | Set-Clipboard
    Write-Host "`nCopied to clipboard." -ForegroundColor Green
} catch {
    Write-Host "`nCopy the key above manually." -ForegroundColor Yellow
}

Start-Process 'https://github.com/settings/ssh/new'
