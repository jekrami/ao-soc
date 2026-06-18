# Prints the SSH commit-signing public key and opens GitHub signing-key settings.
$keyPath = Join-Path $env:USERPROFILE '.ssh\id_rsa.pub'
if (-not (Test-Path $keyPath)) {
    Write-Error "No signing key at $keyPath"
    exit 1
}

Write-Host "`nAdd this key on GitHub as Key type: Signing key`n" -ForegroundColor Cyan
Get-Content $keyPath
Write-Host "`nFingerprint:" -ForegroundColor Cyan
ssh-keygen -lf $keyPath

try {
    Get-Content $keyPath | Set-Clipboard
    Write-Host "`nCopied to clipboard." -ForegroundColor Green
} catch {
    Write-Host "`nCopy the key above manually." -ForegroundColor Yellow
}

Start-Process 'https://github.com/settings/ssh/new'
