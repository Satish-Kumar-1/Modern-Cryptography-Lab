<#
.SYNOPSIS
    CryptoGuard - Ed25519 Document Verification System Launcher (Electron Desktop Application)
#>

$Host.UI.RawUI.WindowTitle = "CryptoGuard - Ed25519 Desktop Application"
Set-Location -Path $PSScriptRoot

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " CryptoGuard - Ed25519 Desktop Application (Electron)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[ERROR] Python was not found in PATH." -ForegroundColor Red
    Write-Host "Please ensure Python 3.9+ is installed and added to PATH." -ForegroundColor Yellow
    exit 1
}

if (Get-Command npm -ErrorAction SilentlyContinue) {
    Write-Host "Starting Electron desktop application..." -ForegroundColor Green
    npm start
} else {
    Write-Host "[WARNING] npm not found in PATH. Launching in local web server mode..." -ForegroundColor Yellow
    python server.py 8080
}
