@echo off
setlocal
title CryptoGuard - Ed25519 Desktop Application
cd /d "%~dp0"

echo ======================================================================
echo  CryptoGuard - Ed25519 Desktop Application (Electron)
echo ======================================================================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python 3 was not found in PATH.
    echo Please install Python 3.9+ from https://python.org and add to PATH.
    pause
    exit /b 1
)

where npm >nul 2>nul
if %errorlevel% equ 0 (
    echo Starting Electron desktop application...
    call npm start
) else (
    echo [WARNING] npm was not found in PATH. Launching in local server mode...
    python server.py 8080
)

pause
