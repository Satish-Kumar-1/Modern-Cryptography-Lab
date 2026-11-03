@echo off
cd /d "%~dp0"
set "SIGNEDCHAT_PORT=5173"
if not "%~1"=="" set "SIGNEDCHAT_PORT=%~1"
if not "%~2"=="" set "BACKEND_URL=%~2"
call npm.cmd run dev -- --host 127.0.0.1 --port %SIGNEDCHAT_PORT%
