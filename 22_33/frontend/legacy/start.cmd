@echo off
cd /d "%~dp0"
java tools/DevServer.java %*
if errorlevel 1 pause
