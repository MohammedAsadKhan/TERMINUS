@echo off
setlocal enabledelayedexpansion
title TERMINUS Autonomous AI SOC Platform - Standalone Service Daemon

set "PYTHONPATH=%~dp0src;%PYTHONPATH%"

echo ===============================================================================
echo   TERMINUS 2.0 - AUTONOMOUS AI SOC & SOAR PLATFORM SERVICE
echo ===============================================================================
echo   [+] Mode: Standalone Background Service (Multi-Tenant AI SOC)
echo   [+] Service Host: 0.0.0.0
echo   [+] Service Port: 8000
echo   [+] Database: terminus.db (SQLite WAL Mode with Idempotent Leases)
echo   [+] Web Console: http://localhost:8000/console/
echo ===============================================================================
echo   Default Credentials:
echo     - Email:    admin@terminus.local
echo     - Password: Password123!
echo ===============================================================================

echo Opening Terminus Operations Center Console in your browser...
start "" http://localhost:8000/console/

where uv >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [✓] Launching with uv environment on port 8000...
    uv run uvicorn terminus.server.app:create_app --factory --host 0.0.0.0 --port 8000
) else if exist "%~dp0.venv\Scripts\python.exe" (
    echo [✓] Launching with local .venv Python environment...
    "%~dp0.venv\Scripts\python.exe" -m uvicorn terminus.server.app:create_app --factory --host 0.0.0.0 --port 8000
) else (
    echo [!] uv not found in PATH; falling back to system Python...
    python -m uvicorn terminus.server.app:create_app --factory --host 0.0.0.0 --port 8000
)

pause
