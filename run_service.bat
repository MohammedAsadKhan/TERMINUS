@echo off
REM File: run_service.bat
REM Author: Team LARP
REM Revision date: 2026-11-12
REM Version: 0.1.0
REM Purpose: Start the loopback TERMINUS evaluation API and open the local console.

setlocal enabledelayedexpansion
title TERMINUS Local Evaluation Service - Loopback Only
cd /d "%~dp0"

set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
set "TERMINUS_REPO_SCAN_ENABLED=true"
REM A generated .env may set the bind values; the current environment wins.
if exist ".env" (
    for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
        if /I "%%A"=="TERMINUS_HOST" if not defined TERMINUS_HOST set "TERMINUS_HOST=%%B"
        if /I "%%A"=="TERMINUS_PORT" if not defined TERMINUS_PORT set "TERMINUS_PORT=%%B"
    )
)
REM Loopback stays the default so the local evaluation account is not exposed.
if not defined TERMINUS_HOST set "TERMINUS_HOST=127.0.0.1"
if not defined TERMINUS_PORT set "TERMINUS_PORT=8000"
set "BROWSER_HOST=127.0.0.1"
if /I "%TERMINUS_HOST%"=="::1" set "BROWSER_HOST=[::1]"

echo ===============================================================================
echo   TERMINUS - LOCAL EVALUATION SERVICE
echo ===============================================================================
echo   [+] Scope: Single-host evaluation API, not a production or autonomous SOC
echo   [+] Service Host: %TERMINUS_HOST%
echo   [+] Service Port: %TERMINUS_PORT%
echo   [+] Database: terminus.db (SQLite WAL in the working folder)
echo   [+] Web Console: http://%BROWSER_HOST%:%TERMINUS_PORT%/console/
echo   [+] Sign-in: local evaluation account documented in docs/INSTALLATION.md
echo ===============================================================================
echo   Boundaries:
echo     - This launcher starts the API only. It does not start workers.
echo     - Investigation and response workers are separate opt-in processes.
echo     - No model key means offline analysis reported as unknown.
echo     - Do not expose this instance to an untrusted network.
echo ===============================================================================

if /I not "%TERMINUS_HOST%"=="127.0.0.1" if /I not "%TERMINUS_HOST%"=="localhost" if /I not "%TERMINUS_HOST%"=="::1" (
    echo [!] This local evaluation launcher refuses non-loopback binding.
    echo [!] Use a separately reviewed hosted deployment for network access.
    exit /b 2
)

echo Opening the loopback console in your browser...
start "" "http://%BROWSER_HOST%:%TERMINUS_PORT%/console/"

where uv >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [+] Launching with uv environment on %TERMINUS_HOST%:%TERMINUS_PORT%...
    uv run --frozen uvicorn terminus.server.app:create_app --factory --host %TERMINUS_HOST% --port %TERMINUS_PORT%
) else if exist "%~dp0.venv\Scripts\python.exe" (
    echo [+] Launching with local .venv Python environment...
    "%~dp0.venv\Scripts\python.exe" -m uvicorn terminus.server.app:create_app --factory --host %TERMINUS_HOST% --port %TERMINUS_PORT%
) else (
    echo [!] Falling back to system Python...
    python -m uvicorn terminus.server.app:create_app --factory --host %TERMINUS_HOST% --port %TERMINUS_PORT%
)

pause
