@echo off
setlocal enabledelayedexpansion
title TERMINUS - Platform Setup & Installation Wizard

set "PYTHONPATH=%~dp0src;%PYTHONPATH%"

echo ===============================================================================
echo   TERMINUS — INTERACTIVE SETUP & SERVICE INSTALLATION WIZARD
echo ===============================================================================
echo   This wizard will initialize your database, configure LLM reasoning providers,
echo   set up SIEM ingestion webhooks, provision your administrator account, and
echo   generate your cryptographic enterprise license.
echo ===============================================================================
echo.

where uv >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [✓] Running setup with uv environment...
    uv run python scripts/setup.py
) else if exist "%~dp0.venv\Scripts\python.exe" (
    echo [✓] Running setup with local .venv Python environment...
    "%~dp0.venv\Scripts\python.exe" scripts/setup.py
) else (
    echo [!] Running setup with standard Python...
    python scripts/setup.py
)

echo.
echo ===============================================================================
echo [✓] Setup configuration complete!
echo [✓] You can now start the service by running 'run_demo_service.bat'
echo ===============================================================================
pause
