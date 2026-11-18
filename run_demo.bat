@echo off
REM File: run_demo.bat
REM Author: Team LARP
REM Revision date: 2026-11-14
REM Version: 0.1.0
REM Purpose: Start the isolated synthetic bank and SOC rehearsal on loopback.

setlocal
cd /d "%~dp0"

echo TERMINUS disposable presentation rehearsal
echo This creates a separate temporary database and serves the bank and SOC on loopback.
echo Existing TERMINUS records are not reset.

where uv >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    uv run --frozen python scripts/presentation_rehearsal.py --bank-demo %*
) else if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" scripts/presentation_rehearsal.py --bank-demo %*
) else (
    echo Install the locked dependencies with uv sync --frozen before starting the demo.
    exit /b 1
)

exit /b %ERRORLEVEL%
