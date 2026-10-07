@echo off
setlocal enabledelayedexpansion
title TERMINUS - Presentation and Live Demo Runner
cd /d "%~dp0"

set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
set "TERMINUS_REPO_SCAN_ENABLED=true"

echo ===============================================================================
echo   TERMINUS - PRESENTATION DEMO AND LIVE ADVERSARY STREAM RUNNER
echo ===============================================================================
echo   [+] Mode: Full Interactive Presentation Demo (Traffic, Alerts and Guardrails)
echo   [+] Target Service: http://127.0.0.1:8000
echo   [+] Web Console: http://127.0.0.1:8000/console/
echo ===============================================================================

:: 1. Clear previous alerts, incidents, workflow runs and transient records
echo [*] Purging previous alert and incident records for a fresh demo state...
where uv >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    uv run --frozen python -c "import sqlite3, os; (conn := sqlite3.connect('terminus.db'), [conn.execute(f'DELETE FROM {t}') for t in ['incidents','alert_claims','workflow_runs','node_runs','workflow_approvals','action_logs','audit_logs','graph_events','incident_alert_links','incident_external_tickets','orchestration_tasks','orchestration_agent_runs','orchestration_evidence','orchestration_help_requests','orchestration_action_attempts','orchestration_action_events'] if os.path.exists('terminus.db')], conn.commit(), conn.close()) if os.path.exists('terminus.db') else None; print('[+] Alert database tables cleared successfully.')" 2>nul
) else if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" -c "import sqlite3, os; (conn := sqlite3.connect('terminus.db'), [conn.execute(f'DELETE FROM {t}') for t in ['incidents','alert_claims','workflow_runs','node_runs','workflow_approvals','action_logs','audit_logs','graph_events','incident_alert_links','incident_external_tickets','orchestration_tasks','orchestration_agent_runs','orchestration_evidence','orchestration_help_requests','orchestration_action_attempts','orchestration_action_events'] if os.path.exists('terminus.db')], conn.commit(), conn.close()) if os.path.exists('terminus.db') else None; print('[+] Alert database tables cleared successfully.')" 2>nul
)

:: 2. Check if Terminus Server is already running on port 8000
powershell -Command "$client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('127.0.0.1', 8000); $client.Close(); exit 0 } catch { exit 1 }" >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [*] Terminus backend is not active. Starting backend service in background window...
    where uv >nul 2>nul
    if !ERRORLEVEL! EQU 0 (
        start "TERMINUS Server Daemon (Port 8000)" cmd /k "title TERMINUS Server Daemon && cd /d ""%~dp0"" && set TERMINUS_REPO_SCAN_ENABLED=true && uv run --frozen uvicorn terminus.server.app:create_app --factory --host 0.0.0.0 --port 8000"
    ) else if exist "%~dp0.venv\Scripts\python.exe" (
        start "TERMINUS Server Daemon (Port 8000)" cmd /k "title TERMINUS Server Daemon && cd /d ""%~dp0"" && set TERMINUS_REPO_SCAN_ENABLED=true && ""%~dp0.venv\Scripts\python.exe"" -m uvicorn terminus.server.app:create_app --factory --host 0.0.0.0 --port 8000"
    ) else (
        start "TERMINUS Server Daemon (Port 8000)" cmd /k "title TERMINUS Server Daemon && cd /d ""%~dp0"" && set TERMINUS_REPO_SCAN_ENABLED=true && python -m uvicorn terminus.server.app:create_app --factory --host 0.0.0.0 --port 8000"
    )
    echo [*] Waiting for Terminus service to initialize...
    timeout /t 3 /nobreak >nul
) else (
    echo [+] Terminus service is actively listening on port 8000.
)

:: 3. Open Console in default browser
echo [+] Opening Terminus Operations Center Console in browser...
start "" http://127.0.0.1:8000/console/

:: 4. Launch live connected services, traffic generation, and phased attack scenarios
echo.
echo ===============================================================================
echo   Starting connected service streams, normal traffic, and simulated attacks...
echo   (Press Ctrl+C at any time to pause or stop the demo stream)
echo ===============================================================================
echo.

where uv >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    uv run --frozen python scripts/live_interactive_flood.py %*
) else if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" scripts/live_interactive_flood.py %*
) else (
    python scripts/live_interactive_flood.py %*
)

pause
