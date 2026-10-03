@echo off
setlocal enabledelayedexpansion
title TERMINUS Live Adversary Attack Simulation & Telemetry Stream

set "PYTHONPATH=%~dp0src;%PYTHONPATH%"

echo ===============================================================================
echo   TERMINUS - LIVE ADVERSARY ATTACK SIMULATION STREAM
echo ===============================================================================
echo   [+] Target Service: http://127.0.0.1:8000
echo   [+] Telemetry Route: POST /webhook/wazuh & POST /webhook/alert
echo   [+] Connection Sensor: POST /service/heartbeat
echo ===============================================================================
echo   Attack Phases:
echo     1. Reconnaissance & Credential Stuffing Surge (Tier-0 Noise Filtering)
echo     2. LockBit 3.0 Ransomware Detonation (ReAct Investigation & Approval Gate)
echo     3. Active Directory DCSync / Golden Ticket (Deterministic Containment Safety)
echo     4. Multi-Host Threat Correlation & Copilot Investigation
echo ===============================================================================

where uv >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    uv run python scripts/live_interactive_flood.py %*
) else if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" scripts/live_interactive_flood.py %*
) else (
    python scripts/live_interactive_flood.py %*
)

pause
