@echo off
setlocal enabledelayedexpansion
title TERMINUS 2.0 - Platform Uninstaller & Reset Tool

echo ===============================================================================
echo   TERMINUS 2.0 — PLATFORM UNINSTALLER & RESET TOOL
echo ===============================================================================
echo.
echo   Select an action:
echo.
echo   [1] Soft Reset: Reset Database & Logs (Keeps Virtualenv & Source)
echo       - Halts running background services (Port 8000)
echo       - Deletes SQLite database (terminus.db, WAL, SHM)
echo       - Removes test caches and generated Wazuh XML
echo       - Resets configuration to clean state
echo.
echo   [2] Full Teardown & Uninstall (Complete Deep Clean)
echo       - Halts running background services (Port 8000)
echo       - Deletes database, logs, and .env configuration
echo       - Removes Python virtual environment (.venv)
echo       - Removes PyInstaller build & dist artifacts
echo       - Cleans all __pycache__ and test caches
echo.
echo   [3] Cancel & Exit
echo.
echo ===============================================================================

set /p choice="Enter option [1-3] (Default: 3): "
if "%choice%"=="" set choice=3

if "%choice%"=="1" goto SOFT_RESET
if "%choice%"=="2" goto FULL_TEARDOWN
if "%choice%"=="3" goto CANCEL

echo [!] Invalid option selected. Exiting.
goto END

:SOFT_RESET
echo.
echo [*] Halting running Terminus services on port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>nul
)

echo [*] Removing database files...
if exist "%~dp0terminus.db" del /f /q "%~dp0terminus.db"
if exist "%~dp0terminus.db-wal" del /f /q "%~dp0terminus.db-wal"
if exist "%~dp0terminus.db-shm" del /f /q "%~dp0terminus.db-shm"

echo [*] Removing caches and temporary files...
if exist "%~dp0.coverage" del /f /q "%~dp0.coverage"
if exist "%~dp0docs\wazuh_integration.xml" del /f /q "%~dp0docs\wazuh_integration.xml"
if exist "%~dp0.pytest_cache" rmdir /s /q "%~dp0.pytest_cache"

echo.
echo ===============================================================================
echo [✓] Soft reset complete!
echo [✓] Run 'setup_terminus.bat' or 'TerminusSetupWizard.exe' to reinitialize.
echo ===============================================================================
goto END

:FULL_TEARDOWN
echo.
echo [!] WARNING: This will completely clean virtual environments and configurations.
set /p confirm="Are you sure you want to perform a FULL teardown? (y/N): "
if /i not "%confirm%"=="y" (
    echo [*] Teardown cancelled.
    goto END
)

echo.
echo [*] Halting running Terminus services on port 8000...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>nul
)

echo [*] Removing database files...
if exist "%~dp0terminus.db" del /f /q "%~dp0terminus.db"
if exist "%~dp0terminus.db-wal" del /f /q "%~dp0terminus.db-wal"
if exist "%~dp0terminus.db-shm" del /f /q "%~dp0terminus.db-shm"

echo [*] Removing configuration & generated files...
if exist "%~dp0.env" del /f /q "%~dp0.env"
if exist "%~dp0docs\wazuh_integration.xml" del /f /q "%~dp0docs\wazuh_integration.xml"
if exist "%~dp0.coverage" del /f /q "%~dp0.coverage"

echo [*] Cleaning build & virtual environment directories...
if exist "%~dp0build" rmdir /s /q "%~dp0build"
if exist "%~dp0dist" rmdir /s /q "%~dp0dist"
if exist "%~dp0.venv" rmdir /s /q "%~dp0.venv"
if exist "%~dp0.pytest_cache" rmdir /s /q "%~dp0.pytest_cache"

echo [*] Purging Python bytecode caches...
for /d /r "%~dp0" %%d in (__pycache__) do (
    if exist "%%d" rmdir /s /q "%%d"
)

echo.
echo ===============================================================================
echo [✓] Full uninstall and clean teardown completed!
echo ===============================================================================
goto END

:CANCEL
echo.
echo [*] Action cancelled. No changes made.
goto END

:END
echo.
pause
