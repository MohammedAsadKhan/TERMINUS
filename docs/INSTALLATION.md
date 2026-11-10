# TERMINUS installation manual

Team LARP | COSC 3370 | Package version 0.1.0 | November 9, 2026

## 1. Prepare the computer

Use a Windows desktop with a modern browser, Python 3.12 or later, and uv on your PATH. The reference host has at least 16 GB of memory, four logical processors, and a 1280 x 720 display. Internet access is needed on first installation to download dependencies. The delivered console is prebuilt, so evaluating it requires no Node.js installation, Wazuh server, or model account.

If uv is missing and Python is already installed, run the following in PowerShell. Reopen PowerShell after installation if the command is still unavailable.

```powershell
py -m pip install uv
uv --version
```

## 2. Extract and start

Extract the source ZIP into a new directory. In PowerShell, enter the extracted TERMINUS folder containing pyproject.toml and uv.lock. Use a fresh folder so the first-run demo account and data are created in a new local database.

```powershell
uv sync --frozen
uv run --frozen uvicorn terminus.server.app:create_app --factory --host 127.0.0.1 --port 8000
```

Keep this window open. After the terminal reports application startup complete, open http://127.0.0.1:8000/health and confirm that it returns a healthy JSON response. Then open http://127.0.0.1:8000/console/.

## 3. Sign in and evaluate

For a fresh local installation, use admin@terminus.local and Password123!. These credentials are for the loopback evaluation instance. Choose Terminus Security Operations if the workspace picker is shown.

- Overview shows the security queue, severity panels, and containment safety status.
- Incidents shows the workspace incident queue. A fresh install can have an empty queue.
- Workflows and Agents show definitions and available views. Recorded activity appears when runs exist.
- The repository evaluation guide explains how to distinguish simulated, fixture, and live lab results.

## 4. Stop or troubleshoot

Press Ctrl+C in the server window. Startup creates terminus.db in the working folder. Retain that file if you want to preserve the workspace.

- If uv is unavailable, verify the installation with uv --version and reopen PowerShell.
- If port 8000 is occupied, use a free port such as 8001 and change both browser URLs to match.
- If the demo credentials fail, check that you extracted into a fresh directory and started in local mode. Existing accounts keep their passwords.
- If the console loads without styles or scripts, confirm the archive contains src/terminus/server/static/console/ with its assets directory.

For source navigation, see docs/IMPLEMENTATION_MAP.md. The separate lab procedures in docs/RESPONSE_DECISIONS.md require the team’s configured VMs and credentials.
