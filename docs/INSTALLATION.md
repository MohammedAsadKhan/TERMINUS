# TERMINUS installation manual

Team LARP | COSC 3370 | Package version 0.1.0 | November 17, 2026

## 1. Scope and prerequisites

This manual starts a disposable, single-host evaluation instance. It is not a production deployment and does not establish an autonomous security operations center. Use a Windows desktop with a modern browser, Python 3.12 or later, and uv on your PATH. The reference host has at least 16 GB of memory, four logical processors, and a 1280 x 720 display. Internet access is needed on first installation to download dependencies. The delivered console is prebuilt, so evaluating it requires no Node.js installation, Wazuh server, or model account.

If uv is missing and Python is already installed, run the following in PowerShell. Reopen PowerShell after installation if the command is still unavailable.

```powershell
py -m pip install uv
uv --version
```

## 2. Extract and start the API

Extract the source ZIP into a new directory. In PowerShell, enter the extracted TERMINUS folder containing pyproject.toml and uv.lock. Use a fresh folder so the first-run local account and database state are created cleanly.

```powershell
uv sync --frozen
.\run_service.bat
```

The batch launcher binds 127.0.0.1 by default and opens the console. To start without it, use the same loopback command directly:

```powershell
uv run --frozen uvicorn terminus.server.app:create_app --factory --host 127.0.0.1 --port 8000
```

Keep this window open. After the terminal reports application startup complete, open http://127.0.0.1:8000/health and confirm that it returns a healthy JSON response. Then open http://127.0.0.1:8000/console/. Startup creates terminus.db in the working folder.

Do not bind to 0.0.0.0 or another reachable interface for evaluation. The local account is intended for loopback only. Hosted use requires explicit hosted configuration, TLS, and a stable license secret; see [.env.example](../.env.example) and [database status](DATABASE_STATUS.md).

## 3. Sign in and evaluate

For a fresh local installation, use admin@terminus.local and Password123!. These credentials are for the loopback evaluation instance only. Existing accounts keep their passwords. Choose Terminus Security Operations if the workspace picker is shown.

- Overview shows the security queue, severity panels, and containment safety status.
- Incidents shows the workspace incident queue. A fresh install can have an empty queue.
- Workflows and Agents show definitions and available views. Recorded activity appears only when runs exist.
- The [evaluation guide](GRADING_GUIDE.md) explains how to distinguish provider, offline, fixture, and live lab results.

With no model key, analysis runs offline and reports an unverified/unknown result. Do not treat its severity, confidence, or recommendations as a provider-backed conclusion or as evidence. `run_demo.bat` opens the separate presentation rehearsal with a temporary database and loopback server; it does not clear this installation's records. Its traffic is synthetic evidence only. The rehearsal uses the OS temporary directory; on Windows, set `TEMP` and `TMP` to a spacious NTFS drive before launching it if the system drive is low on space.

## 4. Runtime boundaries

- **Storage:** The runtime supports the local SQLite database only. PostgreSQL, MySQL, MongoDB, Redis, and an in-memory service backend are not selectable. A database URL does not switch the backend.
- **Workers:** The API does not start investigation or response workers. Enqueued specialist work waits until a scheduler process is started with explicitly installed handlers, and a healthy API does not prove worker readiness. The launcher does not supervise workers. For coordination-only work:

  ```powershell
  uv run --frozen python -m terminus.orchestration.scheduler_cli --database terminus.db --coordination
  ```

  No specialist handlers are bundled. See [scheduler operations](SCHEDULER.md) and [.env.example](../.env.example) for explicit deployment settings.
- **Response:** The separate opt-in worker in scripts/run_response_worker.py is limited to the fixed Wazuh SSH lab scope and requires disposable lab hosts or containers, credentials, and an independent observer. It verifies Wazuh manager and indexer TLS certificates by default. The disposable Docker Compose harness explicitly passes `--insecure-lab-tls` for its generated self-signed certificates; that flag is accepted only for the fixed private Wazuh lab URLs and Docker observer. The disposable target checks every 30 seconds for expired, empty, owned firewall tables; confirm removal with the independent observer before calling recovery complete. Generic block and isolate actions return 501, and file restoration is unavailable. The standard evaluation does not need this worker.
- **Source authentication:** Operator-submitted alert routes (/wazuh, /alert, /webhook/wazuh, /webhook/alert) require an authenticated member or operator API session and are recorded as operator submissions, not attested Wazuh traffic. The separate /sources/wazuh route requires TERMINUS_WAZUH_WEBHOOK_KEY and TERMINUS_WAZUH_WEBHOOK_ORG, binds the receipt to that organization, and stores its raw receipt hash. Genuine source delivery was observed in one disposable Docker lab; repeat it on each fresh installation before treating intake as ready. Do not expose intake routes to an untrusted network.
- **Integrator handoff:** For a disposable private lab, install [custom-terminus](../scripts/lab/custom-terminus) as the Wazuh Integrator script and adapt [the XML example](wazuh_integration.xml) with a unique 32+ character key. Wazuh passes the alert file, key, and URL to the script. It forwards the original JSON bytes to /sources/wazuh and fails visibly if the delivery fails. The example hostname `terminus` works only on the shared private Docker network; use HTTPS for a remote manager. Check manager logs and the stored receipt before calling delivery verified.
- **Wazuh URL:** TERMINUS_WAZUH_URL is the outbound Wazuh REST API base URL used for queries. Genuine source delivery uses /sources/wazuh with the configured source key and organization. The legacy routes are operator-submitted alerts.
- **Lab evidence:** The current audit reproduced authenticated Wazuh delivery from a disposable SSH target and one exact-digest, human-approved 60-second block, independent effect check, kernel expiry, and independent recovery. See [the raw response record](../audit-output/lab/response-target/evidence/approved-response-summary-2026-11-13.md). Two prior Wazuh acknowledgements had no endpoint effect because a manual file copy introduced CRLF into the Linux script shebang; they remain recorded as unverified failures. The current source ZIP passed fresh locked dependency installation, startup, health, console assets, local sign-in, and shutdown on Windows. A fresh Wazuh response cycle, worker supervision, empty firewall-table cleanup, production deployment, broad response adapters, notification delivery, restore rehearsal, and measured analyst benefit remain unverified.

## 5. Optional configuration

Run the setup helper to write only supported TERMINUS_ settings to .env:

```powershell
uv run --frozen terminus-setup
```

It asks for a loopback host and port, an optional OpenAI-compatible endpoint, and an optional outbound Wazuh REST API target. It creates no license token and offers no database backend choice. Local license and token secrets are generated automatically; set stable values explicitly for hosted deployment. Source-key intake is configured separately with TERMINUS_WAZUH_WEBHOOK_KEY and TERMINUS_WAZUH_WEBHOOK_ORG, which must be set together and use a key of at least 32 characters. Use [.env.example](../.env.example) for the hosted and worker setting list.

The optional Windows GUI launcher in `scripts/gui_setup_wizard.py` opens this same supported terminal setup. It no longer writes its own `.env`, changes the Wazuh example, or starts the API. Follow the startup command in section 2 after setup.

## 6. Stop or troubleshoot

Press Ctrl+C in the server window. Retain terminus.db if you want to preserve the workspace.

- If uv is unavailable, verify the installation with uv --version and reopen PowerShell.
- If port 8000 is occupied, set TERMINUS_PORT before launching, for example `$env:TERMINUS_PORT=8001`, and change the browser URL to match.
- If the local account fails, check that you extracted into a fresh directory and started in local mode. Existing accounts keep their passwords.
- If the console loads without styles or scripts, confirm the archive contains src/terminus/server/static/console/ with its assets directory. New browser sessions use the Carbon Matrix dark theme; an explicit Appearance choice in the account menu persists locally.

For source navigation, see [the implementation map](IMPLEMENTATION_MAP.md). The separate lab procedures in [response decisions](RESPONSE_DECISIONS.md) require the team’s configured VMs and credentials.
