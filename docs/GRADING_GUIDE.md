# TERMINUS evaluation guide

Team LARP | COSC 3370 | Package version 0.1.0 | November 17, 2026

Start with the [installation manual](INSTALLATION.md). The standard evaluation starts a clean loopback instance and uses the prebuilt console. It needs no live security connector or model credential.

1. Open the health endpoint and confirm the service responds.
2. Sign in to the console with the local evaluation account listed in the manual.
   A new browser session opens in the Carbon Matrix dark theme. Existing browser theme choices remain saved; use the account menu's Appearance control to switch themes.
3. Review Overview, Incidents, Agents and Workflows. The [QA walkthroughs](QA_LOCAL_EXPLORATION.md) explain how to exercise synthetic intake and inspect recorded activity when those controls are available.
4. Use the [SDD-to-code map](IMPLEMENTATION_MAP.md) to locate the implementation and identify acceptance checks that remain open.

## Interpret the result correctly

- **Synthetic input:** Alerts submitted through the console or QA walkthroughs are fixtures. They demonstrate intake, storage, and deterministic handling, not live sensor coverage.
- **Scripted simulation:** The presentation and simulation paths can use deterministic scripted responses. Treat them as simulated labels and workflow demonstrations, not as model analysis or evidence.
- **No-key analysis:** Without a configured model credential, analysis runs offline and reports an unverified/unknown result. It must not be read as a threat conclusion or provider output.
- **Model-backed analysis:** A provider result requires an explicitly configured named connection or model key. Even then, a claim without source-linked or collected evidence remains unproven.
- **Workers:** The API records work but does not start the scheduler or response worker. Queued specialist work can remain unprocessed while the console stays healthy. Empty agent activity is expected unless a worker is separately running.
- **Source identity:** Operator-submitted intake relies on an authenticated member or operator session and tenant membership; those records are marked as operator submissions, not attested Wazuh traffic. The separate /sources/wazuh route requires TERMINUS_WAZUH_WEBHOOK_KEY and TERMINUS_WAZUH_WEBHOOK_ORG and records a raw receipt hash. One genuine disposable-lab Wazuh delivery succeeded; repeat source and duplicate-delivery checks for each deployment. Do not expose the instance to an untrusted network.
- **Response:** Generic block and isolate actions fail closed with 501. The fixed Wazuh SSH lab path is a separate opt-in process with independent effect and recovery checks in its recorded lab scope. An approval or dispatch status alone does not prove containment.
- **Storage and state:** SQLite holds durable identities, sessions, incidents, workflows, tasks, runs, evidence, and generated report snapshots. Campaign stitching remains process-local. PostgreSQL and other database backends are not supported.

## Verification

Run the regression suite from the extracted source directory. The following command uses a separate SQLite database.

```powershell
uv run --frozen python -c "import pathlib,tempfile,pytest; from terminus.storage.db import Database; tmp=tempfile.TemporaryDirectory(prefix='terminus-tests-', ignore_cleanup_errors=True); Database.reset_instance(str(pathlib.Path(tmp.name)/'tests.db')); raise SystemExit(pytest.main(['-q']))"
```

See the [testing record](TESTING_STATUS.md), [response evidence](RESPONSE_DECISIONS.md), and [November 13 disposable-lab acceptance record](../audit-output/lab/response-target/evidence/approved-response-summary-2026-11-13.md). The current Docker lab verified one exact-digest approved block and independent expiry/recovery; its earlier acknowledged but ineffective attempts remain visible as unverified failures. A fresh extraction of an earlier source ZIP passed dependency installation, API startup, health, console assets, local sign-in, and shutdown. Production deployment and measured analyst benefit remain separate. The presentation launcher creates a separate temporary database and generates simulated traffic on loopback; it does not clear operational records. Do not count its charts or generated activity as measured monitoring.
