# Local QA exploration — synthetic data

Owner: Misha Stegall (Q00). This is a first hands-on QA path, not evidence of live Wazuh defense or model readiness.

## What runs where

The browser console is React. It calls the FastAPI service on the same host. The service stores organizations, incidents, tasks and other records in a local SQLite database. A test alert enters through the authenticated `/wazuh` route, then the pipeline may create an incident. A separate scheduler is needed for durable specialist execution; an incident appearing in the queue does not prove that a specialist or response ran.

## Start a disposable local session

From the repository root, with Python 3.12+ and `uv` installed:

```powershell
uv sync --frozen
uv run --frozen uvicorn terminus.server.app:create_app --factory --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/console/`. The default first-run **local** account is `admin@terminus.local` / `Password123!`. Use it only for an isolated local demo. The project root will hold an ignored `terminus.db`; record whether that database was new or preexisting before you interpret the results. Do not run this walkthrough against a configured lab, hosted service, or organization with notification connections: submitting the test alert uses the real pipeline and configured notifications may fire.

## First walkthrough

Open **QA walkthroughs** in the console sidebar for direct links to each screen. The steps below are the recordable version of that guide.

1. Open **Overview** and record the count of stored incidents. It may be zero in a new database.
2. Select **Choose test alert**. Pick a topic from the dropdown, inspect the prepared JSON, then submit once. You can also choose **Surprise me** or regenerate the details before submitting. Record the time and any error. **Add random test alert** submits immediately from Overview; configured notification channels may receive it. These are synthetic API alerts, not live Wazuh detections.
3. Refresh **Overview**, then open **Incidents**. Find the new record and open its dossier. Compare the rule, host, timestamp, raw log, status and evidence citations to the submitted sample. If a field is missing, record it as missing; do not infer that a specialist supplied it.
4. Open the **Activity** tab. Record which status transitions appear. A resolved incident means the ticket status changed; it does not mean a block was executed or independently verified.
5. Open **Agents** and inspect the task activity view. If there is no task or result, record that gap. A configured agent or catalog entry alone is not execution evidence.
6. Open **Workflows → Dry-Run Simulation**. Its trace is an in-memory workflow check and does not dispatch a response.
7. Open **Settings → Model gateway**. A saved connection, grant or budget is configuration. Look for a recorded evaluation before calling any provider live-verified.

## Example topics

| Topic | What the sample lets you inspect |
| --- | --- |
| SSH password guessing | Scenario A concept: identity triage, source IP and failed-login evidence. |
| Application exploit probe | Scenario B concept: application/API alert details. The actual B target and exploit are still to be selected. |
| Ransomware-like file changes | Endpoint evidence and response recommendations. No files are encrypted. |
| Suspicious remote access | Network/host context; the sample is a log line, not packet capture. |
| Unexpected admin account change | Identity and privilege investigation. No account is changed. |
| Unusual outbound data transfer | Network and evidence handling; transfer intent and content are unverified. |

Each generated event has a fresh alert ID, timestamp, documentation-range source IP and varied details. Its rule description and raw log say `SYNTHETIC`.

## Evidence log

Copy this table for each run. Keep screenshots out of the repository if they contain credentials or real telemetry.

| Field | Record |
| --- | --- |
| Date, tester and commit (`git rev-parse --short HEAD`) | |
| Python/browser versions and fresh or existing DB | |
| Scenario and exact steps | |
| Expected result | |
| Observed result and screenshot reference | |
| API or console error, if any | |
| Synthetic, fixture, live provider or live lab evidence? | |
| Issue, severity and reproducibility | |
| Retest result after a fix | |

## What remains for release QA

Q01–Q03 in the [execution checklist](EXECUTION_CHECKLIST.md) depend on the real scenario, response and deployment gates. They require negative-case results, restart/reconciliation evidence and repeated local/AWS rehearsals. This walkthrough does not complete those tasks.

The [connectivity follow-up](QA_CONNECTIVITY_PLAN.md) lists the real source, model, specialist, notification, and response evidence needed next.
