# QA findings — October 5, 2026

Owner: Misha Stegall, with Codex subagent source audits. Baseline commit: `3dcc0b8`. Findings distinguish observed source behavior from live lab validation. Q00 is a local exploratory task; release gates Q01–Q03 remain open.

| Finding | Evidence | Resolution and status |
| --- | --- | --- |
| Public bank and decoy demonstration routes accepted caller-supplied `X-Org-ID` and could create synthetic incidents in another tenant. | `server/bank_router.py`, `server/routers.py`; both routers were mounted in `server/app.py`. | **Fixed locally:** demo alerts use only `org-terminus-demo`; routers mount only in local mode. Focused tests cover a spoofed header and hosted route absence. Local network exposure and event rate limits need a separate lab decision. |
| The action log treated a missing status or `APPROVED` as `SUCCESS`. | Active console `web/src/views/workbench.tsx`. | **Fixed locally:** unknown stays unknown; approved is shown separately. Approval authorizes a proposal and never establishes an executed or verified response. |
| The incident resolution dialog promised that it archived active alerts, while the API changes the incident status and stores classification/notes. | Active console `web/src/views/workbench.tsx`; `server/routers.py` incident action route. | **Fixed locally:** wording now describes only the supported status change. |
| The overview and queue wording implied live telemetry even for recorded or synthetic incidents. | Active console `web/src/views/workbench.tsx`. | **Improved locally:** wording now says recorded incidents and periodic record refresh. The sample alert dialog remains labeled as a test and warns about configured notifications. Source provenance per incident remains desirable before a true live badge is added. |
| The organization submenu could disappear while the pointer moved to a tenant choice, leaving a model-settings alert under the click target. | Browser fixture `web/e2e/model-settings.spec.ts` initially failed on the Beta SOC switch. | **Fixed locally:** the account menu now lists organization choices directly, without a hover submenu. The focused test and full browser suite pass. |
| Wazuh webhook ingestion still uses a human operator session and tenant selection through membership. | `server/routers.py` webhook route and `server/deps.py` `get_webhook_org`. | **Open under A01:** add a separate source credential bound server-side to one tenant and a specific Wazuh integration; reject replay/duplicates and malformed source events. Preserve the authenticated analyst sample-submit path. Verify against the installed Wazuh lab version before claiming live ingestion. |
| The README verification snapshot was older than the latest recorded checkpoint. | `README.md`, `docs/PRELAB_IMPLEMENTATION.md`, `docs/MODEL_EVALUATION.md`. | **Fixed locally:** README now distinguishes the recorded 1,112/7 pre-lab checks, the focused 33 transport checks, and the limited synthetic Gemini smoke test. No fresh full suite or live defense claim is made. |

## Local verification

- Production TypeScript/Vite build passed and regenerated packaged console assets.
- Eight focused backend tests passed across `tests/test_server.py` and `tests/test_demo_scope.py` on a disposable SQLite database. Python 3.14 required ignoring SQLite resource-finalizer warnings; the test assertions passed. The repository targets Python 3.12+.
- The updated local service returned HTTP 200 for `/health` and `/console/` and served the new console bundle.
- All 8 Chrome/Playwright browser fixture tests passed after adding the synthetic-alert and QA-navigation flow. These use mocked APIs and do not prove live Wazuh or response behavior.

## Misha's first hands-on evidence

Follow [the local exploration guide](QA_LOCAL_EXPLORATION.md), record expected versus observed behavior, and link screenshots or an issue for each reproducible defect. Do not mark Q00 verified until that walkthrough and its evidence log are complete; do not mark Q01–Q03 verified from synthetic records.

The [connectivity follow-up](QA_CONNECTIVITY_PLAN.md) defines the next real connection checks and the evidence needed for each.
