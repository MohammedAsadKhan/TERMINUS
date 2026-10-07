# Pre-lab implementation — October 4, 2026

## October 5/6 local Wazuh integration handoff

Owner - Mohammed | Agent - Codex orchestrator. Read-only connector deployment
and explicit administrator import command implemented; 81 targeted tests passed.
See [Wazuh lab connection](WAZUH_LAB_CONNECTION.md) for endpoints, local commands,
credential prompts, incident-scoped authorization and release boundaries.
Manual manager authentication and five real indexer events were verified by the
operator. Live importer/specialist evidence verification remains pending local
credential entry; do not mark it done from fixture tests. Continuous authenticated
ingestion, certificate trust and approval-bound live response remain open.

## October 5 active handoff: specialist workflow validation

Claimed by - Mohammed | Agent - Codex orchestrator | Status - complete. Done by - Mohammed | Agent - Codex orchestrator and delegated agents.
Parallel ownership: GPT-6.1 Sol reviews specialist execution/failure handling;
GPT-5.6 Sol reviews model controls; GPT-5.6 Sol reviews real activity rendering.
The orchestrator owns integration, local configuration, bounded live validation
and this handoff. Implementation ownership is complete; the next checkpoint is local lab acceptance.

Gemini `gemini-3.5-flash-lite` is the selected free-tier provider; its encrypted
named connection has passed a live API smoke test. Temporary test UI/routes were
removed. The next checkpoint must use actual coordinator/scheduler/specialist
handlers, retain durable activity/evidence, report absent lab telemetry honestly,
and keep operational evidence local unless explicitly classified. Local keys,
database contents and evidence classifications are not source-control artifacts.

Actual integration result: one synthetic SSH incident ran through the existing
main coordinator, alert-handling area coordinator, dedicated scheduler runtime,
triage handler and permissioned tool gateway. `incident.get` created canonical
evidence. A trusted, one-run validation wrapper checked the exact seeded payload,
tenant, incident and task before the administrator explicitly classified that
synthetic evidence `approved_cloud`; no production auto-classification was added.
Gemini returned one same-incident cited finding: 685 input + 83 output = 768 tokens.
The durable reservation settled at the explicitly configured Free-tier rate.

The specialist result was correctly `partial`: `alerts.search` and
`collection.coverage` returned `connector_not_configured`. The first diagnostic
attempt was denied before provider I/O because its 12,000-token cap was below the
65,536-input-token conservative live reservation plus output bound. A 70,000-token
UTC-day cap then admitted one serialized request. Eight exact core-role grants
are configured locally for this connection and `approved_cloud` evidence only;
future roles have no grants, and newly collected operational evidence remains
`local_only`. Default deployment remains tools-only unless explicitly enabled.

The fixture incident, grants, credential and ledger are local ignored SQLite
data, not committed fixtures or credentials. Persistent activity can be inspected
under `/console/agents` → Activity. This validates the triage path and delegation;
the other seven specialists, real telemetry, collaboration against real incidents
and installed response actions still require lab acceptance.

Verified reporting changes: model token counters remain visible while credentials
remain redacted; latest partial specialist analysis propagates incomplete coverage
through area/main task trees. Unexpected model-routing failures retain collected
evidence and produce explicit gaps. Activity shows durable job/run identities,
released leases, run history and same-incident evidence citations.

Validation: 93 focused backend tests, production frontend build and activity
browser checks passed; combined model-settings/activity Chrome checks passed 7/7.
Account-menu organizations are now a flat section; popup layering and viewport
placement no longer block switching organizations. A broad isolated run passed 1,115 tests; three contract
tests required repository-relative fixtures, and all 24 contract tests passed
when rerun from the repository. Local configured-secret scanning passed; .env
and SQLite storage remain ignored. No installed response or real SIEM acceptance
is claimed.

Claimed by Mohammed with the Codex orchestrator. This work addresses the Claude review and implements software that can be verified before real Wazuh telemetry exists.

## Owned work

- Workflow agent: failed/missing/incomplete specialist results, citation validation and report integration.
- Collaboration agent: bounded delegation, same-incident shared evidence, specialist consumption and strict typing.
- Model gateway agent: credential resolution, pinned TLS transport, continuous authorization, budgets and final-result validation. OpenAI is the selected first live-validation provider.
- UI agents: agent activity and model gateway settings, preserving existing configuration workspaces.
- Workflow/response agent: internal approval-bound Scenario A fixture lifecycle and conservative recovery checks.
- Orchestrator: model-settings/catalog APIs, shared documents, integration review and final checks.

Agents work in disjoint files and hand off interfaces explicitly. Do not duplicate these edits while the claim remains in progress. The execution checklist remains authoritative.

## Model settings interface

The existing `/model-connections` API retains encrypted secret storage and masked responses. New `/model-settings` routes use the same current organization and actor; writes require current admin membership and compare-and-swap versions.

| Route | Read | Write |
| --- | --- | --- |
| `/policy` | Current policy or 404 if absent | Exact role/area, connection/version, models and data classifications |
| `/budget/{YYYY-MM-DD}` | UTC-day limit and version | Micro-USD/token limits and expected version |
| `/usage/{YYYY-MM-DD}` | Known cost and reserved/ambiguous exposure | None |
| `/prices/{connection_id}/{model}` | Registered model's explicit rates | Per-million-token micro-USD rates and expected version |
| `/evidence/{evidence_id}/classification` | Not added in this phase | Same-tenant canonical evidence classification and expected version |

Policy JSON arrays are validated through the strict JSON contract; no request can admit a future specialty or widen a connection's model pool. Invalid input never echoes its values. Creating configuration does not establish connected/protected status or verify a provider.

## Validation boundary

Mocked network/provider tests can establish contracts and failure handling. They cannot establish model quality, installed Wazuh capabilities, target response or live recovery. Real model validation needs a named encrypted connection, exact role/model grant, explicit data classification, configured prices/budget and protected credentials. The default runtime database currently has no named OpenAI connection.

Response work in this phase is a durable fixture lifecycle only. No real firewall, endpoint or identity action is enabled before lab testing. Existing legacy investigation remains separate until explicitly replaced.

## Integrated behavior

- Workflow results validate the specialist role, tenant, incident, current run and canonical evidence hashes. Missing, failed or incomplete results cannot silently authorize the success branch. Validated findings and telemetry gaps enter the incident report without inventing severity or evidence.
- Structured help requests enforce bounded delegation and share same-incident evidence. Specialists consume durable peer results; a completed scheduler job with telemetry gaps is not a successful security finding.
- Production model transport uses protected named credentials, pinned HTTPS destinations and repeated authorization checks. Durable admission and budget exposure precede network I/O. Credentials never come from model arguments; the default specialist deployment remains tools-only.
- The console adds agent activity and model gateway settings while retaining existing agent configuration and settings. Catalog entries distinguish core-role coverage from future specialties; registered names never grant execution.
- Response foundations are isolated SQLite fixtures. Immutable proposals, human approval, intent, reconciliation, independent observations and owned-resource undo are software contracts. There is no live response adapter or public fixture dispatch endpoint.

## Next handoff

1. Finish integrated checks and record their results here and in the execution checklist.
2. Configure a named OpenAI connection, server master key, exact role/model policy, evidence classifications, explicit price rates and budget before live validation. Do not paste keys into documents or chat.
3. Build the local lab and verify Wazuh manager/indexer credentials independently; select installed target versions and actual telemetry.
4. Validate the eight specialist roles, Scenario A approval-bound response, independent effect verification and undo against the lab. Select application target B before adding its adapters.
5. Rehearse the complete demonstration locally before AWS migration. Future specialties remain unavailable in 1.0.

No live OpenAI, Wazuh response, recovery or AWS success is established by the pre-lab checks.

## Verification checkpoint

October 4 integrated backend: 1,057 tests passed in 85.04 seconds against a temporary SQLite database. This collection preceded the new response-lifecycle tests. The response namespace subsequently passed 55 focused tests, Ruff and type checks. Both UI views passed six combined Playwright checks using installed Chrome and mocked APIs; the production build passed. Final integrated checks follow below. Focused type checking of the gateway, collaboration/specialists, workflow bridge and new settings/catalog APIs reports zero errors, warnings or notes. Targeted Ruff checks pass. These checks do not use a paid provider or live lab.

Browser reproduction: from `web`, run `npm test` with bundled Playwright Chromium, or set `TERMINUS_PLAYWRIGHT_CHANNEL=chrome` to use installed Chrome. The test configuration starts an isolated local Vite server; API responses are recorded fixtures, not live integrations.

Final backend integration: **1,112 tests passed in 86.89 seconds**, including all 55 response-lifecycle tests. Focused response type checking reports zero errors/warnings/notes; Ruff passes across changed gateway, collaboration, specialist, bridge, settings/catalog and response sources plus new tests. Production TypeScript/Vite build passed and packaged console assets were regenerated. Final combined browser sign-off: **7/7 Playwright tests passed in 14.0 seconds**, including the organization-switch flow. Both activity and model settings remount per organization, discarding stale drafts/selections synchronously.

Pre-lab implementation slice verified. Done by - Mohammed | Agent - Codex orchestrator, GPT-6.1 Sol backend/response and GPT-5.6 Sol collaboration/UI agents | Date - 2026-10-04 | Change - source files and documents in this working tree | Verified - 1,112 isolated backend tests, 7 browser fixture tests, production build, focused Ruff/type checks and diff check. This checkpoint is included with the pre-lab integration commit. Live provider and lab acceptance remain open.

## Tomorrow's order

- [ ] Choose the first funded/free API connection (Gemini free tier is the current budget option; OpenAI needs separate API credit), configure encrypted credentials, exact model/role policy, rates and budget.
- [ ] Run one controlled live model validation using synthetic evidence. Verify structured findings/citations, admission and usage; do not mark the provider verified from configuration alone.
- [ ] Build the isolated local lab: existing Kali attacker, Ubuntu target and Wazuh manager/indexer. Record networking, resource allocations, protected management access and snapshots.
- [ ] Configure manager and indexer credentials separately; verify endpoint collection, authenticated alert ingestion and canonical evidence.
- [ ] Exercise Scenario A SSH activity and confirm durable main/area/specialist tasks plus truthful activity UI. Fill missing adapter/telemetry gaps.
- [ ] Connect approval-bound planning/review to the workflow and implement the installed Wazuh temporary IP-block adapter, reconciliation, independent effect/service checks, expiry and undo. Current response package is fixture-only.
- [ ] Select exact application target B and required telemetry, then implement its remaining adapters. Rehearse/reset locally before AWS migration.

Noah may handle the later DeepSeek/other provider validation. Future-specialty execution stays outside 1.0. Mark completed tasks using the team checklist's Done by convention.
# Agents operation overview

The Agents activity page now groups the bounded task list by incident, with an
optional newest-first execution history. The tasks API accepts `newest_first`
without changing the default ordering of existing storage callers. Selecting
a task loads its incident tree and shows an operation selector, orchestration
ownership, elapsed time, specialist counts and child agent cards. Cards and
the inspector refresh every eight seconds. The activity timeline uses actual
task/run timestamps and evidence collection timestamps; result-only tool calls
show recorded order without invented per-step times. Model analysis that reuses
earlier evidence displays cited records from the same incident tree.

This is recorded activity visibility, not terminal streaming or model internal
reasoning. Future specialties remain disabled. Validation: frontend production
build, four Chrome activity tests and 48 storage/coordination API tests passed.
