# Pre-lab implementation — October 4, 2026

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
