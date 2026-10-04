# Main and area coordination

O04 connects incident objectives to the durable scheduler. Coordination is deterministic bookkeeping; it makes no model calls and installs no defensive tools. Existing alert ingestion and workflows retain their behavior. Starting a coordination plan is an explicit operator action.

## Task hierarchy

An incident objective creates a scheduled `main_orchestrator` task. Its handler creates tasks only for selected areas. Each `area_orchestrator` handler admits its specialist tasks through the same scheduler. Coordinators finish their delegation pass without waiting for children or consuming all available worker slots.

A completed coordinator means its delegation pass finished. It does not mean the specialist tasks finished, the incident was closed, or an endpoint was protected. Incident-tree inspection returns actual persisted task/run/evidence records and a separate aggregate. No incident closure or action verification is inferred from a summary.

The five areas are `alert_handling`, `investigation`, `infrastructure`, `applications_data`, and `response_improvement`. The initial specialty catalog covers eight default roles: triage, identity, endpoint, network, response planning, verification, evidence/reporting, and Application & API Security Analyst (`application_api`). Selecting `applications_data` now delegates to this specialist by default. The eight core roles have fixed, read-only tool plans in `terminus.orchestration.specialists.roles`; catalog-only tools (network, application, reporting and similar) are reported as explicit `tool_not_installed` gaps, never as findings. No plan contains a dispatch tool, and response proposals are deferred to A03. Plans read incident resources an administrator binds per incident as `incident-ref` and `endpoint-ref`; an unbound reference yields a denied gap. Model-assisted execution is not configured by the deployed handlers. Additional cloud/container/repository capabilities require real handlers before they can claim coverage.

## Deployment

Use the same database path as FastAPI:

```powershell
uv run --frozen python -m terminus.orchestration.scheduler_cli --database C:\path\to\terminus.db --coordination
```

This enables only main/area delegation. To execute specialists, add explicit trusted `--handler ROLE=MODULE:FUNCTION` arguments for deployed implementations. Missing handlers leave tasks queued. Coordination roles cannot be overridden through `--handler` when `--coordination` is enabled. Deployable specialist handlers live in `terminus.orchestration.specialists.deploy` (for example `--handler triage=terminus.orchestration.specialists.deploy:triage`, one per core role) and coexist with `--coordination`. They require `TERMINUS_SPECIALIST_DATABASE` and `TERMINUS_SPECIALIST_ACTOR_USER_ID` (a service account that is an operator member); without them each run fails with a configuration error rather than producing a result. FastAPI never starts a second scheduler automatically.

## HTTP boundaries

- `POST /orchestration/incidents/{incident_id}/start`: members/admins submit an objective, explicit areas, priority and idempotency key.
- `GET /orchestration/incidents/{incident_id}/tree`: authenticated incident-scoped inspection.
- `POST /orchestration/help-requests/{help_request_id}/assign`: members/admins route a persisted help request through its responsible area.
- `POST /orchestration/help-requests/{help_request_id}/reconcile`: members/admins resolve an assigned request only after its delegated specialist task completed. Assignment alone never resolves it.

Tenant scope comes from authenticated organization membership. Unknown and foreign incidents/requests return the same not-found response. Request bodies cannot select a tenant, install worker code, or invoke models/tools.

## Reliability and scope

Creation and scheduler admission share SQLite transactions. Durable task keys make retrying a delegation pass reuse children rather than create duplicate work. Handler mutations verify scheduler ownership inside the transaction. Incident work is bounded to 64 tasks and 16 help delegations. One durable objective is accepted per incident; conflicting replacement objectives are rejected. Help requests must originate from a managed specialist and cannot recursively spawn unlimited work. Tree traversal is also bounded.

Task cancellation retains the scheduler's existing per-task semantics. Cancelling a coordinator does not cancel already admitted descendants; operators must cancel those tasks individually. Incident-wide cancellation and incident closure remain future coordination contracts.

Current scheduler defaults allow four active jobs globally and two per organization, which also bounds an incident to at most two under those defaults. A separately configurable per-incident runtime cap remains a future requirement.

Cross-area help admission is a foundation for O06. Richer scope, expected-evidence and model-budget admission, real specialist collaboration and autonomous planning still need implementation. Model routing, credential policy, budgets and live response remain separate tasks. A tree aggregates recorded outcomes; it does not fabricate a synthesized security verdict or resolve disagreements without evidence.

Tests use temporary databases and explicitly labeled test callbacks. Successful fixture execution demonstrates scheduling and coordination, not real endpoint defense.
