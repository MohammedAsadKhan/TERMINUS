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

## Structured help requests (O06)

`CoordinationService.request_help(org_id, requester_task_id, spec: HelpRequestSpec) -> dict` (HTTP `POST /orchestration/tasks/{task_id}/help-requests`, member/admin) is the preferred way for a specialist to ask a peer. `HelpRequestSpec` is strict and bounded: `target_role` (one of the eight core roles; future catalog specialties are rejected by validation), `objective` (1..1000 chars), `expected_evidence_kinds` (<=8 lowercase labels) and `shared_evidence_ids` (<=8). There is no tool, scope, tenant, model or credential field; tenant, incident and requester role come from the authenticated org and the requester task.

Admission, in order, inside one transaction: requester task and incident must exist in the tenant (else not-found); an identical (requester task, target role, normalized objective) returns the existing request with `duplicate: true` and creates no second task (idempotent policy; a concurrent burst yields one task); the incident needs a coordination root; requester must be a managed specialty; a task already inside a help delegation cannot request help (`recursive_delegation`); `self_delegation`; target role must be in the catalog (`role_not_enabled`) and its area must be selected in the incident objective (`area_not_selected`); at most 4 requests per requesting task and 16 per incident (`CoordinationLimitError`); every shared evidence id must belong to the same tenant AND incident, otherwise the call fails with the same not-found as a missing id. Denials raise `CollaborationRejectedError` (a `ValueError`, HTTP 400) with a bounded `.code`. Whether the target role has a deployed handler is not tracked; the scheduler leaves such tasks queued. The legacy `assign_help` endpoint is unchanged and does not enforce the area-selection, recursion or per-task rules.

Shared evidence is stored durably in `orchestration_help_collaboration` (created idempotently on service construction). A peer reads it with `CoordinationService.get_help_context(org_id, task_id) -> dict` (HTTP `GET /orchestration/tasks/{task_id}/help-context`), valid for the help-delegated area task and for its peer specialist task; it returns the ownership view plus `shared_evidence` (full evidence records, re-validated against tenant and incident). Any other task id is not-found.

Ownership view (`CollaborationService.ownership`, also `help_ownership` on every incident-tree node): `help_request_id`, `state` (`requested`, `assigned`, `resolved`, `rejected`), `reason_code` (`peer_failed`, `peer_cancelled`, `area_failed`, `area_cancelled`, `request_cancelled` or null), `requester_task_id/role/area`, `target_role`, `responsible_area`, `delegated_task_id` (responsible area's task), `peer_task_id`, `objective`, `expected_evidence_kinds`, `shared_evidence_ids`. `rejected` is derived; the stored help status is never resolved by a failed or cancelled peer. Resolution still requires `reconcile_help` after the peer task completed.

## Reliability and scope

Creation and scheduler admission share SQLite transactions. Durable task keys make retrying a delegation pass reuse children rather than create duplicate work. Handler mutations verify scheduler ownership inside the transaction. Incident work is bounded to 64 tasks and 16 help delegations. One durable objective is accepted per incident; conflicting replacement objectives are rejected. Help requests must originate from a managed specialist and cannot recursively spawn unlimited work. Tree traversal is also bounded.

Task cancellation retains the scheduler's existing per-task semantics. Cancelling a coordinator does not cancel already admitted descendants; operators must cancel those tasks individually. Incident-wide cancellation and incident closure remain future coordination contracts.

Current scheduler defaults allow four active jobs globally and two per organization, which also bounds an incident to at most two under those defaults. A separately configurable per-incident runtime cap remains a future requirement.

Structured help admission (O06) is described below. Model-budget admission and autonomous planning still need implementation. Model routing, credential policy, budgets and live response remain separate tasks. A tree aggregates recorded outcomes; it does not fabricate a synthesized security verdict or resolve disagreements without evidence.

Tests use temporary databases and explicitly labeled test callbacks. Successful fixture execution demonstrates scheduling and coordination, not real endpoint defense.
