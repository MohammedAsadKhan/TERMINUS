# Architecture decisions and planning record

This document records the current implementation audit and durable incident-task foundation. “Observed” describes code that exists today; “proposed” describes boundaries for review and does not imply implementation or approval. This record includes durable identity/session storage and canonical incidents. Task scheduling, model-provider credential storage and lab integration remain pending.

## P02 — Current server and persistence map (observed)

The service is a FastAPI application using Pydantic models and httpx2; pyproject.toml lists no dedicated scheduler or ORM. src/terminus/server/app.py mounts the route modules and starts an in-process daily-report loop plus the existing workflow sweeper at application startup.

| Route area | Current handler and storage path | Persistence / tenancy notes |
| --- | --- | --- |
| Auth and organizations | /auth/* and /orgs/* in src/terminus/server/routers.py; AuthService, UserStore, OrganizationService, and MembershipStore from src/terminus/server/deps.py | Runtime identity stores are SQLite-backed; session digests, expiry and revocation are durable. Tenant requests read current membership and deny users without memberships. |
| Alert ingest and incident tickets | /wazuh, /alert, /webhook/wazuh, /webhook/alert, /incidents* in routers.py; PipelineRunner and its configured ticket store | The server PipelineDeployment always uses SqliteIncidentRepository as its canonical ticket store. Jira, when configured, is a separate export with a durable external-key mapping. get_webhook_org delegates to the authenticated user's current organization. |
| Workflow definitions | /workflows* in routers.py; SqliteWorkflowRepository | SQLite-backed and queried with the active org_id. Workflow IDs are tenant-scoped by a composite key/index. |
| Workflow runs and node traces | /workflows/runs*, workflow webhook execution, and SqliteWorkflowRunRepository | SQLite tables workflow_runs and node_runs; detail lookup passes both organization and run ID. /workflows/{id}/execute is an in-memory dry run. |
| Approval gates | /workflows/approvals*; SqliteApprovalRepository | SQLite-backed, organization-scoped. Resolution checks pending status and required role before resuming a run. |
| Agents and action history | /agents*; SqliteAgentRepository and SqliteActionLogRepository | SQLite-backed with org-scoped lookups. The action feed may synthesize entries from node runs/incidents when direct logs are sparse. |
| Containment allowlist | /containment/allowlist*; SqliteAllowlistRepository | SQLite-backed and org-scoped. Existing endpoints manage allowlist metadata; this plan adds no live action. |
| Reports | /reports*; get_reports_store() and PipelineRunner ticket store | Report objects are held in a process-local dict. The daily task in app.py also iterates OrganizationStore and writes to that dict, so results are not durable across restarts. |
| Assets | /assets*; SqliteAssetRepository in src/terminus/storage/assets.py | SQLite-backed and org-scoped. The API explicitly treats assets as inventory metadata and reports coverage as not_connected. |
| Investigation graph | /investigation/graph*; GraphEventStore | Reads SQLite graph_events by organization and time window. |
| Copilot | /incidents/{ticket_id}/chat, /copilot/chat; configured LLM and pipeline tools | Request-scoped orchestration over the ticket store; no durable chat/task history repository is wired here. |
| Settings and service status | /settings/*, /service/*; settings object, service_sensor | Configuration/status is in process; settings writes mutate the settings object. This document does not introduce credential persistence. |

Code citations: [app lifecycle and route registration](../src/terminus/server/app.py#L40); [in-memory and SQLite dependency wiring](../src/terminus/server/deps.py#L54); [authenticated organization selection and report store](../src/terminus/server/deps.py#L344); [webhook and workflow/run/approval routes](../src/terminus/server/routers.py#L391); [agent/action and report routes](../src/terminus/server/routers.py#L734); [console incident lookup](../src/terminus/server/console_api.py#L44); [asset routes](../src/terminus/server/assets_api.py#L55); [graph routes](../src/terminus/server/graph.py#L33); [SQLite schema and indexes](../src/terminus/storage/db.py#L80); [pipeline ticket-store creation](../src/terminus/pipeline/runner.py#L125).

### Wazuh integration gaps (observed)

- Incoming alerts use a push webhook that immediately runs the pipeline. The Wazuh adapter in src/terminus/siem/wazuh.py separately supports fetching an alert by ID and an agent by ID; src/terminus/server/deps.py selects it when wazuh_url is configured. There is no Wazuh polling or recurring alert scheduler.
- The Wazuh example in docs/wazuh_integration.xml posts to /webhook/wazuh without showing an auth header, while that route has Depends(require_operator). The deployment/auth contract therefore needs reconciliation before treating the sample as an operational integration.
- WazuhClient caches its JWT in memory and has no refresh/re-authentication path after token expiry. get_agent catches all exceptions and returns an "unknown" result, which obscures connection and authorization failures. These are integration gaps, not changes made by this plan.
- Wazuh credentials are currently configuration values. This proposal does not add credential storage, change the settings API, or contact a Wazuh installation.

### Workflow execution gaps (observed)

- The workflow node schema accepts agent_id, system_prompt_override, and model, but the live agent_llm branch creates a generic InvestigationAgent from the deployment LLM, reads persona_instructions directly, and does not use configured agent_id. This leaves the editor's declared configuration and runtime behavior inconsistent.
- tool_isolate and tool_firewall run guardrail checks, then report status not_configured with executed=false when their provider is absent. There is no live containment dispatcher wired into these branches.
- References: [node config schema](../src/terminus/pipeline/nodes/schemas.py#L54), [agent_llm execution](../src/terminus/pipeline/workflow_engine.py#L410), [isolation result](../src/terminus/pipeline/workflow_engine.py#L461), [firewall result](../src/terminus/pipeline/workflow_engine.py#L497).

## P03 — Incident-task record contract (implemented foundation)

The durable task is an incident-scoped unit of analyst work, without recurring schedules. Strict frozen Pydantic records are defined in src/terminus/orchestration/models.py; SQLite tables and tenant/incident-scoped foreign keys are initialized in src/terminus/storage/db.py. Record IDs default to UUID strings, while organization and incident IDs remain strings to match existing identifiers. DurableRecord contributes org_id, incident_id, and created_at to each record. Datetimes must include a timezone and are normalized to UTC.

| Record | Exact fields (in addition to DurableRecord) |
| --- | --- |
| Task | task_id (UUID string); parent_task_id (optional); area; role; objective; status (queued by default); priority (integer 0–1000, default 100); idempotency_key (optional); updated_at; started_at (optional); completed_at (optional). |
| AgentRun | run_id (UUID string); task_id; agent_id (optional); model_connection_id (optional); model_name (optional); status (queued by default); updated_at; started_at (optional); completed_at (optional); result (JSON value or null); error (optional). |
| EvidenceRecord | evidence_id (UUID string); task_id; source; source_timestamp; collected_at; content (JSON value or null); content_ref (optional); content_hash (required, 64 lowercase hexadecimal characters). Validation requires either content or content_ref. |
| HelpRequest | help_request_id (UUID string); task_id; requested_role; reason; status (open by default); updated_at; completed_at (optional). |
| ActionAttempt | attempt_id (UUID string); task_id; action; targets (1–100 identifiers); status (proposed by default); inputs (JSON object, empty by default); updated_at; completed_at (optional). |
| ActionAttemptEvent | event_id (UUID string); attempt_id; status; timestamp; actor; outputs (JSON object, empty by default); error (optional). Events record the append-only action audit history. |

Exact state labels from src/terminus/orchestration/models.py:

- Task: queued, running, waiting, completed, failed, cancelled.
- AgentRun: queued, running, completed, failed, cancelled.
- HelpRequest: open, assigned, resolved, cancelled.
- ActionAttempt and ActionAttemptEvent: proposed, approved, dispatched, acknowledged, verified, failed, unknown, rejected.

The SQLite contract uses composite references to constrain task children by organization and incident, and parent tasks must share both. Agent runs, evidence, help requests, and action attempts reference a task using (org_id, incident_id, task_id); events reference an attempt using (org_id, incident_id, attempt_id). Idempotency keys are unique within an organization. SQLite status CHECK constraints cover tasks, runs, help requests, and action attempts. Evidence and action events have database triggers preventing update and delete. The JSON payload retains the strict record, with indexed columns for scoped access. Incident IDs are persistent Terminus ticket IDs. Production task admission uses create_incident_task to verify the incident in the same tenant; the low-level create_task interface remains available for legacy/import records.

The SQLite persistence layer is implemented by OrchestrationStore in src/terminus/orchestration/storage.py. Its reads and mutations take org_id; child creation resolves the task within that tenant and carries its incident key into the child record. Task creation is transactional and idempotent per organization/key, with a request hash detecting conflicting reuse. Lifecycle updates use expected-status compare-and-swap and reject illegal transitions; action changes and their append-only event are written in one transaction. List methods cap page size at 200 and support offset pagination. Public task/run/evidence/help/action routes remain deferred. Any future public access must derive the tenant from authenticated membership and preserve the composite organization/incident checks; exact routes and authorization roles remain open decisions. See [record models](../src/terminus/orchestration/models.py#L31), [SQLite schema](../src/terminus/storage/db.py#L413), and [tenant-scoped store](../src/terminus/orchestration/storage.py#L82).

Future model connection and usage reporting are separate proposals. AgentRun currently has optional model_connection_id and model_name fields for provenance. There is no implemented model-connection credential store, gateway invocation contract, usage ledger, token accounting, or cost reporting. Those require a separate design and must not be inferred from the provenance fields.

## P04 — Persistence and execution boundary

**Local foundation choice:** use the existing single-host SQLite database as the authoritative store for the incident-task records through fixed tenant-scoped OrchestrationStore methods. New record IDs default to UUID strings; current organization and incident keys retain their string formats. Timestamps are UTC-aware, state enums are explicit, and organization/incident composite foreign keys enforce task-parent and task-child scope. Evidence and action event history are immutable at the database layer. Task idempotency and status compare-and-swap are transactional. The server now uses the canonical SQLite incident repository. Production task admission verifies the tenant-scoped incident through create_incident_task; low-level imported records do not receive that existence check. Missing or cross-tenant task references return the same not-found error.

**Execution remains pending:** the service currently has in-process background loops, but this contract does not implement or approve a general scheduler. Any future scheduler decision is constrained to one host and the same authoritative SQLite database until separately reviewed. No task execution engine, polling loop, retry policy, worker lease protocol, or external action runs as part of this planning record.

**Approval state:** the SQLite record/schema direction and tenant-scoped persistence contract are adopted for this foundation. The complete P04 scheduler/execution design remains pending. Public API shape, model-gateway connection, and usage schema remain pending review and implementation.
