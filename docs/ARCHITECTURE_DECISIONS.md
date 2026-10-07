# Architecture decisions and planning record

This document records the current implementation audit and durable incident-task foundation. “Observed” describes code that exists today; “proposed” describes boundaries for review and does not imply implementation or approval. This record includes durable identity/session storage and canonical incidents. The dedicated durable scheduler is implemented; model-provider credential storage and lab integration remain pending.

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

The SQLite persistence layer is implemented by OrchestrationStore in src/terminus/orchestration/storage.py. Its reads and mutations take org_id; child creation resolves the task within that tenant and carries its incident key into the child record. Task creation is transactional and idempotent per organization/key, with a request hash detecting conflicting reuse. Lifecycle updates use expected-status compare-and-swap and reject illegal transitions; action changes and their append-only event are written in one transaction. List methods cap page size at 200 and support offset pagination. Authenticated task inspection includes run/evidence/help/action records; enqueue and cancellation require member/admin privileges. Tenant scope comes from authenticated membership and preserves composite organization/incident checks. See [record models](../src/terminus/orchestration/models.py#L31), [SQLite schema](../src/terminus/storage/db.py#L413), and [tenant-scoped store](../src/terminus/orchestration/storage.py#L82).

Future model connection and usage reporting are separate proposals. AgentRun currently has optional model_connection_id and model_name fields for provenance. There is no implemented model-connection credential store, gateway invocation contract, usage ledger, token accounting, or cost reporting. Those require a separate design and must not be inferred from the provenance fields.

## P04 — Persistence and execution boundary

**Local foundation choice:** use the existing single-host SQLite database as the authoritative store for the incident-task records through fixed tenant-scoped OrchestrationStore methods. New record IDs default to UUID strings; current organization and incident keys retain their string formats. Timestamps are UTC-aware, state enums are explicit, and organization/incident composite foreign keys enforce task-parent and task-child scope. Evidence and action event history are immutable at the database layer. Task idempotency and status compare-and-swap are transactional. The server now uses the canonical SQLite incident repository. Production task admission verifies the tenant-scoped incident through create_incident_task; low-level imported records do not receive that existence check. Missing or cross-tenant task references return the same not-found error.

**Scheduler contract adopted for O03:** one dedicated Python/asyncio scheduler process operates alongside FastAPI on the same host and SQLite file. It does not start inside each API worker. A database coordinator lease fences claims, and task leases fence heartbeats and completion. Default global concurrency is four, with two concurrent jobs per organization; both are configurable bounded deployment limits. Higher numeric priority runs first, with deterministic FIFO tie ordering. Only explicitly admitted jobs with registered role handlers execute; existing queued task records are not automatically scheduled.

Admission verifies a tenant-scoped canonical incident and a queued task. A job has at most three attempts by default (configurable one to five), with bounded retry delay. Each claim atomically creates a tracked agent run. Expired leases recover safe work within the attempt budget. Tasks with prior action dispatch history wait for reconciliation on failure rather than automatic retry, even when an action was subsequently marked verified or failed. Dispatched, acknowledged or unknown outcomes also block completion. Cancellation is durable; running handlers receive cooperative cancellation, and uncertain external effects remain unresolved. Late workers cannot publish results using expired or replaced lease tokens.

Registered handlers are asynchronous Python functions deployed explicitly by the operator; no built-in specialist, model provider, shell, or containment executor is installed by O03. Handlers must respect cancellation and check their lease before future consequential tools. Durable scheduling provides ownership and recovery, not exactly-once external effects. Source authentication, response approval binding, secret protection and model policy remain separate requirements.

**Approval state:** the SQLite record/schema direction, tenant-scoped persistence and single-host scheduler contract are adopted for this foundation. The broader P03/P04 model gateway, usage, source authentication and secret-management decisions remain pending. Worker/tool integration and measured lab limits require later validation.

## O04 - Main and lazy area coordination contract

Explicit operator admission stores an incident objective and selected areas as a durable main task. Deterministic coordinator handlers delegate through the O03 scheduler without model calls. Only selected areas activate; specialized tasks require explicitly deployed handlers. All five areas are logical boundaries; selecting an area without a configured specialty must expose a coverage gap rather than imply protection.

Main and area runs complete their delegation passes without awaiting specialist workers. Their completion is not incident closure or endpoint verification. The incident tree aggregates persisted descendant states, results and evidence references separately. Child admission is transactional, idempotent and fenced to the owning coordinator job; no recursive unrestricted spawn interface is introduced.

This is the objective/delegation foundation of O04. Autonomous model planning, scoped real specialist tools (O05), richer collaboration/budget admission (O06), the activity UI and incident closure gates remain separate tasks. See [coordination operations and limits](COORDINATION.md).

### October 4 - Eighth core specialist

Application & API Security Analyst (`application_api`) belongs to `applications_data` and is now part of the eight-role default catalog. It is scheduled only when that area is selected. This adds a durable task role; it does not install application tools, model execution or protection. O05 now covers all eight core specialists.

## T01 - Declarative full toolkit contracts

The approved contract-first baseline is recorded in TOOLKIT_CONTRACTS.md and the packaged toolkit JSON fragments. It maps 60 specialties to 93 proposed tools and 48 connector candidates, with eight pending core bundles. Strict schemas and non-executing validation fixtures define scoped evidence, lease/context checks, approval hashes and independent verification. It installs no handlers or gateway, enables no adapters/credentials, and changes no live workflow/Copilot tool permissions. Copilot write authorization, redaction, fabricated SIEM helpers, approval binding/expiry, quota and response reconciliation are recorded remediation tasks for subsequent implementation.

## T02 - Internal read-only executable foundation

The registry accepts explicit trusted async read/local-analysis implementations, separate connector readiness and exact catalog descriptors. Default installation is empty. Core bundles restrict resolution; future roles, effects, approval-requiring and external-egress tools cannot execute. The internal gateway validates arguments, scope and ownership, persists a reservation before handler I/O, bounds execution/output, and conservatively audits uncertainty. It has no public API and does not redirect legacy Copilot/workflow tool paths.

SQLite admission caps reservations at 20 per task across runs/restarts and denial audit at another 20. Reservations and completions are immutable; late/stale results cannot establish success. Fenced evidence writes require a matching pending invocation and current ownership/deadline. Read outcomes bind persisted evidence to invocation/query/resource/provenance. Unknown read execution has no fabricated dispatch identity; actual dispatch contracts retain their approval/intent requirements.

This foundation adds no production adapter, credential access, model egress or response action. Model spend/redaction policy, authenticated context construction, real specialists and live lab checks remain pending. See [tool execution operations](TOOL_GATEWAY.md).


## October 4: bounded readers and trusted read policies

T03 introduces five explicitly installed internal readers and durable versioned administrator-controlled incident/resource policies. Contexts derive from canonical scheduler leases and current membership, not model arguments. An optional gateway authorization hook rechecks policy during execution and atomically with final audit. Policy revocation suppresses data; uncertain pending requests remain unknown. Manager endpoint context and indexer searches have separate org-scoped connections. Authentication requires the indexer; Sysmon remains optional future enrichment.

Unconfigured SIEM and offline reputation now disclose unavailable/unknown instead of fabricated observations. Missing incident source timestamps cannot become ingestion-time freshness claims. Coverage is explicitly incomplete. See [implementation and integration handoff](INVESTIGATION_READERS.md). Five-reader fixture acceptance is complete (517 isolated tests); public execution routes, O05 handlers, model egress/redaction/budgets and live lab defense remain open.


## October 4: named model connection registry (M01)

The [model connection registry and handoff](MODEL_CONNECTIONS.md) adds multiple named provider/local configurations, encrypted API keys and a masked authenticated settings API. Current admin membership is required for writes, current membership for reads; edits/deletion use version checks and mutation audit is immutable and redacted. The master key comes from `TERMINUS_MODEL_CREDENTIALS_KEY`, outside SQLite; no fallback key is generated. Credentials are bound to organization/connection and cannot silently follow a changed provider or destination. Schema creation and writes preserve enclosing transactions.

All connections remain unverified and perform no outbound calls. The existing single-provider investigation pipeline is unchanged. Native provider adapters, role/data-sharing policy, model routing, budget admission and console settings integration remain M02-M05/U04; this configuration registry does not grant model execution. Tests use temporary databases and placeholder credentials.


## October 4: provider protocol adapters (M02)

The [provider adapter contracts and handoff](MODEL_ADAPTERS.md) implement the seven agreed provider families through pure codecs and an explicit MockTransport-only fixture harness. Shared contracts bound prompts/results, validate a strict JSON-schema subset and bind function calls/results. Native Anthropic and Gemini formats, compatible OpenAI/OpenRouter/DeepSeek/local formats, refusals, truncation, unknown usage, tool signatures and cancellation have fixture coverage. DeepSeek uses documented JSON mode plus local schema validation; strict provider-enforced schema capability is not assumed.

Verification: 670 isolated tests passed, including 100 new protocol checks; targeted Ruff and focused new-source type checks passed. These are synthetic protocol fixtures, not live model evaluation. No real keys, credential lookup, production transport or specialist/model execution is enabled. M03 permissions/locality/redaction is next, followed by M04 routing and M05 financial admission before production transport/O05 integration. Per-model capability evaluation remains M06.


## October 4: model permission and data policy (M03)

The [M03 policy foundation](MODEL_POLICY.md) adds durable organization/role/connection/model grants, evidence-hash classifications, bounded redaction and scheduler-bound first-turn fixture admission. Unclassified evidence stays local; verified private destinations are freshly resolved per attempt. Configuration changes, revoked membership, evidence changes and lost ownership deny calls or suppress in-flight results. Metadata audits exclude raw prompts and credentials.

Verification: 715 tests passed against temporary databases, including 45 new checks; targeted Ruff passed and new-source type checks reported zero errors/warnings (the existing configuration diagnostic remains). This does not enable live model calls or protect the unchanged legacy pipeline. Production socket pinning/transport, M04 routing, M05 financial admission, tool continuation integration and U04 policy UI remain open. Follow the [Claude handoff](CLAUDE_HANDOFF_AFTER_M03.md) and claim the next task before editing.

## October 4: pre-lab integration and fixture response boundary

The [pre-lab checkpoint](PRELAB_IMPLEMENTATION.md) records bounded specialist collaboration, strict workflow result/citation integration, concrete pinned model transport with repeated authorization and durable exposure, authenticated model configuration, and durable activity inspection. Live model execution is explicit opt-in; named configuration alone proves no provider capability. The [response lifecycle](RESPONSE_LIFECYCLE.md) is a private SQLite fixture driver with immutable approval-bound proposals, intent-before-I/O, reconciliation and independent observation contracts. No public dispatch or live response adapter is introduced. Release scope remains eight core roles; future specialties are visible but unavailable. Local lab validation and subsequent AWS reproduction remain mandatory.

## October 6: repository security manager, asset tiering, and guardrail enforcement

Workstreams A, B, and C introduce:
1. **Asset Registry & Tiering:** Idempotent database migrations for asset criticality (`tier0`–`tier3`), `agent_id`, `hostname`, `owner`, `environment`, and `exposure`. `SqliteAssetRepository.find_for_target` prioritized lookup (`agent_id` $\rightarrow$ `hostname` $\rightarrow$ `locator/IP` $\rightarrow$ `name`) with strict tenant isolation. Computed coverage reporting (`scanned`, `stale`, `never_scanned`, `scan_failed` for repositories; `not_connected` for unmanaged infrastructure).
2. **Deterministic Blast-Radius Guardrails:** Registered Tier-0 and Tier-1 infrastructure strictly block automated containment. Registered Tier-0 assets cannot be overridden even with `force_override=True`. Unregistered keyword fallback remains overridable with explicit human override. Repository exceptions fail closed safely.
3. **Repository Security Engine (`terminus.repo_security`):** Isolated sandboxed static analysis for repositories. Enforces strict HTTPS allowlist policy (`github.com`, `gitlab.com`), process-isolated cloning (`core.hooksPath=`, zero code execution), zero raw secret storage in DB/logs (SHA-256 fingerprint deduplication + redacted previews), dependency SBOM extraction & OSV vulnerability checks, suspicious commit heuristics, and immutable audit logs (`repo_finding_events`).
4. **API, HMAC Webhooks & UI:** Gated behind `TERMINUS_REPO_SCAN_ENABLED` feature flag (defaults `false`). GitHub HMAC-SHA256 authenticated webhook for automated push triggers. React/AntD asset view with live scanning drawer, SBOM component inspector, findings status management, and tiering configuration.

