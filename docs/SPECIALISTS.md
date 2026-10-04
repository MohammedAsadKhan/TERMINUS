# Specialist runtime — O05 (fixture level)

Implemented October 4, 2026 by Mohammed with Claude Code (orchestrator) and Claude Sonnet subagents. Fixture-verified only: no lab evidence, no live model transport, no Wazuh credential wiring. O05 stays open until the lab criterion is met.

## Parts

- `orchestration/specialists/runtime.py`: `make_specialist_handler(RoleSpec, SpecialistDeps)` returns a scheduler `JobHandler`. It checkpoints scheduler ownership before the context build, every tool call and the model call, builds a fresh trusted context each time, and calls tools only through `ToolGateway` (max 20 calls). Tenant comes from the leased task only. Every non-ok result, partial coverage, truncation or uninstalled tool becomes an explicit gap. It never synthesizes a finding from absence. An optional model step runs only when routing and a client factory are supplied; findings must cite evidence collected in the same run, and uncited ones are dropped. Results are bounded to 32 KiB. A run with gaps is not a security verdict.
- `specialists/roles.py`, `factory.py`, `deploy.py`: plans for the eight core roles drawn from each role's catalog bundle (no dispatch tools; `response.propose` deferred to A03), `build_specialist_handlers`, and eight module-level coroutines loadable by `scheduler_cli --handler ROLE=module:function`. Deployment reads `TERMINUS_SPECIALIST_DATABASE` and `TERMINUS_SPECIALIST_ACTOR_USER_ID` and fails closed when they are missing. No model transport is configured (tools only). Connector credentials come from the injectable `deploy.configure_connectors` hook.
- `toolkit/evidence_tools.py`: read-only installed tools `evidence.get`, `evidence.timeline`, `evidence.validate_citations`, tenant- and incident-scoped; foreign and missing ids look identical. Evidence ids reach them only through trusted code (`cited_evidence_ids`), never tool arguments. The registry uses a derived catalog adding the `terminus_store` connector to these three tools; the packaged catalog is unchanged and should be updated later.
- `pipeline/specialist_bridge.py` and the `AGENT_LLM` node: with a bridge injected, a live node queues a specialist task (key `workflow:{run_id}:{node_id}`) and returns its recorded result, `WAITING_SPECIALIST`, `NOT_EXECUTED`, `FAILED` or `UNRESOLVED_AGENT`, never a fabricated verdict. Without a bridge, live mode keeps the legacy `InvestigationAgent`, now labeled `legacy_unrecorded`. Dry-run is labeled simulated and no longer sets a fake report verdict. A run waiting on a specialist finalizes as `WAITING_SPECIALIST`; `resume_run` re-evaluates it.

## Installed read tools today

`incident.get`, `alerts.search`, `collection.coverage`, `endpoint.agent`, `identity.auth_events` and the three evidence tools. Network, application, process, file, reputation and verification/reporting tools are descriptors only, so those roles report `tool_not_installed` gaps.

## Production wiring (added October 4, 2026)

- **Configuration signal.** The scheduler is a separate process, so the API and sweeper cannot introspect its handlers. `TERMINUS_SPECIALIST_ROLES` (comma-separated core roles) declares which handlers are deployed with `scheduler_cli --handler`. Unset or empty means the exact legacy path (`legacy_unrecorded`, no bridge). Unknown names are ignored. If `TERMINUS_SPECIALIST_DATABASE` is set and differs from the application database, no bridge is built (tasks would never be seen by the scheduler). The bridge's `handler_roles` are the declared roles, so an undeclared role returns `NOT_EXECUTED` instead of waiting forever. Wiring: `server/deps.get_pipeline_runner` (cached per database and declaration) and `sweeper_background_task`, both via `specialist_bridge_from_environ`. FastAPI never starts a scheduler.
- **WAITING_SPECIALIST** is in `WorkflowRunStatus`, `RunOutcome` and `NodeRunStatus`; a waiting run keeps `completed_at` empty and is returned by run listing and the claim record unchanged.
- **Automatic resume.** Each sweeper pass (`resume_ready_specialist_runs`) scans up to 50 `WAITING_SPECIALIST` runs (oldest heartbeat first), resumes at most 20 whose specialist tasks (looked up by the run's own org and key `workflow:{run}:{node}`) are all terminal (completed, failed, cancelled), and updates the alert claim. An atomic `WAITING_SPECIALIST -> RUNNING` claim makes it idempotent across sweepers; unready runs get their heartbeat touched so they rotate. A crash mid-resume is handled by the existing stale-RUNNING sweep. Latency is the sweeper interval (60 s).
- **Time window.** `QueryBuilder` is `(Task, QueryContext) -> ReadQuery`. The deployed runtime resolves `QueryContext.incident_time` from the durable incident record (`raw_payload_json.timestamp`, the same field `incident.get` checks, tenant-scoped; never from model output) and the window is exactly 55 minutes before to 5 after it (the one-hour read limit). Without a resolver or timestamp, builders fall back to claim time.
- **Missing configuration.** `SpecialistDeploymentError.retryable = False`; the scheduler honors `retryable=False` on handler exceptions, so the job fails terminally without consuming retries.

## Remaining

1. Lab evidence per role (L01-L05, A01-A02), and real connectors for the uninstalled tools.
2. Frontend: show `WAITING_SPECIALIST` status (web/src types are open strings; no tag styling yet).
3. Model step with a live transport (M06), and O06 collaboration/help requests.
4. Retiring the legacy `InvestigationAgent` path from the default workflow.
