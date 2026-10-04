# Specialist runtime — O05 (fixture level)

Implemented October 4, 2026 by Mohammed with Claude Code (orchestrator) and Claude Sonnet subagents. Fixture-verified only: no lab evidence, no live model transport, no Wazuh credential wiring. O05 stays open until the lab criterion is met.

## Parts

- `orchestration/specialists/runtime.py`: `make_specialist_handler(RoleSpec, SpecialistDeps)` returns a scheduler `JobHandler`. It checkpoints scheduler ownership before the context build, every tool call and the model call, builds a fresh trusted context each time, and calls tools only through `ToolGateway` (max 20 calls). Tenant comes from the leased task only. Every non-ok result, partial coverage, truncation or uninstalled tool becomes an explicit gap. It never synthesizes a finding from absence. An optional model step runs only when routing and a client factory are supplied; findings must cite evidence collected in the same run, and uncited ones are dropped. Results are bounded to 32 KiB. A run with gaps is not a security verdict.
- `specialists/roles.py`, `factory.py`, `deploy.py`: plans for the eight core roles drawn from each role's catalog bundle (no dispatch tools; `response.propose` deferred to A03), `build_specialist_handlers`, and eight module-level coroutines loadable by `scheduler_cli --handler ROLE=module:function`. Deployment reads `TERMINUS_SPECIALIST_DATABASE` and `TERMINUS_SPECIALIST_ACTOR_USER_ID` and fails closed when they are missing. No model transport is configured (tools only). Connector credentials come from the injectable `deploy.configure_connectors` hook.
- `toolkit/evidence_tools.py`: read-only installed tools `evidence.get`, `evidence.timeline`, `evidence.validate_citations`, tenant- and incident-scoped; foreign and missing ids look identical. Evidence ids reach them only through trusted code (`cited_evidence_ids`), never tool arguments. The registry uses a derived catalog adding the `terminus_store` connector to these three tools; the packaged catalog is unchanged and should be updated later.
- `pipeline/specialist_bridge.py` and the `AGENT_LLM` node: with a bridge injected, a live node queues a specialist task (key `workflow:{run_id}:{node_id}`) and returns its recorded result, `WAITING_SPECIALIST`, `NOT_EXECUTED`, `FAILED` or `UNRESOLVED_AGENT`, never a fabricated verdict. Without a bridge, live mode keeps the legacy `InvestigationAgent`, now labeled `legacy_unrecorded`. Dry-run is labeled simulated and no longer sets a fake report verdict. A run waiting on a specialist finalizes as `WAITING_SPECIALIST`; `resume_run` re-evaluates it.

## Installed read tools today

`incident.get`, `alerts.search`, `collection.coverage`, `endpoint.agent`, `identity.auth_events` and the three evidence tools. Network, application, process, file, reputation and verification/reporting tools are descriptors only, so those roles report `tool_not_installed` gaps.

## Remaining

1. Lab evidence per role (L01-L05, A01-A02), and real connectors for the uninstalled tools.
2. Production wiring of the bridge into `server/deps.py` and `sweeper.py`, passing deployed handler roles; automatic resume when a specialist run finishes; add `WAITING_SPECIALIST` to the run status enums if anything validates them.
3. Per-incident time window passed by the runtime (current window is claim time minus 55 minutes to plus 5), and a decision on whether failing missing configuration should consume retries.
4. Model step with a live transport (M06), and O06 collaboration/help requests.
5. Retiring the legacy `InvestigationAgent` path from the default workflow.
