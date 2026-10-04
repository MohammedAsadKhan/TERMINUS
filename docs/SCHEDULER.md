# Durable scheduler

The scheduler is a dedicated Python/asyncio process on the same host and SQLite file as FastAPI. The API does not start a scheduler in its lifespan. Existing workflow and daily-report background loops retain their current responsibilities; this scheduler handles explicitly admitted orchestration tasks.

## Admission and inspection

Create incident-scoped tasks through `OrchestrationStore.create_incident_task`. Task creation alone does not schedule work. Authenticated organization members can inspect `/orchestration/tasks` and `/orchestration/tasks/{task_id}`. Members and administrators can enqueue or request cancellation through the corresponding `/enqueue` and `/cancel` endpoints. Tenant scope comes from the authenticated membership, never from a request body. Lease and coordinator tokens are excluded from public responses. Raw execution errors are replaced with a generic diagnostic message, and credential-shaped keys and recognized credential patterns in metadata are scrubbed. Pattern scrubbing is not a guarantee that arbitrary evidence contains no sensitive data; handlers must minimize collected data.

An admitted task must refer to an existing incident in the same organization. Only roles with an explicitly registered handler can be claimed. Unsupported roles stay queued; they do not produce simulated success. Enqueueing the same task uses its existing scheduler job rather than creating another job.

## Dedicated process

Inspect command options with:

```powershell
uv run --frozen python -m terminus.orchestration.scheduler_cli --help
```

After deploying real handler code, the command shape is:

```powershell
uv run --frozen python -m terminus.orchestration.scheduler_cli --database C:\path\to\terminus.db --handler triage=your_deployed_handlers:triage --workers 4 --global-limit 4 --per-org-limit 2 --timeout 60
```

The database path and module in that example must be replaced with the actual deployment configuration. Handler modules are trusted operator-installed Python code; HTTP clients cannot choose imports. Read-only specialist handlers for the eight core roles are provided by `terminus.orchestration.specialists.deploy` (see [coordination operations](COORDINATION.md)); they use only tools-only reads, with no model transport configured, and no connector credentials are wired by default, so connector-backed tools report explicit gaps until a deployment injects readers. No shell or containment handlers are bundled. The optional `--coordination` flag registers deterministic main/area delegation handlers described in [coordination operations](COORDINATION.md). Without that flag the CLI refuses to start without an explicit handler, while the library supports an empty registry for configuration tests.

Handlers are async functions receiving `JobContext` and returning finite, bounded JSON. The context provides the canonical task, tracked run, cancellation event and `await context.checkpoint()` ownership check. Future tool adapters must check ownership and approvals and persist an action-dispatch record before consequential effects. Handlers must cooperate with cancellation and avoid blocking the event loop. This interface is not a sandbox for untrusted code.

## Ownership, recovery and limits

- One coordinator lease owns a database at a time. Worker leases use random fencing tokens; an expired or replaced owner cannot publish completion.
- Default limits are four concurrent jobs globally and two per organization. Higher numeric priority wins, followed by deterministic FIFO ordering. Limits are enforced in SQLite transactions across connections.
- A claim creates a running agent-run record and updates task/job state atomically. Heartbeats renew ownership independently of handler progress.
- Attempts default to three and are bounded from one to five. Safe failures and expired leases use bounded retry delay; exhausted attempts become failed.
- Any recorded prior action dispatch blocks automatic retry after failure, including actions subsequently marked verified or failed. Dispatched, acknowledged or unknown outcomes also block completion. A successful handler with a verified action can complete normally. Unsafe jobs wait for reconciliation; this release has no reconciliation/resume API and no public "force retry" endpoint. Reconciliation must be implemented with the response adapters before live effects are enabled.
- Cancellation is a request for running work, not proof that an external action was undone. Queued work can cancel immediately; uncertain action outcomes remain waiting.
- A callback that suppresses cancellation is held for reconciliation rather than retried. Python cannot forcibly stop arbitrary coroutine code; terminating such a process may require the operator. No automatic replacement may replay its uncertain work.

Persisted task/run/job records are authoritative. Scheduler completion means the registered handler returned successfully; it does not establish that an endpoint was protected or containment was independently verified.

## Verification boundary

Tests use temporary SQLite databases and explicitly registered test callbacks. They exercise concurrent ownership, priority and limits, fencing, restart recovery, cancellation, retry budgets and uncertain-action holds. Lab telemetry, production specialists, provider budgets and live response verification remain separate release tasks.
