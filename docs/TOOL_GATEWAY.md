# Read-only tool execution foundation

The gateway is an internal Python library for trusted server-installed read handlers. It is not an HTTP endpoint, a model-facing authorization service, or a sandbox. No production connector, specialist handler, model call or response action is installed by this change. Existing Copilot and workflow tool paths are not automatically redirected through it.

## Installation and admission

`ExecutableToolRegistry` snapshots and revalidates the declarative catalog. A name or catalog entry never installs code. Trusted composition code supplies an async `InstalledTool` and a separate set of configured connector IDs. The descriptor must exactly match the catalog. Resolution intersects the eight core role bundles, descriptor grants and installed code; all required connectors must be configured. Future specialties/tools, response effects, approval-requiring tools and external-egress tools are rejected.

`ToolGateway.execute(tool_id, arguments, context=...)` receives a server-created `ToolExecutionContext`. The caller must derive tenant, incident, resource/connector grants and policy from authenticated server state and the current scheduler lease. Never deserialize this context from HTTP or model arguments. The library verifies canonical task/run and lease ownership, but it does not create credential policy or authenticate arbitrary supplied contexts. Model input can contain only a strict `ReadQuery`; raw commands, URLs, filesystem paths, SQL/indexer DSL, credentials and dynamic imports have no accepted fields.

Operator-installed code is trusted and must remain read-only, use finite I/O deadlines and cooperate with cancellation. Python cannot forcibly stop arbitrary code or prevent an installed handler from accessing credentials on its own. Credential isolation and source authorization remain adapter requirements.

## Durable execution and limits

`ToolInvocationStore` creates additive SQLite reservation, completion and denial tables when initialized. Transactions serialize reservations across processes. A reservation is persisted before the handler starts. It records organization/incident/task/run, tool/version/effect, policy version, a canonical arguments digest and hashed ownership identity. It stores no raw arguments, credential tokens, exception text or model reasoning.

Each task admits at most 20 invocations across all its runs, retries and restarts. Failed, timed-out and unfinished reservations consume the limit; finalization cannot release a slot. Denial audit has a separate durable cap of 20 records per task. Once exhausted, further requests remain denied without growing the ledger. These are tool-call limits, not model-token or financial budgets; M01-M05 remain pending.

The registry and gateway enforce the descriptor's bounds: at most a one-hour query, 200 records/page, four pages, ten seconds and 64 KiB of model-facing result. Oversized or malformed callback results are rejected rather than silently accepted. Adapters must return explicit `partial` results with coverage/truncation when collection limits are reached. Missing telemetry returns unavailable/unsupported/gaps; a complete empty result requires collection provenance.

Lease loss, cancellation, timeout or uncertain finalization produces an unknown audit outcome and no successful data return. The gateway discards late callback results. Caller cancellation is propagated after a conservative audit completion. An unfinished reservation remains discoverable after restart and is never interpreted as success or resumed by this library.

## Evidence and provenance

The handler receives a copied trusted context whose `invocation_id` is bound to the invocation reservation. Model-spend reservation references remain separate; a tool-call reservation does not authorize spending. `ToolEvidenceWriter(validator, audit).record(...)` checks current ownership, an active matching reservation, deadline, resource/query scope and authorized connector in the same transaction as persistence.

Evidence contains observed finite bounded JSON and a provenance envelope: tool/version, invocation/run, resource, source event IDs, timestamps and query digest. A missing observation cannot become evidence. Source timestamps must fall inside the admitted query. Completion closes the writer's admission, preventing a timed-out callback from publishing late evidence through this writer.

Results refer to immutable evidence by same-incident identity and content hash. Read collection results must bind their persisted envelopes to the invocation, query, resource and supplied provenance; old evidence cannot be relabeled as a newly observed event. Incident-wide peer evidence sharing remains supported by the underlying records and contract validator, but derived local-analysis execution needs a provenance design before it can be enabled. Connectorless analysis tools currently cannot claim collected findings through this gateway.

For a read result, `data` must equal the stored `observed` JSON when there is one evidence reference; for multiple references it must be the list of their `observed` values in reference order. A valid citation cannot justify a different invented finding. Derived conclusions belong to a separately validated analysis/synthesis path. An `ok` collection requires observations, while a complete empty collection uses `empty` with source provenance.

Evidence storage is not model-egress authorization. The later model gateway must minimize/redact evidence and enforce data-locality policy before any external call. External intelligence remains disabled here.

## Acceptance and remaining work

Tests use temporary SQLite databases and explicitly installed callbacks. They cover dormant defaults, future/effect/egress denial, exact role grants, durable quotas, concurrent admission, immutable audit, restart reads, hostile arguments, scoped evidence, output bounds, deadline/cancellation and stale-owner suppression. They do not verify any live Wazuh or model provider.

Next: implement bounded incident, coverage, endpoint and authentication readers; keep Wazuh manager credentials distinct from indexer search credentials. Remove production fabrication fallbacks as those readers are connected. Then implement credentials, model policy, redaction and budgets before wiring eight real specialists. Approval-bound dispatch and effect reconciliation are separate response work.
