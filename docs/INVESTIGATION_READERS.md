# Bounded investigation readers and team handoff

Status: T03 implemented on October 4, 2026. Done by - Mohammed | Agent - Codex orchestrator, two GPT-6.1 Sol implementation agents and GPT-6 Luna cleanup/review. Acceptance uses temporary databases and recorded fixtures; live lab acceptance remains open.

## What exists

`src/terminus/toolkit/readers.py` exposes `InvestigationReadService`, an explicitly constructed internal service. It installs five read tools: `incident.get`, `alerts.search`, `collection.coverage`, `endpoint.agent` and `identity.auth_events`. The default catalog stays dormant. No public execution endpoint, scheduler specialist handler, model call or response action is enabled by constructing the repository's normal server dependencies.

Incident reads preserve canonical raw source payloads rather than synthesized verdicts. Missing payloads or source timestamps produce explicit gaps. Endpoint reads use actual manager observations and heartbeat timestamps. Coverage combines bounded manager and indexer observations concurrently, but remains incomplete: connectivity and alert counts cannot prove host health, collection completeness or absence of tampering.

Historical alert and authentication searches use the [Wazuh indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html); endpoint context uses the [manager API](https://documentation.wazuh.com/current/user-manual/api/reference.html). These are separate HTTPS connections with separate credentials and connector identities. Settings bind each connection to one organization. The operator must also configure source-side tenant/index permissions; an application organization label alone cannot isolate a shared upstream Wazuh installation.

The `identity.auth_events` descriptor now requires the indexer alone. Sysmon remains a future supplemental source, not a fictitious installed prerequisite. The fixed authentication-group filters and stable sort must be checked against the installed lab version and actual rule mappings.

## How an integrator uses it

1. Supply operator-controlled `WazuhManagerReader` and/or `WazuhIndexerReader` settings to an organization-scoped service. Missing connectors remain unavailable. Models never supply connection URLs or credentials.
2. An authenticated organization administrator uses `ToolReadPolicyStore` to create a versioned incident policy and bind incident/endpoint resource references. Endpoint mappings contain the trusted numeric Wazuh agent ID; writes check current admin membership and canonical incident ownership.
3. Claim a genuine scheduler task and pass its lease and trusted actor identity to `execute`. Pass only the strict `ReadQuery` as tool arguments. A future HTTP adapter must derive the actor from its server session, never from the model or request body.
4. `TrustedReadContextFactory` derives organization, incident, role, run, lease, connector/resource grants and read quota from durable state. It intersects policy grants with the installed role bundle. Future specialties cannot acquire executable grants.
5. The gateway checks fresh membership, policy version and ownership before reservation, during execution and at final audit. Revocation cancels pending reads; ambiguous attempts remain durably unknown. Data cannot escape after final authorization changes.

Policies and resource mappings persist in additive SQLite tables. Context issuance bindings are process-local and bounded; restart requires new context issuance. Read invocation quotas and audit identities persist across restart. These are call quotas, not financial model budgets.

## Bounds and evidence

Defaults remain one hour, 200 records per page, four pages, ten seconds total connector time and 64 KiB model-facing result size. Decoded responses are bounded before parsing; fixed typed queries reject arbitrary query languages, paths and URLs. TLS verification defaults on; redirects and ambient proxy settings are disabled by the owned clients. Oversized, incomplete, stale, malformed or missing telemetry yields gaps or conservative errors rather than invented observations.

Evidence publication checks current grants and the gateway's active invocation/lease/deadline. Observations retain source IDs, timestamps and provenance. Empty searches carry query provenance without fabricating events; their window-end trace timestamp is a query boundary, not an observed event. Provider acknowledgement is not independent verification.

Manager authentication tokens are ephemeral in the reader and are not cached or returned. Their upstream lifetime still follows Wazuh configuration; these read adapters do not perform potentially broad session-revocation writes.

Raw internal evidence can contain sensitive data. This service does not authorize model egress or redact arbitrary source payloads. M03 data policy/redaction and M01/M05 credentials/budgets must precede connecting this evidence to external models.

## Legacy behavior corrected

Unconfigured production SIEM dependencies now report unavailable rather than supplying sample host context. Legacy historical searches no longer invent three events. The manager client refuses a supposed manager alert-history endpoint. Offline reputation lookups return unknown/not assessed, and unqueried intelligence is excluded from citations. Explicit fixture/simulation clients remain available for tests.

## Next work and ownership

T03 is finished for fixture acceptance; avoid rebuilding its readers, policy store or context factory. Read the shared [execution checklist](EXECUTION_CHECKLIST.md) and claim the next task before editing.

- Next pre-lab lane: M01 named connection/secret registry, then M03 role/data-sharing policy and M05 durable financial budgets. Coordinate provider adapter interfaces under M02/M04.
- After those gates: O05 wire eight real specialist handlers and workflow run identities to this service. Do not imply that role labels alone execute specialists.
- Independent UI lane: U01-U04 task/agent activity and evidence views, coordinated against existing scheduler APIs.
- Lab lane: L01-L05, then A01/A02 authenticate real alerts, verify endpoint mappings, source clocks, index permissions and authentication filters.
- Response lane: A03-A05 immutable approval-bound proposals, dispatch intent, reconciliation, expiry/owned undo and independent effect/service verification.
- Target B application readers wait for selected target and telemetry. Future-specialty execution remains outside 1.0.

Automated verification covers the complete repository suite plus reader/context/legacy-gap integration tests. See the checklist for the final count. No live provider or lab defense is claimed.
