# Approval-bound response foundation

October 4, 2026. Done by - Mohammed | Agent - Codex orchestrator and GPT-6.1 Sol implementation agent. This is an internal fixture foundation for Scenario A, not a live defense adapter. A03–A05 remain subject to their lab acceptance criteria.

## Contract and ownership

`response/models.py` defines a versioned trusted response policy, opaque registered targets and exact parameter evidence. `response/service.py` creates immutable proposals from a canonical incident and an actual response-planner task/run. Running planners require current scheduler ownership; completed planner records authorize planning only. Model arguments cannot select a tenant, credentials, protected target or executable provider.

Only `response.wazuh_ip_block` is admitted in this foundation. Targets must match the same incident, policy and provider registration. Protected and management targets are excluded. Parameters and supporting evidence must match durable evidence hashes. Changing policy, parameters, evidence or proposal digest invalidates admission.

Human approval requires current administrator membership, an exact proposal digest and unexpired binding. The creator cannot self-approve. Denial has no dispatch. An acknowledgement is never an independently verified effect.

## Durable fixture lifecycle

`response/storage.py` persists policies, proposals, decisions, unique intents and events. `response/fixtures.py` provides a private SQLite-only test driver. There is no public dispatch endpoint or live network, endpoint or identity action in this package.

1. Persist a unique intent and attempt before simulated provider I/O.
2. Treat cancellation, expiry, revocation and stale ownership conservatively.
3. Keep interrupted or ambiguous effects unresolved until reconciliation; restarting does not authorize blind replay.
4. Verify with separately persisted observation evidence, source, run, timestamps and content hashes. Provider acknowledgement alone cannot satisfy effect and legitimate-service checks.
5. Undo or expire only the resource owned by that action. Preserve unrelated resources.

All outcomes expose `fixture_only=true`, `live_executed=false` and `live_verified=false`, including successfully verified fixture observations.

## Remaining integration

- Connect trusted response planning to the toolkit/workflow interfaces and authenticated operator review UI.
- Select the installed Wazuh version, least-privileged manager credential and supported active-response configuration.
- Implement real dispatch and reconciliation through a controlled adapter, with independent telemetry proving attacker-path blocking and management/service health.
- Test timed expiry, undo and demonstration reset in the local lab before AWS migration.

Do not use fixture receipts or test-provided observations as real defense evidence. Current verification results are recorded in [the pre-lab checkpoint](PRELAB_IMPLEMENTATION.md).
