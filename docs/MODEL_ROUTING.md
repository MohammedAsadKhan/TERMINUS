# Model routing and bounded fallback — M04

Implemented October 4, 2026 by Mohammed with Claude Code (Sonnet 5.5). Fixture-only: no live transport, credential resolution or financial admission (M05). The legacy single-provider pipeline is unchanged.

## Behavior

`ModelRoutingService.route_fixture` (`src/terminus/model_gateway/routing.py`) wraps M03 `ModelAdmissionService`. Candidates are built only from the organization policy's exact grants for the task's durable role (and area for area orchestrators), in grant/model order. A candidate is excluded, with an audited reason, when its connection is missing/disabled/tampered (`connection_unavailable`), its version differs from the grant (`connection_version_mismatch`), the model is not on the connection (`model_unavailable`), the provider lacks a required capability (`unsupported_capability`), the capability is not yet admitted (`capability_not_admitted`), or the caller supplies no transport (`transport_unavailable`). Roles outside the eight core roles and orchestrators are not routable.

- **Capabilities:** `structured_output`, `native_schema` (not DeepSeek, which uses json_object plus local validation) and `tool_calls`. M03 admits only a first structured turn, so `tool_calls` routes nowhere until continuation admission exists.
- **Explicit routing:** optional `preferred` (connection, model) goes first; if it is not eligible routing is denied rather than substituted.
- **Fallback:** off by default (`max_attempts=1`, maximum 3). It continues only after a `status="error"` with a retryable code (rate limit, provider/transport unavailable, timeout, auth, unsupported request, invalid contract, oversize). Refusals, truncation and successes never fall back. Ambiguous timeouts keep unknown usage; M05 must keep them reserved.
- **Reauthorization:** every attempt calls `prepare` (fresh grants, evidence classification, membership, lease, destination) and `respond_fixture`. Stale/cancelled ownership or revocation during an attempt ends routing with `ModelRoutingDeniedError`; it is never a fallback trigger. A candidate that admission denies (for example local-only evidence to a hosted provider) is skipped, so fallback cannot widen data grants.
- **No scripted fallback:** there is no path that returns scripted findings. With no eligible route the call raises; if attempts all fail the result carries the last error with `exhausted=True`.

## Provenance

`RoutedModelResult` returns the route ID, final response, every `RouteAttempt` (connection, version, provider, model, policy version, rationale `preferred_request`/`policy_order`/`fallback:<code>`, outcome, admission ID, request digest) and exclusions. `model_routing_audit` is an immutable, append-only SQLite table with bounded vocabulary only (no prompts, evidence, endpoints or credentials) and links to `model_admission_audit` by admission ID.

## Remaining

M05 is complete ([MODEL_BUDGETS.md](MODEL_BUDGETS.md)): every attempt reserves before I/O and settles or stays ambiguous. Still open: production transport remains gated on M03+M04+M05; tool continuation admission, routing settings UI and live evaluation (M06) are open.
