# Model budgets, usage ledger and reconciliation — M05

Implemented October 4, 2026 by Mohammed with the Claude Code orchestrator and three Claude Sonnet subagents (ledger core, provider usage fields, routing integration). Fixture-only: no production transport or live provider has been exercised.

## Ledger (`model_gateway/ledger.py`)

`ModelBudgetStore` keeps integer micro-USD prices per (organization, connection, model), UTC-day budgets per organization (USD and optional tokens), reservations and an immutable `model_usage_ledger` (plus `model_budget_audit` for admin writes). Admins write prices/budgets with compare-and-swap; members read.

- **Atomic reservation:** `reserve` runs in one transaction. It requires a configured price and budget (no price means cost cannot be bounded, so it is denied), computes a conservative bound (input from `max_input_tokens` or request bytes, output from `max_output_tokens`, highest applicable rate) and denies if open exposure plus the bound exceeds the limit. Exposure is summed across the whole organization, so retries, fallback models, other connections and keys cannot bypass the limit. Idempotency keys replay the same reservation; changed parameters conflict.
- **Unknown is never zero:** `settle` computes cost from the reservation's price snapshot only when every billable component is known. Otherwise the reservation becomes `ambiguous`, keeps its full reserve counted, and the ledger stores `cost_known=0` with NULL cost (a CHECK constraint forbids 0). Actual cost above the reserve is recorded honestly and blocks later reservations.
- **Reconciliation:** admins move `ambiguous` to `reconciled` with usage that determines cost or an explicit `confirmed_no_charge`. `recover_stale` turns reservations stuck in `reserved` (crash after intent) into `ambiguous`; nothing is released automatically. `release` is only for attempts where provider I/O provably never started.
- **Usage fields:** `ModelUsage` now carries `cached_input_tokens` and `reasoning_tokens`, normalized per provider (input includes cached; output includes reasoning). Fields a provider does not report are `None`, not 0 (Anthropic reports no separate reasoning count). Malformed values are protocol errors.

## Routing integration

Per attempt: admission `prepare` -> `reserve` (committed) -> `attempt_started` audit -> `respond_fixture` -> `settle`. Budget denial excludes that candidate (`budget_denied`) with no provider I/O, so a cheaper priced model may still route. Provider error responses, unknown usage, cancellation, mid-attempt revocation and unexpected failures all end `ambiguous` (conservative); release happens only if the start audit fails before I/O. `RouteAttempt` and `model_routing_audit` carry `reservation_id`, `cost_known`, `cost_micro_usd` (None when unknown) and `usage_known`. `ModelRoutingService` requires a `ModelBudgetStore` on the same database.

## Remaining

Production transport is still gated: it also needs verified socket pinning, TLS/redirect/SSRF controls and tool-continuation admission. Provider-error attempts stay reserved until an admin reconciles them (no automatic no-charge inference). Budget/price settings API and UI (U04), a scheduled `recover_stale` runner, non-daily windows, and live model evaluation (M06) are open. Cost figures depend on admin-entered prices and are not verified against provider invoices.
