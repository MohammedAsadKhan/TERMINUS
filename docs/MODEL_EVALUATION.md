# Model evaluation and coverage — M06 (partial)

## October 5 Gemini live smoke test

A temporary browser-triggered synthetic test also succeeded: `suspicious`,
matching evidence citation, 157 input / 48 output tokens (205 total). Its browser
control and local API endpoint were removed after validation; they are not part
of the committed product. Production transport regression tests remain.

Done by - Mohammed | Agent - Codex. One authorized synthetic SSH authentication
triage request succeeded with `gemini-3.5-flash-lite` through the production
transport, scheduler admission, explicit triage/data grant and budget ledger in
an isolated temporary SQLite database. The response cited the supplied evidence;
provider-reported usage was 155 input and 71 output tokens (226 total), and the
reservation settled. Zero configured rates represented the selected project's
verified free tier, not an independently verified billing invoice.

The first attempts exposed an HTTP compatibility bug: Google's repeated `Vary`
headers were rejected. Repeated `Vary` values are now accepted; duplicate framing
headers remain rejected. Safe diagnostics log fixed stages, exception types and
allowlisted parser reasons without exception text, credentials or payloads.
Validation: 33 transport tests passed, including repeated-header compatibility
and secret-safe diagnostics; Ruff checks passed.

This smoke test does not establish full M06 case coverage or demo readiness. It
does not change the app's role grants/budgets or enable specialist live execution.
The app's connection remains unverified until its evaluation coverage is recorded
through the normal evaluation path. Lab telemetry and response effects remain
unverified. No endpoint action was performed.

Implemented October 4, 2026 by Mohammed with Claude Code (orchestrator) and two Claude Sonnet subagents. The initial implementation was contract-level evaluation. The October 4 pre-lab integration adds production transport, protected credential resolution and specialist handlers. Gemini has passed a limited synthetic live smoke test; full M06 coverage remains partial. See [current pre-lab status](PRELAB_IMPLEMENTATION.md).

## Parts

- `src/terminus/model_gateway/evaluation_cases.py`: 12 synthetic incident cases covering the eight core roles (triage has two), three of them prompt-injection cases. Evidence uses RFC 5737 addresses and `*.lab.example` hosts. Each case has a closed output schema and `validate_output`, which checks schema conformance, verdict, evidence citations (index in range, key evidence cited), allowed actions, fabricated hosts/IPs and followed injected instructions. No case needs `tool_calls`, which is not admitted yet.
- `src/terminus/model_gateway/evaluation.py`: `ModelEvaluationService`. For each configured connection/model and case it records two tracks in the append-only `model_evaluation_records` table:
  - `contract`: runs through `route_fixture` (admission, budget reservation, routing audit) with a recorded fixture response. Ends in `contract_verified`, `contract_failed` or `policy_denied`. Always labeled `fixture_only`; unknown cost stays unknown.
  - `live`: `credentials_missing` for a hosted connection without a credential, otherwise `transport_unavailable`. `live_verified` requires the concrete production transport and the unified admission/execution path; a caller-supplied boolean cannot establish live execution. Authorization is checked during execution and before accepting the result.
  - `capability_unsupported` and `not_configured` apply to both tracks.
- `coverage_summary` counts the latest record per connection, version, model, case and track. `demo_ready` is true only when the connection's current version has a latest `live_verified` record for every required case. It is false today.

Records hold no prompts, evidence text, endpoints or credentials. Failure reasons are capped (8 entries, 120 characters) and scrubbed.

## Remaining for M06

1. Validate the implemented pinned transport and continuous authorization against a configured OpenAI connection. Local socket fixtures and mocked TLS checks do not establish live provider verification.
2. Exercise the implemented O05 specialist handlers against installed lab telemetry; tool-continuation admission for `tool_calls` cases remains a separate requirement.
3. Live runs against the selected demo models and a local endpoint if configured, with missing credentials recorded.
4. An admin API/UI to view coverage (U04).
