# Model evaluation and coverage — M06 (partial)

Implemented October 4, 2026 by Mohammed with Claude Code (orchestrator) and two Claude Sonnet subagents. The initial implementation was contract-level evaluation. The October 4 pre-lab integration adds production transport, protected credential resolution and specialist handlers. No provider has been evaluated live in this checkout; M06 remains partial. See [current pre-lab status](PRELAB_IMPLEMENTATION.md).

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
