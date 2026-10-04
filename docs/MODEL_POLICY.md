# Model permission and data policy — M03

Implemented October 4, 2026 by Mohammed with the Codex orchestrator and two GPT-5.6 Sol agents. This is an internal, fixture-only admission foundation. It does not enable live model calls, resolve credentials, provide financial admission, expose policy settings APIs or replace the legacy single-provider pipeline.

## Durable authority

`ModelPolicyStore` stores organization-scoped, versioned grants for the eight core roles and main/area orchestrators. Area orchestrator grants identify an exact area. Each grant binds a named connection version, explicit model pool and permitted evidence classifications. Future specialties are rejected. Current administrators configure grants and evidence labels; current membership is checked on reads. Compare-and-swap writes prevent lost updates. Audits contain metadata rather than credentials or evidence.

Evidence classifications bind canonical evidence hashes. Unclassified evidence defaults to `local_only`; this cannot reach a hosted provider. `redacted_cloud` and `approved_cloud` require explicit grants, and both still pass through redaction. An administrator's classification is authorization, not proof that a detector found every sensitive value.

## Admission and fixtures

`ModelAdmissionService.prepare` accepts a scheduler lease, trusted operator identity, connection/model and incident evidence IDs. It derives role, tenant, incident, task and run from durable scheduler records. It rejects unavailable evidence references, altered hashes and foreign incidents. It assembles a fixed defensive instruction and canonical redacted evidence; arbitrary task objectives and raw model prompts are not exported. Sensitive schema metadata is rejected. Tool declarations and multi-turn continuation admission remain integration work.

Prepared calls bind the payload digest, policy/connection versions and evidence labels. They are process-issued and single-use for execution; restart requires fresh preparation. Every fixture attempt rechecks membership, enabled configuration, grants, evidence, scheduler ownership and cancellation. Revocation during I/O cancels the fixture and suppresses its results. Final authorization precedes the immutable completion audit. Cancellation or a denied in-flight call receives a conservative unknown outcome.

## Payload and destination safety

Bounded recursive redaction masks supported credential patterns, structured secret fields, cookies, private keys and common personal identifiers. Oversized, cyclic or ambiguous payloads fail. This is not a universal guarantee of removing arbitrary sensitive prose; classification remains necessary.

Local endpoints require injected resolution to safe private or loopback addresses. Public, mixed, metadata/link-local and malformed destinations fail. Each authorization freshly resolves names, compares the prepared address set and validates the endpoint and short-lived verification record. No default resolver or live network transport is installed.

Production transport must pin the verified socket destination, enforce TLS and redirect policy, and apply destination controls to all applicable endpoints. DNS validation alone does not prove the peer a future HTTP client connects to. Do not enable live execution until M04 routing and M05 budget admission are integrated, including authorization for every fallback and continuation.

## Integration order

1. M04: explicit capability-based routing and bounded approved fallback.
2. M05: atomic budget reservations, usage ledger and conservative reconciliation.
3. Production credential resolution/transport and O05 specialist integration, with fresh permission, data and budget admission for each attempt.
4. U04 policy/settings UI and M06 live provider evaluation.

See [execution checklist](EXECUTION_CHECKLIST.md) and [Claude continuation prompt](CLAUDE_HANDOFF_AFTER_M03.md). All current verification uses temporary databases, injected DNS and recorded model fixtures. No lab/provider capability is claimed verified.
