# Terminus full defensive toolkit contracts

Approved contract-first delivery, October 4, 2026. Product authority: [PRD](PRD.md); release boundary: [MVP](MVP_RELEASE.md) and [future scope](FUTURE_SCOPE.md).

## Delivered boundary

The declarative catalog maps all 60 specialties across five areas to 93 proposed tool contracts and 48 connector candidates. Every specialty records required tool IDs, telemetry, permissions, expected evidence and acceptance checks. Exactly eight core bundles are implementation pending. No tool or connector is available for execution in this catalog.

The catalog is metadata, not an executable registry. It has no handlers, dispatcher, model calls, API routes, credential access or external effects. Existing runtime imports are unchanged. Future specialties remain Planned - Unavailable in 1.0; their exclusive tools cannot appear in core bundles. Matching a roadmap name to a core role does not activate its future capabilities. Scenario A dispatch declarations have no specialist grants.

Full mappings and remediation details: [investigation contracts](TOOLKIT_INVESTIGATION.md), [response/recovery contracts](TOOLKIT_RESPONSE.md). Machine-readable source: `src/terminus/toolkit/investigation_catalog.json` and `response_catalog.json`, assembled by `load_catalog()`. Shared models live in `src/terminus/toolkit/models.py`; `contracts.schema.json` exports their JSON schemas. All catalog references, permissions and release boundaries are validated at load time. No providers are imported by catalog loading.

## Reusable families

| Family | Intended operations |
| --- | --- |
| Incident and alerts | Detection retrieval, enrichment, deduplication, prioritization and incident scoping |
| Collection coverage | Sensor freshness, supported event types, gaps and tampering |
| Identity | Authentication, account privileges, session and credential observations |
| Endpoint | Host context, process, file, persistence and inventory evidence |
| Forensics | Stored memory, disk and browser artifact analysis |
| Network | Connections, flows, DNS, proxy, firewall, packet and wireless evidence |
| Threat investigation | Hunting, malware, ransomware, intelligence, campaigns and insider activity |
| Email | Message authentication, attachments, URLs and phishing evidence |
| Cloud and infrastructure | Cloud audit/storage, containers, Kubernetes, VM/hypervisor and serverless evidence |
| Applications | Access/error logs, API behavior, versions and host correlation |
| Software delivery | Repository, dependencies, CI/CD, supply chain, secrets and configuration |
| Data security | Database access, exfiltration, integrity and cryptography |
| Specialized environments | SaaS, mobile, IoT, OT and AI/LLM evidence |
| Response planning | Capabilities, exclusions, prerequisites and scoped proposals |
| Response execution | Approved network, endpoint, identity and infrastructure changes |
| Recovery | Eradication, backup assessment, restoration, expiry and undo |
| Verification | Independent effects, attacker connectivity, management and service health |
| Improvement and evidence | Detection/control validation, deception, timelines, citations and reports |

Use typed adapters to established collectors and analysis tools. Connector names are candidates requiring version/capability checks, not installations. Wazuh manager endpoint management and Wazuh indexer searches have separate connections/credentials. Alert history belongs to the [indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html), not an assumed manager alert endpoint.

## Shared interfaces

- `ToolDescriptor`: stable ID/version, input/output contract, role grants, connector requirements, incident scope, egress/effect classification, approval/idempotency policy and resource bounds.
- `ReadQuery`: trusted resource reference, UTC interval, named event kind and bounded pagination. Extra fields, arbitrary commands, SQL/DSL, paths and URLs are rejected.
- `ToolExecutionContext`: server-derived tenant/incident/task/run/role, grants, resources/connectors, cancellation, policy/budget references and fenced lease. Never deserialize this from a model or HTTP client.
- `ToolResult`: ok/empty/partial/unavailable/unsupported/denied/error, evidence references with hashes, provenance, event/collection timestamps, coverage, truncation and gaps. Empty requires complete coverage. Missing-source results cannot contain invented findings.
- `ToolInvocation`: audit identity, argument digest, policy decision, connector/tool version, outcome and evidence references. Unknown effects require a dispatch intent, proposal digest and idempotency key.
- `ResponseProposal`/`ApprovalBinding`: exact target IDs, parameters via immutable evidence reference, provider connection, policy version, scope, prerequisites, impact, duration, undo and verification requirements. Canonical proposal digest binds approval; changed targets/parameters, policy, expired approval or self-approval fail validation. Admin approval is the initial contract default. The server constructs scope and provider bindings, never the model.
- `VerificationReport`: provider acknowledgement cannot establish success. Verified requires separately recorded post-dispatch endpoint effect, attacker-path, management-health and service-health evidence; observations must come from a run other than the dispatch run, with distinct endpoint/attacker sources. These are validation criteria, not proof that observations are authentic; trusted collectors and persisted evidence validation remain mandatory.

Read-tool ceilings: one hour, 200 records per page, four pages, ten-second connector deadline, 64 KiB model-facing outcome. Core bundles permit at most 20 invocations per task. Exceeding collection limits returns explicit partial results. Operational exceptions need a named reviewed policy; none exist in this phase.

The `ToolContractValidator` provides non-executing fixture checks against temporary scheduler/evidence stores. It revalidates copied models, ownership, role/resource/connector grants, cancellation and result scope/hash. Evidence may be shared between tasks in the same incident; its original task/source remains recorded. Missing and foreign-incident evidence fail. This helper is not the future gateway: it does not reserve durable budgets, append invocation audits, dispatch adapters, redact arbitrary payloads or authenticate approval actors. A valid contract never constitutes permission to execute a tool.

## Future gateway and effects

The next implementation must build one immutable executable registry and gateway. Resolve trusted context from scheduler ownership and authenticated policy; expose only the intersection of installed handlers, role grants, tenant/incident resources and connector readiness. Persist evidence and invocation audit before synthesis. Apply secret redaction, data-locality checks and untrusted-evidence wrapping before model or external-intelligence egress. Enforce cumulative budgets atomically. Never silently strip tools or downgrade policy on provider failure.

Separate Copilot investigation reads from configuration-changing tools. Configuration writes require fresh server-side operator/admin authorization and audit; specialist grants cannot inherit Copilot write permissions. Existing paths are documented remediation targets, not repaired by this contract-only change.

Response planning cannot approve or dispatch. A later trusted response service must atomically validate approval expiry, protections, durable quota, cancellation and ownership, then persist one idempotent dispatch intent before external I/O. Ambiguous timeout, stale ownership after dispatch or crash goes to unknown/reconciliation, never blind replay. Approval expiry, effect duration and scheduler lease expiry are separate. Undo removes only attempt-owned resources. Acknowledgement cannot substitute for independently collected effect and legitimate-health checks.

## Build dependencies and known gaps

1. Implement the executable registry, gateway, durable invocation audit and evidence envelope using these contracts; add backend future-role rejection at every admission boundary.
2. Implement incident/coverage reads, manager endpoint context and bounded indexer authentication searches. Remove fabricated SIEM history/healthy-host fallbacks and mock reputation claims from production evidence paths.
3. Implement M01-M05 credentials, model capability, data policy and durable budgets before live AI or external intelligence. No source-tenant or credential selection by model arguments.
4. Connect eight specialist handlers and configured workflow-agent identities to real task/run IDs and immutable citations. Existing investigator citation propagation is implemented; enforced finding-to-evidence linkage remains pending.
5. Repair workflow parameter mismatches and approval expiry/bindings; implement durable quota, Scenario A connector, unknown-effect reconciliation, expiry/undo and independent verification. Current containment remains not_configured.
6. Expand application collection after target B/version/logs are selected. Promote future tools only in later releases after telemetry, permissions, rollback and live acceptance are verified.

Lab source authentication, Wazuh version/permissions and collected event types must be established this afternoon before claiming live coverage. No particular tool installation or future cloud resource is authorized by this document.

## Validation

Contract tests use temporary SQLite databases and explicit synthetic fixtures. They validate all 60 mappings, eight bundles, 18 families, reference integrity, dormant catalog state, future grant denial, hostile arguments, bounded outcomes, copied-model scope bypasses, lease/cancellation, cross-incident evidence/hash checks, restart reads, approval expiry/digest and acknowledgement-versus-independent verification. Fixture round trips are contract evidence only; they are not live investigation or response verification. Invocation persistence, timeout execution, cumulative quotas, adapters and gateway integration remain later acceptance tests.
