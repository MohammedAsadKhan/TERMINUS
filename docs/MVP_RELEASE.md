# Terminus first release scope

Planning baseline: October 3, 2026. Product authority: [PRD](PRD.md). Work tracking: [execution checklist](EXECUTION_CHECKLIST.md). Provisional readiness target: November 10, pending presentation confirmation.

## Release promise

An analyst can watch Terminus assign specialist investigations for a real lab alert, inspect evidence, approve a response, and independently verify the result. The same application version demonstrates scenarios A and B locally, then on AWS. Hosting and provider setup alone do not satisfy the release.

## Required vertical slices

| Slice | Must deliver | Exit evidence |
| --- | --- | --- |
| 1 Authentic detection | Kali to Ubuntu SSH activity, Wazuh endpoint collection and detection, authenticated Terminus ingestion | Source IP, endpoint identity, timestamps and original event visible; malformed/duplicate inputs handled |
| 2 Durable work | Main/area planning, persistent tasks, bounded scheduler, shared evidence, eight core specialist roles | Actual tool results and tracked help request; queue ownership, restart and cancellation tests |
| 3 Model control | Multiple named connections/keys, provider catalog, role permissions, routing, data policy, budget ledger | Provider contract tests; blocked egress never dispatches; local-only task stays private; budget reservations prevent concurrent overrun |
| 4 Visible orchestration | Task tree/activity view, provenance, findings, queue and error states | Browser rehearsal matches durable run records; reconnect and failures shown truthfully |
| 5 Verified defense A | Scoped proposal, human approval, Wazuh-backed temporary IP block, expiry/undo, independent verification | Attacker path blocked; protected management works; response evidence and reset recorded |
| 6 Verified defense B | One exact exploit/service combination, necessary telemetry, specialists, scoped response | Complete attack/investigate/respond/verify/reset loop; application specialist enabled if required |
| 7 Delivery | Actual identity and operational persistence, setup corrections, secure configuration, AWS deployment and runbook | Clean install, restart, backup/restore, remote rehearsal, version parity and cost/start-stop evidence |

## Toolkit contract baseline

Follow the [full defensive toolkit contracts](TOOLKIT_CONTRACTS.md) before implementing specialist tools. The catalog specifies capabilities without registering executable handlers. The eight core bundles remain implementation pending; future-exclusive tools cannot be enabled in 1.0. Fixture and schema checks do not establish live telemetry or successful defense.

## Provider acceptance contract

Implement the configuration and adapter interfaces for OpenAI, Anthropic, Gemini, OpenRouter, direct DeepSeek/OpenAI-compatible vendors, and local/private endpoints. Provider absence does not block configuring others. Each configured model must support the task's schemas/tools or be excluded from that task.

Live evaluation uses the credentials available to the team and records exactly which provider/model was tested. Automated protocol tests for an unconfigured adapter are not a live-verified claim. Core live-demo AI tasks require an evaluated model; scripted mode is a labeled backup. Do not reduce the agreed catalog to two providers or assume every model supports identical tool semantics. If live validation of a provider is blocked by credentials, record it as unverified and obtain a scope decision rather than silently claiming support.

## MVP specialist tasks

| Role | Required useful output |
| --- | --- |
| Triage | Incident scope and escalation grounded in detection evidence |
| Identity | Targeted users and supported failed/successful authentication findings |
| Endpoint | Relevant host events, process/file observations where collected, and explicit gaps |
| Network | Source/destination and service observations from available telemetry; no inferred packet visibility |
| Response planner | Scoped action with target justification, exclusions, expiry and undo |
| Verification | Independent post-action checks and legitimate-service/management health |
| Evidence/reporting | Source-linked timeline, disagreements, provenance and outcome; cannot substitute for missing specialist collection |
| Application/API security | Application/API request and log findings, vulnerability context and source-linked evidence; explicit gaps when telemetry is unavailable |

Agents do not need to run for every alert. Parallel execution is justified by independent work; sequential dependencies are visible. The five area orchestrators are logical coordination boundaries, not five mandatory model calls. Routine scheduling and enforcement remain software.

## Future catalog display

The [60-specialty roadmap](FUTURE_SCOPE.md) may be displayed in 1.0. Future specialties must be labeled Planned - Unavailable in 1.0 and cannot be enabled, launched, assigned, scheduled or granted model/tool access. Enforce this server-side as well as through disabled UI controls. Keep display-only definitions separate from the eight-role executable catalog. Core roles remain implementation pending until their real capabilities are verified.

## Scope protections

- Preserve existing incident, Copilot, report, agent, workflow, asset, organization and settings behavior unless an approved requirement changes it.
- Inventory remains truthful: manually registered assets are not protected until an active sensor/connector establishes capability.
- Keep SQLite on one supported host for this release; serialize/constrain writes and prove recovery. A database migration needs an explicit decision.
- Do not implement a native endpoint Watcher, activate the future specialties, add Kubernetes, or host local GPU models in AWS just for architectural appearance.
- SYN flooding is gated on passing A and B and available time/network telemetry. C is optional after core release gates.
- A provider outage or response failure is a visible state, never a fabricated success or silent scripted substitution.

## Calendar and critical path

| Provisional window | Milestone |
| --- | --- |
| October 3-9 | Ratify requirements/owners; local lab; real alert reaches Terminus |
| October 10-16 | Thin approved response A works; durable task/model contracts and identity fixes underway |
| October 17-23 | Tracked specialists, gateway controls and activity view integrated; A rehearsal |
| October 24-30 | B exploit/telemetry/response proven; model/tenant/recovery validation |
| October 31-November 6 | AWS parity, clean install, full rehearsals, contingency recording |
| November 7-10 | Feature freeze, gate fixes, presentation readiness |

This is a proposed sequence, not a capacity estimate. Implementation tasks are up for grabs; follow the claim and `Done by -` instructions in the execution checklist. Rebaseline after task claims and lab/API findings. Prove the thin real-response path early to reduce connector risk before finishing orchestration polish.

Critical path: real lab evidence -> authenticated ingestion -> scoped response connector -> verified A -> B selection and telemetry -> verified B -> AWS parity -> release rehearsals. Task/persistence, model gateway and frontend can proceed in parallel only after contracts are agreed.

## Release sign-off

The internal [read-only tool foundation](TOOL_GATEWAY.md) is implemented with explicit installation, role/scope/lease checks, durable invocation quotas/audit and fenced evidence. No production adapters or live specialist/model/response paths are enabled by this foundation; these remain release gates.

PM and technical/demo owners sign off only when mandatory slices pass. Record commit, environment/version, test evidence, known issues and exact scenario steps. Both mandatory scenarios pass three reset runs; denial, duplicate, timeout, missing connector and restart behavior pass. Source ZIP contains source, prebuilt UI and installation manual in DOCX/PDF. No secrets, live databases or unlabelled mock results are submitted.

If a mandatory scenario cannot pass by the freeze date, the PM explicitly changes the release promise and presentation claims. Do not downgrade live defense to simulation without calling out that scope change.
