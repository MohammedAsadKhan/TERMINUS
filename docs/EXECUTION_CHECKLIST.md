# Terminus team execution checklist

Planning baseline: October 3, 2026. Read [PRD](PRD.md) and [MVP scope](MVP_RELEASE.md) before implementation. These boxes start unchecked: earlier tests and source files do not establish completion of the new release requirements.

## Working rules

Team implementation tasks are up for grabs. Role labels describe relevant expertise, not reserved assignments. Mohammed retains the agreed PM, local-lab and AWS responsibilities; teammates may claim supporting implementation work. A claimed task has one accountable teammate, dependencies, a linked change and verification evidence. Use statuses `not started`, `in progress`, `blocked`, `in review`, `verified`; checkboxes mean verified. Never place API keys in this document.

Task record: `ID | claimed by | agent/tool | status | dependencies | issue/PR/commit | verification | blocker`. This checklist is the shared completion record. Architecture changes require updating PRD/MVP and the decision log before dependent work proceeds.

## Instructions for teammates and their coding agents

1. Read the PRD, MVP scope, this checklist and applicable repository instructions before choosing work. Select an unclaimed task with satisfied dependencies. Ask the teammate for their name if it is not known; do not invent their identity.
2. Before editing implementation files, add a claim to the table below: task ID, teammate name, agent/tool, date and `in progress`. Share that claim through the team's normal collaboration process so others see it. Check current claims before starting; a local document edit is not a distributed lock. Resolve conflicting claims with the teammates instead of duplicating work.
3. Stay within the task's scope and agreed contracts. Record blockers rather than bypassing dependencies or changing acceptance criteria. Supporting subtasks can be claimed separately if their boundaries are documented.
4. Complete the task and its stated acceptance checks. Preserve existing behavior, run appropriate validation and attach concrete evidence. Do not mark a real lab/provider requirement complete using only mocks, a file's existence or an untested agent claim.
5. When verified, change that task's checkbox from `- [ ]` to `- [x]` and append `Done by - <teammate name> | Agent - <agent/tool> | Date - YYYY-MM-DD | Change - <PR/commit or file reference> | Verified - <checks and evidence reference>` to the task entry. Update its claim-table status to `verified`.
6. If unfinished, leave the checkbox unchecked and record `in progress` or `blocked`, remaining work and the blocker. If a verified task later fails, reopen it and record why, preserving the earlier completion note.
7. Update this document in the same change as the implementation so completion is reviewable. Do not push, merge, provision cloud resources, run attacks or use credentials solely because this checklist mentions them; follow the human teammate's authorized scope and environment instructions.

Completion example (format only; does not complete any real task):

```text
- [x] TASK-ID Task description and acceptance criteria. Done by - Teammate Name | Agent - Tool Name | Date - YYYY-MM-DD | Change - PR link | Verified - Test results and evidence link
```

### Shared task claims

Add one row per claimed task. Re-read the current shared version before claiming work. All unlisted team implementation tasks remain available.

| Task ID | Claimed by | Agent or tool | Claimed date | Status | Change and verification | Blocker or handoff |
| --- | --- | --- | --- | --- | --- | --- |
| P02 | Mohammed | Codex orchestrator and GPT-6 Luna audit | 2026-10-03 | verified | [Architecture audit](ARCHITECTURE_DECISIONS.md) reviewed against source | Remaining integration gaps recorded |
| P03 | Mohammed | Codex orchestrator and GPT-6 Luna contracts | 2026-10-03 | in progress | Durable entity contract | Broader model/usage API contracts remain planned |
| P04 | Mohammed | Codex orchestrator | 2026-10-03 | in progress | Single-host storage decision | Scheduler foundation verified as O03; secret/source-auth implementation deferred |
| O01 | Mohammed | Codex orchestrator and GPT-6.1 Sol implementation agents | 2026-10-03 | in progress | Storage/citation foundation verified as O01a | Canonical finding-to-evidence linkage remains with A02; no scheduler or lab actions |
| O01a | Mohammed | Codex orchestrator, GPT-6.1 Sol implementation/review | 2026-10-03 | verified | 173 isolated tests passed, including 24 new checks | Internal repository foundation; public task API and execution remain pending |
| A02a | Mohammed | Codex orchestrator, GPT-6.1 Sol implementation/tests, GPT-6 Luna audit | 2026-10-03 | verified | Canonical SQLite service integration; 188 isolated tests pass | Live Wazuh payload and lab verification remain A01/A02 |
| O02 | Mohammed | Codex orchestrator, GPT-6.1 Sol auth/org storage and GPT-6 Luna API checks | 2026-10-03 | verified | 210 tests pass; durable server identity, sessions and hosted bootstrap | Live AWS deployment remains C03; daily report history remains temporary |
| O03 | Mohammed | Codex orchestrator, GPT-6.1 Sol scheduler storage/runtime and GPT-6 Luna review | 2026-10-04 | verified | Dedicated-process SQLite scheduler, authenticated task inspection/control; 267 isolated tests pass | No specialist/model/response handlers added; held actions require future reconciliation adapters |

| O04 | Mohammed | Codex orchestrator, GPT-6.1 Sol core/API and GPT-6 Luna review | 2026-10-04 | verified | Main/lazy-area coordination, scoped HTTP task tree and help bookkeeping; 312 isolated tests pass | Live specialist/model/response execution remains O05/M01-M06/A03-A05 |

| T01 | Mohammed | Codex orchestrator, GPT-6.1 Sol investigation/response contracts and GPT-6 Luna review | 2026-10-04 | verified | Full toolkit schemas, 60-specialty catalog; 336 isolated tests pass | No adapters, runtime grants or live tools enabled |
| T02 | Mohammed | Codex orchestrator, GPT-6.1 Sol registry/gateway/audit agents and GPT-6 Luna review | 2026-10-04 | verified | Read-only registry/gateway, durable quota/audit and fenced evidence; 421 isolated tests pass | Production adapters, authenticated context wiring, model budgets and live defense remain pending |
| T03 | Mohammed | Codex orchestrator, GPT-6.1 Sol reader/context agents and GPT-6 Luna fallback cleanup/review | 2026-10-04 | verified | Five internal readers, durable trusted policies and honest fallbacks; 517 isolated tests pass | M01/M03/M05 next; live lab and O05 specialist integration remain pending |

## Phase 0 Scope and contracts

- [x] T03 Implement bounded investigation readers and trusted context wiring; remove fabricated history/host/reputation fallbacks. Done by - Mohammed | Agent - Codex orchestrator, two GPT-6.1 Sol implementation agents and GPT-6 Luna cleanup/review | Date - 2026-10-04 | Depends - T02,O02,O03 | Change - [readers and handoff](INVESTIGATION_READERS.md) | Verified - 517 tests against temporary databases; separate manager/indexer credentials, bounded queries, server-derived membership/policy/resource grants, revocation during I/O and before final audit, foreign/stale/missing telemetry denial and honest offline reputation. Targeted Ruff/type checks passed. No public execution API, model egress, real specialist handlers or live response enabled. Next: claim M01 named credentials, then M03 data/role policy and M05 financial budgets; UI work can proceed with coordinated interfaces. Lab validation remains L01-L05/A01-A02.

- [x] T02 Implement the read-only executable registry, permission gateway, fenced evidence writer and durable invocation quota/audit. Done by - Mohammed | Agent - Codex orchestrator, GPT-6.1 Sol registry/gateway/audit agents and GPT-6 Luna review | Date - 2026-10-04 | Depends - T01,O03 | Change - [tool execution foundation](TOOL_GATEWAY.md) | Verified - 421 tests passed against a temporary database, including 109 toolkit checks (85 added); targeted Ruff and diff checks passed. Concurrent/restart quotas, immutable audit, strict arguments, read-data/evidence bindings, deadline/cancellation and late/stale publication tested. No production adapter, public gateway API, model egress or response action enabled; authenticated context wiring, live telemetry and financial budgets remain separate work.

- [x] T01 Define full defensive toolkit contracts and validation fixtures. Done by - Mohammed | Agent - Codex orchestrator, two GPT-6.1 Sol contract agents and GPT-6 Luna review | Date - 2026-10-04 | Change - [toolkit contracts](TOOLKIT_CONTRACTS.md), packaged catalogs, schemas and fixture validators | Verified - 336 tests passed using a temporary database, including 24 toolkit checks; targeted Ruff and diff checks passed. All 60 specialties, 18 families and eight core bundles mapped. Contract-only: no executable adapters, runtime grants, model calls or response actions enabled; lab and production gateway checks remain pending.

- [ ] P00 Confirm presentation date and team availability. Owner: Mohammed. Exit: actual date and allocated capacity recorded; readiness target rechecked.
- [ ] P01 Ratify PRD, eight core roles including Application & API Security Analyst, gates and exclusions. Owner: Mohammed + technical lead. Depends: P00. Exit: reviewed baseline and agreed claim process; tasks remain available for teammates to claim.
- [x] P02 Map current routes to stores and live integration paths. Owner: backend lead. Exit: findings for Wazuh payload/API boundaries, canonical incident IDs, identity and current workflow tools. Done by - Mohammed | Agent - Codex orchestrator and GPT-6 Luna | Date - 2026-10-03 | Change - [architecture audit](ARCHITECTURE_DECISIONS.md) | Verified - source review of dependency wiring, routes, Wazuh adapter and workflow runtime.
- [ ] P03 Agree schemas for task/run/evidence/help request/model connection/usage/action attempt and public API states. Owner: technical lead. Depends: P01,P02. Exit: schema examples and ownership/idempotency rules reviewed by backend/frontend.
- [ ] P04 Record scheduler topology, limits, storage, secret management and source-auth decisions. Owner: technical lead. Depends: P03. Exit: durable recovery plan and bounded execution contract; no competing schedulers by accident.

## Phase 1 Your first local execution tasks

- [ ] L01 Keep existing Kali; import official Wazuh OVA (8 GB/4 vCPU/50 GB); create Ubuntu Server target A (2 GB/2 vCPU/25 GB). Owner: Mohammed. Exit: machine inventory and versions recorded. Confirm host performance; no need to reinstall Kali.
- [ ] L02 Create internal `terminus-lab` attack/telemetry network and separate host-only management path. Kali uses lab network; Wazuh/targets have required management connections. Owner: Mohammed. Depends: L01. Exit: addressing table, route checks, management exclusions; no target bridging or interface forwarding. Temporary update access disconnected for attack rehearsal.
- [ ] L03 Install/enroll Wazuh endpoint agent; configure actual SSH auth-log collection. Owner: Mohammed + SIEM owner. Depends: L02. Exit: target connected and a real failed-login event visible in Wazuh.
- [ ] L04 Snapshot clean and monitoring-configured states; record restore procedure. Owner: Mohammed. Depends: L03. Exit: restore tested; unique endpoint identities and clocks remain correct.
- [ ] L05 Set up dedicated lab accounts/fake data and an independent management check. Owner: Mohammed. Depends: L02. Exit: attacker and administrator paths distinguishable; response cannot target management addresses.

## Phase 2 Thin live defense A

- [ ] A01 Authenticate Wazuh alert delivery and normalize real lab payloads. Owner: backend/SIEM lead. Depends: L03,P03. Exit: source IP, endpoint ID, rule/time/evidence preserved; tenant derived from credential; schema and negative tests pass.
- [ ] A02 Make incident identity/evidence linkage durable across ingestion, workflow and UI. Owner: backend lead. Depends: A01,P03. Exit: same incident ID across records; duplicate alert yields explicit single ownership.
- [x] A02a Unify current server incident storage and verify canonical IDs through API, workflow, claims, graph and task/evidence admission. Owner: Mohammed. Scope: isolated integration tests; live lab payload validation remains A01/A02. Done by - Mohammed | Agent - Codex orchestrator, GPT-6.1 Sol implementation/tests and GPT-6 Luna audit | Date - 2026-10-03 | Change - incident repository, server dependencies, pipeline/workflow linkage and [database notes](DATABASE_STATUS.md) | Verified - 188 tests passed using temporary databases, including concurrent admission, legacy upgrades, restart/API reads/actions, duplicate replay, failed investigation retry, tenant denial, canonical task/evidence references and mocked Jira uncertain export handling. Targeted lint and diff checks pass; no live SIEM/provider validation claimed.
- [ ] A03 Implement scoped action proposal and approval binding; protected target checks. Owner: response lead. Depends: P03,L05,A02. Exit: altered target/expiry invalidates approval; denial produces no dispatch.
- [ ] A04 Implement Wazuh-backed temporary IP-block connector for the installed version. Owner: response lead. Depends: A03. Exit: actual endpoint response evidence, timeout/unknown state handling, least-privileged credentials; no generic remote shell.
- [ ] A05 Verify block, management health, expiry and explicit undo independently. Owner: QA/response lead. Depends: A04. Exit: endpoint rule evidence plus attacker connectivity result and successful restore; acknowledgement alone fails gate.
- [ ] A06 Rehearse thin A before orchestration expansion. Owner: Mohammed + QA. Depends: A05,L04. Exit: real detection-to-approved-response timeline; Wazuh automatic response does not preempt Terminus.

## Phase 3 Parallel work after contracts

### Backend orchestration and persistence lane

- [ ] O01 Add migrations/repositories for durable tasks, agent runs, evidence, help requests and action attempts. Preserve currently dropped investigation citations through report/storage/UI. Owner: backend lead. Depends: P04. Exit: upgrade preserves existing records; schema tests use isolated databases; every cited finding resolves to source evidence.
- [x] O01a Implement and verify O01's internal storage and citation-preservation foundation. Authorized foundation boundary is recorded in [architecture decisions](ARCHITECTURE_DECISIONS.md); full P03/P04 and canonical citation-to-evidence integration remain pending. Done by - Mohammed | Agent - Codex orchestrator and GPT-6.1 Sol implementation/review agents | Date - 2026-10-03 | Change - `src/terminus/orchestration/`, additive database schema and citation propagation | Verified - 173 tests passed using a temporary database; 24 new checks cover legacy upgrades, tenant isolation, restart persistence, CAS/idempotency contention, audit rollback, JSON validation and citation round trips/API responses. No live lab or provider validation claimed.
- [x] O02 Wire durable users/memberships/incident history and configured hosted admin/session lifecycle. Owner: backend lead. Depends: P02. Exit: actual service-path restart and tenant denial tests; no fixed hosted demo credentials. Done by - Mohammed | Agent - Codex orchestrator, GPT-6.1 Sol storage/peer review and GPT-6 Luna API tests | Date - 2026-10-03 | Change - auth/org SQLite adapters, session migration, server dependencies and deployment settings | Verified - 210 isolated tests pass, including fresh-service auth/org/session recovery, durable revocation/expiry, membership removal/role denial, concurrent registration/last-admin/seat guards, legacy user preservation, nested bootstrap rollback, stable local license signer and hosted rejection of imported demo accounts. Targeted lint and diff checks pass. Actual AWS deployment is still unverified.
- [x] O03 Implement scheduler claims/leases/heartbeats, priority, bounded concurrency, cancellation and retry. Owner: orchestration lead. Depends: O01. Exit: two claimers cannot own one task; stale work recovers; uncertain action reconciled before retry. Done by - Mohammed | Agent - Codex orchestrator, GPT-6.1 Sol implementation and GPT-6 Luna review | Date - 2026-10-04 | Change - [durable scheduler](SCHEDULER.md), dedicated CLI and authenticated task endpoints | Verified - 267 tests passed against temporary SQLite databases; targeted lint passed. Uncertain or previously dispatched failed work is held without automatic replay; response reconciliation adapters remain future work. No live specialists, providers or lab actions claimed.
- [x] O04 Implement main and lazy area coordinators with objective/result contracts. Owner: orchestration lead. Depends: O03,P03. Exit: five areas supported logically; unnecessary areas/model calls not created. Done by - Mohammed | Agent - Codex orchestrator, GPT-6.1 Sol core/API and GPT-6 Luna review | Date - 2026-10-04 | Change - [coordination contracts and operations](COORDINATION.md), coordination service/models/API and scheduler CLI | Verified - 312 tests passed using temporary SQLite databases; targeted lint and diff checks passed. Actual scheduler tests cover single-worker main-to-area-to-specialist execution, persisted fixture evidence/results, restart recovery, atomic retry fanout, lease/cancellation fences and bounded help. All five areas supported with unavailable specialties shown as gaps. No live AI, specialist tools, incident closure or lab defense claimed; richer O06 policy remains pending.
- [ ] O05 Implement eight specialists with role-scoped real tools and actual configured-agent resolution; connect workflow AI nodes to recorded specialist runs. Owner: investigation lead. Depends: O04,A02. Exit: each role has fixture and lab evidence tests; missing telemetry returns explicit gaps; seeded status labels or prompts cannot substitute for execution.
- [ ] O06 Add structured collaboration and help-request admission. Owner: orchestration lead. Depends: O05. Exit: useful peer task shares evidence; duplicate/unbounded delegation rejected; cross-area ownership visible.

### Model gateway lane

- [ ] M01 Build named credential/connection registry, secret protection and masked settings. Owner: model/backend lead. Depends: P03,P04. Exit: multiple keys supported, tenant/role access tested, no credential leakage.
- [ ] M02 Add OpenAI-compatible/OpenRouter/direct DeepSeek/local endpoint and Anthropic/Gemini adapters. Owner: model lead. Depends: M01. Exit: provider-specific tool/structured-output contracts tested; configurable catalog contains all agreed families.
- [ ] M03 Implement permission/data-locality/redaction checks before every call/fallback. Owner: model/security lead. Depends: M02. Exit: local-only evidence cannot reach hosted provider; unapproved connection denied; private endpoint verified.
- [ ] M04 Implement capability-based explicit routing and bounded approved fallback. Owner: model lead. Depends: M03. Exit: task model/rationale/provenance recorded; unsupported tools excluded; no silent scripted fallback.
- [ ] M05 Add atomic budget reservations, usage ledger and reconciliation. Owner: model/backend lead. Depends: M04,O01. Exit: concurrent requests cannot exceed admission budget; unknown cost is labeled; retry/key use cannot bypass org limits.
- [ ] M06 Evaluate configured models on incident tasks; record live versus contract-only coverage. Owner: model lead + QA. Depends: M05,O05. Exit: selected demo models pass real schemas/tools; missing credentials recorded; available local endpoint verified if configured.

### Frontend lane

- [ ] U01 Build activity tree/list against task API with queued/running/waiting/failed/cancelled/completed states. Owner: frontend lead. Depends: P03. Can use labeled development fixtures until O01/O03 integration. Exit: task identities, parents, endpoint and timestamps visible.
- [ ] U01a Display the full [60-specialty future catalog](FUTURE_SCOPE.md) with explicit Planned - Unavailable in 1.0 status for future specialties. Owner: frontend/backend leads. Depends: U01. Exit: disabled launch/enable/assignment controls, backend denial of future-role scheduling/help/workflow/model-tool activation, and no fabricated availability or activity. Display metadata remains separate from the eight-role executable catalog.
- [ ] U02 Show tool activity, cited evidence, findings, model/usage and help requests. Owner: frontend lead. Depends: U01,O05,M05. Exit: actual records drive display; no internal chain-of-thought or invented events.
- [ ] U03 Integrate scoped approval and response execution/verification states. Owner: frontend lead. Depends: U01,A05. Exit: denied/expired/unknown/not-configured states understandable; status cannot imply verified success prematurely.
- [ ] U04 Add admin model settings and endpoint capability/health states. Owner: frontend lead. Depends: M01,A01. Exit: secrets masked; inventory distinct from connected/protected devices.
- [ ] U05 Verify reconnection, error paths, keyboard access and existing routes. Owner: QA/frontend lead. Depends: U02,U03,U04. Exit: durable catch-up after disconnect, production build, browser regression evidence.

## Phase 4 Main showcase B

- [ ] B01 Select one exact service version, known lab exploit and observable behavior; confirm instrumentation supports it. Owner: Mohammed + investigation/SIEM leads. Depends: A06. Exit: pinned target/exploit record and evidence-to-response mapping; no unsupported legacy endpoint assumption.
- [ ] B02 Build disposable target B (starting 4 GB/2 vCPU/30 GB), enroll sensor and collect application/process/file/network evidence as needed. Owner: Mohammed + SIEM owner. Depends: B01. Exit: actual expected events visible and reset snapshot verified.
- [ ] B03 Demonstrate controlled exploit and harmless follow-on activity with lab accounts/fake data. Owner: Mohammed + QA. Depends: B02. Exit: timestamped observed behavior; no claim of detection until rule verified.
- [ ] B04 Add required detection and specialist tools; enable application specialist if evidence needs it. Owner: investigation/SIEM lead. Depends: B03,O06. Exit: source-linked findings and meaningful cross-specialty help request.
- [ ] B05 Select and implement action that interrupts observed behavior. Owner: response lead. Depends: B04,A05. Exit: existing shell/local persistence cannot be claimed stopped solely by initial-source IP block; action and rollback tested.
- [ ] B06 Integrate complete B and independently verify service health, stopped behavior and reset. Owner: QA + Mohammed. Depends: B05,U05,M06. Exit: complete incident/task/action evidence package.
- [ ] A07 Integrate tracked agents/model gateway into A. Owner: QA + orchestration lead. Depends: O06,U05,M06,A06. Exit: A no longer only a thin connector rehearsal; full release flow verified.

## Phase 5 Your AWS execution tasks

- [ ] C01 Verify account plan, allowed instance types, credit balance/expiry and region; estimate compute/storage/network/AI spending separately. Owner: Mohammed. Depends: P01. Exit: proposed cost and reserve approved before provisioning; no automatic plan upgrade assumption.
- [ ] C02 Define private lab networking and protected operator access, endpoint/management exclusions and secure secrets. Owner: Mohammed + technical lead. Depends: C01,P04. Exit: reviewed diagram/address plan; vulnerable services not publicly exposed.
- [ ] C03 Reproduce versioned local deployment on AWS using documented configuration and persistent storage. Owner: Mohammed. Depends: A07,B06,O02,C02. Exit: identity/data survive tested restart, same source revision, correct model and Wazuh connectivity.
- [ ] C04 Create and test lab start/stop, health, backup/restore and cleanup procedures. Owner: Mohammed. Depends: C03. Exit: stopped compute confirmed; retained disk/IP/network costs listed; no credentials in scripts or repo.
- [ ] C05 Rehearse A and B through the presentation access path. Owner: Mohammed + QA. Depends: C04. Exit: remote end-to-end evidence and credible latency measurements; desktop RDP and recording contingency documented.

## Phase 6 Release gates and packaging

- [ ] Q01 Test duplicate alerts/tasks, denied/expired approval, cross-tenant access, provider timeout, missing connector, malformed output, budget exhaustion and task cancellation. Owner: QA. Depends: A07,B06. Exit: negative-case results linked; no duplicated consequential action.
- [ ] Q02 Test restart during investigation and around response dispatch; reconcile uncertain outcomes and recover durable work. Owner: QA/backend lead. Depends: O02,A07,B06. Exit: no accepted work silently lost; no blind response replay.
- [ ] Q03 Run three consecutive reset rehearsals for each mandatory scenario locally and on AWS. Owner: QA + Mohammed. Depends: C05,Q01,Q02. Exit: six successful runs per environment; timings/evidence recorded, all blockers resolved.
- [ ] Q04 Verify clean installation and setup configuration; update source ZIP, prebuilt UI, DOCX/PDF manual and runbook. Owner: delivery/QA lead. Depends: Q03. Exit: fresh extraction works; secrets/databases excluded; manuals inside ZIP and version stated.
- [ ] Q05 Record clearly labeled fallback demonstration; prepare architecture and incident timeline presentation. Owner: Mohammed. Depends: Q03. Exit: recording usable without remote access; live-versus-recorded distinction explicit.
- [ ] Q06 Freeze features and sign off MVP gates by provisional November 10 target. Owner: Mohammed + technical/QA leads. Depends: Q04,Q05. Exit: exact commit, known issues, scenario evidence and approved presentation claims.

## Gated extensions

- [ ] X01 SYN-flood extension: choose sensor/metrics, bounded rate/duration, supported mitigation and independent recovery checks. Owner: network/QA lead + Mohammed. Depends: Q03 and PM capacity approval. Exit: controlled lab traffic affects no unrelated systems; real telemetry and mitigation proof. No unconditional flood-resistance claim.
- [ ] X02 Optional Windows/Atomic Red Team scenario: reviewed selected tests, telemetry and reversible response. Owner: endpoint/QA lead. Depends: Q06 and PM approval. Exit: actual detection/response/cleanup proof; does not delay A/B.
- [ ] X03 Native Watcher and remaining specialist catalog. Status: deferred; no implementation in this release without rebaseline.

## Decision and ownership register

| Decision | Owner | Current status |
| --- | --- | --- |
| Presentation date and actual capacity | Mohammed | Pending |
| Backend/orchestration/model/frontend/response/SIEM/QA task claims | Team | Up for grabs; record claimant before work; roles may be combined |
| A target | Mohammed | Ubuntu Server 24.04 proposed; confirm installed version |
| B service, exploit, telemetry and action | Mohammed + technical lead | Pending |
| Scheduler process topology and measured limits | Technical lead | Dedicated Python/asyncio process with SQLite leases implemented; defaults 4 global / 2 per organization |
| Credentials, encryption and data retention | Technical lead + Mohammed | Pending |
| Models, role pools, spend limits and evaluation cases | Model lead + Mohammed | Pending; full catalog retained |
| AWS plan eligibility, sizes, cost and protected access | Mohammed | Pending; no resources authorized by this document |

Update this register when a choice is made, including date, rationale and affected requirement IDs. Keep unresolved choices visible rather than substituting assumptions into implementation.

October 4 scope update: Mohammed included the Application & API Security Analyst (`application_api`, `applications_data`) in the default core catalog. Done by - Mohammed | Agent - Codex | Change - coordination catalog and PRD/MVP role requirements | Verified - 47 coordination/API/CLI tests passed using temporary SQLite databases; targeted lint passed. Real specialist implementation and lab verification remain unchecked under O05.

October 4 future-scope update: Mohammed approved the 60-specialty defensive roadmap for display only in 1.0. Full catalog and activation gates are recorded in FUTURE_SCOPE.md; actual display and backend-boundary verification remain unchecked under U01a.
