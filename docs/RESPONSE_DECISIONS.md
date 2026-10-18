# Incident response decisions

**Status: COMPLETE — scoped prototype acceptance, October 17, 2026.** See the [testing completion record](TESTING_STATUS.md) for test layers and remaining release boundaries.

## Operator controls

Every newly imported incident receives a system recommendation. The scoped console worker can also prepare a pending incident from three new authenticated lab SSH failures; that intake alone never authorizes execution. The incident **Response** tab shows its evidence, impact, target scope, capability, verification and recovery. Existing incidents can use **Prepare / refresh recommendation**. The incident Activity tab and Agents task inspector share the persisted response timeline.

- **Approve once:** record authorization for this exact proposal and queue it. Acceptance is not dispatch or verification.
- **Enable autonomy for this incident:** the reviewed action and targets only, for 30 minutes or incident closure. Default SSH limits: three failures within 120 seconds, 60-second action, 300-second cooldown, maximum three actions per authorization.
- **Reject:** required reason, terminal proposal decision, no dispatch.
- **Defer:** optional note, no dispatch; later approval remains possible while eligible.
- **Stop autonomy / queued authorization:** revoke future dispatch. Existing effects expire and remain subject to reconciliation.
- **Revise duration:** creates an immutable human-authored revision, revokes prior authorization and requires a different administrator to approve it. System-authored proposals permit one administrator to approve.

File restoration is registered as unavailable. File-integrity incidents retain readable recommendations, rejection and deferral, with execution controls disabled. No IP block is inferred from local file changes.

## API and storage

Authenticated, organization-scoped routes:

- `GET /incidents/{id}/response`: proposals, capability state, authorizations, intents and timeline.
- `POST /incidents/{id}/response/refresh`: administrator refresh from canonical evidence; no dispatch.
- `POST /incidents/{id}/response/{proposal}/decision`: exact digest, decision (`approve`, `autonomy`, `reject`, `defer`), optional note; reject requires a reason.
- `POST /incidents/{id}/response/{proposal}/revision`: exact digest and duration (30–120 seconds).
- `POST /incidents/{id}/response/stop`: revoke the incident authorization.

The browser never supplies organization identity, provider credentials, executable commands or arbitrary target parameters. Executable proposals require a trusted reader/import receipt bound to the canonical evidence hash; an operator-created source label alone does not qualify. Fixture proposal/approval tables remain isolated. New `live_response_*` tables retain proposals, decisions, authorizations, unique dispatch intents, independent observations and audit events. Closure revocation is enforced by a database trigger and does not reactivate on reopen.

## Worker and installed lab scope

Run from the repository:

```powershell
uv run python scripts/run_response_worker.py --database terminus.db --org org-terminus-demo --actor usr-LfgGy8A_O5Q --kali-management-ip 192.168.56.102
```

Enter the response API username/password and indexer password locally. Startup enables no incident authorization. Keep the existing indexer SSH tunnel open. The trusted worker uses the lab-only TLS exception; production deployment requires trusted certificates and managed credentials.

The first adapter is fixed to the tested source 10.77.0.10 and agent 001 at 10.77.0.20. A permanent console-dispatch fence prevents the old standalone controller from sending once the console worker takes ownership. Unresolved legacy effects prevent takeover. The adapter binds to one organization per database.

The worker polls every five seconds; the UI polls response state every two seconds. A complete empty collection means a healthy quiet connector, not an outage.

Autonomy reads complete authenticated Wazuh collections and links only new, fresh failures from that exact source/endpoint to one active incident authorization. Ambiguous multiple incident matches are not linked. Arbitrary event categories and unrelated incidents cannot widen authorization.

Before I/O, one writer transaction rechecks authorization, membership, incident state, evidence, target scope, cooldown, quota, replay and outstanding effects. It persists an intent first. Another worker cannot dispatch the same proposal. Unknown/interrupted sends are held for independent reconciliation; never replayed. Manager/indexer failures disable new dispatch while independent recovery checks continue. Provider acknowledgement is shown separately from verified effect and recovery.

## Read-only reconciliation after interruption

```powershell
uv run python scripts/reconcile_response.py --database terminus.db --org org-terminus-demo --actor usr-LfgGy8A_O5Q --kali-management-ip 192.168.56.102
```

This command needs verification keys and current administrator membership, not response credentials. It cannot dispatch. Missing/foreign owned state remains unresolved; recovered state without earlier independent blocking is labeled `recovered_unverified`.

## Validation

Focused tests cover decisions, current admin membership, cross-tenant HTTP access, extra command rejection, revisions/self-approval, stale evidence, revocation during baseline, closure/reopen, expiry, duplicate/concurrent workers, replay, repeat autonomy and durable quota, target correlation, offline recovery and standalone fencing. Browser fixtures cover the exact autonomy confirmation and unavailable-action rejection controls. These tests do not establish new live execution.

## October 17 live rehearsal result

Both new-service SSH response paths passed in the installed isolated lab:

- **Approve once:** incident `TICK-WAZUH-6a91e974229d7cf2e79d`, intent `47a1b9f6-3440-4a9d-98da-2adb296d5277`. Exactly one dispatch, independent active-block verification, and independent recovery.
- **Incident autonomy:** incident `TICK-WAZUH-e574fcc7056e37301060`, intent `a206ca38-829f-422a-b63d-6d6d9445d116`. Exactly one dispatch; the worker was stopped immediately after a separate observer confirmed blocking. Kernel expiry and read-only reconciliation verified recovery without redispatch.
- The actual 300-second cooldown was observed between cycles. All test authorizations were revoked afterward. Final audit at 23:59:06 UTC confirmed both owned sets empty, source SSH and management connectivity restored, and no active authorizations. The response worker is stopped; the API and VMs remain running.
- A quiet-period readiness bug was found during rehearsal: a successful empty collection was incorrectly marked unavailable. The final worker accepts complete empty collections as healthy; an integration regression proves readiness remains available without dispatching. The autonomy rehearsal resumed only after new real failures appeared; no response was sent during the quiet period.
- Full backend suite: **1,243 passed**. After the final polling-intake and quiet-collector refinements, **26 focused response tests passed**. **Nine browser checks passed**, including existing Agents operation and simulation behavior; the console production build passed.
- Live authorizations were issued by the explicitly authorized local administrator rehearsal harness through the same membership/digest/decision service. Browser confirmation and HTTP authentication/tenant restrictions were validated separately; no claim is made of a manually clicked browser-to-provider live rehearsal.
- The canonical initial events were imported by the trusted bounded reader in the live harness. Automatic pending-incident intake, repeated autonomous responses, and revised-duration carry-forward were fixture-validated; the live autonomy rehearsal executed one action before interruption.
- Evidence is saved at `~/Downloads/TERMINUS_Lab_Test_2026-10-17/response-decisions.json`. The real file-integrity response controls were also inspected in Chrome; unsupported execution remained disabled. Screenshot: `response-controls.png` in the same directory.

This validates the bounded lab adapter and decision service, not arbitrary response actions or production deployment. Existing fixture approvals, model recommendations, and historical standalone tests remain separately labeled. Implementation committed and pushed as `4afc1df`.
