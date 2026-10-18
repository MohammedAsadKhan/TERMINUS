# Scenario A live response — completed lab handoff

**Status: COMPLETE for the bounded SSH lab and incident response-decision release, October 17, 2026.** Implementation committed and pushed as `4afc1df`. See [testing status](TESTING_STATUS.md) for the accepted scope and evidence layers.

## Verified completion

- [x] Durable live proposals, exact-digest administrator decisions, incident-scoped autonomy, intent persistence and concurrency/replay guards. Fixture approvals remain separate.
- [x] Installed root-owned nftables endpoint command and bounded Wazuh transport using `!terminus-ip-block` for agent 001 and source 10.77.0.10. No generic remote shell or automatic Wazuh rule owns the decision.
- [x] Three standalone autonomous lab cycles with independent block, management-health and recovery checks; cooldown, quota and active-controller interruption recorded in the [SSH report](LAB_TEST_RESULTS_2026-10-17.md).
- [x] One approve-once and one incident-autonomy cycle through the new decision service, independently verified expiry/recovery and interruption reconciliation without redispatch; see [response decisions](RESPONSE_DECISIONS.md).
- [x] Console decision controls, unavailable-action display, persisted activity and fixture-based permission/failure checks.

Done by — Mohammed / Codex, October 17, 2026; evidence and validation counts are linked above. Live decisions used the authorized local administrator harness; browser and HTTP validation were separate checks.

## Remaining boundaries

The lab used the existing API account. A dedicated least-privileged response account, production certificates/deployment, early undo and automated empty-table cleanup remain unverified. Kernel timeout removes the blocked address; an empty owned table may remain. Broad unattended intake and model-led multispecialist-to-response operation have not received full live acceptance. Automatic pending intake and repeat incident-autonomy behavior have fixture coverage only.

Use the [console worker and read-only reconciliation instructions](RESPONSE_DECISIONS.md) for this implementation. Console dispatch ownership fences the historical standalone controller. Do not reinterpret old fixture records as authorization or run competing dispatchers.

## Manual lab evidence

On October 6, the installed command blocked Kali 10.77.0.10 from SSH to target 10.77.0.20, preserved Windows management access, and expired after 60 seconds. The same sequence passed through the Wazuh manager API for agent 001. API dispatch uses `!terminus-ip-block` to invoke the installed script; the command declaration alone did not populate shared/ar.conf and the unprefixed name returned error 1652. These observations establish manual lab behavior, not autonomous Terminus execution. Empty-table cleanup after the API test remains to be confirmed.
