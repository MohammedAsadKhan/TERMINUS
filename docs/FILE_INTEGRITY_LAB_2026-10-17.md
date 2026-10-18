# File-integrity lab result — October 17, 2026

**Status: COMPLETE — real detection, import, cited analysis and operator test-file restoration.** Response recommendations remain reviewable; automated file restoration is unavailable. See [testing completion](TESTING_STATUS.md).

## Verified live result

Controlled, harmless file tampering on the existing Ubuntu endpoint generated **four real Wazuh events**: two additions, one modification, and one deletion. No malware or vulnerable VM was required.

- Endpoint: terminus-target-a, agent 001.
- Monitored folder: `/home/labadmin/terminus-fim-lab` with real-time syscheck enabled. Original configuration backed up beside `/var/ossec/etc/ossec.conf` before the validated change and agent restart.
- Test changes: 23:22:35–23:22:46 UTC.
- Incident: `TICK-WAZUH-d55332ae62ac35d12d03`.
- Source evidence task: `d31c5080-175a-427f-8e90-44e480511280`.
- Successful Gemini task: `15fce5ed-0504-4569-af1c-fc6bd321813f`.
- Gemini cited all four changes; 4,252 input tokens and 373 output tokens. Configured ledger cost is zero; this is not a provider billing assertion.
- The first model exchange failed with a connection reset. A second, separately recorded request succeeded. The failed attempt remains in execution history.
- Operator-authored review evidence: `f48b9fb7-19c0-470d-ade0-7661ada3bdff`. Recommendations are preserved separately from model findings and displayed as incident recommended actions.

## Recovery and limits

The operator test harness restored both harmless fixture files; this was **not an automated TERMINUS response**. Restored configuration SHA-256: `fa9a9fc3e6543c147bcb73b1e0c968e30516fb8d8d7dbcae567fe63a4c0149d9`. Monitoring remains enabled for this dedicated folder.

The current response adapter supports IP blocking only. File restoration approval and dispatch are unavailable. The review plan records `execution_enabled: false` and `approval_state: not_requested`; no successful approval or execution is claimed. Local file-change telemetry does not establish an attacker IP, ransomware, or malicious intent.

## Implementation and checks

- Added a bounded, endpoint/time/syscheck-group-scoped `file` indexer query.
- Added a separate FIM lab importer, restricted to agent identity and paths within the dedicated lab folder; partial collections and path traversal are rejected. SSH admission remains separate.
- CLI: `scripts/import_wazuh_fim_lab_incident.py` accepts database, organization, actor, and timezone-aware start/end bounds. Indexer credentials are prompted locally. Local tunnel TLS exception is limited to this lab script.
- Saved-evidence analysis objective now describes source evidence rather than assuming every incident is SSH.
- **73 focused tests passed** across source readers, both import types, and autonomous SSH regressions; Ruff checks passed.
- Machine-readable evidence: `~/Downloads/TERMINUS_Lab_Test_2026-10-17/file-integrity.json`.

Open Incidents in the console and locate the exact incident ID above; inspect Agents for the successful Gemini task. Imported real telemetry is not labeled synthetic, while the test narrative explicitly states that the file changes were controlled.
