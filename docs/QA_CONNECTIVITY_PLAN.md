# QA connectivity follow-up

Owner: Misha Stegall (QA), with the connector and lab owners. This is the next verification goal after the local synthetic walkthrough. A green settings control, saved credential, fixture test, or incident created from a sample payload is not enough to mark a live connection verified.

| Path | First real check | Evidence required for a pass | Checklist gate |
| --- | --- | --- | --- |
| Wazuh → Terminus | Deliver a real, versioned lab SSH event through a source credential bound to one organization. | Wazuh event ID and raw log, authenticated receipt, same incident/source fields in the console, duplicate/replay and wrong-tenant rejection. | L03, A01, A02 |
| Terminus → model | Run an incident task through the configured provider or local endpoint. | Provider request/response status, schema/tool result, model/version, usage record, saved evaluation, timeout and denied-policy results. | M06, O05 |
| Incident → specialists | Start the scheduler and run a task against real incident evidence. | Durable task/run IDs, cited source evidence, actual tool result or explicit gap, restart recovery, no duplicate consequential work. | O05, U02, Q02 |
| Notifications | Send a controlled test to each configured channel. | Remote delivery receipt or visible message, failure/timeout state, correct organization and incident reference. | Q01, U05 |
| Approved response → endpoint | In the isolated lab, approve a scoped response after the source event is verified. | Bound approval, dispatch record, endpoint effect, attacker reachability check, management health, expiry/undo and independent recovery proof. | A03–A07, Q01–Q03 |

For each run, record the commit, target/version, configuration with secrets redacted, timestamps, expected result, observed result, IDs, screenshots/log references, and retest outcome in the [QA exploration evidence log](QA_LOCAL_EXPLORATION.md). Run negative cases and repeat the complete scenarios before presentation claims are upgraded from local/fixture to live.
