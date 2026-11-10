# Next testing session — October 18, 2026

## First priority: Rehearse and complete browser-driven SSH defense workflow

Status: open. [SCRUM-14](https://coscterminus.atlassian.net/browse/SCRUM-14) tracks the end-to-end browser rehearsal.

- [ ] Document a repeatable reset state: source commit, VM addresses and clocks, services/tunnel/worker readiness, baseline SSH connectivity, no active test authorization or blocking effect, and treatment of previous incidents and cooldowns. Preserve audit history.
- [ ] Generate controlled SSH failures from the isolated Kali source.
- [ ] Confirm TERMINUS creates the incident automatically, without a manual import or administrator harness substituting for the console flow.
- [ ] Open the investigation in the console and inspect findings and cited source evidence.
- [ ] Approve the exact temporary block in the browser.
- [ ] Observe dispatch acknowledgement and independently verified blocking as separate console states.
- [ ] Watch expiry, confirm independently verified recovery in TERMINUS, and check that source SSH connectivity returns while management remains available.
- [ ] Repeat from the documented reset state until three consecutive runs succeed. Record failures and restart the consecutive-success count after a failed run.

Acceptance: **three consecutive successful browser-driven runs from a documented reset state, with evidence saved.** Record source commit, incident/proposal/intent/task identifiers, timestamps and durations, screenshots, independent observations, results, and every manual intervention. Do not count component, fixture or CLI-approved tests as browser-driven acceptance.

## Alongside the rehearsal

- [ ] Decide and document Scenario B scope. Existing file-integrity detection and cited analysis are verified; automated file restoration remains unavailable. Agree whether recommendation-only behavior satisfies Scenario B before expanding implementation.

## After acceptance passes

- [ ] Containerize the exact working version, then validate the same workflow in the packaged deployment before release automation.

Previous scoped results remain in [testing status](TESTING_STATUS.md). Browser-driven product acceptance is a separate open gate.
