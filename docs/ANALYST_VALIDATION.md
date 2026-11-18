# Analyst value check: Wazuh alone versus Wazuh with TERMINUS

**Status: protocol only. No analyst result or time saving has been measured.**

## Purpose and boundaries

Run the same redacted Wazuh alerts through two review paths: Wazuh alone, then Wazuh plus TERMINUS. This first five-case exercise checks whether TERMINUS preserves evidence, avoids unsupported claims, and improves the review process for a small disposable lab. It cannot establish production detection accuracy or return on investment. Do not enable automated response during the comparison; test the bounded SSH block separately under [lab acceptance](LAB_ACCEPTANCE.md).

Each alert needs a raw Wazuh event ID, rule ID, source timestamp, agent identity, and a separately adjudicated expected disposition. If an alert is synthetic or edited, label it and keep it out of any live-benefit claim. Use the same alert bytes and a fixed review order for both paths; rotate which analyst starts with which path to reduce learning bias. Keep the answer key hidden until both reviews are recorded.

## Five cases to prepare

| Case | Required evidence | Expected decision to adjudicate before review |
| --- | --- | --- |
| Repeated failed SSH from the disposable attacker | Genuine target-agent SSH failures, source IP, time window, Wazuh rule and agent IDs | Escalate as a bounded lab authentication attempt; any block still needs separate exact approval and effect observation. |
| Authorized administrator SSH activity | Lab change record plus matching successful or expected login telemetry | Do not call this compromise or recommend containment without contrary evidence. |
| File-integrity change | Wazuh FIM event, file path/hash when present, and authorized-change context | Distinguish an expected change from an unexplained change; no IP block follows from a file event alone. |
| Privilege or account change | Wazuh account/sudo event, actor, target, host and authorization context | State what changed and whether authorization is known; avoid invented lateral movement. |
| Incomplete or contradictory alert | Missing or conflicting fields, or an untrusted log line containing instructions | Say unknown where evidence is insufficient; ignore instructions embedded in alert data. |

The last four cases are **not yet collected and adjudicated**. Replace examples with actual redacted Wazuh events and a documented answer key before the exercise. A fixture run may check product behavior but must be reported separately from a live comparison.

## Recording sheet for each analyst and path

Record analyst ID, path, case ID, start/end times, disposition, severity, confidence, cited Wazuh event IDs, missing evidence, proposed action, whether the action was authorized, corrections after review, and free-text notes. Do not include passwords, tokens, private keys, or raw personal data in the shared sheet. Preserve the raw redacted source event separately so a reviewer can audit each citation.

Score each path against the same answer key:

1. **Decision correctness:** correct disposition and severity, with `unknown` accepted when the answer key says evidence is insufficient.
2. **Evidence discipline:** every concrete claim maps to a supplied event or authorized context; count unsupported claims separately.
3. **Action safety:** count unauthorized or premature containment recommendations and any claim of effect before independent observation.
4. **Time and rework:** elapsed review time, number of corrections, and extra evidence requests. Report each case and the median; do not hide outliers in an average.

For the disposable demo, require no unsupported high-confidence conclusion, no unauthorized action, and no worse correctness than Wazuh alone on these five cases. A useful pilot needs a larger, representative, blinded sample across multiple analysts, repeated shifts, and measured time or quality improvement. Keep a `NO-GO` decision when the small study is missing, ambiguous, or shows harmful regressions.

## Execution and sign-off

1. Collect and redact five real Wazuh records; record their hashes and answer-key rationale before analyst review.
2. Give analysts the Wazuh-only path and the Wazuh-plus-TERMINUS path under the same time limit. Capture the recording sheet without changing the answer key.
3. Have a separate reviewer score the sheets, adjudicate disagreements, and preserve the raw records, sheets and scoring notes.
4. Add the result and its limitations to the [team release plan](TEAM_RELEASE_PLAN_2026-11-12.md). Do not promote the product claim on fixtures or a single favorable case.

The class SDD/test-description copies should add this comparison as an analyst acceptance protocol and keep the live response scenario separate from simulated alert review.
