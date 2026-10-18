# Lab testing evidence — October 17, 2026

**Status: COMPLETE — standalone autonomous SSH lab acceptance.** The later [console decision-service rehearsal](RESPONSE_DECISIONS.md) adds two separately recorded cycles; [file-integrity testing](FILE_INTEGRITY_LAB_2026-10-17.md) also passed. See [overall scoped completion](TESTING_STATUS.md).

Scope: isolated Scenario A SSH defense. Real Wazuh observations and real nftables effects are kept separate from fixture tests and presentation simulations.

## Live baseline

- Kali attack address 10.77.0.10; host-only management 192.168.56.102.
- Ubuntu target 10.77.0.20 / management 192.168.56.103; agent 001.
- Dedicated verification key works on both guests with strict host-key checking.
- Ubuntu read-only nftables inspection works without password prompts.
- Kali can reach target SSH; Windows management SSH works.
- VM UTC clocks agreed within about one second at 22:57 UTC.

## Autonomous run 1

- Policy enabled at 22:59:26 UTC for 30 minutes; fixed Kali source and agent 001; three distinct failures within 120 seconds; 60-second block; five-minute cooldown; three-action durable quota.
- One failed connection from Kali was observed at 22:59:50 UTC. While below threshold there was no intent and Kali SSH remained reachable.
- Two more failures were observed at 23:00:18 UTC. The authenticated indexer returned all three source events.
- Canonical incident: `TICK-WAZUH-70611a7d4f3426c3dd1a`.
- Intent: `9875d09a-26ba-4695-b4d1-caa2c254ea26`.
- Durable in-flight intent at 23:00:36.535 UTC, manager acknowledgement at 23:00:36.819 UTC, independently verified blocked at 23:00:39.594 UTC.
- A separate observer invocation also confirmed the action-owned nftables set contained Kali and Kali SSH failed, while Windows management SSH still returned the target hostname.
- Recovery and repeat/negative results are recorded below.

This autonomous path is a deterministic policy on fresh authenticated events. It does not wait for Gemini or a multi-specialist investigation. Read-only investigation tasks are queued separately. No claim of full production readiness is made.

## Recovery and negative checks

- First cycle independently recovered at **23:01:45.792 UTC**. A second observer invocation confirmed the owned set was empty and Kali SSH reachable.
- Three new Kali failures during cooldown produced `cooldown`; the durable action count remained one.
- Three actual invalid-user SSH events from the Windows management source were retrieved from the authenticated indexer. The response selector admitted zero of those records, and the durable action count remained one.
- A bounded reader pointed at an unavailable local indexer endpoint returned `unavailable/unknown`. The actual controller admission returned `incomplete_collection` without dispatch; the primary indexer tunnel was left intact. This validates the failure gate, not a disruption of the main production polling process.
- A 14-module targeted regression run passed **289 tests** using temporary databases. Fixture checks are recorded separately from the live observations above.
- Reconciliation now observes expired action-owned state after interruption without sending or renewing a response. A recovered state cannot retroactively invent evidence that the block was verified; unknown sends without verified blocking remain `recovered_unverified` if recovery can be positively established.


## Repeat and controller interruption

- Cycle two: incident `TICK-WAZUH-edd7d21016958d39d715`, intent `7a54d97e-8231-48bd-aafa-d1dbfd6a1d38`; in-flight at 23:06:10.811 UTC and verified blocked at 23:06:14.049 UTC. Independent reconciliation confirmed recovery without redispatch. This interruption was near expiry, so the final test below supplies the active-phase interruption proof.
- Final cycle: incident `TICK-WAZUH-65e3e11b83ceb5fdcfa5`, intent `3118e1c5-0bd1-4b90-8cc4-779e850f8fc6`; intent created at 23:12:50.669 UTC. An independent observer confirmed the owned set contained Kali, Kali SSH was denied, and management still worked. Controller PID 28384 was terminated at **23:12:57.847 UTC**, approximately seven seconds after intent creation.
- With the controller stopped, kernel timeout removed the blocked address. Read-only reconciliation positively verified the empty owned set, restored Kali SSH, and working management, then recorded `recovered`. The action count stayed exactly three: no redispatch.
- Replaying the saved observations against the current policy returned `quota_exhausted`; the no-dispatch guard was not invoked.
- Final independent audit confirmed all three intents recovered, all three owned sets empty, and baseline connectivity restored. Controller PID 28384 was absent. VMs and the indexer tunnel remain running.
- The focused autonomous-policy and lab-plan suite additionally passed **37 tests** after the final changes; the broader targeted regression passed **289 tests**.
- Machine-readable evidence is saved locally in `~/Downloads/TERMINUS_Lab_Test_2026-10-17/results.json` and `interruption.json`. These contain identifiers and verification outcomes, not credentials.

## Scope of completion

Tonight's isolated SSH lab milestone is complete: real ingestion, earlier saved Gemini analysis, deterministic autonomous blocking, independent recovery, repeat operation, cooldown, protected source, stale replay, unavailable-endpoint admission, active controller interruption, reconciliation, and durable quota. Response UI projection and the incident decision service subsequently passed their scoped checks; see [response decisions](RESPONSE_DECISIONS.md). Production deployment, notification delivery, other executable response types and a model-led multi-specialist response decision remain outside this completed milestone. Implementation committed and pushed as `4afc1df`.
