# Authorized disposable-lab response evidence

At 2026-11-13 07:32:58 UTC, genuine failed SSH attempts from `10.77.0.10` against target `10.77.0.20` (Wazuh agent `002`) produced source-backed TERMINUS incident `TICK-WAZUH-dd746fa9141091912bad`. The generated proposal `9805ec55-1bc9-4e4e-9584-15bcf185cda9` was `Ready` with digest `3b2045955b8b64c323aba93d6897749f66b41389b34a280d43f3dc20bc750e84` and a 60-second duration. A lab administrator approved that exact digest at 07:33:23 UTC.

TERMINUS reserved intent `6af9fe25-b7bb-4432-9dc8-5f8f666ab995` before provider I/O. The Wazuh API acknowledged at 07:33:26 UTC. The endpoint script logged `accepted`, and an independent observer verified the attacker SSH probe was denied, management SSH remained healthy, and the exact identity-owned nftables set contained only the configured source. TERMINUS recorded `verified_blocked` at 07:33:31 UTC. Raw observer output: [blocked](approved-blocked-2026-11-13.json).

After kernel timeout, TERMINUS recorded `recovered` at 07:34:43 UTC. An independent observer verified attacker SSH connectivity was restored, management SSH remained healthy, and the owned set was empty. Raw observer output: [recovered](approved-recovered-2026-11-13.json).

Two earlier approved attempts got Wazuh API acknowledgements but no endpoint effect because the manually copied Python script had CRLF line endings in its shebang. They were recorded as `unknown`, then `recovered_unverified` only after the independent observer confirmed the exact table was absent and SSH was reachable. The corrected install normalizes line endings. Those failures remain in the lab database; they are not counted as successful response tests.

The empty identity-owned nftables table remains after expiry. It has no blocked source. A lifecycle cleanup path and repeated action test are still required before a pilot or production deployment.
