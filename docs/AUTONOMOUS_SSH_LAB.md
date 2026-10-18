# Autonomous SSH lab runner

This is a separate, opt-in live lab controller. It does not reinterpret the fixture-only response service, enable future specialties, or give models response credentials.

## Implemented behavior

`run_autonomous_wazuh_lab.py` polls the authenticated manager and indexer every five seconds. A complete collection must contain at least three distinct, fresh SSH authentication failure events from **10.77.0.10** against **agent 001 / 10.77.0.20**, after the policy was enabled and within 120 seconds. The manager must currently report the expected endpoint active. Console login failures and sudo activity do not count.

Once authorized at launch, the deterministic policy decides without per-alert approval or paid model calls. Its fixed response lasts 60 seconds. The authorization expires after 30 minutes. At most three actions are permitted in the durable lab history, with a five-minute cooldown. Reusing a source event, restarting, or opening a second controller cannot duplicate dispatch. Changing/resetting the database must never be used to clear an unresolved action.

Before dispatch, independent observers must establish Kali SSH access, Windows management access, and read-only firewall access. The controller stores the immutable proposal digest, policy snapshot, exact event IDs, canonical incident evidence and in-flight intent before external I/O. Cancellation or ambiguity cannot trigger automatic redispatch.

After Wazuh accepts the command, independent SSH observations must show Kali denied, Windows management still available, and the correct action-owned nftables set containing the source. Recovery requires the same owned set empty and Kali SSH working after expiry. Acknowledgement alone is never verified success. Unknown outcomes halt further actions pending reconciliation. Kernel expiry works even if the controller stops. Empty owned tables may remain; automated cleanup/early undo is not implemented by this runner.

## Live prerequisites — not yet verified

- Keep Kali adapter 1 on `terminus-lab`. Add a second **host-only** management adapter (never bridged) so Windows can SSH into Kali without using the blocked attack path. Record its `192.168.56.x` address.
- Configure a dedicated SSH key from Windows to `kali@KALI_MANAGEMENT_IP` and `labadmin@192.168.56.103`. Verify host fingerprints interactively first. The observer uses BatchMode and strict host-key checking and never accepts unknown keys automatically.
- Provision tightly scoped, read-only sudo access for the Ubuntu observer: `/usr/sbin/nft --json list tables` and `/usr/sbin/nft --json list table inet terminus_*`. Do not grant firewall-write or arbitrary shell sudo access. Have the administrator review the exact sudoers rule with `visudo`.
- The existing root-owned `terminus-ip-block` endpoint script must still be installed. The ordinary verification user is not expected to execute that script; it runs only through Wazuh. Use a separate Wazuh response API account restricted to `active-response:command` for `agent:id:001`; source and command restrictions are additionally enforced by Terminus and the endpoint script.
- Keep the indexer SSH tunnel open. Verify all VM clocks and the Kali/Windows SSH baselines. Independent live baseline passed on October 17: Kali SSH probe, Ubuntu management access, read-only nft inspection. Autonomous dispatch remains unverified until a complete live cycle is recorded.

## Run

From the repository in PowerShell:

```powershell
uv run python scripts/run_autonomous_wazuh_lab.py --database terminus.db --org org-terminus-demo --actor usr-LfgGy8A_O5Q --kali-management-ip KALI_MANAGEMENT_IP --enable-autonomous-lab
```

Passwords are prompted locally, never saved or passed in command arguments. The runner uses the existing local-lab TLS exception for Wazuh; production requires trusted certificates. Failed baseline checks enable no policy and send no action. Generate new SSH failures only after the runner reports the policy enabled.

This runner creates canonical incidents and queues the existing read-only investigation tasks; a separately deployed specialist worker can consume them. Autonomous blocking is a deterministic policy decision on fresh authenticated observations, not a completed multi-specialist/model investigation. UI response event projection, explicit revocation/reconciliation controls, notification delivery, and production deployment remain separate work.

## Validation

Recorded fixtures and temporary databases cover admission, protected/wrong sources, old/future data, insufficient/partial collections, durable intent before I/O, acknowledgement versus effect, recovery, duplicate events, cooldown, expiry, membership revocation, cancellation/timeout, and restart holds. These are fixture checks, not installed-environment proof.

## Read-only reconciliation after interruption

After an interrupted effect has had time to expire (duration plus 15 seconds), run:

```powershell
uv run python scripts/reconcile_autonomous_wazuh_lab.py --database terminus.db --org org-terminus-demo --actor usr-LfgGy8A_O5Q --kali-management-ip 192.168.56.102
```

This uses only the dedicated SSH verification key, not Wazuh response credentials. It verifies the stored policy/proposal binding, action-owned empty set, source connectivity and management connectivity. It never sends or renews a response. Missing/foreign ownership or unavailable observations stay unresolved. If blocking was never verified, successful reconciliation records recovery as unverified rather than fabricating a successful containment.
