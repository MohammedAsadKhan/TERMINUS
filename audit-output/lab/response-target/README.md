# Terminus response-target lab

Disposable three-container stack for exercising the shipped Wazuh endpoint command
(`scripts/lab/terminus_ip_block.py`) against an SSH target, with an independent
observer that does not run commands inside the target container.

Status: **local endpoint verification and one full TERMINUS approved block/recovery
passed on 2026-11-13 UTC** on Docker Desktop for Windows (Linux containers).
See [the exact authorized response record](evidence/approved-response-summary-2026-11-13.md).
Nothing in this directory has been run against the class lab's Kali host or
Windows worker.

## What was verified

- Ubuntu 24.04 target with nftables and Wazuh agent `4.14.10-1` enrolls to the
  existing single-node manager and reports `Active`.
- Three bounded failed SSH attempts from `10.77.0.10` produce Wazuh rule `5710`
  (`groups: syslog, sshd, authentication_failed, invalid_login`) with
  `srcip=10.77.0.10` from `/var/log/auth.log`.
- One 60-second block/recovery cycle:
  - baseline: attacker reaches `10.77.0.20:22`, target management SSH works;
  - add: endpoint returns `state=accepted`, table
    `terminus_49470716abfda0511303c0d7`;
  - blocked: attacker probe is denied, table comment matches the full identity,
    set contains `10.77.0.10`, management SSH still works;
  - recovered after kernel expiry: probe reaches the target again, set is empty,
    table remains (owned tables are only removed by an ownership-checked delete);
  - delete: table is absent and the attacker probe still succeeds.
- The target now starts a 30-second bounded cleanup loop for expired, empty,
  ownership-matched tables. This new loop has offline fixture tests but was not
  present during the November 13 live cycle; automatic deletion and separate
  `table-absent` observation still need a fresh lab run.
- Negative checks: a duplicate `add` returns `already_owned` without renewing the
  timeout; a wrong `srcip` is rejected with `state=unknown` and exit code 1 for
  both `add` and `delete`.

## Topology

| Container | Image | Management (`single-node_default`) | Attack path |
| --- | --- | --- | --- |
| `response-target` (`terminus-target-a`) | Ubuntu 24.04 + nftables + Wazuh agent | DNS alias `target` (dynamic address) | `10.77.0.20` |
| `response-attacker` (`terminus-attacker`) | Ubuntu 24.04 + `sshpass` | DNS alias `attacker` (dynamic address) | `10.77.0.10` |
| `response-observer` (`terminus-observer`) | Alpine 3.20 + OpenSSH client | DNS alias `observer` | none |

- `response-target-attack` is a dedicated `10.77.0.0/24` bridge with
  `internal: true`. The shipped endpoint command hard-codes `10.77.0.10` and the
  product observer hard-codes `10.77.0.20` / `10.77.0.10`, so the attack path
  uses those exact addresses without editing product code.
- `single-node_default` is the existing Disposable Wazuh lab network. That
  network rejects operator-supplied static addresses, so management checks use
  Docker DNS aliases instead of IPs.
- No ports are published to the host. SSH is reachable only from the private
  Docker networks.
- `labadmin` on the target is key-only. Its sudoers entry only allows read-only
  `nft --json list tables` and `nft --json list table inet terminus_*`; the
  observer therefore cannot write firewall state.
- The target's root-owned cleanup loop uses the same installed endpoint script.
  It cannot add a block or renew a TTL; it deletes only an empty table with the
  expected full identity comment and lab table structure. A bounded inventory
  or malformed observation stops cleanup rather than broadening deletion.
- The observer copies the bind-mounted private key to `/tmp` and enforces mode
  `0600` because Windows bind mounts do not preserve POSIX modes.

## Prerequisites

- Docker Desktop with Linux containers, `docker compose`, and PowerShell.
- `ssh-keygen` on `PATH` (the Windows OpenSSH client is sufficient).
- The existing single-node Wazuh stack running, with `single-node_default`
  present and the manager reachable as `wazuh.manager` on ports 1514/1515.
- No manager configuration change is required: the agent auto-enrolls because
  `target/ossec.conf` enables enrollment.

## Bring-up

Run from `audit-output/lab/response-target`:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1
docker compose up -d --build
docker compose ps
```

`setup.ps1` generates the disposable client key and pinned target/attacker host
keys under `.state/`. That directory is git-ignored and must not be committed.
The generated private key triggers a Windows `UNPROTECTED PRIVATE KEY FILE`
warning when inspected with Windows ACLs; the observer copies it inside the
container and sets `0600`, so lab operation is unaffected.

Wait for `response-target` and `response-attacker` to report `healthy`, then
confirm enrollment:

```powershell
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

The agent name is always `terminus-target-a`. The manager assigns the ID, so it
can change after a container recreation (`001` on first enrollment, `002` after
the rebuild during this verification).

## Generate SSH failure telemetry

```powershell
docker exec response-attacker /usr/local/bin/attack.sh 3
docker exec response-target sh -c "grep -E 'Failed password|Invalid user' /var/log/auth.log | tail -8"
docker exec single-node-wazuh.manager-1 sh -c "grep terminus-target-a /var/ossec/logs/alerts/alerts.json | tail -3"
```

Observed on the target:

```text
sshd[316]: Invalid user invalid-lab-user from 10.77.0.10 port 47908
sshd[316]: Failed password for invalid user invalid-lab-user from 10.77.0.10 port 47908 ssh2
```

Observed on the manager (abridged):

```json
{"rule":{"id":"5710","groups":["syslog","sshd","authentication_failed","invalid_login"]},
 "agent":{"id":"002","name":"terminus-target-a","ip":"172.19.0.7"},
 "data":{"srcip":"10.77.0.10"},"location":"/var/log/auth.log"}
```

sshd must log through syslog for these lines to exist. The entrypoint therefore
starts `/usr/sbin/sshd -D` (not `-e`); `-e` sends sshd messages to stderr, which
leaves only PAM lines and Wazuh rule `5503` (`pam,syslog,authentication_failed`).
Rule `5503` also fires in this lab, but the product live-response path requires
the `sshd` group, so `5710` is the relevant evidence.

## Run the block/recovery cycle

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run-block-cycle.ps1 -DurationSeconds 60
```

The script computes the identity exactly as the endpoint command does:

```text
identity = sha256(intent + ":" + digest)
table    = "terminus_" + identity[:24]
```

It then runs four independent observer stages (`baseline`, `blocked`,
`recovered`, `table-absent`) over SSH and invokes the installed endpoint command
inside the target with this payload shape:

```json
{
  "command": "add",
  "parameters": {
    "alert": {
      "data": {
        "srcip": "10.77.0.10",
        "terminus_intent_id": "response-target-20261113T022455Z",
        "terminus_proposal_digest": "3a6b5739d98c140111b559441bed4497a33bdf5d1c79d2d8cd159aa2c831d299",
        "terminus_duration_seconds": 60
      }
    }
  }
}
```

Observed result for the 60-second cycle:

| Stage | Attacker probe to `10.77.0.20:22` | Target management SSH | nftables |
| --- | --- | --- | --- |
| baseline | reachable (`PROBE_STATUS:0`) | OK | no owned table |
| blocked | denied (`PROBE_STATUS:1`) | OK | table + set present, `10.77.0.10` element |
| recovered | reachable (`PROBE_STATUS:0`) | OK | table present, set empty |
| table-absent | reachable | OK | table deleted |

The run printed `BLOCK/RECOVERY CYCLE VERIFIED`. Timing came from the kernel
timeout: the script waited `duration + 5` seconds before checking recovery.

## Negative checks

```powershell
$intent = "neg-test-20261113"
$digest = "3a6b5739d98c140111b559441bed4497a33bdf5d1c79d2d8cd159aa2c831d299"
function Send([string]$cmd, [string]$src) {
  $m = @{ command = $cmd; parameters = @{ alert = @{ data = @{
    srcip = $src; terminus_intent_id = $intent
    terminus_proposal_digest = $digest; terminus_duration_seconds = 60
  } } } } | ConvertTo-Json -Compress -Depth 8
  $o = $m | docker compose exec -T target /usr/local/sbin/terminus-ip-block
  "cmd=$cmd src=$src exit=$LASTEXITCODE out=$($o -join ' ')"
}
Send add    "10.77.0.10"   # accepted, exit 0
Send add    "10.77.0.10"   # already_owned, exit 0, TTL not renewed
Send add    "10.77.0.99"   # unknown, exit 1
Send delete "10.77.0.99"   # unknown, exit 1
Send delete "10.77.0.10"   # accepted, exit 0
```

`verified:false` in the endpoint output is intentional: the command reports that
it cannot independently verify its own effect. The observer stages provide the
independent evidence.

## Limitations

1. **The product path passed once in this disposable lab.** TERMINUS now binds
   the response agent ID and management IP from lab settings. The current lab
   registered Wazuh agent `002` with management IP `172.19.0.5`; the fixed
   attack path remains `10.77.0.10` to `10.77.0.20`. A separate Docker observer
   independently checked effect and recovery. These addresses are lab-specific.
2. **Wazuh manager API dispatch passed once.** The manager accepted
   `!terminus-ip-block` on agent `002`, the endpoint script logged `accepted`,
   and TERMINUS recorded `verified_blocked` and then `recovered`. The direct
   endpoint cycle below remains a separate script test, not evidence of product
   approval or Wazuh dispatch. Two earlier API acknowledgements without effect
   are retained as `recovered_unverified`; a manually copied CRLF shebang was
   the cause.
3. **The attack network has no route to the host or the class lab.** It is an
   internal bridge by design, so the observed source is a Docker address, not a
   routed external network.
4. **Alerts may create Terminus lab incidents.** The existing manager has a
   `custom-terminus` integration that forwards alerts at level 5 or higher to
   `http://terminus:8000/sources/wazuh`. Generated SSH alerts are therefore
   visible to the running Terminus instance.
5. **Agent ID is not stable.** Recreating the target re-enrolls it and the
   manager assigns the next free ID. Remove the stale agent before recreating,
   and update the TERMINUS binding rather than assuming `002` forever.
6. **Keep the Linux script shebang LF-only.** The target entrypoint normalizes
   line endings at install time (`sed 's/\r$//'`) and `.gitattributes` requests
   LF for the source. A manual `docker cp` of a CRLF file caused two failed
   dispatches despite Wazuh API HTTP 200.
7. **Management addresses are dynamic.** `single-node_default` rejects
   `--ip`-style static addresses, so management checks resolve the `target` and
   `attacker` DNS aliases. Only the attack path has fixed addresses.

## Cleanup

```powershell
cd audit-output/lab/response-target
docker compose down -v
docker exec single-node-wazuh.manager-1 sh -c "printf 'y\n' | /var/ossec/bin/manage_agents -r <agent-id>"
Remove-Item -Recurse -Force .\.state
```

`down -v` removes the containers and the `response-target-attack` network; the
external `single-node_default` network is left alone. Removing `.state` discards
the disposable keys and pinned host keys; rerun `setup.ps1` before the next
bring-up.

## Files

| Path | Purpose |
| --- | --- |
| `compose.yaml` | Services, networks, mounts, healthchecks |
| `setup.ps1` | Generates `.state/` client and host keys and `known_hosts` |
| `run-block-cycle.ps1` | Drives baseline → add → blocked → recovered → delete |
| `target/Dockerfile`, `target/entrypoint.sh` | Ubuntu target, endpoint install, rsyslog/sshd/agent startup |
| `target/ossec.conf` | Minimal agent config collecting `/var/log/auth.log` |
| `target/sshd_config` | Password auth enabled for failure telemetry; no host ports |
| `attacker/attack.sh` | Bounded failed SSH attempts from `10.77.0.10` |
| `observer/observe.py` | Independent staged SSH and nftables checks |
| `.gitignore` | Excludes `.state/` and local artifacts |
