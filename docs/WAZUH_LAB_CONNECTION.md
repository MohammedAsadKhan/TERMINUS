# Wazuh lab connection

The dedicated specialist worker can now create bounded, read-only manager and
indexer readers from explicit deployment environment settings. Credentials are
separate and bound to `TERMINUS_SPECIALIST_WAZUH_ORG_ID`; other tenants receive
no readers. Existing incident policy, endpoint bindings, operator membership,
scheduler leases, quotas and evidence auditing still apply. Configuring a
connector does not create an incident, grant permissions or enable responses.

## Verified lab endpoints

- Manager: `https://192.168.56.104:55000`, user `wazuh-wui`.
- Indexer: `https://127.0.0.1:19200`, user `admin`, SSH tunnel required.
- Target: agent `001`, `terminus-target-a`, `10.77.0.20`.
- Kali: `10.77.0.10`.
- Manual indexer search returned five real journald authentication alerts:
  four rule 5710 events and one rule 5503 event. Manager authentication returned
  HTTP 200/error 0. These were operator curl checks, not live specialist checks.

## Local launch

Keep this tunnel running in a separate Windows terminal:

```powershell
ssh -N -L 127.0.0.1:19200:127.0.0.1:9200 wazuh-user@192.168.56.104
```

Stop any existing scheduler before launching another against the same database.
Use the current organization's actual ID and a current operator's user ID:

```powershell
uv run python scripts/run_wazuh_lab_worker.py --database terminus.db --org ORGANIZATION_ID --actor OPERATOR_USER_ID
```

The launcher prompts for both passwords locally, passes them only in the child
worker environment, and does not write them to disk or command arguments. It
installs triage, identity and endpoint handlers, with live model calls disabled.
This explicit local-lab launcher skips TLS certificate verification for the
OVA's certificates; production must keep verification enabled. A trusted CA /
certificate deployment remains a follow-up. The SSH tunnel must stay available.

## Import and authorize the first real incident

From another terminal in the repository, while the tunnel and worker run:

```powershell
uv run python scripts/import_wazuh_lab_incident.py --database terminus.db --org org-terminus-demo --actor usr-LfgGy8A_O5Q --start 2026-10-06T01:13:00+00:00 --end 2026-10-06T01:16:00+00:00
```

This trusted local administrator command prompts for both passwords, verifies
manager endpoint access, selects failed authentication events from Kali, and
imports one incident for that bounded event set. It stores original provider
records as durable source evidence and the latest alert as the incident payload.
Initial severity/confidence are explicitly provisional, not a model assessment.
It grants only triage investigation reads, binds the incident and endpoint, and
queues main/area/triage work through the existing scheduler. Replaying the same
event set retains the incident without expanding grants or rescheduling work.
The CLI trusts a local operator with database access; it is not a public API or
replacement for authenticated UI authorization. No passwords are saved by it.

The historical time window above matches the first SSH test; for subsequent
tests select the actual timestamps (maximum one hour). An empty/partial/failed
collection creates no incident. This is explicit import, not continuous polling.

## Remaining live integration gates

First live worker run completed main/area/triage but produced partial evidence:
the broad one-hour detection search exceeded 64 KiB, and current manager
heartbeats could not establish historical coverage. Authentication incidents now
use a fixed authentication query (failures AND successes) and smaller 20-record
pages; other incidents retain general detection searches. Endpoint inventory is
anchored to task time, independently of the historical alert window. Historical
coverage still reports gaps rather than inferring past sensor health from a
current heartbeat. Limits, source timestamps and partial results remain intact.

After restarting the lab worker to load changed code, an administrator can
explicitly request another read-only attempt without reimporting events:

```powershell
uv run python scripts/retry_wazuh_lab_triage.py --database terminus.db --org org-terminus-demo --actor usr-LfgGy8A_O5Q --incident TICK-WAZUH-3192b337a29a7de92c6d
```

The original attempt and evidence remain in history. The lab worker must still
be launched with live models disabled. No credential is needed by the retry
command; connector credentials remain in the worker environment.

- Configure authenticated alert ingestion into canonical incidents. The reader
  deployment does not poll alerts into new incidents.
- The local admin import command now creates read policy and agent bindings;
  an authenticated UI setup path remains future work. Models cannot establish
  those permissions.
- Run an actual leased specialist task and inspect durable evidence/audit results.
- Preserve management access, stabilize management IPs, and snapshot the VMs.
- Implement and validate approval-bound response dispatch, reconciliation,
  independent verification, expiry and undo separately.

Do not mark these gates complete based on successful manual curl requests.
# Gemini lab budget

Live saved-evidence validation succeeded in task
`6157536a-4495-4f7e-8409-9c0e6acd99e4`: Gemini returned three cited findings,
8,861 input tokens and 317 output tokens (9,178 total), with a recorded
zero-dollar cost under the configured lab pricing. This does not verify Google
billing. Earlier attempts were rejected for duplicate evidence exceeding the
24 KiB model payload bound, then received a provider error and a 30-second
timeout. The lab launcher now permits 75 seconds; the successful retry completed
in a few seconds, so the evidence supports intermittent provider behavior,
not a claim that every request requires the longer deadline. The production
transport default remains 30 seconds. Historical sensor completeness remains
unverified, and no response action was executed.

The local demo administrator selected no Terminus daily token cap for the
Gemini free-tier lab. The organization's dollar budget remains zero, and model
selection, evidence redaction, invocation limits and usage auditing still apply.
This is a local database setting, not a change to Google billing or API quota.
The saved-evidence analysis launcher carries the existing zero-dollar budget
and optional token cap into a new UTC day. Unknown usage reservations remain
in the audit ledger; removing a token cap does not erase or reconcile them.
