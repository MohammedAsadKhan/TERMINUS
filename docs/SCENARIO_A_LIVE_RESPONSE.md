# Scenario A live response — implementation handoff

Status: transport and endpoint command implemented. Manual lab checks validated
Wazuh command delivery, source blocking, management access, and timed recovery.
The Terminus durable live response lifecycle is not connected. No automatic policy is enabled. Existing response policies
and lifecycle remain fixture-only. Do not use the transport directly from a
model, workflow, or public API.

## Implemented

- `src/terminus/response/wazuh_transport.py`: bounded Wazuh 4.x manager transport,
  separate response credentials, one fixed installed-script command (`!terminus-ip-block`), one configured
  endpoint/source, ten-second total deadline, 64 KiB response bound, no retries
  or redirects. Provider acceptance remains unverified. Ambiguous send outcomes
  require reconciliation.
- `scripts/lab/terminus_ip_block.py`: Ubuntu lab command using nftables. Only
  source `10.77.0.10` is permitted. The action's intent and proposal digest derive
  a dedicated owned table. A timed IPv4 set element expires after 30–900 seconds
  independently of the worker. Duplicate dispatch cannot renew the timeout.
  Delete validates table ownership before removing only that table. Empty tables
  remain after expiry until ownership-checked cleanup.

## Work required before any live dispatch

1. Add a durable live authorization/lifecycle boundary. Existing
   `ResponsePolicy.fixture_only=True` must not be reinterpreted as live approval.
   Bind an administrator-configured autonomous policy to exact registered
   target, source, fresh canonical evidence, threshold, duration, exclusions,
   connector identity and policy version. Record admission and dispatch intent
   before I/O. Enforce quotas and ownership atomically. Never replay an unknown
   or interrupted send.
2. Install and validate nftables on Ubuntu. Copy the endpoint script root-owned,
   mode 0750, into `/var/ossec/active-response/bin/terminus-ip-block`. Register the
   command on the Wazuh manager (inside `ossec_config`):

   ```xml
   <command>
     <name>terminus-ip-block</name>
     <executable>terminus-ip-block</executable>
     <timeout_allowed>no</timeout_allowed>
   </command>
   ```

   The endpoint implements its own kernel timeout. Do not attach an automatic
   Wazuh rule trigger: Terminus must own the decision. Verify installed Wazuh
   configuration and command delivery in the lab before relying on this snippet.
3. Provision a separate response account restricted to
   `active-response:command` for `agent:id:001`. Wazuh's permission allows other
   commands on that endpoint; Terminus must enforce its fixed command boundary.
4. Add independent observation and conservative reconciliation: inspect the
   owned table, blocked source and remaining TTL; observe SSH from Kali failing
   after a successful baseline; verify Windows management SSH still works.
   Provider acknowledgement cannot satisfy these checks.
5. Test expiry and ownership-checked cleanup, then observe Kali SSH recovery.
   Test cancellation, crash before/after send, unknown outcomes, changed policy,
   protected addresses and duplicate alerts. Persist results in the operation
   history. Do not call a fixture check live verification.
6. Connect continuous bounded Wazuh intake and specialist investigation to the
   approved autonomous policy. Enable only after the live rehearsal passes.

## References

- [Wazuh 4.14 API reference](https://documentation.wazuh.com/4.14/user-manual/api/reference.html)
- [Wazuh 4.14 API specification](https://github.com/wazuh/wazuh/blob/v4.14.0/api/api/spec/spec.yaml)
- [Custom active response scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)

Claim protocol: mark each completed item with `Done by — <name/agent>, <date>,
<validation evidence>`. Keep live-validation items unchecked until observed in
the installed environment. Transport and endpoint command: implemented by Codex;
fixture tests cover scope, bounded output, ambiguous timeout, ownership, duplicate
dispatch and TTL construction. No live block has been attempted.

## Manual lab evidence

On October 6, the installed command blocked Kali 10.77.0.10 from SSH to target 10.77.0.20, preserved Windows management access, and expired after 60 seconds. The same sequence passed through the Wazuh manager API for agent 001. API dispatch uses `!terminus-ip-block` to invoke the installed script; the command declaration alone did not populate shared/ar.conf and the unprefixed name returned error 1652. These observations establish manual lab behavior, not autonomous Terminus execution. Empty-table cleanup after the API test remains to be confirmed.
