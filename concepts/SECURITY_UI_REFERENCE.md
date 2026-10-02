# Security console reference points

These prototypes are interface explorations for Terminus. The work surface should resemble an analyst tool rather than a presentation board.

## What real tools prioritize

- **Wazuh Dashboard:** security events, endpoint and agent status, severity, threat hunting, MITRE ATT&CK, rules and decoders, reports, and server state. Analysts can query and drill into events rather than only read summary charts. [Wazuh dashboard navigation](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/navigating-the-wazuh-dashboard.html)
- **Elastic Security:** a detection and response view focuses on recent alerts, cases, hosts, and users. Alert details expose rule reason, highlighted fields, related activity, investigation guidance, and actions. [Detection and Response dashboard](https://www.elastic.co/guide/en/security/current/detection-response-dashboard.html) · [Alert details](https://www.elastic.co/guide/en/security/current/view-alert-details.html)
- **Snort 3:** Snort is a detection engine. Its alert outputs include timestamp, protocol, source and destination, rule identifier, classification/priority, and action. A Terminus UI should make such source evidence inspectable; it should not imply Snort has a native console design. [Snort alert logging](https://docs.snort.org/start/alert_logging)

## Terminus prototype requirements

1. Open directly into a full-screen workbench, with navigation to Overview, Incidents, Reports, Agent Fleet, Workflows, Integrations, Organization, and Settings.
2. Make alert search, time range, severity, status, host, and rule context easy to inspect.
3. Provide an incident dossier with raw event, policy reason, evidence, timeline, affected asset, and explicit analyst actions.
4. Treat graphics as support for triage; use them to show trends, concentration, and relationships, not to displace the queue.
5. Distinguish configured integrations from verified health and suggested response from executed response.
6. Use realistic but clearly illustrative data in the standalone prototypes.
