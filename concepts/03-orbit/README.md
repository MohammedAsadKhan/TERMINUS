# Orbit — analyst workbench concept

Orbit is a standalone, local-data prototype for the Terminus AI SOC console. Open `index.html` directly. It starts in the analyst workbench, with the alert queue and selected evidence dossier visible at once. The queue supports text search, severity and time filters, and active/all/resolved states. Select an alert to inspect summary, observed events, normalized raw data, and response. Investigation, resolution, notes, report generation, and workflow validation update local prototype state only.

The visual language uses deep indigo, compact mono metadata, cyan focus, and restrained orbital geometry. The small entity relation graphic supports the evidence readout; it is deliberately secondary to alert triage. All eight product sections are full-screen navigation destinations.

The workbench follows the operational shape of a SOC console: persistent navigation and monitoring context; a dense queue; then an alert detail surface that keeps rule reason, important fields, source and destination, investigation history, raw fields, and response state close together. The Wazuh dashboard documentation describes navigation across security events and operational modules. Elastic Security's alert details documentation describes overview, field table, JSON, investigation, entity graph, and response affordances. Snort's alert logging field list informed the sample network IDS event's source/destination addresses, ports, protocol, service, and rule SID.

References:

- [Wazuh dashboard navigation](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/navigating-the-wazuh-dashboard.html)
- [Elastic detection alert details](https://www.elastic.co/docs/solutions/security/detect-and-alert/view-detection-alert-details)
- [Snort alert logging](https://docs.snort.org/start/alert_logging)

All names, IP addresses, cases, and counts in this concept are sample data. Controls that would need a backend announce that they are simulated. No production application files were changed.
