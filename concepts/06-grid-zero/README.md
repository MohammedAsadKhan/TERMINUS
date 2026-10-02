# Grid Zero — Terminus console concept

Grid Zero is a standalone, eight-section interaction prototype. Open `index.html` in a browser. It uses local demo data and keeps changes in memory until reload; it does not call the Terminus API.

The visual system borrows from Swiss information design: a fixed modular grid, sharp dividers, compressed headings, oversized operational numbers, and almost no decoration. Cobalt marks navigation and investigation context. Scarlet is reserved for critical severity and high-impact actions. Yellow identifies a human decision gate. Severity labels retain text so color is not the only signal.

The incident queue is the center of the product. Search, severity/status filters, and time ranges narrow the list. The dossier exposes the rule reason, highlighted event fields, raw event JSON, timeline, related alert context, and guarded response actions. The overview remains a compact shift monitor. Other screens provide task-shaped controls for reports, agent definitions, workflows, integrations, membership, and settings.

Reference patterns: [Wazuh dashboard navigation](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/navigating-the-wazuh-dashboard.html), [Elastic alert details](https://www.elastic.co/docs/solutions/security/detect-and-alert/view-detection-alert-details), and [Snort alert logging](https://docs.snort.org/start/alert_logging). This is an independent visual concept, not a reproduction of those products.
