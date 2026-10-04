# Terminus future defensive scope

Product authority: [PRD](PRD.md). Version 1.0 boundary: [MVP release scope](MVP_RELEASE.md). Approved roadmap expansion: October 4, 2026, by Mohammed.

## Catalog and release boundary

The roadmap contains 60 defensive specialties across five coordination areas. They describe intended coverage, not 60 implemented agents or verified protection. Related specialties may share an execution engine while retaining distinct tool permissions and acceptance criteria. Main and area orchestrators are separate coordination roles.

Version 1.0 may display the entire catalog. Future specialties must show **Planned - Unavailable in 1.0**, with descriptions and disabled launch/enable/assignment controls. They cannot enter the executable role registry, scheduler admission, workflow selection, help-request routing or model/tool dispatch. A frontend label alone is insufficient: backend admission must enforce the release boundary. No fabricated runs, findings, counters or protection indicators. Display-only catalog metadata stays separate from the executable coordination catalog.

The eight core execution roles planned for 1.0 remain triage, identity, endpoint, network, response planner, verification, evidence/reporting and application/API security. They are implementation pending until real handlers, connections, permissions and acceptance checks exist. Containment/remediation map to the core Response Planner; evidence review/reporting map to the core Evidence & Reporting Analyst. Matching a roadmap specialty to a core role does not enable additional specialized tools or future capabilities.

## Full roadmap catalog

### Alert handling (8)

- Triage Analyst
- Alert Enrichment Analyst
- Incident Prioritization Analyst
- Alert Deduplication Analyst
- Incident Scoping Analyst
- Behavioral Anomaly Analyst
- Telemetry Health & Tampering Analyst
- Detection Validation Analyst

### Investigation (14)

- Endpoint Forensics Investigator
- Network Analyst
- Identity & Authentication Analyst
- Malware Analyst
- Threat Intelligence Analyst
- Campaign Correlation Analyst
- Email & Phishing Analyst
- Threat Hunter
- Memory Forensics Investigator
- Disk & Filesystem Forensics Investigator
- Browser Forensics Investigator
- Ransomware Investigator
- Insider Threat Analyst
- Persistence & Lateral Movement Investigator

### Infrastructure (14)

- Cloud Security Analyst
- Container Security Analyst
- Kubernetes Security Analyst
- Asset Exposure Analyst
- Configuration & Hardening Analyst
- VM & Hypervisor Security Analyst
- Firewall Security Analyst
- Network Segmentation Analyst
- DNS & Proxy Security Analyst
- Wireless Security Analyst
- Mobile Device Security Analyst
- IoT Security Analyst
- OT & Industrial Systems Security Analyst
- Serverless Security Analyst

### Applications and data (12)

- Repository & Dependency Security Analyst
- Application & API Security Analyst
- Database Security Analyst
- Data Access & Exfiltration Analyst
- CI/CD Security Analyst
- Software Supply Chain Analyst
- Secrets & Credential Exposure Analyst
- Certificate & Cryptographic Security Analyst
- SaaS Security Analyst
- Cloud Storage Security Analyst
- AI & LLM Security Analyst
- Data Integrity Analyst

### Response and improvement (12)

- Containment Planner
- Remediation Planner
- Recovery Verification Analyst
- Detection Engineer
- Evidence Review Analyst
- Incident Reporting Analyst
- Malware & Persistence Eradication Specialist
- Identity & Session Revocation Specialist
- Network Blocking Specialist
- Backup & Recovery Specialist
- Deception & Honeypot Specialist
- Defensive Control Validation Analyst

## Explicit capability additions

- Threat hunting: proactively investigate supported evidence rather than require an existing alert.
- Telemetry health and tampering: identify disconnected sensors, collection gaps and attempts to disable visibility.
- Identity response: scoped account, credential and session revocation with protected-account exclusions and verification.
- Eradication and recovery: remove supported malicious persistence, restore clean services and independently check legitimate operation.
- Backup defense: verify backup integrity and restoration readiness; recovery cannot assume backups are clean.
- Deception: monitor controlled decoys and honeypots within authorized environments.
- AI/LLM, SaaS, CI/CD and supply-chain defense: dedicated evidence sources, permissions and useful specialist findings.
- OT, IoT, mobile, wireless and virtualization: environment-specific collection and response contracts; generic host tools do not establish coverage.

## Activation gates after 1.0

Each capability needs an owner, defined objective, required telemetry/connectors, permitted tools, data-sharing rules, model/budget policy, approval conditions, recovery/undo behavior where applicable, and independent acceptance evidence. Missing inputs produce explicit gaps. Consequential response requires approved targets and recorded outcomes; acknowledgement alone does not establish success.

Promoting a planned specialty requires a later release decision and updates to PRD, executable catalog, permissions, UI availability and verification records. This document authorizes roadmap/display requirements only; it does not authorize future execution in 1.0.

## Reference basis

This is a Terminus product taxonomy informed by [NIST NICE](https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center/nice-framework-current-versions), [MITRE D3FEND](https://d3fend.mitre.org/), [NIST incident-response guidance](https://csrc.nist.gov/pubs/sp/800/61/r3/final) and [CISA ransomware guidance](https://www.cisa.gov/stopransomware/ransomware-guide). It is not an official framework role list or an exhaustive guarantee of defense for every environment.
