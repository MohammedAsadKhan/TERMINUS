# Investigation toolkit contracts

`src/terminus/toolkit/investigation_catalog.json` supplies 48 exact roadmap specialties from [FUTURE_SCOPE.md](FUTURE_SCOPE.md), grouped by coordination area ID. It records proposed read tools, connector requirements and five bounded core bundles. These are metadata contracts: there are no adapters, registrations, credential installation, model calls, network calls or scheduler admission changes here. Every core capability is `implementation_pending`; every future capability is `planned`. None claims implemented defense.

The five roadmap aliases use only their core bundle. Endpoint Forensics Investigator maps to `endpoint`; its 1.0 bundle covers recorded process/FIM evidence, not memory or disk acquisition. Aliases do not enable advanced roadmap capabilities. Other specialties have dedicated future contracts and specialty-specific permissions; they cannot enter 1.0 dispatch. Response/improvement contracts belong to the separate response fragment.

## Core read bundles

| Core role | Required tool IDs | Invocation bound |
| --- | --- | --- |
| `triage` | `incident.get`, `alerts.search`, `assets.get`, `collection.coverage`, `indicators.reputation` | 20 |
| `identity` | `incident.get`, `alerts.search`, `assets.get`, `collection.coverage`, `identity.auth_events`, `identity.directory` | 20 |
| `endpoint` | `incident.get`, `alerts.search`, `assets.get`, `collection.coverage`, `endpoint.agent`, `endpoint.processes`, `endpoint.files`, `payload.decode`, `indicators.reputation` | 20 |
| `network` | `incident.get`, `alerts.search`, `assets.get`, `collection.coverage`, `network.connections`, `network.dns`, `network.firewall`, `indicators.reputation` | 20 |
| `application_api` | `incident.get`, `alerts.search`, `assets.get`, `collection.coverage`, `application.requests`, `application.inventory`, `payload.decode` | 20 |

All queries are incident scoped with organization credentials. Proposed defaults are a 3,600-second window, 200 records/page, four pages, ten-second timeout and 65,536 output bytes. Metadata does not enforce these limits in legacy clients. Results require source IDs, UTC timestamps, coverage, truncation, errors and provenance. Missing telemetry cannot establish a clean finding. Indicator lookups require approved provider egress policy and exclude file uploads. `payload.decode` performs local analysis without execution.

## Roadmap mappings

Full telemetry, permissions, expected evidence and acceptance criteria are recorded per specialty in JSON. Core rows require their bundle; other rows require the listed dedicated future tool.

| Specialty | Area | Core alias or future tool |
| --- | --- | --- |
| Triage Analyst | `alert_handling` | `triage` (pending core) |
| Alert Enrichment Analyst | `alert_handling` | `alerts.enrich` (planned) |
| Incident Prioritization Analyst | `alert_handling` | `alerts.prioritize` (planned) |
| Alert Deduplication Analyst | `alert_handling` | `alerts.deduplicate` (planned) |
| Incident Scoping Analyst | `alert_handling` | `incident.scope` (planned) |
| Behavioral Anomaly Analyst | `alert_handling` | `behavior.baseline_compare` (planned) |
| Telemetry Health & Tampering Analyst | `alert_handling` | `collection.tampering` (planned) |
| Detection Validation Analyst | `alert_handling` | `detection.replay_compare` (planned) |
| Endpoint Forensics Investigator | `investigation` | `endpoint` (pending core) |
| Network Analyst | `investigation` | `network` (pending core) |
| Identity & Authentication Analyst | `investigation` | `identity` (pending core) |
| Malware Analyst | `investigation` | `malware.static_review` (planned) |
| Threat Intelligence Analyst | `investigation` | `threat_intelligence.lookup` (planned) |
| Campaign Correlation Analyst | `investigation` | `threat.campaign_correlate` (planned) |
| Email & Phishing Analyst | `investigation` | `email.message_trace` (planned) |
| Threat Hunter | `investigation` | `threat.hunt` (planned) |
| Memory Forensics Investigator | `investigation` | `forensics.memory_review` (planned) |
| Disk & Filesystem Forensics Investigator | `investigation` | `forensics.disk_review` (planned) |
| Browser Forensics Investigator | `investigation` | `forensics.browser_review` (planned) |
| Ransomware Investigator | `investigation` | `threat.ransomware_review` (planned) |
| Insider Threat Analyst | `investigation` | `threat.insider_review` (planned) |
| Persistence & Lateral Movement Investigator | `investigation` | `threat.persistence_lateral` (planned) |
| Cloud Security Analyst | `infrastructure` | `cloud.audit_review` (planned) |
| Container Security Analyst | `infrastructure` | `container.inventory_review` (planned) |
| Kubernetes Security Analyst | `infrastructure` | `kubernetes.audit_review` (planned) |
| Asset Exposure Analyst | `infrastructure` | `assets.exposure_review` (planned) |
| Configuration & Hardening Analyst | `infrastructure` | `configuration.baseline_review` (planned) |
| VM & Hypervisor Security Analyst | `infrastructure` | `virtualization.inventory_review` (planned) |
| Firewall Security Analyst | `infrastructure` | `firewall.configuration_review` (planned) |
| Network Segmentation Analyst | `infrastructure` | `network.segmentation_review` (planned) |
| DNS & Proxy Security Analyst | `infrastructure` | `network.dns_proxy_review` (planned) |
| Wireless Security Analyst | `infrastructure` | `wireless.capture_review` (planned) |
| Mobile Device Security Analyst | `infrastructure` | `mobile.posture_review` (planned) |
| IoT Security Analyst | `infrastructure` | `iot.telemetry_review` (planned) |
| OT & Industrial Systems Security Analyst | `infrastructure` | `ot.passive_review` (planned) |
| Serverless Security Analyst | `infrastructure` | `serverless.audit_review` (planned) |
| Repository & Dependency Security Analyst | `applications_data` | `repository.dependency_review` (planned) |
| Application & API Security Analyst | `applications_data` | `application_api` (pending core) |
| Database Security Analyst | `applications_data` | `database.audit_review` (planned) |
| Data Access & Exfiltration Analyst | `applications_data` | `data.exfiltration_review` (planned) |
| CI/CD Security Analyst | `applications_data` | `delivery.pipeline_review` (planned) |
| Software Supply Chain Analyst | `applications_data` | `supply_chain.provenance_review` (planned) |
| Secrets & Credential Exposure Analyst | `applications_data` | `secrets.exposure_review` (planned) |
| Certificate & Cryptographic Security Analyst | `applications_data` | `crypto.inventory_review` (planned) |
| SaaS Security Analyst | `applications_data` | `saas.audit_review` (planned) |
| Cloud Storage Security Analyst | `applications_data` | `storage.access_review` (planned) |
| AI & LLM Security Analyst | `applications_data` | `ai.audit_review` (planned) |
| Data Integrity Analyst | `applications_data` | `data.integrity_review` (planned) |

## Connector candidates and source boundaries

Connector capabilities enumerate proposed support, not verified deployment. `not_configured` marks existing provider/client or repository code that lacks this toolkit's verified organization connection. `planned` requires a new adapter or evidence-import contract. All require source version, least privilege, incident target binding, TLS, redacted secrets and explicit gaps. Organization ownership never licenses unrestricted reads.

| Candidate sources | Intended evidence | Remaining dependency |
| --- | --- | --- |
| Terminus repositories | Incident references and registered asset context | Scoped adapter, source provenance and sensor-state distinction |
| Wazuh manager | Agent enrollment, keepalive and collection context | Verified manager authentication/read endpoints and explicit failures |
| Wazuh indexer | Historical alert, authentication, process and FIM events | Separate endpoint/credentials, allowed indices, pagination and event coverage |
| Sysmon, Velociraptor, Volatility 3, Sleuth Kit, browser exports | Endpoint and acquired forensic artifacts | Authorized acquisition/import, hashes, custody and parser/version records |
| Zeek, Suricata, firewall and proxy exports | Passive connections, DNS, traffic and network configuration | Vantage, retention, incident scope and read-only import |
| Microsoft Graph and Microsoft 365 trace exports | Directory/sign-ins and email delivery evidence | Provider-specific scopes, retention/licensing checks and data policy |
| VirusTotal and AbuseIPDB | Hash/IP reputation only | Indicator egress policy, source timestamps and rate-limit/error tests |
| AWS CloudTrail, inventory and S3 evidence | Account/resource changes, serverless and storage observations | Account/region binding, data-event coverage and read-only credentials |
| Docker/Kubernetes and hypervisor exports | Runtime/control-plane inventory and audit | Separate cluster/host controls; no command execution or Secret values |
| Kismet, MDM, IoT and passive OT exports | Environment-specific device and protocol evidence | Dedicated authorized collection; generic host tools do not establish coverage |
| Repository, CI/CD, SBOM and redacted secret-scan exports | Commit/build/artifact and dependency evidence | Stable revisions, digest/provenance checks and redaction |
| Database, SaaS, certificates, AI gateway and integrity exports | Object-access, policy and application evidence | Provider-specific collection/read contracts and trustworthy baselines |

The [Wazuh server API](https://documentation.wazuh.com/current/user-manual/api/index.html) and [Wazuh indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/index.html) are separate integration candidates. Historical alert search belongs to the indexer contract, not a presumed manager `/alerts/{id}` route. [Microsoft Graph sign-in reads](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0) and [AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html) offer documented evidence-source interfaces; Terminus integration and acceptance remain pending. Other named products are adapter/artifact-import candidates without compatibility or deployment claims.

## Existing-code gaps

- `tools/siem_search.py` returns a fixed `query_prior_events` sequence and can fabricate an active host in `get_host_context` after an exception. Neither is admissible live evidence. Replace both with source queries and explicit error/gap results before adapter wiring.
- `siem/wazuh.py` has manager authentication and agent reads. Its alert route is not proof of indexer search; errors collapsed to `unknown` need typed failures. Manager connectivity does not establish historical event coverage.
- `siem/static.py` returns fixtures. Keep simulations labeled and isolated from live acceptance.
- `tools/threat_intel.py` contains VirusTotal hash and AbuseIPDB IP calls plus offline signature heuristics. GreyNoise credentials alone do not implement a GreyNoise request. Heuristics/address classification cannot substitute for provider reputation. Policy, timestamps, limits and provenance remain pending.
- `tools/deobfuscator.py` is a real local text decoder. It needs a bounded wrapper and source references; suspicious strings establish neither execution nor malicious impact.
- Specialist handlers, query/result adapters, credential policy, backend admission, artifact imports and independent real-lab checks remain later dependencies. Catalog parsing proves consistency only. Activation requires [FUTURE_SCOPE.md](FUTURE_SCOPE.md) and [MVP_RELEASE.md](MVP_RELEASE.md) release gates.
