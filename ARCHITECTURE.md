# Terminus System Architecture & Technical Specification

## Overview

Terminus is an autonomous, multi-tenant Security Operations Center (SOC) incident investigation platform. It acts as an intelligence layer on top of SIEM solutions (such as **Wazuh**), converting raw alert floods into actionable, triaged tickets.

---

## High-Level Pipeline Data Flow

```
                      +-----------------------------+
                      |   SIEM Webhook (Wazuh 4.x)  |
                      +--------------+--------------+
                                     | POST /wazuh (SiemAlert)
                                     v
                      +-----------------------------+
                      |    FastAPI Boundary Layer   |
                      |  - Header Resolution        |
                      |  - Session / Tenant Check   |
                      +--------------+--------------+
                                     |
                                     v
                      +-----------------------------+
                      |   Policy Engine (Fast Triage)|
                      |  - Level < 5:  IGNORE       |
                      |  - Level 5-9: TRIAGE       |
                      |  - Level >=10: ESCALATE     |
                      +--------------+--------------+
                                     | (If Should Investigate)
                                     v
                      +-----------------------------+
                      |   Investigation Agent       |
                      |  - Evidence Collector       |
                      |  - LLM Reasoning Engine     |
                      |  - Verdict Parser           |
                      +--------------+--------------+
                                     |
                                     +----------------------+
                                     |                      |
                                     v                      v
                      +---------------------+ +---------------------+
                      |    Ticket Store     | | Multi-Channel Notif |
                      | (Memory / Database) | | (Slack / SMS / Log) |
                      +----------+----------+ +---------------------+
                                 |
                                 v
                      +---------------------+
                      |  Analyst Dashboard  |
                      |  (GET /incidents)   |
                      +---------------------+
```

---

## Core Technical Layers

### 1. HTTP Boundary & Ingestion (`terminus.server`)
- FastAPI handles HTTP `POST /wazuh` requests.
- Pydantic models validate raw JSON into standard `SiemAlert` value objects.
- Multi-tenant tenant ID (`OrgId`) is extracted from headers (`X-Org-ID`) or defaults seamlessly for open webhook integrations.

### 2. Deterministic Policy Engine (`terminus.policies`)
- A zero-latency, pure rule evaluation engine (`PolicyEngine`).
- Evaluates threat severity levels before triggering external LLM reasoning calls, protecting API token budgets and preventing denial-of-wallet attacks.

### 3. AI Investigation Agent (`terminus.agent`)
- Gathers structured evidence (`Evidence`) from alert logs, host attributes, and MITRE tactics.
- Prompts the LLM engine to perform forensic reasoning and output a validated JSON schema containing:
  - Severity (`low`, `medium`, `high`, `critical`)
  - Confidence rating (`low`, `medium`, `high`)
  - Human-readable forensic summary
  - Recommended containment actions

### 4. Persistence & Ticketing Layer (`terminus.ticketing`)
- Thread-safe storage abstraction (`TicketStore`) maintaining investigation tickets and audit trails.
- Supports `MemoryTickets` for high-throughput zero-dependency operation, easily pluggable to PostgreSQL/SQLite backends.

### 5. Multi-Tenant SaaS & Cryptographic Licensing (`terminus.orgs`, `terminus.licensing`)
- Cryptographic HMAC-SHA256 license token signing and validation with expiration enforcement.
- Feature gating across `COMMUNITY`, `PRO`, and `ENTERPRISE` tiers.
- Role-Based Access Control (RBAC) and seat tracking per organization.
