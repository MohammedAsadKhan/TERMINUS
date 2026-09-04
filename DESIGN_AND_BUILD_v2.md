# DESIGN_AND_BUILD_v2.md — Agentic SOC Platform Master Architectural Blueprint (v2.0 Ultimate)

> **Document Status:** Comprehensive, Decision-Complete Deep Specification.
> **Scope:** Full product architecture combining core MVP pipeline, 6 Market-Dominating Innovations, 10 Enterprise Production Features, 5 Specialized SOC Operations, Database Schemas, IAM Adapters, PII Sanitizer Pipelines, State Machine Specifications, and Web UI Protocols.

---

## 0. Executive Summary & Core Platform Invariants

Build `src/terminus` — a multi-tenant **Agentic SOC Platform** for enterprise security teams and Managed Service Providers (MSPs). An AI agent ingests Wazuh SIEM alerts, correlates multi-event attack timelines over 30-day windows, performs active endpoint forensics, anonymizes PII, detonates unknown binaries in sandboxes, generates structured verdicts, and executes reversible safety-leased actions (tickets, notifications, dynamic active response, identity session revocation).

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    TERMINUS ARCHITECTURE ENGINE                                  │
└────────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                 │
      ┌──────────────────────────────────────────┼──────────────────────────────────────────┐
      ▼                                          ▼                                          ▼
┌───────────────────────────┐      ┌───────────────────────────┐      ┌───────────────────────────┐
│     Ingestion & Graph     │      │     AI Forensics Loop     │      │  Safety Leases & Action   │
├───────────────────────────┤      ├───────────────────────────┤      ├───────────────────────────┤
│ • Wazuh Webhook Listener  │      │ • Groq Llama 3.3 70B      │      │ • 15-Min Dynamic Leases   │
│ • 5-Min Dedup Window      │ ───► │ • DeepSeek R1 / V3        │ ───► │ • Active Response Revert  │
│ • Asset Criticality Tags  │      │ • Zero-Knowledge PII Token│      │ • Identity Session Reset  │
│ • 30-Day Attack Graph     │      │ • OSQuery Live Queries    │      │ • React Command Dashboard │
│ • Sandbox Detonation      │      │ • Few-Shot RLHF Vector RAG│      │ • SOC2 / CMMC Audit PDFs  │
└───────────────────────────┘      └───────────────────────────┘      └───────────────────────────┘
```

---

## 1. Complete Relational Database Schema (SQLModel / Async SQLAlchemy)

The persistence layer uses a dual-mode Async SQLAlchemy Engine (SQLite for dev/tests, PostgreSQL for production scale). Below is the complete relational schema specification:

```sql
-- Organizations (Tenants)
CREATE TABLE organizations (
    org_id VARCHAR(32) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    license_ref TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Users (Platform Identities)
CREATE TABLE users (
    user_id VARCHAR(32) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    totp_secret VARCHAR(64),
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Memberships (Org Tenancy Scoping)
CREATE TABLE memberships (
    membership_id VARCHAR(32) PRIMARY KEY,
    org_id VARCHAR(32) NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    user_id VARCHAR(32) NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role VARCHAR(32) NOT NULL, -- admin, member, viewer
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT uq_org_user UNIQUE (org_id, user_id)
);

-- Assets (Inventory & Criticality Tagging)
CREATE TABLE assets (
    asset_id VARCHAR(32) PRIMARY KEY,
    org_id VARCHAR(32) NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    criticality INTEGER NOT NULL DEFAULT 5, -- 1 (Low) to 10 (Critical)
    business_role VARCHAR(100), -- PCI-DB, Domain-Controller, Web-Server, Dev-Laptop
    owner_email VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Alerts (Ingested & Parsed Telemetry)
CREATE TABLE alerts (
    id VARCHAR(64) PRIMARY KEY,
    org_id VARCHAR(32) NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    rule_id INTEGER NOT NULL,
    level INTEGER NOT NULL,
    description TEXT,
    mitre_id VARCHAR(32),
    agent_id VARCHAR(64),
    agent_name VARCHAR(255),
    src_ip VARCHAR(45),
    raw_payload JSONB NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Incidents (Correlated Multi-Alert Attack Graphs)
CREATE TABLE incidents (
    incident_id VARCHAR(32) PRIMARY KEY,
    org_id VARCHAR(32) NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    primary_alert_id VARCHAR(64) REFERENCES alerts(id),
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(32) NOT NULL, -- low, medium, high, critical
    status VARCHAR(32) NOT NULL, -- new, investigating, pending_approval, resolved, closed
    attack_chain JSONB, -- Array of correlated alert IDs & MITRE steps
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Action Leases (Reversible Safety-Leased Containment)
CREATE TABLE action_leases (
    lease_id VARCHAR(32) PRIMARY KEY,
    org_id VARCHAR(32) NOT NULL REFERENCES organizations(org_id) ON DELETE CASCADE,
    incident_id VARCHAR(32) REFERENCES incidents(incident_id),
    action_type VARCHAR(64) NOT NULL, -- isolate_host, block_ip, revoke_session
    target_identifier VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL, -- leased_active, auto_reverted, extended, approved_permanent, rejected
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    active_script TEXT,
    revert_script TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Audit Logs (Immutable Event Ledger)
CREATE TABLE audit_logs (
    audit_id VARCHAR(32) PRIMARY KEY,
    org_id VARCHAR(32) NOT NULL REFERENCES organizations(org_id),
    actor_id VARCHAR(32) NOT NULL,
    action_type VARCHAR(100) NOT NULL,
    target_resource VARCHAR(255) NOT NULL,
    details JSONB,
    event_hash VARCHAR(64) NOT NULL, -- Cryptographic link to prior event
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL
);
```

---

## 2. The Action Lease State Machine (`agent/approval.py`)

Every high-risk containment operation follows a strict, formal state machine enforcing **Safety Leases**:

```
                  ┌───────────────────────────────┐
                  │    Trigger High-Risk Action   │
                  └───────────────┬───────────────┘
                                  │
                                  ▼
                  ┌───────────────────────────────┐
                  │      LEASED_ACTIVE (15m)      │
                  │ Dynamic Active Response Exec  │
                  └───────────────┬───────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         │ (15 mins elapse)       │ (Analyst Click)        │ (Analyst Click)
         ▼                        ▼                        ▼
┌─────────────────┐      ┌─────────────────┐      ┌─────────────────┐
│ AUTO_REVERTED   │      │ APPROVED_PERM   │      │ REJECTED        │
│ Active Response │      │ Lease Extended  │      │ Immediate Revert│
│ Script Undone   │      │ Permanently     │      │ Script Executed │
└─────────────────┘      └─────────────────┘      └─────────────────┘
```

### Invariants:
1. When an active response is triggered, `active_script` is executed immediately and an `anyio` timer task is scheduled for `expires_at`.
2. If `expires_at` is reached without human analyst intervention, the background task executes `revert_script` and transitions state to `AUTO_REVERTED`.
3. Analysts can click **Approve Permanent** (cancels lease timer, retains rule), **Extend +15m** (adds 900 seconds to timer), or **Reject Now** (immediately executes `revert_script`).

---

## 3. PII Anonymization & Zero-Knowledge Tokenizer Pipeline (`llm/sanitizer.py`)

To prevent internal network IPs, usernames, and hostnames from leaking to external cloud LLM APIs, `terminus` uses a two-pass **Zero-Knowledge Sanitizer**:

```python
class PiiSanitizer:
    """Tokenizes sensitive network data before LLM dispatch and re-hydrates responses."""
    
    def sanitize(self, text: str) -> tuple[str, dict[str, str]]:
        # Replaces internal IPs (10.x, 172.16-31.x, 192.168.x) -> [IP_TOKEN_1]
        # Replaces internal domains (*.internal, *.local) -> [HOST_TOKEN_1]
        # Replaces corporate emails -> [USER_TOKEN_1]
        # Returns (sanitized_prompt, token_mapping_dict)
        ...

    def rehydrate(self, llm_output: str, token_mapping: dict[str, str]) -> str:
        # Replaces tokens [IP_TOKEN_1] back to real IP addresses for display in Web UI
        ...
```

---

## 4. Identity & Session Revocation Adapters (`agent/identity.py`)

When an identity compromise is detected, `terminus` interfaces directly with Identity Providers (IdPs):

1. **Microsoft Entra ID (Azure AD) Adapter**:
   - Uses Microsoft Graph API (`POST /v1.0/users/{id}/revokeSignInSessions`).
   - Forces password reset (`PATCH /v1.0/users/{id}` with `forceChangePasswordNextSignIn: true`).
2. **Active Directory On-Prem LDAP / WinRM Adapter**:
   - Executes PowerShell `Revoke-ADUserSession` and sets `pwdLastSet = 0`.
3. **Okta API Adapter**:
   - Issues `POST /api/v1/users/{id}/lifecycle/expire_password` and clears active user sessions.

---

## 5. Web UI Real-Time SSE Protocol & React Architecture (`web/`, `server/sse.py`)

The Analyst Command Center Web UI is a React + Vite SPA served via static files from FastAPI. Real-time updates use **Server-Sent Events (SSE)** at `/api/v1/sse/alerts`:

### SSE Event Payload Types:
```json
// Event: "alert_ingested"
{
  "event_type": "alert_ingested",
  "data": {
    "alert_id": "alert-9912",
    "rule_id": 5710,
    "level": 9,
    "agent_name": "prod-db-01",
    "timestamp": "2026-09-04T01:20:00Z"
  }
}

// Event: "lease_created"
{
  "event_type": "lease_created",
  "data": {
    "lease_id": "lease-4410",
    "action_type": "isolate_host",
    "target": "prod-db-01",
    "expires_at": "2026-09-04T01:35:00Z"
  }
}
```

---

## 6. Default Configuration & API Credentials

```ini
# Groq & OpenCode API Credentials
TERMINUS_GROQ_API_KEY=gsk_your_groq_api_key_here
TERMINUS_OPENCODE_API_KEY=sk_your_opencode_api_key_here

# Model Selection
TERMINUS_LLM_PROVIDER=groq
TERMINUS_LLM_BASE_URL=https://api.groq.com/openai/v1
TERMINUS_LLM_MODEL=llama-3.3-70b-versatile

# Deduplication & Safety Lease Settings
TERMINUS_DEDUP_WINDOW_SECONDS=300
TERMINUS_LEASE_DURATION_SECONDS=900
TERMINUS_RETENTION_DAYS=90
```

---

## 7. Master File Directory Layout (`src/terminus/`)

```
src/terminus/
├── agent/
│   ├── approval.py       # ActionLease state machine & background expiration timers
│   ├── identity.py       # Azure AD, Active Directory & Okta session revokers
│   ├── investigator.py   # InvestigationAgent coordinating evaluation
│   └── tools.py          # InvestigationTools (OSQuery, Wazuh Active Response, VT)
├── auth/
│   ├── models.py         # User, Session, Membership models
│   ├── password.py       # PBKDF2 salted hashing
│   ├── service.py        # AuthService (registration, login, sessions)
│   └── totp.py           # TOTP 2FA verification engine
├── config.py             # Settings (pydantic-settings, TERMINUS_ prefix)
├── core/
│   ├── audit.py          # Immutable AuditLog store with event hashing
│   ├── base.py           # Repository[T] ABC, MemoryRepository[T], Service
│   ├── ids.py            # Branded primitives (OrgId, UserId, TicketId, LeaseId, etc.)
│   ├── retention.py      # Background data retention purge worker
│   └── sql_repo.py       # SQLRepository[T] (Postgres & SQLite async implementation)
├── graph/
│   └── timeline.py       # Temporal Entity Attack Graph Engine (30-day sliding window)
├── http.py               # Standardized httpx2 client factory
├── licensing/
│   ├── crypto.py         # HMAC-SHA256 sign/encode/decode
│   ├── models.py         # License model
│   ├── service.py        # LicenseService
│   └── tiers.py          # LicenseTier feature mapping & seat limits
├── llm/
│   ├── base.py           # LlmClient Protocol, LlmError
│   ├── client.py         # OpenAiCompatibleLlm, ScriptedLlm, CircuitBreaker
│   ├── memory.py         # Few-shot RLHF vector memory store
│   ├── sanitizer.py      # Zero-Knowledge PII Anonymizer
│   └── verdict.py        # SOC Analyst prompt builder & VerdictParser
├── models.py             # SiemAlert, Verdict, PolicyResult, Evidence, ActionLease, Asset
├── notifiers/
│   ├── base.py           # Notifier Protocol
│   ├── builder.py        # CompositeNotifier fan-out
│   ├── log.py            # LogNotifier
│   ├── pagerduty.py      # PagerDutyNotifier
│   ├── slack.py          # SlackNotifier
│   ├── twilio.py         # TwilioSmsNotifier
│   └── webhook.py        # GenericWebhookNotifier
├── orgs/
│   ├── assets.py         # Asset Inventory & Criticality Tagging store
│   ├── models.py         # Organization, Membership, OrganizationRole
│   ├── service.py        # OrganizationService
│   └── store.py          # OrganizationStore, MembershipStore
├── pipeline/
│   ├── dedup.py          # Sliding window alert deduplication engine
│   ├── deployment.py     # PipelineDeployment container
│   └── runner.py         # PipelineRunner orchestrator
├── policies/
│   └── engine.py         # PolicyEngine (static + dynamic YAML rule parser)
├── reports/
│   ├── analytics.py      # MTTD, MTTI, MTTR & cost savings KPI calculator
│   ├── compliance.py     # Audit PDF/Markdown compliance generator
│   └── rca.py            # Post-Incident Root Cause Analysis generator
├── server/
│   ├── app.py            # FastAPI app factory create_app() & main()
│   ├── deps.py           # Dependency injection container
│   ├── routers.py        # REST routers (Auth, Orgs, License, Webhook, Approvals, Assets)
│   └── sse.py            # Real-time SSE alert streaming router
├── siem/
│   ├── base.py           # SiemClient Protocol
│   ├── static.py         # StaticSiemClient (JSON fixtures)
│   └── wazuh.py          # WazuhClient REST API client
├── simulate.py           # Standalone CLI simulator runner
├── ticketing/
│   ├── base.py           # TicketStore Protocol
│   ├── jira.py           # JiraTickets REST adapter
│   └── memory.py         # MemoryTickets store
├── tools/
│   └── sandbox.py        # CAPE / Hybrid Analysis / Cuckoo sandbox submitter & report parser
└── web/
    ├── static/           # CSS/JS React command center dashboard assets
    └── templates/        # HTML templates
```
