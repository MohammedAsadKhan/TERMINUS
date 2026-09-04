# Agentic SOC Solution — Design Document

**Status:** MVP-1 (in development)
**Version:** 0.1.0
**Team:** Mohammed (Mo), ejr9090, SH3EEESH, Misha, Noah, sell

---

## 1. Problem

Small and mid-size businesses use a SIEM (Wazuh) but cannot afford a 24/7 SOC analyst
team. Alerts pile up, high-severity incidents get lost in the noise, and when an incident
is real, responding takes too long and often requires a vendor call.

**Value proposition:** An AI investigation agent that sits on top of a Wazuh SIEM,
triage-and-investigates every alert, produces a human-readable report with a confidence
and severity verdict, and pushes a ticket + notification to the right person. Humans
stay in the loop for anything that changes state.

## 2. Principles

1. **Human-in-the-loop for anything that mutates state.** Investigate and notify are
   automatic *only* for reversible actions. Lockdown / isolation (irreversible) requires
   human approval.
2. **Reversible-first.** MVP-1 ships only investigation + ticket + notification. Host
   isolation is a later milestone behind an explicit approval gate.
3. **Runs fully offline.** The school/enterprise network is isolated. No CDN or external
   service may be required at runtime. The LLM layer is provider-agnostic so it can point
   at OpenCode Go, a local Ollama on Mohammed's 3080, or Groq as a backup.
4. **Provider-agnostic everywhere.** SIEM, LLM, notifier, and ticketing are each behind a
   `Protocol` so we can swap implementations without touching the core pipeline.
5. **Strict, typed Python.** Pydantic v2 at every trust boundary, frozen dataclasses
   internally, exhaustive `match`, zero `Any` / `# type: ignore`.

## 3. Architecture

```
                     ┌──────────────────────────────────────────────┐
                     │            Wazuh SIEM (self-hosted)          │
                     │   ingest ← vulnerable Apache VM (bridged)     │
                     └───────────────┬──────────────────────────────┘
                                     │ alert webhook (JSON)
                                     ▼
                     ┌──────────────────────────────────────────────┐
                     │      FastAPI listener  (src/terminus/server) │
                     │        POST /wazuh  → parse alert → enqueue   │
                     └───────────────┬──────────────────────────────┘
                                     ▼
                     ┌──────────────────────────────────────────────┐
                     │        Policy Engine  (src/terminus/policies)│
                     │   decides tier: ignore / triage / escalate    │
                     └───────────────┬──────────────────────────────┘
                                     ▼
                     ┌──────────────────────────────────────────────┐
                     │      Investigation Agent  (src/terminus/agent)│
                     │  tools: wazuh (alert/agent context),          │
                     │         virustotal, mitre lookup              │
                     │  → LLM verdict (severity, confidence, summary)│
                     └───────────────┬──────────────────────────────┘
                                     ▼
                     ┌──────────────────────────────────────────────┐
                     │        Action layer (reversible only)        │
                     │  TicketStore (Jira / memory)                  │
                     │  Notifier   (SMS→936-499-2155, Slack, log)    │
                     └──────────────────────────────────────────────┘
```

### Components

| Component | Responsibility | Module |
|---|---|---|
| **Listener** | Receives Wazuh alert webhooks, parses untrusted JSON into a typed `SiemAlert`, enqueues for processing. | `server/` |
| **Policy Engine** | Maps alert (rule id, level, MITRE) → `Tier` (triage/escalate) and the action set to run. Pure, testable, no I/O. | `policies/` |
| **Investigation Agent** | Runs the investigation loop: gather evidence (Wazuh agent/alerts, VirusTotal for hashes/URLs), then ask the LLM for a structured verdict. | `agent/` |
| **Action Layer** | Executes reversible actions: creates a ticket and sends a notification. Both via `Protocol`s so real adapters can be swapped in. | `notifiers/`, `ticketing/` |

### Integration surfaces (all behind Protocols)

- **SIEM:** `WazuhClient` (REST API: agents + alerts). Test/sim path uses a `StaticSiem` fed from fixture JSON.
- **LLM:** `OpenAiCompatibleLlm` — speaks the OpenAI-compatible `/chat/completions`
  REST shape, so it works against OpenCode Go, Ollama, Groq, or any OpenAI-compatible
  endpoint by changing `base_url` + `model` + `api_key`. Structured JSON verdict via
  `response_format={"type": "json_object"}`.
- **Notifier:** `Notifier` protocol. Implementations: `LogNotifier` (always on, prints the
  exact message that would be sent), `TwilioSmsNotifier` (SMS → **936-499-2155**),
  `SlackNotifier` (incoming webhook). Composite notifier fans out to multiple.
- **Ticketing:** `TicketStore` protocol. Implementations: `MemoryTickets` (in-memory store
  for sim/tests), `JiraTickets` (Jira REST API for production).

## 4. Tech Stack

| Layer | Choice | Justification |
|---|---|---|
| Language | Python 3.12 | Installed; team familiarity |
| Package mgr | `uv` | Fast, lockfile, toolchain |
| Web | FastAPI | Async, Pydantic-native, OpenAPI |
| HTTP client | `httpx2[http2,brotli,zstd]` | Mandated, HTTP/2 + tuned pool |
| Validation | Pydantic v2 | Boundary parsing |
| Config | `pydantic-settings` | Env-driven, typed |
| Async | `anyio` | Forced over bare asyncio |
| Type check | `basedpyright` (`all`) | Strictest |
| Lint/fmt | `ruff` (`ALL`) | Strict |
| Tests | `pytest` | Standard |
| LLM client | thin OpenAI-compatible client (httpx2) | Provider-agnostic, no framework lock-in, testable with a fake transport |

## 5. MVP-1 Scope (this milestone)

**In scope (pipeline + platform foundations):**
- [x] Typed alert ingest (SiemAlert) + FastAPI `/wazuh` webhook (org-scoped)
- [x] Config from env (LLM provider, Wazuh, SMS recipient, Slack, Jira, license/token secret)
- [x] **Org platform:** Organization + membership + multi-tenancy scoping
- [x] **Auth:** user registration/login, bearer sessions, role-based access (admin/member/viewer)
- [x] **Licensing:** HMAC-signed license generation + validation, tier entitlement matrix
- [x] **Composition:** `Deployment` wires an org's LLM/SIEM/notifier/store/policy by constructor injection
- [x] Policy engine (triage vs escalate, rule-driven)
- [x] Investigation agent: gathers evidence, LLM verdict (severity/confidence/summary/actions)
- [x] Reversible actions: ticket (memory impl) + notification (log + Twilio/Slack adapters)
- [x] Offline simulation runner (`uv run terminus-simulate`) that drives a sample alert end-to-end
- [x] Unit + integration tests, TDD

**Explicitly deferred (NOT in MVP-1):**
- Wazuh active response / automated host lockdown (tier-3, human-approval) — **M2**
- Web dashboard (RED→GREEN) — **M3**
- Persistence (SQLAlchemy + Postgres), dedup, alert correlation — **M3**
- Real Jira/Twilio live wiring — once creds are provided (`JiraTickets`, `TwilioSmsNotifier` exist, just unconfigured)
- Billing / payments / Stripe — **M3** (license *generation* ships now; payment capture later)
- Email verification, password reset, SSO — **M3**

## 6. Tiers & Human-in-the-Loop

| Tier | Action set | Auto? | Example |
|---|---|---|---|
| **T0 – Ignore** | none | auto | benign, known-baseline events |
| **T1 – Triage** | ticket + notify | auto | medium confidence, non-destructive |
| **T2 – Escalate** | ticket + notify (urgent) | auto | high severity/confidence |
| **T3 – Isolate** (deferred) | host lockdown | **human approval required** | confirmed compromise |

MVP-1 implements T0/T1/T2. T3 is designed-for but not wired.

## 7. Product Platform (SaaS / MSP)

This is a **commercial product**, not a single-tenant pipeline. The core investigation
engine is the value, but delivery requires a tenant/org platform around it.

### 7.1 Multi-tenancy

One `terminus` server hosts many **Organizations** (businesses). Each organization owns:

- **Users** (people who log in / act on its alerts),
- **License** (its paid tier + entitlement),
- **Deployment** (the wired pipeline pointing at *that org's* Wazuh).

The tenancy seam is `src/terminus/orgs/`. Every resource query is scoped by an
`OrganizationId`; no document/alert crosses org boundaries.

### 7.2 Organizations & members

| Concept | Notes |
|---|---|
| `Organization` | name, id, license ref, created/updated |
| `Membership` | binds a `User` to an `Organization` with a `OrgRole` |
| Roles | `admin` (manage users/license/billing), `member` (investigate/act), `viewer` (read-only) |

Domain rules enforced in `OrganizationService`: an org cannot be deleted while it has
members; you cannot remove the last admin; role changes are audit-logged.

### 7.3 User management & authentication

- Users are platform-wide identities; **org membership** is separate from authentication.
- **AuthN:** register/login issues a bearer `SessionToken` (opaque, stored in a
  `UserStore` backed by memory now, Postgres later). Passwords stored as salted hashes
  (never plaintext).
- **AuthZ:** FastAPI dependency resolves token → user → org role and enforces required
  role per route (admin/member/viewer).
- A user may belong to multiple orgs; the token carries which org context is active.

### 7.4 License generation

Licenses are **signed** so they can be validated without a round-trip to the server
(matters for offline air-gapped deployments).

| Concept | Notes |
|---|---|
| `LicenseTier` | `trial`, `standard`, `enterprise` |
| License payload | org, tier, `not_before`, `expires_at`, `max_seats`, feature flags |
| Signing | HMAC-SHA256 over the canonical payload with a server-held `LICENSE_SECRET`; the license string is `payload_base64.signature_hex` |
| Validation | `LicenseService.validate()` re-derives the HMAC (tamper-proof), checks expiry + active tier |
| Feature flags | e.g. `automated_actions`, `sla_priority`, `custom_policy` gate pipeline capability per tier |

`LicenseTier` → feature mapping lives in `licensing/tiers.py` so policy code asks
"does this deployment's license allow X?" instead of hard-coding tiers.

### 7.5 OOP design principles (applied throughout)

Class-first, layered, polymorphic. Every component is an object with an interface.

1. **Abstraction** — domain services expose narrow, well-named public methods; callers
   never touch internals.
2. **Polymorphism** — one interface, many implementations. `SiemClient`
   (Wazuh/Static), `Notifier` (Log/Slack/Twilio), `TicketStore` (Memory/Jira),
   `LlmClient` (OpenAI-compatible/mock). Router code depends on the interface, never an
   implementation.
3. **Composition over inheritance** — a `Deployment` *owns* its injected components
   (LLM, SIEM, notifier, store, policy engine) rather than subclassing them. Swap by
   constructor injection.
4. **Encapsulation** — private state (`_`-prefixed), no leaking of internal structures;
   objects expose behavior, not fields.
5. **Inheritance only where it earns its keep** — shared implementation via `ABC`
   (`Repository` base gives `create`/`get` memory semantics), shape-only via `Protocol`.
6. **Single responsibility** — each class owns exactly one concern (a `Pipeline` is not a
   `LicenseService`).

This is deliberately *not* functional-style or procedural: the codebase is organized
around objects and their collaborations.

```
softengproj/
├── DESIGN.md
├── README.md
├── pyproject.toml
├── .gitignore
├── src/terminus/
│   ├── __init__.py
│   ├── config.py            # pydantic-settings (env-driven)
│   ├── models.py            # SiemAlert, Verdict, Tier, etc. (Pydantic/enums)
│   ├── http.py              # httpx2 client factory (canonical defaults)
│   ├── core/                # shared OOP foundations (ABCs, repositories, services)
│   │   ├── __init__.py
│   │   ├── base.py          # Repository ABC + Service ABC
│   │   └── ids.py           # branded IDs (OrgId, UserId, TicketId, ...)
│   ├── licensing/           # license generation + validation
│   │   ├── __init__.py
│   │   ├── models.py        # License, LicenseTier, Feature flags
│   │   ├── tiers.py         # tier -> feature entitlement matrix
│   │   ├── crypto.py        # HMAC-SHA256 signing/verifying
│   │   └── service.py       # LicenseService (generate/validate)
│   ├── auth/                # user management + authN/authZ
│   │   ├── __init__.py
│   │   ├── models.py        # User, SessionToken, hashed password
│   │   ├── password.py      # salted password hashing
│   │   └── service.py       # AuthService (register/login/verify, role checks)
│   ├── orgs/                # multi-tenancy
│   │   ├── __init__.py
│   │   ├── models.py        # Organization, OrganizationRole, Membership
│   │   ├── store.py         # OrganizationStore (memory) + Repository impl
│   │   └── service.py       # OrganizationService (domain rules)
│   ├── llm/
│   │   ├── __init__.py
│   │   ├── base.py          # LlmClient protocol
│   │   ├── client.py        # OpenAiCompatibleLlm (chat/completions + json_object)
│   │   └── verdict.py       # prompt builder + Verdict parse
│   ├── siem/
│   │   ├── __init__.py
│   │   ├── base.py          # SiemClient protocol
│   │   ├── wazuh.py         # WazuhClient (REST)
│   │   └── static.py        # StaticSiem (fixture/offline)
│   ├── notifiers/
│   │   ├── __init__.py
│   │   ├── base.py          # Notifier protocol + CompositeNotifier
│   │   ├── log.py           # LogNotifier
│   │   ├── slack.py         # SlackNotifier
│   │   └── twilio.py        # TwilioSmsNotifier → 936-499-2155
│   ├── ticketing/
│   │   ├── __init__.py
│   │   ├── base.py          # TicketStore protocol + Ticket
│   │   ├── memory.py        # MemoryTickets
│   │   └── jira.py          # JiraTickets
│   ├── policies/
│   │   ├── __init__.py
│   │   └── engine.py        # PolicyEngine: alert → Tier + action set
│   ├── agent/
│   │   ├── __init__.py
│   │   ├── tools.py         # evidence gathering (siem + virustotal + mitre)
│   │   └── investigator.py  # Investigator: orchestrates evidence → verdict
│   ├── pipeline/
│   │   ├── __init__.py
│   │   ├── deployment.py    # Deployment: composes per-org components
│   │   └── runner.py        # PipelineRunner: alert → policy → investigate → act
│   ├── server/
│   │   ├── __init__.py
│   │   ├── app.py           # FastAPI platform: auth, orgs, licenses, webhook
│   │   ├── deps.py          # FastAPI dependencies (authN/authZ, resource scoping)
│   │   └── routers.py       # /auth, /orgs, /licenses, /wazuh, /health
│   └── simulate.py          # offline e2e runner (uv run terminus-simulate)
├── data/
│   └── sample_alert.json    # sample Wazuh alert for offline sim
└── tests/
    ├── test_models.py
    ├── test_licensing.py
    ├── test_auth.py
    ├── test_orgs.py
    ├── test_policies.py
    ├── test_investigator.py
    └── test_e2e_simulate.py
```

## 9. Success Criteria (MVP-1)

| Var | Default | Purpose |
|---|---|---|
| `TERMINUS_LLM_BASE_URL` | `https://opencode.ai/zen/go/v1` | OpenAI-compatible endpoint (OpenCode Go) |
| `TERMINUS_LLM_API_KEY` | *(empty)* | API key (OpenCode Go / Groq / none for Ollama) |
| `TERMINUS_LLM_MODEL` | `deepseek-v4-flash` | Model name |
| `TERMINUS_WAZUH_URL` | *(empty)* | Wazuh REST base URL |
| `TERMINUS_WAZUH_USER` / `_PASS` | *(empty)* | Wazuh basic auth |
| `TERMINUS_SMS_TO` | `9364992155` | Alert SMS recipient |
| `TERMINUS_TWILIO_SID` / `_TOKEN` / `_FROM` | *(empty)* | Twilio creds (SMS off until set) |
| `TERMINUS_SLACK_WEBHOOK` | *(empty)* | Slack incoming webhook (off until set) |
| `TERMINUS_JIRA_URL` / `_USER` / `_TOKEN` / `_PROJECT` | *(empty)* | Jira creds (off until set) |
| `TERMINUS_LICENSE_SECRET` | *(auto-generated)* | HMAC secret used to sign/verify licenses |
| `TERMINUS_TOKEN_SECRET` | *(auto-generated)* | Secret for hashing session tokens |

## 9. Success Criteria (MVP-1)

1. `uv run simulate` ingests `data/sample_alert.json`, runs policy + investigation, prints
   a verdict, creates a ticket (memory store), and emits a notification to the log — all
   offline, no network required.
2. `uv run pytest` passes (unit + e2e scenario).
3. `uv run basedpyright` and `uv run ruff check` pass with zero errors.
4. With real creds present, the same pipeline emits an SMS to 936-499-2155 and can create
   a Jira ticket — driven purely by config, no code change.
5. Human-in-the-loop invariant: MVP-1 performs **no** irreversible action.
