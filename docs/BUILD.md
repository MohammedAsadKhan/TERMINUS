# BUILD.md — Agent-Executable Build Specification

> **Read this first.** This is the decision-complete work package for building the Agentic
> SOC platform. It is intentionally prescriptive: every contract, signature, endpoint, and
> file is specified so the builder executes **without asking the user questions**. The
> builder resolves ambiguity using: (1) the fixed defaults given here, (2) its own
> web/toolchain research, then (3) records each resolution as a one-line decision note in
> Section 18. Do not bounce anything back to the user unless the decision changes product
> scope or non-negotiable rules.
>
> `DESIGN.md` explains the *why*; this file is the *how*.
>
> **Scope discipline:** This file specifies MVP-1 only. Future milestones are listed in
> Section 17 (Roadmap) as expansion hooks — they are NOT in scope for this build.

---

## 0. Objective

Build `src/terminus` — a multi-tenant **Agentic SOC platform** for businesses. An AI agent
ingests Wazuh SIEM alerts, investigates them, and emits human-readable verdicts plus
reversible actions (ticket + notification). Around the engine sits a product platform:
**organizations** (multi-tenancy), **users/authN + role-based authZ**, and **HMAC-signed
license generation/validation**. Persistence is in-memory behind a `Repository` interface
(Postgres comes later in M3).

**Non-negotiable product rules:**
1. **Multi-tenant by organization.** Every resource is scoped by `OrgId`. No cross-org data.
2. **License generation + validation** are real, signed, tamper-evident.
3. **User management** with roles (`admin` / `member` / `viewer`) enforced on routes.
4. **It is a product for businesses** — org + member + license lifecycle is first-class.
5. **OOP principles, always.** Class-first layered design: abstraction, polymorphism,
   composition over inheritance, encapsulation, single responsibility.
6. **Human-in-the-loop for state-mutating actions.** MVP-1 performs NO irreversible action.

---

## 1. Toolchain & Environment

| Item | Decision |
|---|---|
| Language | Python `>=3.12` (3.12.7 installed) |
| Package manager | **uv** only (never pip/poetry/conda) |
| Layout | `src/terminus/` (src layout), hatchling build backend |
| Type checker | **basedpyright** `typeCheckingMode = "all"` (no `Any`, no `cast`, no `# type: ignore`) |
| Linter/formatter | **ruff** `select = ["ALL"]` |
| Tests | pytest (Given/When/Then, TDD red→green→refactor) |
| Async | **anyio** only — `import asyncio` is banned |
| HTTP client | **httpx2[http2,brotli,zstd]** — `import httpx2` (Pydantic-maintained fork of httpx, drop-in replacement) |
| Web | FastAPI + Pydantic v2 + pydantic-settings |
| Data | Pydantic v2 at trust boundaries; frozen dataclasses internally; enums; branded `NewType` IDs |
| LLM layer | Thin OpenAI-compatible client (~80 LOC). **No langchain / pydantic-ai / llama-index.** |

### Project deps (`pyproject.toml`)

```toml
[project]
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115",
    "uvicorn[standard]>=0.30",
    "pydantic>=2.9",
    "pydantic-settings>=2.6",
    "httpx2[http2,brotli,zstd]>=0.1",
    "anyio>=4.6",
]
# dev group:
#   basedpyright>=1.21, ruff>=0.8, pytest>=8, pytest-cov>=5, pytest-asyncio>=0.24
```

Two console scripts:
- `terminus-simulate = "terminus.simulate:main"`
- `terminus-serve = "terminus.server.app:main"`

Provide `.gitignore` and `.env.example` (documenting every `TERMINUS_*` var).

### File map (`src/terminus/`)

```
core/base.py  core/ids.py
licensing/{models,tiers,crypto,service}.py
auth/{models,password,service}.py
orgs/{models,store,service}.py
models.py  config.py  http.py
llm/{base,client,verdict}.py
siem/{base,wazuh,static}.py
notifiers/{base,log,slack,twilio,builder}.py
ticketing/{base,memory,jira}.py
policies/engine.py
agent/{tools,investigator}.py
pipeline/{deployment,runner}.py
server/{app,deps,routers}.py
simulate.py
data/sample_alert.json
```

`__init__.py` in every package (may be empty).

---

## 2. `config.py` — Settings

Prefix `TERMINUS_`. All fields have defaults → app boots offline with zero env vars.

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TERMINUS_", env_file=".env")

    # LLM
    llm_base_url: str = "https://api.groq.com/openai/v1"
    llm_api_key: str = ""
    llm_model: str = "llama-3.3-70b-versatile"

    # Wazuh
    wazuh_url: str = ""
    wazuh_user: str = ""
    wazuh_password: str = ""

    # Notifications
    sms_to: str = "9364992155"
    twilio_sid: str = ""
    twilio_token: str = ""
    twilio_from: str = ""
    slack_webhook: str = ""

    # Ticketing
    jira_url: str = ""
    jira_user: str = ""
    jira_token: str = ""
    jira_project: str = ""

    # Secrets (auto-generate + warn if empty)
    license_secret: str = ""
    token_secret: str = ""
```

If `license_secret` / `token_secret` are empty at first load, generate
`secrets.token_hex(32)` in-memory and log a warning.

Provide `get_settings()` (cached) and `reset_settings()` (for tests).

---

## 3. `core/` — OOP Foundations

**`core/ids.py`** — all branded IDs defined once, imported everywhere:
```python
OrgId = NewType("OrgId", str)
UserId = NewType("UserId", str)
TicketId = NewType("TicketId", str)
AgentId = NewType("AgentId", str)
RuleId = NewType("RuleId", int)
SessionToken = NewType("SessionToken", str)
LicenseId = NewType("LicenseId", str)
```

**`core/base.py`**
```python
class NotFoundError(LookupError): ...


class Repository(ABC, Generic[_RecordT]):
    @abstractmethod
    def create(self, record: _RecordT, org_id: OrgId) -> _RecordT: ...
    @abstractmethod
    def get(self, record_id: str, org_id: OrgId) -> _RecordT: ...
    @abstractmethod
    def list(self, org_id: OrgId) -> list[_RecordT]: ...


class MemoryRepository(Repository[_RecordT]):
    """Dict-backed, threading.Lock-protected generic repository."""

    # key = (org_id, record_id)
    # Enforces org isolation: get/list never return cross-org records.


class Service(ABC): ...  # marker base for domain services
```

> **Decision:** `create()` takes `org_id` as a separate parameter so tenancy isolation
> is enforced at the repository layer, not just inside individual record fields.

---

## 4. `models.py` — Pipeline Trust-Boundary Models

Pydantic `ConfigDict(frozen=True)`. `extra="allow"` ONLY on `SiemAlert`.
All other models `extra="forbid"`.

**Import `RuleId`, `AgentId` from `core.ids` — do NOT redefine them here.**

```python
from pydantic import AliasChoices, AliasPath


class SiemAlert(BaseModel):
    model_config = ConfigDict(frozen=True, extra="allow")

    id: str
    rule_id: RuleId = Field(
        validation_alias=AliasChoices(AliasPath("rule", "id"), "rule_id")
    )
    level: int = Field(
        validation_alias=AliasChoices(AliasPath("rule", "level"), "level")
    )
    description: str = Field(
        validation_alias=AliasChoices(AliasPath("rule", "description"), "description"),
        default="",
    )
    mitre: str | None = Field(
        validation_alias=AliasChoices(AliasPath("rule", "mitre", "id"), "mitre"),
        default=None,
    )
    agent_id: AgentId | None = Field(
        validation_alias=AliasChoices(AliasPath("agent", "id"), "agent_id"),
        default=None,
    )
    agent_name: str | None = Field(
        validation_alias=AliasChoices(AliasPath("agent", "name"), "agent_name"),
        default=None,
    )
    timestamp: str = ""
    location: str = ""
    hash: str | None = None
    src_ip: str | None = Field(
        validation_alias=AliasChoices(AliasPath("data", "srcip"), "src_ip"),
        default=None,
    )
```

> **Decision:** Dotted string aliases (`alias="rule.id"`) do NOT traverse nested dicts
> in Pydantic v2. Empirically verified: `AliasChoices(AliasPath(...), field_name)` is
> the correct approach. Handles both raw nested Wazuh JSON and flat pre-parsed dicts.

```python
class Verdict(BaseModel):        # extra="forbid", frozen
class PolicyResult(BaseModel):   # extra="forbid", frozen

@dataclass(frozen=True, slots=True)
class Evidence: ...

@dataclass(frozen=True, slots=True)
class InvestigationReport: ...
```

Enums: `Tier`, `Severity`, `Confidence` (all `StrEnum`).

---

## 5. `http.py` — httpx2 Client Factory

Every network call uses this factory. A bare `httpx2.AsyncClient()` is a bug.

```python
import socket
import httpx2


def create_async_client() -> httpx2.AsyncClient:
    limits = httpx2.Limits(
        max_connections=200, max_keepalive_connections=40, keepalive_expiry=30.0
    )
    timeout = httpx2.Timeout(connect=5.0, read=30.0, write=10.0, pool=10.0)
    transport = httpx2.AsyncHTTPTransport(
        http2=True,
        retries=3,
        limits=limits,
        socket_options=[(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)],
    )
    return httpx2.AsyncClient(
        transport=transport, timeout=timeout, follow_redirects=True
    )
```

Also provide a sync `create_client()` variant.

---

## 6. Licensing (`licensing/`)

**`models.py`** — `LicenseTier(StrEnum)`, `Feature(StrEnum)`, `License(BaseModel)`.

**`tiers.py`** — `TIER_FEATURES`, `features_for()`, `MAX_SEATS_BY_TIER`. Pure data, no I/O.

**`crypto.py`** — stdlib only (`hmac`, `hashlib`, `base64`, `json`).
- `canonical_bytes(license) -> bytes`: deterministic JSON, features as sorted list.
- `sign(canonical, secret) -> str`: HMAC-SHA256 hexdigest.
- `encode(license, secret) -> str`: `<urlsafe_b64(canonical)>.<urlsafe_b64(sig)>`.
- `decode(raw, secret) -> License`: verify HMAC before parsing. `LicenseError` on tamper.

**`service.py`** — `LicenseService(Service)`: `generate()`, `validate()`, `entitled()`.
Pure, synchronous. Uses `datetime.now(timezone.utc)` everywhere.

> **Decision:** `datetime.utcnow()` is deprecated in Python 3.12. All timestamps use
> `datetime.now(timezone.utc)` and are timezone-aware.

---

## 7. Auth (`auth/`)

**`password.py`** — `hash_password()`, `verify_password()` using
`hashlib.pbkdf2_hmac("sha256", ...)`. Format: `"pbkdf2$sha256$210000$<salt>$<hash>"`.
16-byte salt via `secrets.token_bytes`.

**`models.py`** — `User(BaseModel)` with email validation.

**`service.py`** — `AuthService(Service)`:
`register()`, `login() -> SessionToken`, `logout()`, `verify() -> User`.
Errors: `AuthError`, `DuplicateEmailError`.

---

## 8. Organizations (`orgs/`)

**`models.py`** — `OrganizationRole(StrEnum)`, `Organization(BaseModel)`,
`Membership(BaseModel)`.

**`store.py`** — `OrganizationStore(MemoryRepository[Organization])`,
`MembershipStore(MemoryRepository[Membership])` with `role_of()` and
`memberships_for()` helpers.

**`service.py`** — `OrganizationService(Service)`:
`create_org()`, `add_member()`, `remove_member()`, `change_role()`,
`activate_license()`, `list_for_user()`.
Errors: `ForbiddenError`, `SeatLimitError`, `LastAdminError`.

**Tenancy invariant:** every method takes `org_id`, never returns cross-org records.

---

## 9. LLM (`llm/`)

**`base.py`** — `LlmClient(Protocol)` with `async def respond_json(system, user)`.
`LlmError(RuntimeError)`.

**`client.py`** — `OpenAiCompatibleLlm`: POST `{base_url}/chat/completions`.
`ScriptedLlm`: deterministic fixed verdict for sim/tests, still goes through
`VerdictParser` so the parse path is exercised.

**`verdict.py`** — `build_prompt(evidence) -> (system, user)`.
`VerdictParser.parse(raw) -> Verdict`.

---

## 10. SIEM (`siem/`)

**`base.py`** — `SiemClient(Protocol)`: `get_alert()`, `get_agent()`.

**`wazuh.py`** — `WazuhClient`: Wazuh REST API via httpx2. JWT auth via
`POST /security/user/authenticate`.

**`static.py`** — `StaticSiemClient`: loads `data/sample_alert.json` fixtures for
offline sim and tests.

---

## 11. Notifiers (`notifiers/`)

**`base.py`** — `Notifier(Protocol)`: `async def notify(report, org_id) -> bool`.

**`log.py`** — `LogNotifier`: prints formatted verdict to stdout. Always active.

**`slack.py`** — `SlackNotifier`: incoming webhook via httpx2. Inactive if no URL.

**`twilio.py`** — `TwilioSmsNotifier`: SMS to `settings.sms_to`. Inactive if no creds.

**`builder.py`** — `CompositeNotifier`: fans out to all active notifiers via
`anyio.create_task_group()`.

---

## 12. Ticketing (`ticketing/`)

**`base.py`** — `TicketStore(Protocol)`: `create_ticket()`, `get_ticket()`.

**`memory.py`** — `MemoryTickets`: thread-safe dict keyed by `(org_id, ticket_id)`.

**`jira.py`** — `JiraTickets`: Jira REST API via httpx2. Inactive if no creds.

---

## 13. Policy Engine (`policies/engine.py`)

```python
class PolicyEngine:
    """Pure, deterministic, zero-I/O rule evaluator."""
    def evaluate(self, alert: SiemAlert, org_id: OrgId) -> PolicyResult:
        # level < 5  → IGNORE, should_investigate=False
        # level 5-9  → TRIAGE, should_investigate=True
        # level >= 10 or MITRE critical technique → ESCALATE, should_investigate=True
```

---

## 14. Investigation Agent (`agent/`)

**`tools.py`** — `InvestigationTools`:
`gather_evidence(alert, org_id) -> Evidence`.
Queries SIEM for agent context, performs VirusTotal hash lookup (if hash present),
formats MITRE technique notes.

**`investigator.py`** — `InvestigationAgent`:
`investigate(alert, org_id) -> InvestigationReport`.
Calls `PolicyEngine.evaluate()` → if `should_investigate`, calls
`tools.gather_evidence()` → `build_prompt()` → `llm.respond_json()` →
`VerdictParser.parse()`. Assembles final `InvestigationReport`.

---

## 15. Pipeline (`pipeline/`)

**`deployment.py`** — frozen dataclass composing: `PolicyEngine`, `InvestigationAgent`,
`Notifier`, `TicketStore`.

**`runner.py`** — `PipelineRunner`:
`process_alert(alert, org_id) -> InvestigationReport`.
Runs: investigate → create ticket → notify. Returns report.

---

## 16. Server & Simulation (`server/`, `simulate.py`)

**`server/deps.py`** — FastAPI dependency injection: `get_current_user()`,
`get_current_org()`, service accessors.

**`server/routers.py`** — API routes:
- `POST /auth/register`, `POST /auth/login`, `POST /auth/logout`
- `POST /orgs`, `GET /orgs`, `POST /orgs/{org_id}/members`
- `POST /orgs/{org_id}/license`
- `POST /wazuh` — webhook ingestion, validates `SiemAlert`, runs pipeline
- `GET /health`

**`server/app.py`** — `create_app()` factory, lifespan handler, exception handlers,
`main()` entrypoint calling `uvicorn.run()`.

**`simulate.py`** — offline CLI runner:
1. Loads `data/sample_alert.json`
2. Wires `ScriptedLlm` + `StaticSiemClient` + `MemoryTickets` + `LogNotifier`
3. Runs `PipelineRunner.process_alert()`
4. Prints `InvestigationReport` to stdout

---

## 17. Roadmap — Future Expansion Hooks

These are explicitly **NOT in MVP-1 scope**. They are documented here so the
architecture accommodates them without requiring rewrites.

### M2 — Active Response & Containment
- `agent/approval.py`: Action Lease state machine (15-min reversible safety leases)
- `Tier.ISOLATE` wired with human approval gate
- Wazuh Active Response execution adapter

### M3 — Persistence, Dashboard & Scale
- `core/sql_repo.py`: Async SQLAlchemy `SQLRepository[T]` (SQLite dev / Postgres prod)
- `pipeline/dedup.py`: Sliding-window alert deduplication (configurable, default 5 min)
- `web/`: React + Vite SPA analyst command center with SSE real-time streams
- `server/sse.py`: Server-Sent Events streaming endpoint

### M4 — Enterprise Security & Compliance
- `auth/totp.py`: TOTP 2FA (Google Authenticator)
- `core/audit.py`: Immutable append-only audit log with cryptographic event chaining
- `core/retention.py`: Background data retention purge worker
- `reports/compliance.py`: SOC2/ISO27001 audit package generator (PDF/Markdown)
- `reports/analytics.py`: MTTD, MTTI, MTTR, noise reduction KPI calculator

### M5 — Advanced AI & Threat Intelligence
- `graph/timeline.py`: Temporal Entity Attack Graph (30-day sliding window)
- `llm/memory.py`: RLHF analyst feedback vector memory (few-shot RAG)
- `llm/sanitizer.py`: Zero-Knowledge PII tokenizer (anonymize before cloud LLM)
- `tools/sandbox.py`: CAPE / Hybrid Analysis malware sandbox dispatcher
- `agent/identity.py`: Azure AD, Active Directory, Okta session revocation adapters

### M6 — Integrations & Deployment
- `notifiers/pagerduty.py`, `notifiers/webhook.py`: PagerDuty + generic webhook
- `orgs/assets.py`: Asset inventory with criticality tagging (1-10)
- `policies/engine.py` extension: custom YAML/JSON per-org policy rules
- `reports/rca.py`: Post-incident root cause analysis generator
- Docker Compose / Helm chart packaging
- `LlmClient` circuit breaker with local Ollama fallback

### Expansion architecture principles:
1. Every Protocol defined in MVP-1 can gain new implementations without touching callers.
2. `MemoryRepository` → `SQLRepository` swap is a constructor injection change, not a refactor.
3. The `Deployment` dataclass gains optional fields; existing wiring doesn't break.
4. New server routes are added as separate `APIRouter` instances, not modifications to existing ones.

---

## 18. Decision Log

- **Decision 1 (Pydantic aliases):** Dotted `alias="rule.id"` does NOT traverse nested
  dicts. Use `validation_alias=AliasChoices(AliasPath("rule", "id"), "rule_id")`.
  Empirically verified with Pydantic 2.13.4.
- **Decision 2 (httpx2):** `httpx2` is the Pydantic-maintained fork of `httpx`. Import as
  `import httpx2`. API is identical to httpx. `AsyncHTTPTransport`, `Limits`, `Timeout`,
  `socket_options` all confirmed working.
- **Decision 3 (Datetimes):** `datetime.utcnow()` deprecated in 3.12. Standardized on
  `datetime.now(timezone.utc)` everywhere.
- **Decision 4 (Branded IDs):** Single definition in `core/ids.py`. Models import from
  there. No redefinition in `models.py`.
- **Decision 5 (Repository.create):** Takes explicit `org_id` parameter for tenant
  isolation at the repository layer.

---

## 19. Success Criteria (MVP-1)

1. `uv run terminus-simulate` ingests `data/sample_alert.json`, runs policy +
   investigation with `ScriptedLlm`, prints verdict, creates ticket (memory), emits
   notification to log — **all offline, zero network required**.
2. `uv run pytest` passes all unit + integration + e2e tests.
3. `uv run basedpyright` and `uv run ruff check` pass with **zero errors**.
4. With real Groq API key set, the pipeline produces a real LLM verdict.
5. With Twilio/Slack/Jira creds set, notifications and tickets flow to real services —
   driven purely by config, no code change.
6. Human-in-the-loop invariant: MVP-1 performs **no** irreversible action.

---

## 20. Build Execution Order

```
Phase 1 — Fix Foundations (existing code has 4 bugs)
  1. Fix models.py: AliasPath/AliasChoices, remove duplicate branded IDs
  2. Fix core/base.py: add MemoryRepository[T], fix create() signature
  3. Implement config.py
  4. Write test_models.py, test_config.py

Phase 2 — Licensing & Auth
  5. licensing/models.py, tiers.py, crypto.py, service.py
  6. auth/password.py, models.py, service.py
  7. Write test_licensing.py, test_auth.py

Phase 3 — Organizations & Tenancy
  8. orgs/models.py, store.py, service.py
  9. Write test_orgs.py (including tenancy isolation)

Phase 4 — Core Pipeline
  10. http.py
  11. llm/base.py, client.py (ScriptedLlm first), verdict.py
  12. siem/base.py, static.py
  13. policies/engine.py
  14. agent/tools.py, investigator.py
  15. notifiers/base.py, log.py, builder.py
  16. ticketing/base.py, memory.py
  17. pipeline/deployment.py, runner.py
  18. Write tests for each module

Phase 5 — Server & Simulation
  19. server/deps.py, routers.py, app.py
  20. simulate.py + data/sample_alert.json
  21. Write test_e2e_simulate.py
  22. Verify: basedpyright clean, ruff clean, pytest green

Phase 6 — Live Adapters (config-gated, no new interfaces)
  23. siem/wazuh.py
  24. notifiers/slack.py, notifiers/twilio.py
  25. ticketing/jira.py
```
