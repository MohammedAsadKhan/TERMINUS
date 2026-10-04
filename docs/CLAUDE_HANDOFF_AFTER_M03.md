# Claude Code handoff after M03

Paste the following prompt into Claude Code opened in this repository:

```text
Continue Terminus after M03. First inspect git status, branch, recent commits and any AGENTS.md; preserve existing changes. Read README.md, docs/EXECUTION_CHECKLIST.md, PRD.md, MVP_RELEASE.md, ARCHITECTURE_DECISIONS.md, MODEL_CONNECTIONS.md, MODEL_ADAPTERS.md, MODEL_POLICY.md, TOOL_GATEWAY.md, SCHEDULER.md and COORDINATION.md (resolve actual filenames before assuming they exist).

M01 encrypted named connections, M02 pure provider codecs/fixture harness and M03 durable role/data policy plus fixture admission are implemented. Do not duplicate them. M03 does not enable live transport, credential resolution, financial admission, public policy settings APIs or multi-turn tool admission. The legacy single-provider pipeline is unchanged and must not be described as protected by the new gateway.

Claim M04 in the shared execution checklist before editing, identifying the responsible human and agent. Implement capability-based explicit routing and bounded approved fallback using only exact policy-granted connection versions and models. Record the model, routing rationale and provenance. Exclude unsupported capabilities, unavailable connections and future specialties. Reauthorize every attempt; never silently switch to scripted findings or broaden role/data grants. Use separate economical subagents for independent files if your environment supports them, with explicit ownership; review their work yourself.

Complete and verify M04 before claiming M05. M05 needs atomic financial reservations, durable usage/cost ledger and reconciliation across concurrent requests, retries, fallback models and API keys under organization limits. Missing usage/cost is unknown, never zero. Persist intent/reservations before external I/O; ambiguous outcomes stay conservatively reserved until reconciled. Account for provider usage fields such as cache/reasoning tokens where supported rather than inventing costs.

Do not enable production model transport until permission/data policy, routing and financial admission jointly pass. Production transport must enforce verified socket destination pinning, TLS, redirects and SSRF controls for applicable endpoints, including local DNS rebinding. Every fallback and tool continuation needs fresh scheduler ownership, cancellation, tenant, grant, classification and budget checks. Existing evidence is untrusted input; model arguments cannot choose credentials or widen scope. Keep audits bounded and redacted. Never put secrets in logs, prompts or commits.

Then follow the checklist dependencies for O05 eight actual specialist handlers and trusted workflow/run identities, and U01-U04 activity/settings UI using real records. Do not fabricate agent activity or expose chain-of-thought. All 60 roadmap specialties remain display-only outside the eight admitted core roles. Response planning cannot dispatch consequential actions.

Lab work will be performed with Mohammed separately. Do not provision a lab, run attacks, spend cloud money or activate response actions from this handoff. Later response work requires immutable proposal-bound human approvals, protected management access, expiry/owned-resource undo, durable intent, ambiguity reconciliation and independent verification. Provider acknowledgement is not verification.

Use temporary databases before test collection. Example:
uv run --frozen python -c "import tempfile,pathlib,pytest; from terminus.storage.db import Database; Database.reset_instance(str(pathlib.Path(tempfile.mkdtemp(prefix='terminus-check-'))/'tests.db')); raise SystemExit(pytest.main(['-q','--tb=short']))"
Run targeted Ruff/type checks and git diff --check. The current type configuration has an existing unrecognized reportMissingReturnType setting; distinguish that diagnostic from source errors. Record actual checks/counts, limitations and remaining work. Mark tasks Done by - only after acceptance passes; update relevant architecture/release documents. Work one verified task at a time. Do not commit or push unless the human requests it.
```

Current M03 work may still be uncommitted when this prompt is used. Inspect the working tree instead of assuming a commit exists. The checklist is the authoritative claim/status record.
