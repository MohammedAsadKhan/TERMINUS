# TERMINUS audit index

Scope: `main` at **`a7369e0a0dc4e66dede10b447c8c783ef189b228`**, audited **2026-11-12, America/Chicago**. Stage 1 static baseline and Stage 2 isolated synthetic execution preceded this separate Stage 3 decision session. Audit files are under `audit-output/`; no product code changed. E0 = document, E1 = read-only code, E2 = isolated fixture, E4 = authorized live lab, E5 = representative operations. **No E4/E5 evidence was produced.**

| Start here | Purpose |
|---|---|
| [Executive verdict](00_EXECUTIVE_VERDICT.md) | Plain-language answer and north star |
| [Provenance](00_PROVENANCE.md) · [Audit log](AUDIT_LOG.md) | SHA, environment, actions and limits |
| [System explained](01_SYSTEM_EXPLAINED.md) | Current processes, paths and UI map |
| [Capability truth ledger](02_CAPABILITY_TRUTH_LEDGER.md) · [CSV](02_CAPABILITY_TRUTH_LEDGER.csv) | Claim-by-claim status, tier and promotion gate |
| [Static demo illusion](02b_DEMO_ILLUSION_STATIC.md) · [runtime confirmation](02d_DEMO_ILLUSION_RUNTIME.md) | Misleading cues and what was executed |
| [Limited secrets scan](02c_SECRETS_SCAN.md) | Candidate locations and scan limitations |
| [Findings and scorecard](03_FINDINGS.md) | Ranked mechanisms, impact and remedies |
| [Analyst experience](04_USER_EXPERIENCE_AND_PRODUCT_VALUE.md) | Jobs, local journey and baseline gap |
| [Tests and reproduction](05_TESTS_AND_REPRODUCTION.md) | Commands, raw evidence and unrun checks |
| [Security and trust](06_SECURITY_AND_TRUST.md) | Trust boundaries and E4 lab plan |
| [Competitors and positioning](07_COMPETITORS_AND_POSITIONING.md) | Primary-source alternatives, accessed 2026-11-12 |
| [Decision and roadmap](08_DECISION_AND_ROADMAP.md) | Routes, cuts, truth policy and go/no-go gates |
| [Open questions](09_OPEN_QUESTIONS_AND_UNVERIFIED.md) | Evidence gaps and exact settling tests |

Raw local artifacts and the audit-only harness are in [evidence](evidence/) and [repros](repros/); they contain synthetic fixtures and should not be presented as live lab proof. Stage 2's first synthetic run unexpectedly inherited a provider alias; later offline evidence cleared all provider aliases and is the basis for no-key conclusions. No credential value appears in these reports.

**README-ready capability statement today:** “TERMINUS is a local evaluation prototype for security incident intake, deterministic policy checks and case review. It can record and deduplicate submitted alerts in SQLite; an unconfigured model path uses scripted output that must be treated as demo data. Wazuh readers and a narrowly scoped SSH response controller require separate configuration and workers. Independent live effect, recovery and analyst-benefit validation are pending.”
