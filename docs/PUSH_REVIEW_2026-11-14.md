# TERMINUS proposed GitHub push

**Review only · 2026-11-14 · no commit or push authorized yet**

GitHub `main` and local `HEAD` both point to `a7369e0a0dc4e66dede10b447c8c783ef189b228` (`Document source and align the class code delivery`, November 9). The preceding commits are `cd89580` (October 17 scoped lab record) and `4afc1df` (October 17 approval and response implementation). The working tree contains the later audit remediation and is uncommitted.

## Proposed destination and contents

Push a review branch named `codex/terminus-audit-remediation` and open a draft PR against `main` **only after the user approves**. Do not push directly to `main`. The branch would contain:

1. **Trust and analyst truth:** safe offline verdicts, prompt-injection evidence boundaries, source-keyed and tenant-bound Wazuh intake with receipt hashes, no default presentation seeds, truthful console labels and empty/error states, and focused source/provenance tests.
2. **Bounded response and operations:** exact-digest approval and effect-state fixes, independent observer/worker behavior, TLS certificate verification by default with an explicit fixed-endpoint disposable Docker lab exception, a bounded target cleanup loop for expired owned firewall tables, loopback launcher, supported SQLite setup, retirement of the unsafe legacy GUI provisioning path in favor of the maintained CLI, an isolated non-destructive presentation launcher, a reproducible private Docker lab harness, and negative-case tests. The historical single successful lab block/recovery is recorded as evidence; automatic cleanup and a second fresh-ZIP Wazuh cycle are still unverified live.
3. **Durable analyst context and delivery:** tenant-scoped report snapshots and campaign assignments, restart/duplicate/tenant tests, updated implementation/installation/grading/team docs, rebuilt prebuilt console assets, the Word/PDF installation manuals, and the source ZIP.

Include the small redacted audit summary, findings, reproduction instructions, and approved lab effect/recovery records needed by the linked docs. Keep the upstream `audit-output/lab/wazuh-docker/` copy, local runtime state, raw or bulk audit output, test caches, private credentials/keys, SQLite databases, installed dependencies, and virtual environments out of the branch. The 958 untracked `audit-output` paths are **not** an automatic add list. Review the exact staged manifest and secret scan before any commit.

## Verification and remaining gates

- Full backend: **1,259 passed** on November 14 with temp on D:, including the TLS worker and target cleanup changes. The 13 focused endpoint tests, 4 focused worker tests, and targeted Ruff passed.
- Console build: passed on November 14; browser suite: **14 passed** in the earlier focused run.
- New campaign module and tests: Ruff and Basedpyright clean; current release-wide Ruff **213 findings** after retiring the unsafe GUI path, Basedpyright `src` **1,613 errors / 242 warnings**. `git diff --check` passed after rebuilding HTML from LF source.
- The pre-cleanup ZIP passed the archive check (477 entries) and a fresh D: extraction: locked dependency installation, server health, console HTML and asset, local sign-in, and shutdown/closed port. The current 478-entry ZIP includes the cleanup and GUI revisions; its archive check, packaged-file inspection and Compose validation passed, and its D: backup hash matches. The Word and PDF manuals were regenerated from the installation Markdown, and the two-page PDF was rendered and inspected. LibreOffice cannot start on this host, so DOCX visual rendering remains unverified. A fresh extraction of this exact ZIP and the Wazuh response cycle remain unverified.
- Production release remains **NO-GO**: static-analysis gate, fresh-ZIP Wazuh response and automatic-cleanup acceptance, worker supervision, backup/restore, and measured analyst benefit remain open.

Approval of a review-branch push would authorize only the reviewed file manifest and draft PR. It would not approve merging, deployment, production claims, or destructive disk/cloud work.

## November 16 update before approval

GitHub still has no open PRs; merged PR [#1](https://github.com/MohammedAsadKhan/TERMINUS/pull/1) is the only PR returned. Remote `main` still points to `a7369e0`. The isolated presentation revision now labels synthetic alert evidence and does not approve actions for an analyst. The 12 focused tests and full backend suite (**1,270 passed in 361.42 seconds**) passed, as did the console build and four-second loopback rehearsal. Release-wide Ruff reports **207 findings**; Basedpyright `src` reports **1,613 errors and 242 warnings**. The 479-entry source ZIP passed integrity checks, and a fresh extraction installed 43 locked dependencies, served health and console HTML/CSS, accepted local sign-in, and shut down with the port closed. The planned branch and draft PR remain a proposal only; no commit or push has occurred.
