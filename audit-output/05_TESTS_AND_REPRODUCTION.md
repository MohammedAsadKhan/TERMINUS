# Stage 2 tests and reproduction

Target SHA `a7369e0a0dc4e66dede10b447c8c783ef189b228`, Windows, Python 3.12.7, Node 22.19.0. All new environments, databases, harnesses, build outputs and raw logs are under `audit-output/`. No committed installer or `run_demo.bat` was executed. No authorized Wazuh/effect lab existed.

## Executed checks

| Check | Exact boundary/result | Raw evidence |
|---|---|---|
| `uv sync --frozen` with `UV_PROJECT_ENVIRONMENT=audit-output/.venv`, cache under audit-output | Exit 0; locked 43 packages installed. This used the existing checkout, not a fresh ZIP. | `evidence/uv-sync.txt` |
| Local TestClient journey, offline rerun | Exit 0; health 200, console HTML 200/1,175 bytes, anonymous incidents 401, local admin login 200; four synthetic alerts accepted, malformed alert 422, duplicate accepted with stored result, inline block 501. | `repros/isolated_journey.py`, `evidence/offline-stdout.txt`, `evidence/offline-instance/journey.json` |
| Backend full suite from isolated `audit-output/evidence/test-instance` cwd | Exit 1: **1,242 passed, 3 failed, 1,245 total**, 317.24 s. Three `test_toolkit_contracts.py` failures were `FileNotFoundError` on repo-relative `src/...` paths because cwd was intentionally outside the repo. | `evidence/pytest-full.txt` |
| Affected test module from repo root with provider aliases removed | Exit 0: **24 passed** in 0.47 s, including the prior three failures. This resolves the path failure for that module, but is not a second full suite. | `evidence/pytest-toolkit-root.txt` |
| `ruff check src tests` | Exit 1: **208 errors**; 29 marked fixable. Current quality gate fails. | `evidence/ruff.txt` |
| `basedpyright src tests` | Exit 1: **11,167 errors, 730 warnings**. Current strict all-code type gate fails; this count is not a count of runtime defects. | `evidence/basedpyright.txt` |
| Console `npm ci`, `npm run build` in copied `audit-output/web-build` | Both exit 0; 123 npm packages installed, TypeScript/Vite build completed. Output was written under audit-output, not product source. | `evidence/npm-ci.txt`, `evidence/npm-build.txt` |
| `npm audit --json` in copied tree | Exit 1: two **high** advisories, on `source-map-js` and `vite` ranges recorded in JSON. Both are build/dev dependency exposure; exploitability of deployed static assets was not established. | `evidence/npm-audit.json` |
| `git diff --check`, status | Exit 0; no tracked product-code diff. `audit-output/` is untracked. | `AUDIT_LOG.md` |

The first local journey, before the offline rerun, inherited the host's `GROQ_API_KEY` via `config.py:78-94`. It may have sent only synthetic fixture text to a model provider. Its raw output is `evidence/journey-stdout.txt` and `evidence/journey.json`; it is **not** evidence of an authorized live provider acceptance and no cost/charge observation was available. The harness was then patched to remove all provider aliases before importing the app; the full suite command also removed them. No key value was printed or retained.

## Reproduce the important offline results

1. Use an isolated cwd and a fresh SQLite file. Clear `TERMINUS_LLM_API_KEY`, `LLM_API_KEY`, `GROQ_API_KEY`, and `OPENAI_API_KEY` before any app import. The harness does this itself.
2. Run `audit-output/.venv/Scripts/python.exe F:/Terminus/audit-output/repros/isolated_journey.py` from that cwd. The script writes `journey.json` locally. Do not run it in a valuable database directory: app startup seeds default objects.
3. Inspect `alert incomplete`, `alert conflicting`, and `alert injection` in JSON. Expected safe behavior: distinguish missing/conflicting telemetry and detector warning from attack evidence. Observed: zero-citation high-confidence scripted summary for the first two, and critical/high scripted exploit narrative for the latter.
4. Inspect `alert duplicate`, `alert malformed`, and `inline block` for the positive boundaries: stored duplicate result, 422 shape rejection, 501 no external action.

The synthetic cases did not use a real Wazuh receipt, manager/indexer reads, provider effect, network block or independent observer. No real SSH/provider result, cost, memory, write-throughput, or latency benchmark was measured. `pytest` names marked “e2e” are local scenario tests, not live E4 tests. A quick inventory found 85 Python test files, 14 containing TestClient/AsyncClient, 60 containing fixture/monkeypatch/mock text, and no `@pytest.mark.e2e` or integration markers via `rg`; this is a rough file-level classification, not a precise assertion count. The suite exercises many SQLite and API boundaries, but it cannot promote unrun Wazuh/provider actions to live proof.

## Uncovered or blocked checks

- Browser rendering, screenshots, workflow approval toast, loading/error states and first-source connection were not executed. Static JSX evidence remains E1.
- No disposable Wazuh/provider/effect lab authorization was supplied. E4/E5 security effect, protected management health, expiry and recovery remain unverified. The exact plan is in `06_SECURITY_AND_TRUST.md`.
- No clean extracted source ZIP, full manual shutdown/restart, multi-process contention, backup/restore, five-alert analyst comparison, memory/throughput or token-cost measurement was performed.
- Python dependency vulnerability scanning with a dedicated scanner was not run. `npm audit` covers only the console dependency tree.

Three cwd-sensitive failures demonstrate that the suite is not wholly portable to an arbitrary execution directory; the affected module passes from the repository root. The product behavior findings are based on the offline API journey, not on this suite's passing count.
