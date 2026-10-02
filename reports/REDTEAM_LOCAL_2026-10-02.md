# Local red-team exercise — 2026-10-02

## Scope and method

Target: the bundled First Heritage bank decoy on `127.0.0.1:8002`, with Terminus running in scripted/offline model mode. This was a bounded HTTP exercise against synthetic data. No external service, production bank, Wazuh manager, endpoint agent, or firewall was targeted. The same requests form the "raw event stream" comparison; this is not a head-to-head Wazuh benchmark.

Run: `python scripts/redteam_benchmark.py --target http://127.0.0.1:8002 --concurrency 16`. Machine-readable results: [redteam-local.json](redteam-local.json).

| Input | Requests | Observed result |
| --- | ---: | --- |
| Benign branch searches | 50 | 0 incident tickets |
| Failed administrator logins | 150 | 150 incident tickets |
| SQL injection probes | 150 | 150 blocked search responses and tickets |
| JNDI lookup probes | 60 | 60 blocked search responses and tickets |
| Treasury canary access | 25 | 25 decoy access tickets |
| Synthetic customer export | 15 | 15 decoy export tickets |
| **Total** | **450** | **400 incident tickets; 0 request failures** |

The load phase took 0.96 seconds on this local process (470.1 requests/s). Round-trip latency was 30.8 ms p50, 41.1 ms p95, and 100.8 ms p99. These are local, scripted-model numbers, not a production capacity claim. The search route returned `blocked` for all 210 SQL/JNDI probes. Its own application code recognizes those strings; the result does not prove that Terminus can block arbitrary network attacks.

Each of the 400 hostile events created an incident, so the current implementation did **not** reduce the hostile event queue. Fifty benign controls were filtered. Campaign IDs persisted across requests after a lifecycle fix, but the two campaign IDs here mostly reflect the two decoy hosts and shared loopback source; they are not reliable attribution. All 400 incidents recorded `mitigation_status: NOT_EXECUTED`.

## Live model spot check

A separate instance on `127.0.0.1:8003` used the configured Groq model for four representative probes: SQL injection, JNDI lookup, canary access, and synthetic customer export. All four generated incidents. The Copilot called `list_incidents`, cited the four incident IDs, distinguished blocked search probes from decoy access, identified `127.0.0.1` as local test traffic, and correctly stated that no isolation or IP block had executed. Script: [redteam_live_check.py](../scripts/redteam_live_check.py).

## What this demonstrates, and what it does not

Terminus currently adds a tenant incident queue, deterministic triage, recorded assessments, campaign metadata, and a natural-language investigation surface over Wazuh-shaped telemetry. In the live spot check, the Copilot answered a cross-incident question from recorded evidence without inventing containment.

This run does **not** establish superiority over Wazuh. Wazuh already supports custom rules, alert grouping, dashboards, and active response: [rules](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html), [dashboards](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/creating-custom-dashboards.html), [active response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html). A defensible product comparison needs both systems deployed against the same labeled telemetry, with detection accuracy, analyst work, response time, action verification, throughput, and cost measured side by side.

The largest gaps exposed here are duplicate incident volume, campaign attribution from loopback traffic, and lack of verified containment. The offline load benchmark also does not measure Groq capacity or cost under hundreds of simultaneous investigations.
