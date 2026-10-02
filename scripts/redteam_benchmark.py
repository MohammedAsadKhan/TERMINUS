"""Bounded, local-only attack simulation against the bundled bank decoy.

Uses real HTTP requests to the bank service. The comparison is with the same
requests as a raw alert stream, not with a separately deployed Wazuh manager.
Run with the LLM disabled for the load phase so results do not consume hundreds
of paid model calls: TERMINUS_LLM_API_KEY='' on the target process.
"""

# ruff: noqa: INP001

from __future__ import annotations

import argparse
import asyncio
import json
import random
import time
from collections import Counter
from pathlib import Path
from typing import Any

import httpx2


def scenarios() -> list[tuple[str, str, str, dict[str, str] | None]]:
    rows: list[tuple[str, str, str, dict[str, str] | None]] = []
    rows += [("benign", "GET", "/bank/api/search", {"q": "branch hours"})] * 50
    rows += [("password_guess", "POST", "/bank/api/login", {"username": "treasury_admin", "password": "wrong-password"})] * 150
    rows += [("sqli", "GET", "/bank/api/search", {"q": "' OR '1'='1' --"})] * 150
    rows += [("jndi", "GET", "/bank/api/search", {"q": "${jndi:ldap://example.invalid/probe}"})] * 60
    rows += [("canary", "GET", "/bank/api/admin/treasury-keys", None)] * 25
    rows += [("decoy_export", "GET", "/bank/api/customers/export", None)] * 15
    random.Random(20261002).shuffle(rows)  # noqa: S311 - deterministic test ordering
    return rows


def percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int((len(ordered) - 1) * pct))], 1)


async def run(target: str, concurrency: int) -> dict[str, Any]:
    if not target.startswith("http://127.0.0.1:") and not target.startswith("http://localhost:"):
        raise ValueError("This benchmark only runs against a loopback target")
    async with httpx2.AsyncClient(base_url=target, timeout=60.0) as client:
        login = await client.post("/auth/login", json={"email": "admin@terminus.local", "password": "Password123!"})
        login.raise_for_status()
        auth = {"Authorization": "Bearer " + login.json()["session_token"]}
        orgs = await client.get("/orgs", headers=auth)
        orgs.raise_for_status()
        headers = {**auth, "X-Org-ID": orgs.json()[0]["org_id"]}
        before = await client.get("/incidents", headers=headers)
        before.raise_for_status()
        starting_ids = {item["id"] for item in before.json()}

        rows = scenarios()
        semaphore = asyncio.Semaphore(concurrency)
        results: list[dict[str, Any]] = []

        async def send(row: tuple[str, str, str, dict[str, str] | None]) -> None:
            category, method, path, data = row
            async with semaphore:
                started = time.perf_counter()
                try:
                    if method == "POST":
                        response = await client.post(path, headers=headers, json=data)
                    else:
                        response = await client.get(path, headers=headers, params=data)
                    payload = response.json()
                    results.append({
                        "category": category,
                        "http_status": response.status_code,
                        "application_status": payload.get("status"),
                        "latency_ms": (time.perf_counter() - started) * 1000,
                    })
                except Exception as exc:
                    results.append({"category": category, "error": type(exc).__name__, "latency_ms": (time.perf_counter() - started) * 1000})

        started = time.perf_counter()
        await asyncio.gather(*(send(row) for row in rows))
        elapsed = time.perf_counter() - started
        after = await client.get("/incidents", headers=headers)
        after.raise_for_status()
        tickets = [item for item in after.json() if item["id"] not in starting_ids]

    expected_codes = {"benign": 200, "password_guess": 401, "sqli": 200, "jndi": 200, "canary": 200, "decoy_export": 200}
    completed = [r for r in results if r.get("http_status") == expected_codes[r["category"]]]
    blocked = [r for r in results if r["category"] in {"sqli", "jndi"} and r.get("application_status") == "blocked"]
    ticket_counts = Counter(str(t.get("policy_tier")) for t in tickets)
    campaign_ids = {str(t.get("campaign_id")) for t in tickets if t.get("campaign_id")}
    output = {
        "scope": "Local bundled bank decoy; no external target or real Wazuh manager",
        "model_mode": "Scripted/offline for load phase",
        "raw_requests": len(rows),
        "hostile_requests": sum(1 for row in rows if row[0] != "benign"),
        "benign_controls": sum(1 for row in rows if row[0] == "benign"),
        "categories": dict(Counter(row[0] for row in rows)),
        "expected_http_responses": len(completed),
        "transport_or_server_failures": len(rows) - len(completed),
        "search_exploits_blocked": len(blocked),
        "search_exploits_total": sum(1 for row in rows if row[0] in {"sqli", "jndi"}),
        "new_incidents": len(tickets),
        "incident_tiers": dict(ticket_counts),
        "distinct_campaign_ids": len(campaign_ids),
        "max_recorded_campaign_alert_count": max((int(t.get("campaign_alert_count") or 0) for t in tickets), default=0),
        "recorded_mitigation_statuses": dict(Counter(str(t.get("mitigation_status")) for t in tickets)),
        "elapsed_seconds": round(elapsed, 2),
        "requests_per_second": round(len(rows) / elapsed, 1),
        "latency_ms": {"p50": percentile([r["latency_ms"] for r in results], 0.5), "p95": percentile([r["latency_ms"] for r in results], 0.95), "p99": percentile([r["latency_ms"] for r in results], 0.99)},
        "comparison_note": "Raw stream size is the input count. Wazuh filtering, detection accuracy, and performance were not measured.",
    }
    if output["transport_or_server_failures"]:
        raise RuntimeError("Some requests failed")
    if output["new_incidents"] != output["hostile_requests"]:
        raise RuntimeError("Hostile requests did not all produce incidents")
    if output["search_exploits_blocked"] != output["search_exploits_total"]:
        raise RuntimeError("A search exploit was not blocked")
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://127.0.0.1:8002")
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument("--output", default="reports/redteam-local.json")
    args = parser.parse_args()
    result = asyncio.run(run(args.target, args.concurrency))
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
