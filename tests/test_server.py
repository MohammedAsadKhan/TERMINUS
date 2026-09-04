"""Integration tests for Terminus FastAPI REST API endpoints."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from terminus.server.app import create_app


@pytest.fixture
def client() -> TestClient:
    """Fixture providing TestClient for FastAPI app."""
    app = create_app()
    return TestClient(app)


def test_health_endpoint(client: TestClient) -> None:
    """Test /health endpoint returns status ok."""
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok", "service": "terminus"}


def test_auth_and_org_lifecycle_e2e(client: TestClient) -> None:
    """Test complete lifecycle: Register -> Login -> Create Org -> List Orgs -> Ingest Webhook Alert."""
    # 1. Register User 1 (Admin)
    res = client.post(
        "/auth/register",
        json={
            "email": "admin@acme-corp.com",
            "password": "SecurePassword123!",
            "display_name": "Alice Admin",
        },
    )
    assert res.status_code == 201
    user1_data = res.json()
    assert user1_data["email"] == "admin@acme-corp.com"

    # 2. Login User 1
    res = client.post(
        "/auth/login",
        json={
            "email": "admin@acme-corp.com",
            "password": "SecurePassword123!",
        },
    )
    assert res.status_code == 200
    login_data = res.json()
    token1 = login_data["session_token"]
    assert token1.startswith("tok-")

    headers1 = {"Authorization": f"Bearer {token1}"}

    # 3. Create Org
    res = client.post(
        "/orgs",
        headers=headers1,
        json={"name": "Acme Security Operations"},
    )
    assert res.status_code == 201
    org = res.json()
    org_id = org["org_id"]
    assert org_id.startswith("org-")

    # 4. List Orgs for User 1
    res = client.get("/orgs", headers=headers1)
    assert res.status_code == 200
    user_orgs = res.json()
    assert len(user_orgs) == 1
    assert user_orgs[0]["org_id"] == org_id

    # 5. Ingest Wazuh Webhook Alert with X-Org-ID and Auth headers
    sample_path = Path(__file__).parent.parent / "data" / "sample_alert.json"
    with sample_path.open("r", encoding="utf-8") as f:
        alert_payload = json.load(f)

    webhook_headers = {
        "Authorization": f"Bearer {token1}",
        "X-Org-ID": org_id,
    }
    res = client.post("/wazuh", headers=webhook_headers, json=alert_payload)
    assert res.status_code == 200
    report = res.json()
    assert report["alert_id"] == "1732100000.123456"
    assert report["policy"]["tier"] == "escalate"
    assert report["verdict"]["severity"] == "medium"


def test_agents_and_workflows_api(client: TestClient) -> None:
    """Test AI Agents and Workflows REST API endpoints."""
    # 1. List pre-seeded agents
    res = client.get("/agents")
    assert res.status_code == 200
    agents = res.json()
    assert len(agents) >= 4
    agent_ids = [a["id"] for a in agents]
    assert "agent-triage" in agent_ids
    assert "agent-forensic" in agent_ids

    # 2. Create new agent
    res = client.post(
        "/agents",
        json={
            "name": "Malware Sandbox Agent",
            "role_description": "Executes dynamic binary detonation in isolated VM sandbox.",
            "master_prompt": "You are the Malware Sandbox Agent. Execute PE files in Cuckoo Sandbox.",
        },
    )
    assert res.status_code == 201
    new_agent = res.json()
    assert new_agent["name"] == "Malware Sandbox Agent"
    assert new_agent["status"] == "active"

    # 3. Patch agent status (toggle to paused)
    res = client.patch(
        f"/agents/{new_agent['id']}",
        json={"status": "paused"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "paused"

    # 4. List pre-seeded workflows
    res = client.get("/workflows")
    assert res.status_code == 200
    workflows = res.json()
    assert len(workflows) >= 2

    # 5. Execute test workflow
    res = client.post(f"/workflows/{workflows[0]['id']}/execute")
    assert res.status_code == 200
    assert res.json()["status"] == "success"


def test_tenant_isolation_unauthorized_access(client: TestClient) -> None:
    """Test that users cannot submit alerts to orgs they are not members of."""
    # Register & Login User 1 -> Create Org A
    client.post(
        "/auth/register",
        json={
            "email": "u1@org-a.com",
            "password": "Pass123!Password",
            "display_name": "U1",
        },
    )
    res1 = client.post(
        "/auth/login", json={"email": "u1@org-a.com", "password": "Pass123!Password"}
    )
    token1 = res1.json()["session_token"]
    res_org_a = client.post(
        "/orgs", headers={"Authorization": token1}, json={"name": "Org A"}
    )
    org_a_id = res_org_a.json()["org_id"]

    # Register & Login User 2 -> Create Org B
    client.post(
        "/auth/register",
        json={
            "email": "u2@org-b.com",
            "password": "Pass123!Password",
            "display_name": "U2",
        },
    )
    res2 = client.post(
        "/auth/login", json={"email": "u2@org-b.com", "password": "Pass123!Password"}
    )
    token2 = res2.json()["session_token"]

    # User 2 attempts to send webhook alert specifying Org A's ID
    bad_headers = {
        "Authorization": token2,
        "X-Org-ID": org_a_id,
    }
    sample_path = Path(__file__).parent.parent / "data" / "sample_alert.json"
    with sample_path.open("r", encoding="utf-8") as f:
        alert_payload = json.load(f)

    res = client.post("/wazuh", headers=bad_headers, json=alert_payload)
    assert res.status_code == 403
    assert "not a member" in res.json()["detail"]
