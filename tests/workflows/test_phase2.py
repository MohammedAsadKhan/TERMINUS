import pytest
from pathlib import Path
from fastapi.testclient import TestClient

from terminus.server.app import create_app
from terminus.storage.db import init_db


@pytest.fixture
def client(tmp_path: Path) -> TestClient:
    db_path = tmp_path / "phase2_test.db"
    init_db(db_path)
    app = create_app()
    return TestClient(app)


def test_phase2_endpoints_and_tenancy(client: TestClient):
    # 1. Register admin and get session token
    reg_res = client.post(
        "/auth/register",
        json={
            "email": "testadmin@phase2.local",
            "password": "Password123!",
            "display_name": "Phase2 Admin",
        },
    )
    assert reg_res.status_code == 201

    login_res = client.post(
        "/auth/login",
        json={"email": "testadmin@phase2.local", "password": "Password123!"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["session_token"]
    auth_header = {"Authorization": f"Bearer {token}"}

    # Create Org 1 and Org 2
    org1_res = client.post("/orgs", json={"name": "Tenant 1"}, headers=auth_header)
    assert org1_res.status_code == 201
    org1_id = org1_res.json()["org_id"]

    org2_res = client.post("/orgs", json={"name": "Tenant 2"}, headers=auth_header)
    assert org2_res.status_code == 201
    org2_id = org2_res.json()["org_id"]

    headers_org1 = {"Authorization": f"Bearer {token}", "X-Org-ID": org1_id}
    headers_org2 = {"Authorization": f"Bearer {token}", "X-Org-ID": org2_id}

    # 2. Node Registry (T-API-1)
    res_reg = client.get("/workflows/node-registry", headers=headers_org1)
    assert res_reg.status_code == 200
    types = [n["type"] for n in res_reg.json()]
    assert len(types) == 8
    assert "trigger_wazuh" in types
    assert "tool_isolate" in types
    assert "trigger_cron" not in types

    # 3. Create Workflow in Org 1 (T-API-2)
    wf_data = {
        "id": "wf-p2-01",
        "name": "Phase 2 Triage Flow",
        "enabled": False,
        "nodes": [
            {"id": "n1", "type": "trigger_wazuh", "config": {"min_level": 5}},
            {"id": "n2", "type": "tool_slack", "config": {"channel": "#alerts"}},
        ],
        "edges": [
            {"id": "e1", "source": "n1", "target": "n2", "source_handle": "default"},
        ],
    }
    res_create = client.post("/workflows", json=wf_data, headers=headers_org1)
    assert res_create.status_code == 201
    created = res_create.json()
    assert created["id"] == "wf-p2-01"
    assert created["version"] == 1

    # 4. Invalid Workflow Schema Rejected with 422 (T-API-3)
    res_invalid = client.post(
        "/workflows",
        json={"id": "wf-bad", "name": "Bad", "nodes": [{"id": "n1", "type": "unknown_type"}]},
        headers=headers_org1,
    )
    assert res_invalid.status_code == 422

    # 5. Version Conflict Check (T-API-4, T-API-5)
    # Update with wrong expected_version -> 409
    res_conflict = client.put(
        "/workflows/wf-p2-01?expected_version=99",
        json={**wf_data, "name": "Updated Flow Name"},
        headers=headers_org1,
    )
    assert res_conflict.status_code == 409

    # Update with correct expected_version -> 200 and version becomes 2
    res_ok = client.put(
        "/workflows/wf-p2-01?expected_version=1",
        json={**wf_data, "name": "Updated Flow Name", "version": 1},
        headers=headers_org1,
    )
    assert res_ok.status_code == 200
    assert res_ok.json()["version"] == 2

    # 6. Toggle Enabled (T-API-6)
    res_toggle = client.patch(
        "/workflows/wf-p2-01/enabled",
        json={"enabled": True},
        headers=headers_org1,
    )
    assert res_toggle.status_code == 200
    assert res_toggle.json()["enabled"] is True

    # 7. Tenant Isolation for Workflows (T-TEN-1)
    # Org 1 sees its workflow
    res_list_org1 = client.get("/workflows", headers=headers_org1)
    assert any(w["id"] == "wf-p2-01" for w in res_list_org1.json())

    # Org 2 does not see Org 1's workflow
    res_list_org2 = client.get("/workflows", headers=headers_org2)
    assert not any(w["id"] == "wf-p2-01" for w in res_list_org2.json())

    # 8. SOC Agent Fleet CRUD & Tenancy (T-API-8, T-TEN-2)
    agent_payload = {
        "name": "Custom SOC Analyst",
        "role_description": "Analyzes specialized network flows",
        "master_prompt": "You are specialized in network security.",
    }
    res_agent_create = client.post("/agents", json=agent_payload, headers=headers_org1)
    assert res_agent_create.status_code == 201
    created_agent = res_agent_create.json()
    agent_id = created_agent["id"]

    res_agents_org1 = client.get("/agents", headers=headers_org1)
    assert any(a["id"] == agent_id for a in res_agents_org1.json())

    res_agents_org2 = client.get("/agents", headers=headers_org2)
    assert not any(a["id"] == agent_id for a in res_agents_org2.json())

    # 9. Containment Allowlist CRUD & Tenancy (T-API-9, T-TEN-3)
    allow_res = client.post(
        "/containment/allowlist",
        json={"kind": "host", "value": "critical-vault-01.corp", "note": "Primary Vault"},
        headers=headers_org1,
    )
    assert allow_res.status_code == 201

    al_list1 = client.get("/containment/allowlist", headers=headers_org1)
    assert len(al_list1.json()) == 1
    assert al_list1.json()[0]["value"] == "critical-vault-01.corp"

    al_list2 = client.get("/containment/allowlist", headers=headers_org2)
    assert len(al_list2.json()) == 0

    # 10. Runs and Approvals Listing (T-API-10)
    res_runs = client.get("/workflows/runs", headers=headers_org1)
    assert res_runs.status_code == 200
    assert isinstance(res_runs.json(), list)

    res_approvals = client.get("/workflows/approvals/pending", headers=headers_org1)
    assert res_approvals.status_code == 200
    assert isinstance(res_approvals.json(), list)

    # 11. Delete Workflow (T-API-7)
    res_del = client.delete("/workflows/wf-p2-01", headers=headers_org1)
    assert res_del.status_code in (200, 204)
    res_get_del = client.get("/workflows/wf-p2-01", headers=headers_org1)
    assert res_get_del.status_code == 404
