"""HTTP authentication, strict admission, tenant boundaries and safe inspection."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from terminus.auth.models import User
from terminus.core.ids import UserId
from terminus.orchestration import OrchestrationStore
from terminus.orgs.models import OrganizationRole
from terminus.storage.db import Database


class _Auth:
    def verify(self, token: str) -> User:
        if token not in {"operator", "viewer"}:
            raise ValueError("Invalid test session")
        return User(
            user_id=UserId(token), email=f"{token}@example.test",
            password_hash="unused", display_name=token, created_at=datetime.now(UTC),
        )


class _Memberships:
    def role_of(self, org_id: str, user_id: str) -> OrganizationRole | None:
        if org_id == "org-a" and user_id == "operator":
            return OrganizationRole.MEMBER
        if org_id == "org-a" and user_id == "viewer":
            return OrganizationRole.VIEWER
        return None


@pytest.fixture
def api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[TestClient, OrchestrationStore]]:
    # deps constructs repositories at import: establish a scratch singleton first.
    db = Database(str(tmp_path / "coordination-api.db"))
    monkeypatch.setattr(Database, "_instance", db)
    from terminus.orchestration.coordination import CoordinationService
    from terminus.server.coordination_api import get_coordination_service, router
    from terminus.server.deps import get_auth_service, get_membership_store

    now = datetime.now(UTC).isoformat()
    for suffix in ("a", "b"):
        db.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (f"org-{suffix}", f"Organization {suffix}", now),
        )
        db.execute(
            """INSERT INTO incidents(
                ticket_id,org_id,alert_id,severity,confidence,summary,
                recommended_actions,policy_tier,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (f"incident-{suffix}", f"org-{suffix}", f"alert-{suffix}",
             "high", "high", "Test incident", "[]", "standard", now),
        )
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_auth_service] = _Auth
    app.dependency_overrides[get_membership_store] = _Memberships
    app.dependency_overrides[get_coordination_service] = lambda: CoordinationService(db)
    with TestClient(app) as client:
        yield client, OrchestrationStore(db)
    db.close()


def _headers(user: str = "operator", org: str = "org-a") -> dict[str, str]:
    return {"Authorization": f"Bearer {user}", "X-Org-ID": org}


def _objective(**changes: Any) -> dict[str, Any]:
    return {"objective": "Investigate incident", "areas": ["investigation"],
            "idempotency_key": "start-1", **changes}


@pytest.mark.parametrize(("method", "path"), [
    ("POST", "/orchestration/incidents/incident-a/start"),
    ("GET", "/orchestration/incidents/incident-a/tree"),
    ("POST", "/orchestration/help-requests/missing/assign"),
    ("POST", "/orchestration/help-requests/missing/reconcile"),
])
def test_requires_authenticated_active_membership(api, method: str, path: str) -> None:
    client, _ = api
    kwargs = {"json": _objective()} if path.endswith("/start") else {}
    assert client.request(method, path, **kwargs).status_code == 401
    assert client.request(method, path, headers=_headers("bad-token"), **kwargs).status_code == 401
    assert client.request(method, path, headers=_headers(org="org-b"), **kwargs).status_code == 403


def test_viewer_can_inspect_but_cannot_start_or_assign(api) -> None:
    client, store = api
    assert client.post("/orchestration/incidents/incident-a/start", headers=_headers("viewer"),
                       json=_objective()).status_code == 403
    assert client.post("/orchestration/help-requests/missing/assign",
                       headers=_headers("viewer")).status_code == 403
    assert client.post("/orchestration/help-requests/missing/reconcile",
                       headers=_headers("viewer")).status_code == 403
    assert client.get("/orchestration/incidents/incident-a/tree",
                      headers=_headers("viewer")).status_code == 200
    assert store.list_tasks("org-a") == []


@pytest.mark.parametrize("changes", [
    {"objective": ""}, {"objective": "   "}, {"objective": 42},
    {"areas": []}, {"areas": "investigation"}, {"areas": ["unknown"]},
    {"areas": ["investigation", "investigation"]},
    {"priority": "100"}, {"priority": True}, {"priority": -1}, {"priority": 1001},
    {"idempotency_key": ""}, {"org_id": "org-b"}, {"incident_id": "incident-b"},
    {"role": "main"}, {"model_name": "foreign"}, {"tool": "execute"},
])
def test_start_rejects_invalid_or_foreign_scope_body(api, changes: dict[str, Any]) -> None:
    client, store = api
    response = client.post("/orchestration/incidents/incident-a/start", headers=_headers(),
                           json=_objective(**changes))
    assert response.status_code == 400
    assert store.list_tasks("org-a") == []


@pytest.mark.parametrize("field", ["objective", "areas", "idempotency_key"])
def test_start_requires_explicit_objective_areas_and_key(api, field: str) -> None:
    client, _ = api
    payload = _objective()
    del payload[field]
    assert client.post("/orchestration/incidents/incident-a/start", headers=_headers(),
                       json=payload).status_code == 400


def test_all_five_areas_are_explicitly_accepted(api) -> None:
    client, _ = api
    areas = ["alert_handling", "investigation", "infrastructure",
             "applications_data", "response_improvement"]
    response = client.post("/orchestration/incidents/incident-a/start", headers=_headers(),
                           json=_objective(areas=areas))
    assert response.status_code == 202
    tree = client.get("/orchestration/incidents/incident-a/tree", headers=_headers()).json()
    assert set(tree["planned_areas"]) == set(areas)


def test_validation_error_does_not_echo_supplied_credentials(api) -> None:
    client, _ = api
    response = client.post("/orchestration/incidents/incident-a/start", headers=_headers(),
                           json=_objective(priority="secret-password-value"))
    assert response.status_code == 400
    assert "secret-password-value" not in response.text


def test_start_is_durable_idempotent_and_tenant_scoped(api) -> None:
    client, store = api
    path = "/orchestration/incidents/incident-a/start"
    first = client.post(path, headers=_headers(), json=_objective())
    second = client.post(path, headers=_headers(), json=_objective())
    assert first.status_code == second.status_code == 202
    assert first.json()["task_id"] == second.json()["task_id"]
    assert first.json()["priority"] == 100
    assert len(store.list_tasks("org-a")) == 1
    assert client.post(path, headers=_headers(),
                       json=_objective(objective="Changed objective")).status_code == 409
    assert store.list_agent_runs("org-a") == []
    assert store.list_action_attempts("org-a") == []
    for incident in ("incident-b", "missing"):
        assert client.post(f"/orchestration/incidents/{incident}/start", headers=_headers(),
                           json=_objective()).status_code == 404
        assert client.get(f"/orchestration/incidents/{incident}/tree",
                          headers=_headers()).status_code == 404
    assert store.list_tasks("org-b") == []


def test_assign_help_is_idempotent_and_hides_foreign_records(api) -> None:
    from terminus.orchestration.coordination_models import AreaObjective

    client, store = api
    root = client.post("/orchestration/incidents/incident-a/start", headers=_headers(),
                       json=_objective()).json()
    area_objective = AreaObjective(area="investigation", objective="Inspect", roles=["network"])
    area = store.create_incident_task("org-a", "incident-a", "investigation", "area_orchestrator", area_objective.model_dump_json(),
                                      parent_task_id=root["task_id"])
    task = store.create_incident_task("org-a", "incident-a", "investigation", "network", "Inspect",
                                      parent_task_id=area.task_id)
    help_request = store.create_help_request("org-a", task.task_id, "network", "Need network evidence")
    path = f"/orchestration/help-requests/{help_request.help_request_id}/assign"
    first = client.post(path, headers=_headers())
    second = client.post(path, headers=_headers())
    assert first.status_code == second.status_code == 202
    assert first.json()["task_id"] == second.json()["task_id"]
    assert store.get_help_request("org-a", help_request.help_request_id).status == "assigned"
    foreign_task = store.create_incident_task("org-b", "incident-b", "investigation", "network", "Inspect")
    foreign = store.create_help_request("org-b", foreign_task.task_id, "network", "Private incident")
    assert client.post(f"/orchestration/help-requests/{foreign.help_request_id}/assign",
                       headers=_headers()).status_code == 404
    assert store.get_help_request("org-b", foreign.help_request_id).status == "open"
    assert client.post("/orchestration/help-requests/missing/assign", headers=_headers()).status_code == 404


def test_tree_reports_persisted_states_and_redacts_nested_data(api) -> None:
    client, store = api
    root = client.post("/orchestration/incidents/incident-a/start", headers=_headers(),
                       json=_objective(objective="Inspect password=supersecret")).json()
    assert "supersecret" not in json.dumps(root)
    task_id = root["task_id"]
    run = store.create_agent_run("org-a", task_id, model_name="persisted-metadata")
    store.transition_agent_run("org-a", run.run_id, "queued", "running")
    store.transition_agent_run("org-a", run.run_id, "running", "failed",
                               error="Unstructured private runtime diagnostic")
    store.create_evidence("org-a", task_id, "test", datetime.now(UTC),
                          content={"api_key": "private-api-key", "nested": {"password": "private-password"},
                                   "note": "Bearer abcdefghijklmnopqrstuvwxyz"})
    tree = client.get("/orchestration/incidents/incident-a/tree", headers=_headers()).json()
    text = json.dumps(tree)
    assert task_id in text
    assert run.run_id in text
    assert "queued" in text
    assert "failed" in text
    assert "aggregate_status" in tree
    assert tree["incident_closed"] is False
    assert "private-api-key" not in text
    assert "private-password" not in text
    assert "abcdefghijklmnopqrstuvwxyz" not in text
    assert "supersecret" not in text
    assert "Unstructured private runtime diagnostic" not in text
    assert "supersecret" in store.get_task("org-a", task_id).objective


def test_reconcile_requires_completed_delegated_specialist_and_hides_foreign_help(api) -> None:
    from terminus.orchestration.coordination import _key
    from terminus.orchestration.coordination_models import AreaObjective

    client, store = api
    root = client.post("/orchestration/incidents/incident-a/start", headers=_headers(),
                       json=_objective()).json()
    area_objective = AreaObjective(area="investigation", objective="Inspect", roles=["network"])
    area = store.create_incident_task("org-a", "incident-a", "investigation", "area_orchestrator", area_objective.model_dump_json(),
                                      parent_task_id=root["task_id"])
    task = store.create_incident_task("org-a", "incident-a", "investigation", "network", "Inspect",
                                      parent_task_id=area.task_id)
    help_request = store.create_help_request("org-a", task.task_id, "network", "Inspect password=supersecret")
    prefix = f"/orchestration/help-requests/{help_request.help_request_id}"
    delegated = client.post(f"{prefix}/assign", headers=_headers()).json()
    response = client.post(f"{prefix}/reconcile", headers=_headers())
    assert response.status_code == 200
    assert response.json()["status"] == "assigned"
    assert "supersecret" not in response.text
    child = store.create_incident_task("org-a", "incident-a", "investigation", "network", "Inspect",
                                       parent_task_id=delegated["task_id"],
                                       idempotency_key=_key(delegated["task_id"], "network"))
    store.transition_task("org-a", child.task_id, "queued", "running")
    assert client.post(f"{prefix}/reconcile", headers=_headers()).json()["status"] == "assigned"
    store.transition_task("org-a", child.task_id, "running", "completed")
    # Reading the tree leaves bookkeeping untouched even after child completion.
    assert client.get("/orchestration/incidents/incident-a/tree", headers=_headers()).status_code == 200
    assert store.get_help_request("org-a", help_request.help_request_id).status == "assigned"
    assert client.post(f"{prefix}/reconcile", headers=_headers()).json()["status"] == "resolved"
    assert client.post(f"{prefix}/reconcile", headers=_headers()).json()["status"] == "resolved"
    foreign_task = store.create_incident_task("org-b", "incident-b", "investigation", "network", "Inspect")
    foreign = store.create_help_request("org-b", foreign_task.task_id, "network", "Private incident")
    assert client.post(f"/orchestration/help-requests/{foreign.help_request_id}/reconcile",
                       headers=_headers()).status_code == 404
    assert store.get_help_request("org-b", foreign.help_request_id).status == "open"
