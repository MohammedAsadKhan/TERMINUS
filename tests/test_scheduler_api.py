"""Tenant-isolated HTTP coverage for persisted scheduler controls."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import pytest
from fastapi import FastAPI, Header
from fastapi.testclient import TestClient

from terminus.auth.models import User
from terminus.core.ids import OrgId, UserId
from terminus.orgs.models import OrganizationRole
from terminus.orchestration import OrchestrationStore
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.server.deps import (
    get_current_org,
    get_current_user,
    get_membership_store,
)
from terminus.server.orchestration_api import (
    get_orchestration_store,
    get_scheduler_store,
    router,
)
from terminus.storage.db import Database


class _Memberships:
    def role_of(self, org_id: str, user_id: str) -> OrganizationRole | None:
        if user_id == "operator" and org_id in {"org-a", "org-b"}:
            return OrganizationRole.MEMBER
        if user_id == "viewer" and org_id in {"org-a", "org-b"}:
            return OrganizationRole.VIEWER
        return None


@pytest.fixture
def api(tmp_path: Path) -> tuple[TestClient, OrchestrationStore, SchedulerStore]:
    db = Database(str(tmp_path / "scheduler-api.db"))
    now = datetime.now(UTC).isoformat()
    for org_id in ("org-a", "org-b"):
        db.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org_id, org_id, now),
        )
    db.execute(
        """INSERT INTO incidents(
            ticket_id,org_id,alert_id,severity,confidence,summary,
            recommended_actions,policy_tier,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?)""",
        (
            "incident-a", "org-a", "alert-a", "high", "high", "Test incident",
            "[]", "standard", now,
        ),
    )
    db.execute(
        """INSERT INTO incidents(
            ticket_id,org_id,alert_id,severity,confidence,summary,
            recommended_actions,policy_tier,created_at
        ) VALUES(?,?,?,?,?,?,?,?,?)""",
        (
            "incident-b", "org-b", "alert-b", "high", "high", "Test incident",
            "[]", "standard", now,
        ),
    )
    store = OrchestrationStore(db)
    scheduler = SchedulerStore(db)
    app = FastAPI()
    app.include_router(router)

    def current_user(
        user_id: Annotated[str, Header(alias="X-Test-User")] = "operator",
    ) -> User:
        return User(
            user_id=UserId(user_id),
            email=f"{user_id}@example.test",
            password_hash="unused",
            display_name=user_id,
            created_at=datetime.now(UTC),
        )

    def current_org(
        org_id: Annotated[str, Header(alias="X-Org-ID")] = "org-a",
    ) -> OrgId:
        return OrgId(org_id)

    app.dependency_overrides[get_current_user] = current_user
    app.dependency_overrides[get_current_org] = current_org
    app.dependency_overrides[get_membership_store] = _Memberships
    app.dependency_overrides[get_orchestration_store] = lambda: store
    app.dependency_overrides[get_scheduler_store] = lambda: scheduler
    return TestClient(app), store, scheduler


def _task(store: OrchestrationStore, org_id: str = "org-a", incident_id: str = "incident-a"):
    return store.create_incident_task(
        org_id, incident_id, "triage", "analyst", "Investigate this incident"
    )


def test_list_paging_and_task_detail_include_persisted_children(api) -> None:
    client, store, _ = api
    first = _task(store)
    _task(store)
    store.create_agent_run("org-a", first.task_id, model_name="metadata-only")
    store.create_evidence(
        "org-a", first.task_id, "siem", datetime.now(UTC), content={"event": "alert"}
    )
    store.create_help_request("org-a", first.task_id, "forensics", "Need logs")
    store.create_action_attempt("org-a", first.task_id, "isolate", ["host-1"])

    all_tasks = client.get("/orchestration/tasks").json()["items"]
    page = client.get("/orchestration/tasks?limit=1&offset=1")
    assert page.status_code == 200
    assert page.json()["items"] == all_tasks[1:2]
    assert page.json()["limit"] == 1
    assert client.get("/orchestration/tasks?limit=201").status_code == 400
    assert client.get("/orchestration/tasks?offset=-1").status_code == 400

    detail = client.get(f"/orchestration/tasks/{first.task_id}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["task"]["task_id"] == first.task_id
    assert payload["scheduler_job"] is None
    assert len(payload["runs"]) == 1
    assert len(payload["evidence"]) == 1
    assert len(payload["help_requests"]) == 1
    assert payload["actions"][0]["action"] == "isolate"


def test_cross_tenant_task_and_enqueue_are_hidden(api) -> None:
    client, store, _ = api
    task = _task(store)
    headers = {"X-Org-ID": "org-b"}
    assert client.get(f"/orchestration/tasks/{task.task_id}", headers=headers).status_code == 404
    assert client.post(
        f"/orchestration/tasks/{task.task_id}/enqueue", headers=headers, json={}
    ).status_code == 404


def test_enqueue_validates_body_canonical_incident_and_queued_state(api) -> None:
    client, store, scheduler = api
    task = _task(store)
    response = client.post(
        f"/orchestration/tasks/{task.task_id}/enqueue", json={"max_attempts": 5}
    )
    assert response.status_code == 202
    assert response.json()["max_attempts"] == 5
    assert scheduler.get_job("org-a", task.task_id).max_attempts == 5
    assert "lease_token" not in response.json()

    invalid = client.post(
        f"/orchestration/tasks/{task.task_id}/enqueue",
        json={"max_attempts": 0},
    )
    assert invalid.status_code == 400
    extra = client.post(
        f"/orchestration/tasks/{task.task_id}/enqueue",
        json={"org_id": "org-b", "max_attempts": 3},
    )
    assert extra.status_code == 400

    legacy = store.create_task(
        "org-a", "legacy-no-canonical-incident", "triage", "analyst", "Legacy"
    )
    assert client.post(
        f"/orchestration/tasks/{legacy.task_id}/enqueue", json={}
    ).status_code == 404

    running = _task(store)
    store.transition_task("org-a", running.task_id, "queued", "running")
    conflict = client.post(
        f"/orchestration/tasks/{running.task_id}/enqueue", json={}
    )
    assert conflict.status_code == 409


def test_cancel_is_operator_only_and_persisted(api) -> None:
    client, store, scheduler = api
    task = _task(store)
    assert client.post(f"/orchestration/tasks/{task.task_id}/enqueue", json={}).status_code == 202
    response = client.post(
        f"/orchestration/tasks/{task.task_id}/cancel",
        headers={"X-Test-User": "viewer"},
    )
    assert response.status_code == 403
    cancelled = client.post(f"/orchestration/tasks/{task.task_id}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["cancellation_requested"] is True
    assert scheduler.get_job("org-a", task.task_id).cancellation_requested is True


def test_reads_require_authentication_and_job_lease_secret_is_never_returned(api) -> None:
    client, store, scheduler = api
    task = _task(store)
    assert client.post(f"/orchestration/tasks/{task.task_id}/enqueue", json={}).status_code == 202
    job = scheduler.get_job("org-a", task.task_id).model_copy(
        update={"lease_token": "lease-secret-value"}
    )
    scheduler.db.execute(
        "UPDATE orchestration_scheduler_jobs SET payload_json=? WHERE org_id=? AND task_id=?",
        (job.model_dump_json(), "org-a", task.task_id),
    )
    response = client.get(f"/orchestration/tasks/{task.task_id}")
    assert response.status_code == 200
    assert "lease_token" not in response.text
    assert "lease-secret-value" not in response.text

    unauthenticated = FastAPI()
    unauthenticated.include_router(router)
    anonymous_client = TestClient(unauthenticated)
    assert anonymous_client.get("/orchestration/tasks").status_code == 401


def test_public_responses_scrub_free_text_credentials_and_hide_raw_errors(api) -> None:
    client, store, scheduler = api
    task = _task(store)
    job = scheduler.enqueue_task("org-a", task.task_id).model_copy(
        update={"error": "Provider rejected opaque-private-value"}
    )
    scheduler.db.execute(
        "UPDATE orchestration_scheduler_jobs SET payload_json=? WHERE org_id=? AND task_id=?",
        (job.model_dump_json(), "org-a", task.task_id),
    )
    store.create_evidence(
        "org-a", task.task_id, "siem", datetime.now(UTC),
        content={"message": "password=private-password-value", "api_key": "private-key-value"},
    )
    response = client.get(f"/orchestration/tasks/{task.task_id}")
    assert response.status_code == 200
    for secret in ("opaque-private-value", "private-password-value", "private-key-value"):
        assert secret not in response.text
    assert "Execution error; inspect protected diagnostics" in response.text
