# ruff: noqa: F811
"""Settings changes require current tenant-admin authority and durable CAS."""

import json

from tests.test_model_connections_api import api  # noqa: F401


def test_policy_json_grants_round_trip_and_version_conflict(api):
    client, _, _, ids = api
    connection = client.post(
        "/model-connections",
        headers=ids["admin"],
        json={
            "name": "Private",
            "provider": "local",
            "base_url": "http://127.0.0.1:11434/v1",
            "models": ["fixture-model"],
            "enabled": True,
        },
    ).json()
    payload = {
        "expected_version": 0,
        "enabled": True,
        "grants": [
            {
                "role": "triage",
                "area": None,
                "connection_id": connection["connection_id"],
                "connection_version": connection["version"],
                "models": ["fixture-model"],
                "classifications": ["local_only"],
            }
        ],
    }
    response = client.put("/model-settings/policy", headers=ids["admin"], json=payload)
    assert response.status_code == 200, response.text
    assert response.json()["version"] == 1
    assert (
        client.get("/model-settings/policy", headers=ids["viewer"]).json()["grants"]
        == payload["grants"]
    )
    assert (
        client.put(
            "/model-settings/policy", headers=ids["admin"], json=payload
        ).status_code
        == 409
    )
    assert (
        client.get("/model-settings/policy", headers=ids["foreign"]).status_code == 404
    )


def test_model_settings_writes_require_admin_and_demotion_is_immediate(api):
    client, db, _, ids = api
    payload = {"expected_version": 0, "limit_micro_usd": 10000}
    for role in ("member", "viewer"):
        assert (
            client.put(
                "/model-settings/budget/2026-10-04", headers=ids[role], json=payload
            ).status_code
            == 403
        )
    db.execute(
        "UPDATE memberships SET role=? WHERE org_id=? AND user_id=?",
        ("member", ids["org_id"], ids["users"]["admin"]["user_id"]),
    )
    assert (
        client.put(
            "/model-settings/budget/2026-10-04", headers=ids["admin"], json=payload
        ).status_code
        == 403
    )


def test_budget_round_trip_unknown_usage_and_tenant_isolation(api):
    client, _, _, ids = api
    path = "/model-settings/budget/2026-10-04"
    payload = {"expected_version": 0, "limit_micro_usd": 10000, "limit_tokens": 1000}
    result = client.put(path, headers=ids["admin"], json=payload)
    assert result.status_code == 200, result.text
    assert client.get(path, headers=ids["member"]).json()["version"] == 1
    assert client.put(path, headers=ids["admin"], json=payload).status_code == 409
    assert client.get(path, headers=ids["foreign"]).status_code == 404
    assert (
        client.get(
            "/model-settings/usage/2026-10-04", headers=ids["viewer"]
        ).status_code
        == 200
    )


def test_settings_invalid_inputs_never_echo_secrets(api):
    client, _, _, ids = api
    for body in (
        '{"secret":"never-echo"',
        json.dumps({"grants": [], "api_key": "never-echo"}),
    ):
        response = client.put(
            "/model-settings/policy",
            headers={**ids["admin"], "Content-Type": "application/json"},
            content=body,
        )
        assert response.status_code == 422
        assert "never-echo" not in response.text
    future = {
        "grants": [
            {
                "role": "malware",
                "connection_id": "not-real",
                "connection_version": 1,
                "models": ["m"],
            }
        ],
        "expected_version": 0,
    }
    assert (
        client.put(
            "/model-settings/policy", headers=ids["admin"], json=future
        ).status_code
        == 422
    )


def test_price_requires_registered_tenant_model_and_cas(api):
    client, _, _, ids = api
    connection = client.post(
        "/model-connections",
        headers=ids["admin"],
        json={
            "name": "OpenAI",
            "provider": "openai",
            "models": ["fixture-model"],
        },
    ).json()
    path = f"/model-settings/prices/{connection['connection_id']}/fixture-model"
    payload = {
        "input_per_mtok_micro_usd": 1000000,
        "output_per_mtok_micro_usd": 2000000,
    }
    response = client.put(path, headers=ids["admin"], json=payload)
    assert response.status_code == 200, response.text
    assert client.get(path, headers=ids["member"]).status_code == 200
    assert client.put(path, headers=ids["admin"], json=payload).status_code == 409
    assert client.get(path, headers=ids["foreign"]).status_code == 404
    assert (
        client.put(
            path.replace("fixture-model", "not-registered"),
            headers=ids["admin"],
            json=payload,
        ).status_code
        == 404
    )


def test_catalog_is_authenticated_metadata_not_execution_grant(api):
    client, _, _, ids = api
    assert client.get("/orchestration/catalog").status_code == 401
    response = client.get("/orchestration/catalog", headers=ids["viewer"])
    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 60
    assert all(item["execution_available"] is False for item in items)
    assert len({item["core_role"] for item in items if item["core_role"]}) == 8
    assert all(
        item["status_label"] == "Planned — unavailable in 1.0"
        for item in items
        if item["core_role"] is None
    )
