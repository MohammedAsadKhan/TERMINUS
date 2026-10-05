"""Keep synthetic public demo traffic out of other tenants and hosted mode."""

from __future__ import annotations

import asyncio
import importlib
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.requests import Request

from terminus.server.bank_router import get_bank_treasury_keys
from terminus.server.routers import get_decoy_vault_secrets


class RecordingRunner:
    def __init__(self) -> None:
        self.orgs: list[str] = []

    async def process_alert(self, _alert: Any, org_id: Any) -> None:
        self.orgs.append(str(org_id))


def spoofed_request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/decoy/vault-secrets",
            "headers": [(b"x-org-id", b"org-another-tenant")],
            "client": ("127.0.0.1", 54321),
        }
    )


@pytest.mark.parametrize("handler", [get_bank_treasury_keys, get_decoy_vault_secrets])
def test_public_demo_alert_ignores_caller_selected_org(handler: Any) -> None:
    runner = RecordingRunner()
    asyncio.run(handler(spoofed_request(), runner, SimpleNamespace()))
    assert runner.orgs == ["org-terminus-demo"]


def test_hosted_app_does_not_mount_public_demo_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    app_module = importlib.import_module("terminus.server.app")
    monkeypatch.setattr(
        app_module,
        "get_settings",
        lambda: SimpleNamespace(deployment_mode="hosted"),
    )
    app = app_module.create_app()
    routes = {getattr(route, "path", None) for route in app.routes}
    assert "/decoy/vault-secrets" not in routes
    assert "/decoy/customer-pii" not in routes
    assert "/bank/api/admin/treasury-keys" not in routes
