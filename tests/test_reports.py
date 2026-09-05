"""Unit and integration tests for Daily Incident Reports and Report Manager API."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from terminus.models import ReportType
from terminus.reports.service import generate_daily_report
from terminus.server.app import create_app
from terminus.ticketing.memory import MemoryTickets


@pytest.mark.anyio
async def test_generate_daily_report_service() -> None:
    """Test report generation service creates valid Quick and 24h Daily Reports."""
    store = MemoryTickets()

    # Generate Quick Report
    report_quick = await generate_daily_report("org-00000001", ReportType.QUICK, store)
    assert report_quick.id.startswith("rep-")
    assert report_quick.report_type == ReportType.QUICK
    assert "Quick Report" in report_quick.title
    assert report_quick.metrics.total_incidents == 0

    # Generate 24h Daily Summary Report
    report_24h = await generate_daily_report("org-00000001", ReportType.DAILY_24H, store)
    assert report_24h.id.startswith("rep-")
    assert report_24h.report_type == ReportType.DAILY_24H
    assert "24-Hour Operations Summary" in report_24h.title


def test_reports_api_lifecycle() -> None:
    """Test REST API endpoints: GET /reports, POST /reports/quick, POST /reports/daily, GET /reports/{id}."""
    app = create_app()
    client = TestClient(app)

    # Register & Login User -> Create Org
    client.post(
        "/auth/register",
        json={
            "email": "reports-admin@acme-corp.com",
            "password": "SecurePassword123!",
            "display_name": "Reports Admin",
        },
    )
    res_login = client.post(
        "/auth/login",
        json={
            "email": "reports-admin@acme-corp.com",
            "password": "SecurePassword123!",
        },
    )
    assert res_login.status_code == 200
    token = res_login.json()["session_token"]
    res_org = client.post(
        "/orgs",
        headers={"Authorization": f"Bearer {token}"},
        json={"name": "Reports Testing Org"},
    )
    assert res_org.status_code == 201
    org_id = res_org.json()["org_id"]
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Org-ID": org_id,
    }

    # 1. GET /reports empty initially
    res = client.get("/reports", headers=headers)
    assert res.status_code == 200
    assert res.json() == []

    # 2. POST /reports/quick generates new quick report based on logs from start of day to now
    res_quick = client.post("/reports/quick", headers=headers)
    assert res_quick.status_code == 201
    quick_data = res_quick.json()
    assert quick_data["report_type"] == "quick"
    assert quick_data["id"].startswith("rep-")
    first_report_id = quick_data["id"]

    # 3. POST /reports/daily generates new 24h daily summary report
    res_daily = client.post("/reports/daily", headers=headers)
    assert res_daily.status_code == 201
    daily_data = res_daily.json()
    assert daily_data["report_type"] == "daily_24h"

    # 4. GET /reports list contains all created reports
    res_list = client.get("/reports", headers=headers)
    assert res_list.status_code == 200
    all_reports = res_list.json()
    assert len(all_reports) == 2

    # 5. GET /reports/{report_id} fetches specific report
    res_single = client.get(f"/reports/{first_report_id}", headers=headers)
    assert res_single.status_code == 200
    assert res_single.json()["id"] == first_report_id
