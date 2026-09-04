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

    # 1. GET /reports initializes quick report if empty
    res = client.get("/reports")
    assert res.status_code == 200
    reports = res.json()
    assert len(reports) >= 1
    first_report_id = reports[0]["id"]

    # 2. POST /reports/quick generates new quick report based on logs from start of day to now
    res_quick = client.post("/reports/quick")
    assert res_quick.status_code == 201
    quick_data = res_quick.json()
    assert quick_data["report_type"] == "quick"
    assert quick_data["id"].startswith("rep-")

    # 3. POST /reports/daily generates new 24h daily summary report
    res_daily = client.post("/reports/daily")
    assert res_daily.status_code == 201
    daily_data = res_daily.json()
    assert daily_data["report_type"] == "daily_24h"

    # 4. GET /reports list contains all created reports
    res_list = client.get("/reports")
    assert res_list.status_code == 200
    all_reports = res_list.json()
    assert len(all_reports) >= 3

    # 5. GET /reports/{report_id} fetches specific report
    res_single = client.get(f"/reports/{first_report_id}")
    assert res_single.status_code == 200
    assert res_single.json()["id"] == first_report_id
