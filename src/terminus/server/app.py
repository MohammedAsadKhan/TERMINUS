"""FastAPI application factory and server entrypoint."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from terminus.config import get_settings
from terminus.models import ReportType
from terminus.reports.service import generate_daily_report
from terminus.server.deps import get_org_store, get_pipeline_runner, get_reports_store
from terminus.server.routers import (
    agent_router,
    auth_router,
    health_router,
    org_router,
    report_router,
    webhook_router,
    workflow_router,
)


async def _daily_report_scheduler_task() -> None:
    """Background task running every 24 hours to generate daily operations summary reports."""
    while True:
        try:
            await asyncio.sleep(86400)  # 24 hours
            settings = get_settings()
            pipeline_runner = get_pipeline_runner(settings)
            org_store = get_org_store()
            reports_store = get_reports_store()

            for org in org_store.list_all():
                report = await generate_daily_report(
                    org.org_id,
                    ReportType.DAILY_24H,
                    pipeline_runner.deployment.ticket_store,
                )
                if org.org_id not in reports_store:
                    reports_store[org.org_id] = {}
                reports_store[org.org_id][report.id] = report
                print(
                    f"[Scheduler] Automatically produced 24h Daily Incident Report '{report.id}' for org {org.org_id}"
                )
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[Scheduler] Error generating daily report: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """App lifespan context manager for startup and shutdown hooks."""
    settings = get_settings()
    print(f"Terminus platform booting up... (LLM Base URL: {settings.llm_base_url})")

    # Spawn 24h automatic daily report scheduler background task
    task = asyncio.create_task(_daily_report_scheduler_task())
    yield
    task.cancel()
    print("Terminus platform shutting down.")


def create_app() -> FastAPI:
    """FastAPI application factory."""
    app = FastAPI(
        title="Terminus — Agentic SOC Platform",
        description="Multi-tenant commercial AI SOC engine for Wazuh SIEM.",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(org_router)
    app.include_router(webhook_router)
    app.include_router(agent_router)
    app.include_router(workflow_router)
    app.include_router(report_router)

    return app


def main() -> None:
    """CLI entry point for terminus-serve command."""
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
