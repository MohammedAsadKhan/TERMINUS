"""FastAPI application factory and server entrypoint for TERMINUS 2.0."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from terminus.config import get_settings
from terminus.core.base import ConflictError, NotFoundError
from terminus.models import ReportType
from terminus.reports.service import generate_daily_report
from terminus.server.bank_router import bank_router
from terminus.server.console_api import router as console_router
from terminus.server.copilot import copilot_router, global_copilot_router
from terminus.server.deps import get_org_store, get_pipeline_runner, get_reports_store
from terminus.server.graph import graph_router
from terminus.server.routers import (
    agent_router,
    allowlist_router,
    auth_router,
    decoy_router,
    health_router,
    org_router,
    report_router,
    webhook_router,
    workflow_router,
)
from terminus.server.streaming import streaming_router


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
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[Scheduler] Error generating daily report: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """App lifespan context manager for startup and shutdown hooks."""
    settings = get_settings()
    # Auto-configure baseline SOC configuration (allowlists, agents, workflows)
    from terminus.server.deps import (
        _sqlite_agent_repo,
        _sqlite_allowlist_repo,
        _sqlite_workflow_repo,
    )
    from terminus.service.sensor import service_sensor

    for default_org in ["org-default", "org-terminus-demo"]:
        service_sensor.auto_configure_baseline(
            default_org,
            _sqlite_agent_repo,
            _sqlite_workflow_repo,
            _sqlite_allowlist_repo,
        )

    # Spawn 24h automatic daily report scheduler background task
    task = asyncio.create_task(_daily_report_scheduler_task())
    # Spawn 60s sweeper background task with initialized deployment (D24)
    from terminus.pipeline.sweeper import sweeper_background_task
    pipeline_runner = get_pipeline_runner(settings)
    sweeper_task = asyncio.create_task(sweeper_background_task(deployment=pipeline_runner.deployment))
    yield
    task.cancel()
    sweeper_task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    try:
        await sweeper_task
    except asyncio.CancelledError:
        pass
    print("Terminus platform shutting down.")


def create_app() -> FastAPI:
    """FastAPI application factory."""
    app = FastAPI(
        title="Terminus — Agentic SOC Platform",
        description="Multi-tenant commercial AI SOC engine for Wazuh SIEM.",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    assets = Path(__file__).parent / "static" / "console" / "assets"
    app.mount("/console/assets", StaticFiles(directory=str(assets), check_dir=False), name="console-assets")

    @app.exception_handler(NotFoundError)
    async def not_found(request: Request, exc: NotFoundError) -> JSONResponse:
        return JSONResponse({"detail": "Record not found"}, status_code=404)

    @app.exception_handler(ConflictError)
    async def conflict_handler(request: Request, exc: ConflictError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.middleware("http")
    async def browser_security(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            origin = request.headers.get("origin")
            if origin and origin != str(request.base_url).rstrip("/"):
                return JSONResponse({"detail": "Cross-origin writes are not allowed"}, status_code=403)
            if (
                request.url.path not in {"/auth/login", "/auth/register"}
                and not request.url.path.startswith("/bank")
                and not request.url.path.startswith("/stream")
                and request.cookies.get("terminus_session")
                and not request.headers.get("Authorization")
                and not request.headers.get("X-Session-Token")
                and request.headers.get("X-Terminus-Request") != "1"
            ):
                return JSONResponse({"detail": "Missing request protection header"}, status_code=403)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["X-Frame-Options"] = "DENY"
        if not request.url.path.startswith("/console/assets"):
            response.headers["Cache-Control"] = "no-store"
        return response

    app.include_router(console_router)
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(org_router)
    app.include_router(webhook_router)
    app.include_router(agent_router)
    app.include_router(workflow_router)
    app.include_router(allowlist_router)
    app.include_router(report_router)
    app.include_router(decoy_router)
    app.include_router(bank_router)
    app.include_router(streaming_router)
    app.include_router(copilot_router)
    app.include_router(global_copilot_router)
    app.include_router(graph_router)

    return app


app = create_app()


def main() -> None:
    """CLI entry point for terminus-serve command."""
    settings = get_settings()
    uvicorn.run(app, host=settings.host, port=settings.port)


if __name__ == "__main__":
    main()
