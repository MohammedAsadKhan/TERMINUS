"""FastAPI application factory and server entrypoint."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from fastapi.middleware.cors import CORSMiddleware

from terminus.config import get_settings
from terminus.server.routers import (
    auth_router,
    health_router,
    org_router,
    webhook_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """App lifespan context manager for startup and shutdown hooks."""
    settings = get_settings()
    # Log startup status
    print(f"Terminus platform booting up... (LLM Base URL: {settings.llm_base_url})")
    yield
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

    return app


def main() -> None:
    """CLI entry point for terminus-serve command."""
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
