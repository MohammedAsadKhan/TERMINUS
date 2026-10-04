"""Dedicated scheduler entry point with explicitly deployed Python handlers."""

from __future__ import annotations

import argparse
import asyncio
import importlib
import inspect
import signal
from collections.abc import Awaitable, Callable
from contextlib import suppress
from typing import cast

from pydantic import JsonValue

from terminus.orchestration.scheduler import (
    JobContext,
    SchedulerAlreadyRunningError,
    SchedulerRuntime,
)
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.storage.db import Database

Handler = Callable[[JobContext], Awaitable[JsonValue]]


def load_handlers(specifications: list[str]) -> dict[str, Handler]:
    """Load trusted deployment code; HTTP clients cannot supply these imports."""
    handlers: dict[str, Handler] = {}
    for specification in specifications:
        role, separator, reference = specification.partition("=")
        module_name, colon, function_name = reference.partition(":")
        if not separator or not colon or not role.strip() or not module_name or not function_name:
            raise ValueError("Handler must be ROLE=python.module:async_function")
        if role in handlers:
            raise ValueError(f"Duplicate handler role: {role}")
        handler = getattr(importlib.import_module(module_name), function_name)
        if not inspect.iscoroutinefunction(handler):
            raise ValueError(f"Handler for {role} must be an async function")
        handlers[role] = cast("Handler", handler)
    return handlers


async def _run(arguments: argparse.Namespace, handlers: dict[str, Handler]) -> None:
    store = SchedulerStore(Database(arguments.database))
    runtime = SchedulerRuntime(
        store, handlers,
        worker_count=arguments.workers,
        global_limit=arguments.global_limit,
        per_org_limit=arguments.per_org_limit,
        run_timeout_seconds=arguments.timeout,
    )
    loop = asyncio.get_running_loop()
    registered_signal = False
    with suppress(NotImplementedError, RuntimeError):
        loop.add_signal_handler(signal.SIGTERM, runtime.request_stop)
        registered_signal = True
    try:
        await runtime.run()
    finally:
        if registered_signal:
            loop.remove_signal_handler(signal.SIGTERM)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run Terminus's dedicated single-host scheduler")
    parser.add_argument("--database", required=True, help="Same SQLite file used by FastAPI")
    parser.add_argument("--handler", action="append", default=[], metavar="ROLE=MODULE:FUNCTION", help="Trusted async handler; repeat for each supported role")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--global-limit", type=int, default=4)
    parser.add_argument("--per-org-limit", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=60)
    arguments = parser.parse_args(argv)
    if not arguments.handler:
        parser.error("Configure at least one trusted role handler; no specialist handlers are bundled yet")
    try:
        handlers = load_handlers(arguments.handler)
        asyncio.run(_run(arguments, handlers))
    except (ValueError, ImportError, AttributeError, SchedulerAlreadyRunningError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
