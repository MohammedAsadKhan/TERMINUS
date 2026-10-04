"""Dedicated process configuration never executes unspecified worker code."""

from types import ModuleType

import pytest


def test_cli_loads_only_explicit_async_handlers(monkeypatch):
    from terminus.orchestration.scheduler_cli import load_handlers

    module = ModuleType("trusted_handlers")

    async def investigate(context):
        return {"result": "test"}

    module.investigate = investigate
    monkeypatch.setitem(__import__("sys").modules, "trusted_handlers", module)
    assert load_handlers(["triage=trusted_handlers:investigate"]) == {"triage": investigate}
    with pytest.raises(ValueError, match="Duplicate handler"):
        load_handlers(["triage=trusted_handlers:investigate"] * 2)
    module.synchronous = lambda context: {}
    with pytest.raises(ValueError, match="async function"):
        load_handlers(["triage=trusted_handlers:synchronous"])


def test_cli_rejects_missing_handler_without_opening_database(tmp_path):
    from terminus.orchestration.scheduler_cli import main

    path = tmp_path / "must-not-create.db"
    with pytest.raises(SystemExit) as exc:
        main(["--database", str(path)])
    assert exc.value.code == 2
    assert not path.exists()


def test_cli_coordination_is_explicit_and_does_not_require_specialist_handlers(monkeypatch, tmp_path):
    from terminus.orchestration import scheduler_cli

    calls = []

    async def capture(arguments, handlers):
        calls.append((arguments.coordination, handlers))

    monkeypatch.setattr(scheduler_cli, "_run", capture)
    scheduler_cli.main(["--database", str(tmp_path / "unused.db"), "--coordination"])
    assert calls == [(True, {})]
    assert not (tmp_path / "unused.db").exists()


@pytest.mark.asyncio
async def test_dedicated_process_registers_coordination_and_preserves_specialists(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from terminus.orchestration import scheduler_cli

    captured = {}

    class Runtime:
        def __init__(self, store, handlers, **options):
            captured.update(handlers)
            self.store = store

        def request_stop(self):
            pass

        async def run(self):
            self.store.db.close()

    async def triage(context):
        return {"fixture": True}

    monkeypatch.setattr(scheduler_cli, "SchedulerRuntime", Runtime)
    arguments = SimpleNamespace(
        database=str(tmp_path / "cli.db"), coordination=True, workers=1,
        global_limit=1, per_org_limit=1, timeout=10,
    )
    await scheduler_cli._run(arguments, {"triage": triage})
    assert set(captured) == {"triage", "main_orchestrator", "area_orchestrator"}
    assert captured["triage"] is triage
    with pytest.raises(ValueError, match="cannot be overridden"):
        await scheduler_cli._run(arguments, {"main_orchestrator": triage})
