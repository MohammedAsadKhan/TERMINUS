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
