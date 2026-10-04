"""Real SQLite contention checks for durable task admission and transitions."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from threading import Barrier

from terminus.orchestration import OrchestrationConflictError, OrchestrationStore
from terminus.storage.db import Database


def test_parallel_admission_and_transition_have_one_owner(tmp_path: Path) -> None:
    db = Database(str(tmp_path / "contention.db"))
    db.execute(
        "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
        ("org", "Test", datetime.now(UTC).isoformat()),
    )
    store = OrchestrationStore(db)
    barrier = Barrier(2)

    def admit() -> str:
        try:
            barrier.wait(timeout=5)
            return store.create_task(
                "org", "incident", "alerts", "triage", "Review alert",
                idempotency_key="same-alert",
            ).task_id
        finally:
            db._get_connection().close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        ids = list(pool.map(lambda _: admit(), range(2)))
    assert ids[0] == ids[1]
    assert len(store.list_tasks("org")) == 1

    barrier = Barrier(2)

    def claim() -> str:
        try:
            barrier.wait(timeout=5)
            try:
                store.transition_task("org", ids[0], "queued", "running")
            except OrchestrationConflictError:
                return "conflict"
            return "running"
        finally:
            db._get_connection().close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: claim(), range(2)))
    assert sorted(outcomes) == ["conflict", "running"]
    assert store.get_task("org", ids[0]).status == "running"
    db._get_connection().close()
