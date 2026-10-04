"""Bridge from workflow AI nodes to recorded orchestration specialist runs.

The bridge never fabricates a verdict. It admits one specialist task per
workflow node (idempotency key ``workflow:{run_id}:{node_id}``), reports
whether a recorded terminal run exists, and otherwise returns an explicit
non-executed state. Tenant and incident come only from the trusted workflow
run context; node configuration may only select a role.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Literal, final

from pydantic import JsonValue

from terminus.orchestration.coordination import DEFAULT_CATALOG, MAX_INCIDENT_TASKS
from terminus.orchestration.models import AgentRun, Task
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.orchestration.storage import (
    OrchestrationConflictError,
    OrchestrationNotFoundError,
    OrchestrationStore,
)
from terminus.storage.db import Database

CORE_ROLES: dict[str, str] = {spec.role: spec.area for spec in DEFAULT_CATALOG}

BridgeState = Literal[
    "completed",
    "waiting",
    "failed",
    "not_executed",
    "unresolved_agent",
    "simulated",
]


@dataclass(frozen=True)
class BridgeOutcome:
    state: BridgeState
    role: str | None = None
    task_id: str | None = None
    run_id: str | None = None
    result: JsonValue = None
    evidence_ids: tuple[str, ...] = ()
    gap: str | None = None

    def to_output(self) -> dict[str, JsonValue]:
        out: dict[str, JsonValue] = {
            "specialist_state": self.state,
            "role": self.role,
            "task_id": self.task_id,
            "run_id": self.run_id,
            "executed": self.state == "completed",
            "recorded_run": self.run_id is not None and self.state == "completed",
        }
        if self.state == "completed":
            out["result"] = self.result
            out["evidence_ids"] = list(self.evidence_ids)
        if self.gap:
            out["gap"] = self.gap
        if self.state == "simulated":
            out["simulated"] = True
            out["dry_run"] = True
        return out


def resolve_role(config: Mapping[str, object] | None) -> str | None:
    """Return a core role only when the node names one unambiguously."""
    cfg: Mapping[str, object] = config or {}
    role: object = cfg.get("role")
    agent_id: object = cfg.get("agent_id")
    if role is not None and not (isinstance(role, str) and role in CORE_ROLES):
        return None
    if agent_id is not None and not (isinstance(agent_id, str) and agent_id in CORE_ROLES):
        return None
    if role is not None and agent_id is not None and role != agent_id:
        return None
    resolved = role if role is not None else agent_id
    return resolved if isinstance(resolved, str) else None


def _unresolved() -> BridgeOutcome:
    return BridgeOutcome(
        "unresolved_agent",
        gap=f"Node must name one core role via role/agent_id (allowed: {', '.join(sorted(CORE_ROLES))}).",
    )


def simulate(config: Mapping[str, object] | None) -> BridgeOutcome:
    """Dry-run: no task, no run, no verdict."""
    role = resolve_role(config)
    if role is None:
        return _unresolved()
    return BridgeOutcome(
        "simulated",
        role=role,
        gap="Dry-run simulation only: no specialist task was created and no recorded run exists.",
    )


@final
class SpecialistBridge:
    def __init__(self, db: Database, *, handler_roles: Collection[str] | None = None) -> None:
        self.db: Database = db
        self.records: OrchestrationStore = OrchestrationStore(db)
        self.scheduler: SchedulerStore = SchedulerStore(db)
        # None means handler availability is not known to this process.
        self.handler_roles: frozenset[str] | None = (
            None if handler_roles is None else frozenset(handler_roles)
        )

    def _terminal_run(self, org_id: str, task_id: str) -> AgentRun | None:
        runs = self.records.list_agent_runs(org_id, task_id=task_id, limit=50)
        terminal = [r for r in runs if r.status in {"completed", "failed", "cancelled"}]
        if not terminal:
            return None
        pool = [r for r in terminal if r.status == "completed"] or terminal
        return max(pool, key=lambda r: (r.completed_at or r.updated_at, r.run_id))

    def request(  # noqa: PLR0911 - ordered explicit outcomes
        self,
        *,
        org_id: str,
        incident_id: str | None,
        run_id: str,
        node_id: str,
        workflow_id: str,
        config: Mapping[str, object] | None,
    ) -> BridgeOutcome:
        role = resolve_role(config)
        if role is None:
            return _unresolved()
        if not incident_id:
            return BridgeOutcome(
                "not_executed",
                role=role,
                gap="Workflow run has no orchestration incident; no specialist task was created.",
            )
        if self.handler_roles is not None and role not in self.handler_roles:
            return BridgeOutcome(
                "not_executed",
                role=role,
                gap=f"No specialist handler is registered for role '{role}'; nothing ran.",
            )
        key = f"workflow:{run_id}:{node_id}"
        try:
            task = self._admit(org_id, incident_id, role, key, workflow_id, node_id)
        except OrchestrationNotFoundError:
            return BridgeOutcome(
                "not_executed",
                role=role,
                gap="Incident not found in the orchestration store for this organization.",
            )
        except OrchestrationConflictError as exc:
            return BridgeOutcome(
                "not_executed", role=role, gap=f"Specialist task admission conflict: {exc}"
            )
        run = self._terminal_run(org_id, task.task_id)
        if run is None:
            if task.status in {"failed", "cancelled"}:
                return BridgeOutcome(
                    "failed",
                    role=role,
                    task_id=task.task_id,
                    gap=f"Specialist task ended as {task.status} without a recorded run.",
                )
            return BridgeOutcome(
                "waiting",
                role=role,
                task_id=task.task_id,
                gap="Specialist task is queued or running; no terminal run is recorded yet.",
            )
        if run.status != "completed":
            return BridgeOutcome(
                "failed",
                role=role,
                task_id=task.task_id,
                run_id=run.run_id,
                gap=f"Specialist run ended as {run.status}.",
            )
        result = run.result
        ids = result.get("evidence_ids") if isinstance(result, dict) else None
        evidence = tuple(str(i) for i in ids) if isinstance(ids, list) else ()
        return BridgeOutcome(
            "completed",
            role=role,
            task_id=task.task_id,
            run_id=run.run_id,
            result=result,
            evidence_ids=evidence,
        )

    def _admit(
        self,
        org_id: str,
        incident_id: str,
        role: str,
        key: str,
        workflow_id: str,
        node_id: str,
    ) -> Task:
        existing = self.db.fetchone(
            "SELECT 1 FROM orchestration_tasks WHERE org_id=? AND idempotency_key=?",
            (org_id, key),
        )
        if existing is None:
            row = self.db.fetchone(
                "SELECT COUNT(*) AS count FROM orchestration_tasks WHERE org_id=? AND incident_id=?",
                (org_id, incident_id),
            )
            if row and row["count"] >= MAX_INCIDENT_TASKS:
                raise OrchestrationConflictError("incident task limit reached")
        task = self.records.create_incident_task(
            org_id,
            incident_id,
            CORE_ROLES[role],
            role,
            f"Workflow {workflow_id} node {node_id}: specialist analysis for this incident",
            idempotency_key=key,
        )
        _ = self.scheduler.enqueue_task(org_id, task.task_id)
        return self.records.get_task(org_id, task.task_id)
