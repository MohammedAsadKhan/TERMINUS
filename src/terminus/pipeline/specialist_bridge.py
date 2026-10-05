"""Bridge from workflow AI nodes to recorded orchestration specialist runs.

The bridge never fabricates a verdict. It admits one specialist task per
workflow node (idempotency key ``workflow:{run_id}:{node_id}``), reports
whether a recorded terminal run exists, and otherwise returns an explicit
non-executed state. Tenant and incident come only from the trusted workflow
run context; node configuration may only select a role.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast, final

from pydantic import JsonValue, ValidationError

from terminus.orchestration.coordination import DEFAULT_CATALOG, MAX_INCIDENT_TASKS
from terminus.orchestration.models import AgentRun, Task
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.orchestration.specialists.models import Finding, SpecialistResult
from terminus.orchestration.storage import (
    OrchestrationConflictError,
    OrchestrationNotFoundError,
    OrchestrationStore,
)
from terminus.storage.db import Database

CORE_ROLES: dict[str, str] = {spec.role: spec.area for spec in DEFAULT_CATALOG}

_LOGGER = logging.getLogger(__name__)
ROLES_ENV = "TERMINUS_SPECIALIST_ROLES"
DATABASE_ENV = "TERMINUS_SPECIALIST_DATABASE"
TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled"})

BridgeState = Literal[
    "completed",
    "partial",
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
    findings: tuple[Finding, ...] = ()
    evidence_citations: tuple[dict[str, JsonValue], ...] = ()

    def to_output(self) -> dict[str, JsonValue]:
        out: dict[str, JsonValue] = {
            "specialist_state": self.state,
            "role": self.role,
            "task_id": self.task_id,
            "run_id": self.run_id,
            "executed": self.run_id is not None,
            "recorded_run": self.run_id is not None,
        }
        if self.result is not None:
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
    if agent_id is not None and not (
        isinstance(agent_id, str) and agent_id in CORE_ROLES
    ):
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
    def __init__(
        self, db: Database, *, handler_roles: Collection[str] | None = None
    ) -> None:
        self.db: Database = db
        self.records: OrchestrationStore = OrchestrationStore(db)
        self.scheduler: SchedulerStore = SchedulerStore(db)
        # None means handler availability is not known to this process.
        self.handler_roles: frozenset[str] | None = (
            None if handler_roles is None else frozenset(handler_roles)
        )

    def workflow_task_key(self, run_id: str, node_id: str) -> str:
        return f"workflow:{run_id}:{node_id}"

    def task_status(self, org_id: str, run_id: str, node_id: str) -> str | None:
        """Status of the specialist task admitted for a node (tenant-scoped), else None."""
        row = self.db.fetchone(
            "SELECT status FROM orchestration_tasks WHERE org_id=? AND idempotency_key=?",
            (org_id, self.workflow_task_key(run_id, node_id)),
        )
        return None if row is None else str(cast("object", row["status"]))

    def _terminal_run(self, org_id: str, task: Task) -> AgentRun | None:
        # The scheduler's current attempt is authoritative. An older completed
        # run must never override a newer failed or still-running attempt.
        job = self.scheduler.get_job(org_id, task.task_id)
        if (
            job.org_id != org_id
            or job.task_id != task.task_id
            or job.incident_id != task.incident_id
            or job.role != task.role
        ):
            raise OrchestrationConflictError(
                "Scheduler job does not match admitted specialist task"
            )
        if job.status not in TERMINAL_TASK_STATUSES or job.run_id is None:
            return None
        return self.records.get_agent_run(org_id, job.run_id)

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
        key = self.workflow_task_key(run_id, node_id)
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
                "not_executed",
                role=role,
                gap=f"Specialist task admission conflict: {exc}",
            )
        try:
            run = self._terminal_run(org_id, task)
        except (OrchestrationNotFoundError, OrchestrationConflictError):
            return BridgeOutcome(
                "failed",
                role=role,
                task_id=task.task_id,
                gap="Scheduler attempt is missing or does not match the admitted specialist task.",
            )
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
        return self._recorded_outcome(org_id, incident_id, role, task, run)

    def _recorded_outcome(
        self, org_id: str, incident_id: str, role: str, task: Task, run: AgentRun
    ) -> BridgeOutcome:
        if (
            run.org_id != org_id
            or run.incident_id != incident_id
            or run.task_id != task.task_id
            or task.role != role
            or task.incident_id != incident_id
        ):
            return BridgeOutcome(
                "failed",
                role=role,
                task_id=task.task_id,
                gap="Recorded specialist run does not match the workflow incident/task/role.",
            )
        if run.status != "completed" or task.status != "completed":
            return BridgeOutcome(
                "failed",
                role=role,
                task_id=task.task_id,
                run_id=run.run_id,
                gap=f"Specialist run ended as {run.status}.",
            )
        return self._validated_result(org_id, incident_id, role, task, run)

    def _validated_result(
        self, org_id: str, incident_id: str, role: str, task: Task, run: AgentRun
    ) -> BridgeOutcome:
        try:
            result = SpecialistResult.model_validate_json(json.dumps(run.result))
            if result.role != role:
                raise ValueError("result role does not match the admitted core role")
            citations: list[dict[str, JsonValue]] = []
            for evidence_id in dict.fromkeys(result.evidence_ids):
                record = self.records.get_evidence(org_id, evidence_id)
                if record.incident_id != incident_id:
                    raise ValueError("cited evidence belongs to a different incident")
                citations.append(
                    {
                        "evidence_id": record.evidence_id,
                        "org_id": record.org_id,
                        "incident_id": record.incident_id,
                        "task_id": record.task_id,
                        "run_id": run.run_id,
                        "role": role,
                        "source": record.source,
                        "source_timestamp": record.source_timestamp.isoformat(),
                        "collected_at": record.collected_at.isoformat(),
                        "content_hash": record.content_hash,
                        "content_ref": record.content_ref,
                    }
                )
            allowed = set(result.evidence_ids)
            if any(not set(f.evidence_ids) <= allowed for f in result.findings):
                raise ValueError(
                    "finding cites evidence absent from the recorded result"
                )
            if result.status == "completed" and (result.gaps or not allowed):
                raise ValueError(
                    "completed result must contain evidence and no telemetry gaps"
                )
        except (ValidationError, ValueError, OrchestrationNotFoundError) as exc:
            _LOGGER.warning(
                "Invalid specialist result for run %s (%s)",
                run.run_id,
                type(exc).__name__,
            )
            return BridgeOutcome(
                "failed",
                role=role,
                task_id=task.task_id,
                run_id=run.run_id,
                gap="Recorded specialist result failed schema, role, or evidence validation.",
            )
        state: BridgeState = (
            "completed"
            if result.status == "completed"
            else "partial"
            if result.status == "partial"
            else "failed"
        )
        return BridgeOutcome(
            state,
            role=role,
            task_id=task.task_id,
            run_id=run.run_id,
            result=run.result,
            evidence_ids=result.evidence_ids,
            findings=result.findings if state in {"completed", "partial"} else (),
            evidence_citations=tuple(citations),
            gap=None
            if state == "completed"
            else f"Specialist result is {result.status}; default workflow continuation is blocked.",
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


def specialist_bridge_from_environ(
    db: Database, environ: Mapping[str, str] | None = None
) -> SpecialistBridge | None:
    """Build a bridge only when specialist handlers are declared as deployed.

    The scheduler runs in a separate process, so the only honest signal is an
    explicit declaration: ``TERMINUS_SPECIALIST_ROLES`` lists the core roles whose
    handlers are deployed (``scheduler_cli --handler ROLE=...``). Unset or empty
    means legacy behavior (no bridge). Unknown role names are ignored. If
    ``TERMINUS_SPECIALIST_DATABASE`` is set and names a different file than ``db``
    the scheduler would never see the queued tasks, so no bridge is built.
    """
    env = os.environ if environ is None else environ
    declared = {r.strip() for r in env.get(ROLES_ENV, "").split(",") if r.strip()}
    if not declared:
        return None
    roles = declared & CORE_ROLES.keys()
    if declared - roles:
        _LOGGER.warning(
            "Ignoring unknown specialist roles: %s", sorted(declared - roles)
        )
    if not roles:
        return None
    scheduler_db = env.get(DATABASE_ENV, "").strip()
    if (
        scheduler_db
        and scheduler_db != ":memory:"
        and Path(scheduler_db).resolve() != Path(db.db_path).resolve()
    ):
        _LOGGER.error(
            "%s differs from the application database; specialist bridge disabled",
            DATABASE_ENV,
        )
        return None
    return SpecialistBridge(db, handler_roles=roles)
