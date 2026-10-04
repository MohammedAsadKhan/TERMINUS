"""Opt-in, bounded main/area delegation on the existing durable scheduler.

Completion of an orchestrator records delegation only. Specialist callbacks
must be installed separately; this module collects no evidence, invokes no
models and never closes incidents or waits for children inside a worker.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import cast

from pydantic import JsonValue

from terminus.orchestration.collaboration import CollaborationService
from terminus.orchestration.coordination_models import (
    AreaObjective,
    HelpRequestSpec,
    IncidentObjective,
    MainObjective,
    SpecialistDefinition,
)
from terminus.orchestration.models import HelpRequest, Task
from terminus.orchestration.scheduler import JobContext, JobHandler
from terminus.orchestration.scheduler_models import JobLease
from terminus.orchestration.scheduler_store import SchedulerLeaseError, SchedulerStore
from terminus.orchestration.storage import (
    OrchestrationConflictError,
    OrchestrationNotFoundError,
    OrchestrationStore,
)
from terminus.storage.db import Database

MAX_INCIDENT_TASKS = 64
MAX_HELP_DELEGATIONS = 16
MAX_CATALOG_ROLES = 24
DEFAULT_CATALOG = (
    SpecialistDefinition(role="triage", area="alert_handling"),
    SpecialistDefinition(role="identity", area="investigation"),
    SpecialistDefinition(role="endpoint", area="investigation"),
    SpecialistDefinition(role="network", area="investigation"),
    SpecialistDefinition(role="response_planner", area="response_improvement"),
    SpecialistDefinition(role="verification", area="response_improvement"),
    SpecialistDefinition(role="evidence_reporting", area="response_improvement"),
    SpecialistDefinition(role="application_api", area="applications_data"),
)


class CoordinationLimitError(ValueError):
    """Delegation exceeds the bounded incident or catalog capacity."""


class CoordinationRoleError(ValueError):
    """The requested specialty is not enabled in the explicit catalog."""


def _key(*parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode()).hexdigest()
    return f"coord:{digest}"


def _help_key(root_id: str, help_id: str) -> str:
    return "coord:help:" + _key(root_id, "help", help_id)[6:]


class CoordinationService:
    def __init__(
        self,
        db: Database,
        *,
        catalog: Sequence[SpecialistDefinition] | None = None,
    ) -> None:
        specs = list(DEFAULT_CATALOG if catalog is None else catalog)
        if not 1 <= len(specs) <= MAX_CATALOG_ROLES:
            raise CoordinationLimitError("catalog must contain 1..24 specialties")
        if any(not isinstance(spec, SpecialistDefinition) for spec in specs):
            raise CoordinationRoleError("catalog entries must be SpecialistDefinition")
        if len({spec.role for spec in specs}) != len(specs) or any(
            spec.role in {"main_orchestrator", "area_orchestrator"} for spec in specs
        ):
            raise CoordinationRoleError("catalog roles must be unique specialties")
        self.db = db
        self.records = OrchestrationStore(db)
        self.scheduler = SchedulerStore(db)
        self.catalog = {spec.role: spec.area for spec in specs}
        self.collaboration = CollaborationService(self)

    def _incident(self, org_id: str, incident_id: str) -> None:
        if not self.db.fetchone(
            "SELECT 1 FROM incidents WHERE org_id=? AND ticket_id=?",
            (org_id, incident_id),
        ):
            raise OrchestrationNotFoundError("Orchestration record not found")

    def _root(self, org_id: str, incident_id: str) -> Task | None:
        row = self.db.fetchone(
            "SELECT payload_json FROM orchestration_tasks WHERE org_id=? "
            "AND incident_id=? AND parent_task_id IS NULL "
            "AND json_extract(payload_json,'$.role')='main_orchestrator' "
            "AND idempotency_key LIKE 'coord:%' "
            "ORDER BY created_at,task_id LIMIT 1",
            (org_id, incident_id),
        )
        return Task.model_validate_json(row["payload_json"]) if row else None

    def _existing(self, org_id: str, key: str) -> Task | None:
        row = self.db.fetchone(
            "SELECT payload_json FROM orchestration_tasks "
            "WHERE org_id=? AND idempotency_key=?",
            (org_id, key),
        )
        return Task.model_validate_json(row["payload_json"]) if row else None

    def _admit(
        self,
        org_id: str,
        incident_id: str,
        area: str,
        role: str,
        objective: str,
        key: str,
        *,
        parent: Task | None = None,
        priority: int = 100,
    ) -> Task:
        if self._existing(org_id, key) is None:
            row = self.db.fetchone(
                "SELECT COUNT(*) AS count FROM orchestration_tasks "
                "WHERE org_id=? AND incident_id=?",
                (org_id, incident_id),
            )
            if row and row["count"] >= MAX_INCIDENT_TASKS:
                raise CoordinationLimitError("incident task limit (64) reached")
        task = self.records.create_incident_task(
            org_id,
            incident_id,
            area,
            role,
            objective,
            parent_task_id=parent.task_id if parent else None,
            priority=priority,
            idempotency_key=key,
        )
        self.scheduler.enqueue_task(org_id, task.task_id)
        return task

    def start_incident(
        self, org_id: str, incident_id: str, request: IncidentObjective
    ) -> Task:
        if not isinstance(request, IncidentObjective):
            raise TypeError("request must be an IncidentObjective")
        with self.db.transaction():
            self._incident(org_id, incident_id)
            root = self._root(org_id, incident_id)
            if root:
                saved = MainObjective.model_validate_json(root.objective)
                if saved.request != request:
                    raise OrchestrationConflictError(
                        "Incident already has a different coordination objective"
                    )
                return root
            plan = MainObjective(
                request=request,
                plans=[
                    AreaObjective(
                        area=area,
                        objective="",
                        roles=[
                            role
                            for role, owner in self.catalog.items()
                            if owner == area
                        ],
                    )
                    for area in request.areas
                ],
            )
            return self._admit(
                org_id,
                incident_id,
                "main",
                "main_orchestrator",
                plan.model_dump_json(),
                _key(org_id, incident_id, request.idempotency_key),
                priority=request.priority,
            )

    def handlers(self) -> Mapping[str, JobHandler]:
        return {
            "main_orchestrator": self._main,
            "area_orchestrator": self._area,
        }

    def _fence(self, lease: JobLease) -> None:
        # A checkpoint alone leaves a cancellation/lease race before BEGIN.
        # Check the scheduler's durable fence inside the same write transaction.
        job = self.scheduler._owned(lease, self.scheduler._now())  # noqa: SLF001
        if job.cancellation_requested:
            raise SchedulerLeaseError("Cancellation requested")

    async def _main(self, context: JobContext) -> JsonValue:
        await context.checkpoint()
        task = context.task
        plan = MainObjective.model_validate_json(task.objective)
        with self.db.transaction():
            self._fence(context.lease)
            root = self._root(task.org_id, task.incident_id)
            if root is None or root.task_id != task.task_id:
                raise OrchestrationConflictError("Unmanaged main coordinator")
            children = [
                self._admit(
                    task.org_id,
                    task.incident_id,
                    area.area,
                    "area_orchestrator",
                    area.model_copy(
                        update={"objective": plan.request.objective}
                    ).model_dump_json(),
                    _key(task.task_id, area.area),
                    parent=task,
                    priority=task.priority,
                ).task_id
                for area in plan.plans
            ]
            self._fence(context.lease)
        return {"delegation_only": True, "child_task_ids": children}

    async def _area(self, context: JobContext) -> JsonValue:
        await context.checkpoint()
        task = context.task
        plan = AreaObjective.model_validate_json(task.objective)
        with self.db.transaction():
            self._fence(context.lease)
            root = self._root(task.org_id, task.incident_id)
            key = (
                _help_key(root.task_id, plan.help_request_id)
                if root and plan.help_request_id
                else _key(root.task_id, plan.area)
                if root
                else None
            )
            if (
                root is None
                or task.parent_task_id != root.task_id
                or task.idempotency_key != key
                or task.area != plan.area
            ):
                raise OrchestrationConflictError("Unmanaged area coordinator")
            if len(plan.roles) != len(set(plan.roles)) or any(
                self.catalog.get(role) != plan.area for role in plan.roles
            ):
                raise CoordinationRoleError(
                    "Area plan contains unavailable specialties"
                )
            if plan.help_request_id:
                request = self.records.get_help_request(
                    task.org_id, plan.help_request_id
                )
                if request.status != "assigned":
                    return {
                        "delegation_only": True,
                        "child_task_ids": [],
                        "gaps": ["Help request is no longer assigned"],
                    }
            children = [
                self._admit(
                    task.org_id,
                    task.incident_id,
                    plan.area,
                    role,
                    plan.objective,
                    _key(task.task_id, role),
                    parent=task,
                    priority=task.priority,
                ).task_id
                for role in plan.roles
            ]
            self._fence(context.lease)
        return {
            "delegation_only": True,
            "child_task_ids": children,
            "gaps": [] if plan.roles else ["No enabled specialty in selected area"],
            "help_request_id": plan.help_request_id,
        }

    def request_help(
        self, org_id: str, requester_task_id: str, spec: HelpRequestSpec
    ) -> dict[str, object]:
        """Structured peer-help admission; see ``collaboration.py``."""
        return self.collaboration.request_help(org_id, requester_task_id, spec)

    def get_help_context(self, org_id: str, task_id: str) -> dict[str, object]:
        """Request contract and shared evidence for a help-delegated task."""
        return self.collaboration.get_help_context(org_id, task_id)

    def assign_help(self, org_id: str, help_request_id: str) -> Task:
        """Admit one request through its responsible area's scheduled callback.

        The returned task is the area's delegation task. Only its handler may
        create the distinct specialty child. Assignment is not resolution.
        """
        with self.db.transaction():
            request = self.records.get_help_request(org_id, help_request_id)
            self._incident(org_id, request.incident_id)
            root = self._root(org_id, request.incident_id)
            if root is None:
                raise OrchestrationConflictError(
                    "Incident has no coordination objective"
                )
            parent = self.records.get_task(org_id, request.task_id)
            current = parent
            for _ in range(3):
                if current.parent_task_id is None:
                    break
                current = self.records.get_task(org_id, current.parent_task_id)
            if current.task_id != root.task_id or parent.role not in self.catalog:
                raise CoordinationRoleError(
                    "Help must originate from a managed specialty"
                )
            area = self.catalog.get(request.requested_role)
            if area is None:
                raise CoordinationRoleError("Requested specialty is not enabled")
            key = _help_key(root.task_id, help_request_id)
            existing = self._existing(org_id, key)
            if existing:
                return existing
            if request.status != "open":
                raise OrchestrationConflictError("Help request is not open")
            row = self.db.fetchone(
                "SELECT COUNT(*) AS count FROM orchestration_tasks WHERE org_id=? "
                "AND incident_id=? AND idempotency_key LIKE 'coord:help:%'",
                (org_id, request.incident_id),
            )
            if row and row["count"] >= MAX_HELP_DELEGATIONS:
                raise CoordinationLimitError(
                    "incident help delegation limit (16) reached"
                )
            plan = AreaObjective(
                area=area,
                objective=request.reason,
                roles=[request.requested_role],
                help_request_id=request.help_request_id,
            )
            task = self._admit(
                org_id,
                request.incident_id,
                area,
                "area_orchestrator",
                plan.model_dump_json(),
                key,
                parent=root,
                priority=parent.priority,
            )
            self.records.transition_help_request(
                org_id, help_request_id, "open", "assigned"
            )
            return task

    def reconcile_help(self, org_id: str, help_request_id: str) -> HelpRequest:
        """Resolve only after the explicitly delegated specialist completed."""
        with self.db.transaction():
            request = self.records.get_help_request(org_id, help_request_id)
            self._incident(org_id, request.incident_id)
            root = self._root(org_id, request.incident_id)
            if root and request.status == "assigned":
                area = self._existing(org_id, _help_key(root.task_id, help_request_id))
                child = (
                    self._existing(org_id, _key(area.task_id, request.requested_role))
                    if area
                    else None
                )
                if child and child.status == "completed":
                    return self.records.transition_help_request(
                        org_id, help_request_id, "assigned", "resolved"
                    )
            return request

    @staticmethod
    def _aggregate(  # noqa: PLR0911 - ordered lifecycle precedence
        task: Task, children: list[dict[str, object]], gaps: list[str]
    ) -> str:
        states = [str(child["aggregate_status"]) for child in children]
        if task.status in {"failed", "cancelled"}:
            return task.status
        if "failed" in states:
            return "failed"
        if task.status == "running" or "running" in states:
            return "running"
        if task.status == "waiting" or "waiting" in states:
            return "waiting"
        if task.status == "queued" or "queued" in states:
            return "queued"
        if gaps or "incomplete" in states or "cancelled" in states:
            return "incomplete"
        return "completed"

    def _node(self, task: Task, depth: int = 0) -> dict[str, object]:
        if depth > 3:
            raise CoordinationLimitError("coordinator tree depth exceeded")
        rows = self.db.fetchall(
            "SELECT payload_json FROM orchestration_tasks WHERE org_id=? "
            "AND incident_id=? AND parent_task_id=? ORDER BY created_at,task_id LIMIT 65",
            (task.org_id, task.incident_id, task.task_id),
        )
        children = [
            self._node(Task.model_validate_json(row["payload_json"]), depth + 1)
            for row in rows[:MAX_INCIDENT_TASKS]
        ]
        node = cast("dict[str, object]", task.model_dump(mode="json"))
        gaps: list[str] = []
        if task.role == "main_orchestrator":
            plan = MainObjective.model_validate_json(task.objective)
            node["objective"] = plan.request.objective
            node["planned_areas"] = plan.request.areas
            if task.status == "completed" and any(
                not any(
                    child["idempotency_key"] == _key(task.task_id, area)
                    for child in children
                )
                for area in plan.request.areas
            ):
                gaps.append("Planned area delegation is missing")
        elif task.role == "area_orchestrator":
            plan_area = AreaObjective.model_validate_json(task.objective)
            node["objective"] = plan_area.objective
            node["planned_roles"] = plan_area.roles
            node["help_request_id"] = plan_area.help_request_id
            if not plan_area.roles:
                gaps.append("No enabled specialty in selected area")
            elif task.status == "completed" and any(
                not any(
                    child["idempotency_key"] == _key(task.task_id, role)
                    for child in children
                )
                for role in plan_area.roles
            ):
                gaps.append("Planned specialty delegation is missing")
        if len(rows) > MAX_INCIDENT_TASKS:
            gaps.append("Additional children omitted by tree bound")
        # Per-task results are bounded; expose truncation, never claim full coverage.
        runs = self.records.list_agent_runs(
            task.org_id, task_id=task.task_id, limit=200
        )
        evidence = self.records.list_evidence(
            task.org_id, task_id=task.task_id, limit=200
        )
        help_requests = self.records.list_help_requests(
            task.org_id, task_id=task.task_id, limit=200
        )
        if any(request.status in {"open", "assigned"} for request in help_requests):
            gaps.append("Unresolved help request")
        if any(len(records) == 200 for records in (runs, evidence, help_requests)):
            gaps.append("Record page limit reached; additional records may exist")
        node.update(
            children=children,
            runs=[run.model_dump(mode="json") for run in runs],
            evidence=[record.model_dump(mode="json") for record in evidence],
            help_requests=[record.model_dump(mode="json") for record in help_requests],
            help_ownership=[
                self.collaboration.ownership(task.org_id, record.help_request_id)
                for record in help_requests
            ],
            gaps=gaps,
            delegation_only=task.role in {"main_orchestrator", "area_orchestrator"},
            aggregate_status=self._aggregate(task, children, gaps),
        )
        return node

    def get_incident_tree(self, org_id: str, incident_id: str) -> dict[str, object]:
        with self.db.transaction():
            self._incident(org_id, incident_id)
            count = self.db.fetchone(
                "SELECT COUNT(*) AS count FROM orchestration_tasks WHERE org_id=? AND incident_id=?",
                (org_id, incident_id),
            )
            if count and count["count"] > MAX_INCIDENT_TASKS:
                raise CoordinationLimitError(
                    "incident tree exceeds inspection bound (64)"
                )
            root = self._root(org_id, incident_id)
            node = self._node(root) if root else None
            return {
                "org_id": org_id,
                "incident_id": incident_id,
                "roots": [node] if node else [],
                "aggregate_status": node["aggregate_status"] if node else "not_started",
                "incident_closed": False,
                "planned_areas": node.get("planned_areas", []) if node else [],
                "gaps": node["gaps"] if node else [],
            }
