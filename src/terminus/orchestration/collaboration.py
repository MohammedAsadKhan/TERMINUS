"""Structured peer-help admission, shared-evidence linkage and ownership view.

Deterministic bookkeeping only: no model calls, tools or scope selection. The
requester proposes a bounded contract; the server derives tenant, incident and
requester role, validates every shared evidence id inside that tenant AND
incident, and then reuses ``CoordinationService.assign_help`` to admit the
peer through its responsible area.

Duplicate policy: an identical (requester task, target role, normalized
objective digest) returns the existing request idempotently (``duplicate`` is
true); it never creates a second task.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Protocol, cast, final

from pydantic import TypeAdapter

from terminus.orchestration.coordination_models import (
    AreaObjective,
    CoordinationLimitError,
    HelpRequestSpec,
    MainObjective,
)
from terminus.orchestration.models import EvidenceRecord, HelpRequest, Task
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.orchestration.specialists.models import SpecialistResult
from terminus.orchestration.storage import (
    OrchestrationNotFoundError,
    OrchestrationStore,
)
from terminus.storage.db import Database

MAX_HELP_PER_TASK = 4
MAX_HELP_PER_INCIDENT = 16
HELP_KEY_PREFIX = "coord:help:"
_STRINGS = TypeAdapter(list[str])


Row = Mapping[str, object]


def _cell(row: Row, key: str) -> object:
    return row[key]


def _text(row: Row, key: str) -> str:
    return str(_cell(row, key))


def _string_list(row: Row, key: str) -> list[str]:
    return _STRINGS.validate_json(_text(row, key))


class CollaborationBackend(Protocol):
    db: Database
    records: OrchestrationStore
    scheduler: SchedulerStore
    catalog: dict[str, str]

    def require_incident(self, org_id: str, incident_id: str) -> None: ...

    def root_task(self, org_id: str, incident_id: str) -> Task | None: ...

    def existing_task(self, org_id: str, key: str) -> Task | None: ...

    def assign_admitted_help(self, org_id: str, help_request_id: str) -> Task: ...


@final
class CollaborationRejectedError(ValueError):
    """Admission denied. ``code`` is a bounded machine-readable reason."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code: str = code


def objective_digest(objective: str) -> str:
    normalized = " ".join(objective.casefold().split())
    return hashlib.sha256(normalized.encode()).hexdigest()


def _state(  # noqa: PLR0911 - lifecycle precedence is intentionally explicit
    request: HelpRequest,
    area: Task | None,
    peer: Task | None,
    result: SpecialistResult | None,
) -> tuple[str, str | None]:
    if request.status == "resolved":
        if result is None:
            return "incomplete", "peer_result_missing"
        if result.status != "completed":
            return "incomplete", f"peer_result_{result.status}"
        return "resolved", None
    if request.status == "cancelled":
        return "rejected", "request_cancelled"
    if request.status == "open":
        return "requested", None
    for label, task in (("peer", peer), ("area", area)):
        if task is not None and task.status in {"failed", "cancelled"}:
            return "rejected", f"{label}_{task.status}"
    if peer is not None and peer.status == "completed" and result is None:
        return "incomplete", "peer_result_missing"
    return "assigned", None


@final
class CollaborationService:
    def __init__(self, service: CollaborationBackend) -> None:
        self.service: CollaborationBackend = service
        self.db: Database = service.db
        for statement in (
            """CREATE TABLE IF NOT EXISTS orchestration_help_collaboration (
                org_id TEXT NOT NULL, help_request_id TEXT NOT NULL,
                incident_id TEXT NOT NULL, requester_task_id TEXT NOT NULL,
                target_role TEXT NOT NULL, objective_digest TEXT NOT NULL,
                expected_kinds_json TEXT NOT NULL, evidence_ids_json TEXT NOT NULL,
                result_json TEXT,
                created_at TEXT NOT NULL,
                PRIMARY KEY(org_id, help_request_id),
                UNIQUE(org_id, requester_task_id, target_role, objective_digest),
                FOREIGN KEY(org_id, help_request_id)
                    REFERENCES orchestration_help_requests(org_id, help_request_id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_orch_collab_incident ON orchestration_help_collaboration(org_id, incident_id)",
        ):
            _ = self.db.execute(statement)
        columns = {
            _text(cast("Row", row), "name")
            for row in self.db.fetchall(
                "PRAGMA table_info(orchestration_help_collaboration)"
            )
        }
        if "result_json" not in columns:
            _ = self.db.execute(
                "ALTER TABLE orchestration_help_collaboration ADD COLUMN result_json TEXT"
            )

    # -- internals ---------------------------------------------------------
    def _row(self, org_id: str, help_request_id: str) -> Row | None:
        return cast(
            "Row | None",
            self.db.fetchone(
                "SELECT * FROM orchestration_help_collaboration WHERE org_id=? AND help_request_id=?",
                (org_id, help_request_id),
            ),
        )

    def _evidence(
        self, org_id: str, incident_id: str, ids: list[str]
    ) -> list[EvidenceRecord]:
        records: list[EvidenceRecord] = []
        for evidence_id in ids:
            row = cast(
                "Row | None",
                self.db.fetchone(
                    "SELECT payload_json FROM orchestration_evidence WHERE org_id=? AND incident_id=? AND evidence_id=?",
                    (org_id, incident_id, evidence_id),
                ),
            )
            if row is None:  # foreign and missing are indistinguishable
                raise OrchestrationNotFoundError("Orchestration record not found")
            records.append(
                EvidenceRecord.model_validate_json(_text(row, "payload_json"))
            )
        return records

    def _delegated(
        self, org_id: str, request: HelpRequest
    ) -> tuple[Task | None, Task | None]:
        svc = self.service
        root = svc.root_task(org_id, request.incident_id)
        if root is None:
            return None, None
        area = svc.existing_task(
            org_id, help_task_key(root.task_id, request.help_request_id)
        )
        peer = (
            svc.existing_task(org_id, task_key(area.task_id, request.requested_role))
            if area
            else None
        )
        return area, peer

    # -- admission ---------------------------------------------------------
    def request_help(
        self, org_id: str, requester_task_id: str, spec: HelpRequestSpec
    ) -> dict[str, object]:
        """Admit a structured peer-help request and return its ownership view
        plus ``duplicate``. Raises ``OrchestrationNotFoundError`` for missing or
        foreign tasks/evidence, ``CoordinationLimitError`` for caps and
        ``CollaborationRejectedError`` (with ``code``) for other denials."""
        svc = self.service
        digest = objective_digest(spec.objective)
        with self.db.transaction():
            requester = svc.records.get_task(org_id, requester_task_id)
            svc.require_incident(org_id, requester.incident_id)
            existing = cast(
                "Row | None",
                self.db.fetchone(
                    """SELECT help_request_id FROM orchestration_help_collaboration
                       WHERE org_id=? AND requester_task_id=? AND target_role=?
                       AND objective_digest=?""",
                    (org_id, requester_task_id, spec.target_role, digest),
                ),
            )
            if existing:
                view = self.ownership(org_id, _text(existing, "help_request_id"))
                view["duplicate"] = True
                return view
            root = svc.root_task(org_id, requester.incident_id)
            if root is None:
                raise CollaborationRejectedError(
                    "no_coordination", "Incident has no coordination objective"
                )
            if requester.role not in svc.catalog:
                raise CollaborationRejectedError(
                    "requester_not_specialist",
                    "Help must originate from a managed specialty",
                )
            parent = (
                svc.records.get_task(org_id, requester.parent_task_id)
                if requester.parent_task_id
                else None
            )
            if parent and (parent.idempotency_key or "").startswith(HELP_KEY_PREFIX):
                raise CollaborationRejectedError(
                    "recursive_delegation",
                    "A help-delegated task cannot request further help",
                )
            if spec.target_role == requester.role:
                raise CollaborationRejectedError(
                    "self_delegation", "A specialist cannot delegate to its own role"
                )
            area = svc.catalog.get(spec.target_role)
            if area is None:
                raise CollaborationRejectedError(
                    "role_not_enabled", "Requested specialty is not enabled"
                )
            plan = MainObjective.model_validate_json(root.objective)
            if area not in plan.request.areas:
                raise CollaborationRejectedError(
                    "area_not_selected", "Responsible area is not selected"
                )
            per_task = cast(
                "Row | None",
                self.db.fetchone(
                    """SELECT COUNT(*) AS count FROM orchestration_help_collaboration
                       WHERE org_id=? AND requester_task_id=?""",
                    (org_id, requester_task_id),
                ),
            )
            if per_task and cast("int", _cell(per_task, "count")) >= MAX_HELP_PER_TASK:
                raise CoordinationLimitError(
                    f"task help request limit ({MAX_HELP_PER_TASK}) reached"
                )
            per_incident = cast(
                "Row | None",
                self.db.fetchone(
                    """SELECT COUNT(*) AS count FROM orchestration_help_requests
                       WHERE org_id=? AND incident_id=?""",
                    (org_id, requester.incident_id),
                ),
            )
            if (
                per_incident
                and cast("int", _cell(per_incident, "count")) >= MAX_HELP_PER_INCIDENT
            ):
                raise CoordinationLimitError(
                    f"incident help delegation limit ({MAX_HELP_PER_INCIDENT}) reached"
                )
            _ = self._evidence(org_id, requester.incident_id, spec.shared_evidence_ids)
            request = svc.records.create_help_request(
                org_id, requester_task_id, spec.target_role, spec.objective
            )
            _ = self.db.execute(
                """INSERT INTO orchestration_help_collaboration(
                       org_id,help_request_id,incident_id,requester_task_id,
                       target_role,objective_digest,expected_kinds_json,
                       evidence_ids_json,created_at)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (
                    org_id,
                    request.help_request_id,
                    requester.incident_id,
                    requester_task_id,
                    spec.target_role,
                    digest,
                    json.dumps(spec.expected_evidence_kinds),
                    json.dumps(spec.shared_evidence_ids),
                    request.created_at.isoformat(),
                ),
            )
            _ = svc.assign_admitted_help(org_id, request.help_request_id)
            view = self.ownership(org_id, request.help_request_id)
            view["duplicate"] = False
            return view

    # -- read paths --------------------------------------------------------
    def ownership(self, org_id: str, help_request_id: str) -> dict[str, object]:
        """Bounded cross-area ownership record for one help request."""
        svc = self.service
        request = svc.records.get_help_request(org_id, help_request_id)
        requester = svc.records.get_task(org_id, request.task_id)
        row = self._row(org_id, help_request_id)
        area_task, peer = self._delegated(org_id, request)
        result = (
            SpecialistResult.model_validate_json(_text(row, "result_json"))
            if row is not None and _cell(row, "result_json") is not None
            else None
        )
        state, reason = _state(request, area_task, peer, result)
        return {
            "help_request_id": help_request_id,
            "incident_id": request.incident_id,
            "state": state,
            "reason_code": reason,
            "requester_task_id": requester.task_id,
            "requester_role": requester.role,
            "requester_area": requester.area,
            "target_role": request.requested_role,
            "responsible_area": svc.catalog.get(request.requested_role),
            "delegated_task_id": area_task.task_id if area_task else None,
            "peer_task_id": peer.task_id if peer else None,
            "objective": request.reason,
            "expected_evidence_kinds": (
                _string_list(row, "expected_kinds_json") if row else []
            ),
            "shared_evidence_ids": (
                _string_list(row, "evidence_ids_json") if row else []
            ),
            "result": result.model_dump(mode="json") if result else None,
        }

    def help_request_for_task(self, org_id: str, task_id: str) -> str | None:
        """Help request id a delegated task (area task or peer child) serves."""
        svc = self.service
        task = svc.records.get_task(org_id, task_id)
        candidates = [task]
        if task.parent_task_id:
            candidates.append(svc.records.get_task(org_id, task.parent_task_id))
        for candidate in candidates:
            if candidate.role == "area_orchestrator" and (
                candidate.idempotency_key or ""
            ).startswith(HELP_KEY_PREFIX):
                return AreaObjective.model_validate_json(
                    candidate.objective
                ).help_request_id
        return None

    def get_help_context(self, org_id: str, task_id: str) -> dict[str, object]:
        """What a delegated peer may cite: the request contract and shared
        evidence records, re-validated against the same tenant and incident.
        Non-delegated, missing and foreign tasks all raise NotFound."""
        with self.db.transaction():
            help_id = self.help_request_for_task(org_id, task_id)
            row = self._row(org_id, help_id) if help_id else None
            if help_id is None or row is None:
                raise OrchestrationNotFoundError("Orchestration record not found")
            view = self.ownership(org_id, help_id)
            evidence_ids = _string_list(row, "evidence_ids_json")
            evidence = self._evidence(
                org_id, _text(row, "incident_id"), evidence_ids
            )
            return {
                **view,
                "shared_evidence": [e.model_dump(mode="json") for e in evidence],
            }

    def require_assignment(self, org_id: str, help_request_id: str) -> HelpRequest:
        """Revalidate the durable structured contract before scheduler admission."""
        request = self.service.records.get_help_request(org_id, help_request_id)
        row = self._row(org_id, help_request_id)
        if row is None:
            raise CollaborationRejectedError(
                "unstructured_request", "Help requires a structured admission contract"
            )
        requester = self.service.records.get_task(org_id, request.task_id)
        root = self.service.root_task(org_id, request.incident_id)
        if root is None:
            raise CollaborationRejectedError(
                "no_coordination", "Incident has no coordination objective"
            )
        parent = (
            self.service.records.get_task(org_id, requester.parent_task_id)
            if requester.parent_task_id
            else None
        )
        if requester.role not in self.service.catalog:
            raise CollaborationRejectedError(
                "requester_not_specialist", "Help must originate from a managed specialty"
            )
        if parent and (parent.idempotency_key or "").startswith(HELP_KEY_PREFIX):
            raise CollaborationRejectedError(
                "recursive_delegation", "A help-delegated task cannot request further help"
            )
        if requester.role == request.requested_role:
            raise CollaborationRejectedError(
                "self_delegation", "A specialist cannot delegate to its own role"
            )
        area = self.service.catalog.get(request.requested_role)
        if area is None:
            raise CollaborationRejectedError(
                "role_not_enabled", "Requested specialty is not enabled"
            )
        plan = MainObjective.model_validate_json(root.objective)
        if area not in plan.request.areas:
            raise CollaborationRejectedError(
                "area_not_selected", "Responsible area is not selected"
            )
        ids = _string_list(row, "evidence_ids_json")
        _ = self._evidence(org_id, request.incident_id, ids)
        if (
            _text(row, "requester_task_id") != requester.task_id
            or _text(row, "target_role") != request.requested_role
            or _text(row, "incident_id") != request.incident_id
        ):
            raise CollaborationRejectedError(
                "contract_mismatch", "Help admission contract does not match the request"
            )
        return request

    def persist_result(
        self, org_id: str, help_request_id: str, peer: Task
    ) -> SpecialistResult | None:
        """Copy a completed peer's bounded output into the durable help record."""
        job = self.service.scheduler.get_job(org_id, peer.task_id)
        if job.status != "completed" or job.run_id is None:
            return None
        run = self.service.records.get_agent_run(org_id, job.run_id)
        if run.status != "completed" or run.result is None:
            return None
        try:
            result = SpecialistResult.model_validate_json(
                json.dumps(run.result, allow_nan=False)
            )
        except (TypeError, ValueError):
            return None
        _ = self.db.execute(
            """UPDATE orchestration_help_collaboration SET result_json=?
               WHERE org_id=? AND help_request_id=? AND result_json IS NULL""",
            (result.model_dump_json(), org_id, help_request_id),
        )
        return result


def task_key(*parts: str) -> str:
    digest = hashlib.sha256("\0".join(parts).encode()).hexdigest()
    return f"coord:{digest}"


def help_task_key(root_id: str, help_id: str) -> str:
    return "coord:help:" + task_key(root_id, "help", help_id)[6:]
