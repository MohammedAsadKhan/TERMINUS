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
from typing import TYPE_CHECKING, Any

from terminus.orchestration.coordination_models import (
    AreaObjective,
    HelpRequestSpec,
    MainObjective,
)
from terminus.orchestration.models import EvidenceRecord, HelpRequest, Task
from terminus.orchestration.storage import OrchestrationNotFoundError

if TYPE_CHECKING:
    from terminus.orchestration.coordination import CoordinationService

MAX_HELP_PER_TASK = 4
MAX_HELP_PER_INCIDENT = 16
HELP_KEY_PREFIX = "coord:help:"


class CollaborationRejectedError(ValueError):
    """Admission denied. ``code`` is a bounded machine-readable reason."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def objective_digest(objective: str) -> str:
    normalized = " ".join(objective.casefold().split())
    return hashlib.sha256(normalized.encode()).hexdigest()


def _state(
    request: HelpRequest, area: Task | None, peer: Task | None
) -> tuple[str, str | None]:
    if request.status == "resolved":
        return "resolved", None
    if request.status == "cancelled":
        return "rejected", "request_cancelled"
    if request.status == "open":
        return "requested", None
    for label, task in (("peer", peer), ("area", area)):
        if task is not None and task.status in {"failed", "cancelled"}:
            return "rejected", f"{label}_{task.status}"
    return "assigned", None


class CollaborationService:
    def __init__(self, service: CoordinationService) -> None:
        self.service = service
        self.db = service.db
        for statement in (
            """CREATE TABLE IF NOT EXISTS orchestration_help_collaboration (
                org_id TEXT NOT NULL, help_request_id TEXT NOT NULL,
                incident_id TEXT NOT NULL, requester_task_id TEXT NOT NULL,
                target_role TEXT NOT NULL, objective_digest TEXT NOT NULL,
                expected_kinds_json TEXT NOT NULL, evidence_ids_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(org_id, help_request_id),
                UNIQUE(org_id, requester_task_id, target_role, objective_digest),
                FOREIGN KEY(org_id, help_request_id)
                    REFERENCES orchestration_help_requests(org_id, help_request_id)
            )""",
            "CREATE INDEX IF NOT EXISTS idx_orch_collab_incident ON orchestration_help_collaboration(org_id, incident_id)",
        ):
            _ = self.db.execute(statement)

    # -- internals ---------------------------------------------------------
    def _row(self, org_id: str, help_request_id: str) -> dict[str, Any] | None:
        return self.db.fetchone(
            "SELECT * FROM orchestration_help_collaboration "
            "WHERE org_id=? AND help_request_id=?",
            (org_id, help_request_id),
        )

    def _evidence(
        self, org_id: str, incident_id: str, ids: list[str]
    ) -> list[EvidenceRecord]:
        records: list[EvidenceRecord] = []
        for evidence_id in ids:
            row = self.db.fetchone(
                "SELECT payload_json FROM orchestration_evidence "
                "WHERE org_id=? AND incident_id=? AND evidence_id=?",
                (org_id, incident_id, evidence_id),
            )
            if row is None:  # foreign and missing are indistinguishable
                raise OrchestrationNotFoundError("Orchestration record not found")
            records.append(EvidenceRecord.model_validate_json(row["payload_json"]))
        return records

    def _delegated(
        self, org_id: str, request: HelpRequest
    ) -> tuple[Task | None, Task | None]:
        from terminus.orchestration.coordination import (
            _help_key,
            _key,
        )

        svc = self.service
        root = svc._root(org_id, request.incident_id)  # noqa: SLF001
        if root is None:
            return None, None
        area = svc._existing(  # noqa: SLF001
            org_id, _help_key(root.task_id, request.help_request_id)
        )
        peer = (
            svc._existing(org_id, _key(area.task_id, request.requested_role))  # noqa: SLF001
            if area
            else None
        )
        return area, peer

    # -- admission ---------------------------------------------------------
    def request_help(  # noqa: C901 - ordered admission checks
        self, org_id: str, requester_task_id: str, spec: HelpRequestSpec
    ) -> dict[str, Any]:
        """Admit a structured peer-help request and return its ownership view
        plus ``duplicate``. Raises ``OrchestrationNotFoundError`` for missing or
        foreign tasks/evidence, ``CoordinationLimitError`` for caps and
        ``CollaborationRejectedError`` (with ``code``) for other denials."""
        from terminus.orchestration.coordination import (
            CoordinationLimitError,
        )

        if not isinstance(spec, HelpRequestSpec):
            raise TypeError("spec must be a HelpRequestSpec")
        svc = self.service
        digest = objective_digest(spec.objective)
        with self.db.transaction():
            requester = svc.records.get_task(org_id, requester_task_id)
            svc._incident(org_id, requester.incident_id)  # noqa: SLF001
            existing = self.db.fetchone(
                "SELECT help_request_id FROM orchestration_help_collaboration "
                "WHERE org_id=? AND requester_task_id=? AND target_role=? "
                "AND objective_digest=?",
                (org_id, requester_task_id, spec.target_role, digest),
            )
            if existing:
                view = self.ownership(org_id, existing["help_request_id"])
                view["duplicate"] = True
                return view
            root = svc._root(org_id, requester.incident_id)  # noqa: SLF001
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
            per_task = self.db.fetchone(
                "SELECT COUNT(*) AS count FROM orchestration_help_collaboration "
                "WHERE org_id=? AND requester_task_id=?",
                (org_id, requester_task_id),
            )
            if per_task and per_task["count"] >= MAX_HELP_PER_TASK:
                raise CoordinationLimitError(
                    f"task help request limit ({MAX_HELP_PER_TASK}) reached"
                )
            per_incident = self.db.fetchone(
                "SELECT COUNT(*) AS count FROM orchestration_help_requests "
                "WHERE org_id=? AND incident_id=?",
                (org_id, requester.incident_id),
            )
            if per_incident and per_incident["count"] >= MAX_HELP_PER_INCIDENT:
                raise CoordinationLimitError(
                    f"incident help delegation limit ({MAX_HELP_PER_INCIDENT}) reached"
                )
            _ = self._evidence(org_id, requester.incident_id, spec.shared_evidence_ids)
            request = svc.records.create_help_request(
                org_id, requester_task_id, spec.target_role, spec.objective
            )
            _ = self.db.execute(
                "INSERT INTO orchestration_help_collaboration(org_id,help_request_id,"
                "incident_id,requester_task_id,target_role,objective_digest,"
                "expected_kinds_json,evidence_ids_json,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
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
            _ = svc.assign_help(org_id, request.help_request_id)
            view = self.ownership(org_id, request.help_request_id)
            view["duplicate"] = False
            return view

    # -- read paths --------------------------------------------------------
    def ownership(self, org_id: str, help_request_id: str) -> dict[str, Any]:
        """Bounded cross-area ownership record for one help request."""
        svc = self.service
        request = svc.records.get_help_request(org_id, help_request_id)
        requester = svc.records.get_task(org_id, request.task_id)
        row = self._row(org_id, help_request_id)
        area_task, peer = self._delegated(org_id, request)
        state, reason = _state(request, area_task, peer)
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
                json.loads(row["expected_kinds_json"]) if row else []
            ),
            "shared_evidence_ids": (
                json.loads(row["evidence_ids_json"]) if row else []
            ),
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

    def get_help_context(self, org_id: str, task_id: str) -> dict[str, Any]:
        """What a delegated peer may cite: the request contract and shared
        evidence records, re-validated against the same tenant and incident.
        Non-delegated, missing and foreign tasks all raise NotFound."""
        with self.db.transaction():
            help_id = self.help_request_for_task(org_id, task_id)
            row = self._row(org_id, help_id) if help_id else None
            if help_id is None or row is None:
                raise OrchestrationNotFoundError("Orchestration record not found")
            view = self.ownership(org_id, help_id)
            evidence = self._evidence(
                org_id, row["incident_id"], view["shared_evidence_ids"]
            )
            return {
                **view,
                "shared_evidence": [e.model_dump(mode="json") for e in evidence],
            }
