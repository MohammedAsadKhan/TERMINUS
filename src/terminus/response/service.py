# pyright: reportAny=false, reportExplicitAny=false, reportPrivateUsage=false
"""Approval-bound durable response foundation with private, isolated fixtures.

There is no live provider or public dispatch/verification interface here. Every
receipt and outcome remains fixture-only, including independently checked cases.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, final
from uuid import uuid4

from pydantic import TypeAdapter

from terminus.core.ids import OrgId, UserId
from terminus.orchestration.models import AgentRun, EvidenceRecord, Task
from terminus.orchestration.scheduler_store import SchedulerLeaseError, SchedulerStore
from terminus.orchestration.storage import OrchestrationStore
from terminus.orgs.models import OrganizationRole
from terminus.orgs.storage import SqliteMembershipStore
from terminus.response.models import (
    ParameterBinding,
    ProposalDraft,
    RegisteredTarget,
    ResponsePolicy,
)
from terminus.response.storage import (
    ResponseConflictError,
    ResponseDeniedError,
    ResponseNotFoundError,
    ResponseStore,
    canonical,
    digest,
)
from terminus.storage.db import Database
from terminus.toolkit.models import (
    ApprovalBinding,
    Id,
    ResponseProposal,
)

_ID = TypeAdapter[str](Id)
FixtureOutcome = Literal[
    "acknowledged",
    "failed",
    "unknown_before_apply",
    "unknown_after_apply",
    "crash_before_apply",
    "crash_after_apply",
]


@final
class ResponseContractService:
    def __init__(
        self, db: Database, *, clock: Callable[[], datetime] | None = None
    ) -> None:
        self.db = db
        self.store = ResponseStore(db)
        self.records = OrchestrationStore(db)
        self.scheduler = SchedulerStore(db)
        self.memberships = SqliteMembershipStore(db)
        self.clock = clock or (lambda: datetime.now(UTC))

    def _now(self) -> datetime:
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Response clock requires a timezone")
        return now.astimezone(UTC)

    def _member(self, org_id: str, actor_id: str, *, admin: bool = False) -> None:
        for value in (org_id, actor_id):
            _ = _ID.validate_python(value, strict=True)
        role = self.memberships.role_of(OrgId(org_id), UserId(actor_id))
        allowed = (
            {OrganizationRole.ADMIN}
            if admin
            else {OrganizationRole.ADMIN, OrganizationRole.MEMBER}
        )
        if role not in allowed:
            raise ResponseDeniedError(
                "Current organization admin required"
                if admin
                else "Current organization operator required"
            )

    def _incident(self, org_id: str, incident_id: str) -> None:
        if not self.db.fetchone(
            "SELECT 1 FROM incidents WHERE org_id=? AND ticket_id=?",
            (org_id, incident_id),
        ):
            raise ResponseNotFoundError("Response record not found")

    def install_policy(
        self,
        actor_id: str,
        policy: ResponsePolicy,
        targets: tuple[RegisteredTarget, ...],
    ) -> None:
        """Trusted admin provisioning only; never callable from model arguments."""
        policy = ResponsePolicy.model_validate(policy.model_dump())
        targets = tuple(
            RegisteredTarget.model_validate(target.model_dump()) for target in targets
        )
        with self.db.transaction():
            self._member(policy.org_id, actor_id, admin=True)
            self._incident(policy.org_id, policy.incident_id)
            self._validate_registered_targets(policy, targets)
            previous = self.db.fetchone(
                "SELECT version FROM response_active_policies WHERE org_id=? AND incident_id=?",
                (policy.org_id, policy.incident_id),
            )
            expected = 1 if previous is None else previous["version"] + 1
            if policy.version != expected:
                raise ResponseConflictError(
                    "Response policy requires the next immutable version"
                )
            _ = self.db.execute(
                "INSERT INTO response_policies VALUES(?,?,?,?,?)",
                (
                    policy.org_id,
                    policy.incident_id,
                    policy.version,
                    policy.policy_version,
                    policy.model_dump_json(),
                ),
            )
            for target in targets:
                _ = self.db.execute(
                    "INSERT INTO response_targets VALUES(?,?,?,?,?)",
                    (
                        policy.org_id,
                        policy.incident_id,
                        policy.policy_version,
                        target.target_id,
                        target.model_dump_json(),
                    ),
                )
            _ = self.db.execute(
                "INSERT INTO response_active_policies VALUES(?,?,?) ON CONFLICT(org_id,incident_id) DO UPDATE SET version=excluded.version",
                (policy.org_id, policy.incident_id, policy.version),
            )

    @staticmethod
    def _validate_registered_targets(
        policy: ResponsePolicy, targets: tuple[RegisteredTarget, ...]
    ) -> None:
        if len({target.target_id for target in targets}) != len(targets):
            raise ResponseDeniedError("Duplicate response target registration")
        if not set(policy.allowed_target_ids) <= {
            target.target_id for target in targets
        }:
            raise ResponseDeniedError(
                "Every allowed target must have a trusted registration"
            )
        for target in targets:
            if (target.org_id, target.incident_id, target.provider_connection_id) != (
                policy.org_id,
                policy.incident_id,
                policy.provider_connection_id,
            ):
                raise ResponseDeniedError(
                    "Response target registration has a foreign binding"
                )

    def _policy(self, org_id: str, incident_id: str) -> ResponsePolicy:
        row = self.db.fetchone(
            "SELECT p.payload_json FROM response_policies p JOIN response_active_policies a ON p.org_id=a.org_id AND p.incident_id=a.incident_id AND p.version=a.version WHERE p.org_id=? AND p.incident_id=?",
            (org_id, incident_id),
        )
        if row is None:
            raise ResponseDeniedError("Response policy not configured")
        policy = ResponsePolicy.model_validate_json(row["payload_json"])
        if not policy.enabled or (policy.org_id, policy.incident_id) != (
            org_id,
            incident_id,
        ):
            raise ResponseDeniedError("Response policy disabled or mismatched")
        return policy

    def _scope(self, org_id: str, task_id: str) -> tuple[Task, AgentRun]:
        task = self.records.get_task(org_id, task_id)
        self._incident(org_id, task.incident_id)
        job = self.scheduler.get_job(org_id, task_id)
        if (
            task.role != "response_planner"
            or job.role != task.role
            or (job.org_id, job.incident_id, job.task_id)
            != (org_id, task.incident_id, task_id)
            or task.status not in {"running", "completed"}
            or job.status not in {"running", "completed"}
            or job.cancellation_requested
            or job.run_id is None
        ):
            raise ResponseDeniedError(
                "An actual current response_planner task/run is required"
            )
        run = self.records.get_agent_run(org_id, job.run_id)
        if (run.org_id, run.incident_id, run.task_id) != (
            org_id,
            task.incident_id,
            task_id,
        ) or run.status not in {"running", "completed"}:
            raise ResponseDeniedError(
                "Planner run is not an actual matching recorded run"
            )
        if task.status != job.status or run.status != job.status:
            raise ResponseDeniedError("Planner task/run/job lifecycle does not match")
        if job.status == "running":
            try:
                lease = self.scheduler._lease(job, task, run)  # noqa: SLF001
                _ = self.scheduler._owned(lease, self._now())  # noqa: SLF001
            except SchedulerLeaseError as exc:
                raise ResponseDeniedError(
                    "Planner ownership or coordinator lease expired"
                ) from exc
        return task, run

    def _evidence(
        self, org_id: str, incident_id: str, evidence_id: str
    ) -> EvidenceRecord:
        evidence = self.records.get_evidence(org_id, evidence_id)
        owner = self.records.get_task(org_id, evidence.task_id)
        if (evidence.org_id, evidence.incident_id, owner.incident_id) != (
            org_id,
            incident_id,
            incident_id,
        ):
            raise ResponseDeniedError(
                "Response evidence must belong to the canonical incident"
            )
        if (
            digest({"content": evidence.content, "content_ref": evidence.content_ref})
            != evidence.content_hash
        ):
            raise ResponseDeniedError(
                "Response evidence content hash does not match its durable record"
            )
        return evidence

    def _effect(self, proposal: ResponseProposal, policy: ResponsePolicy) -> None:
        if (proposal.provider_connection_id, proposal.policy_version) != (
            policy.provider_connection_id,
            policy.policy_version,
        ):
            raise ResponseDeniedError(
                "Exact current provider and policy binding required"
            )
        effect = proposal.effect
        if (
            effect.action not in policy.allowed_actions
            or effect.duration_seconds > policy.max_duration_seconds
            or effect.undo_strategy != "owned_resource_only"
        ):
            raise ResponseDeniedError("Effect exceeds the trusted response policy")
        if not set(effect.target_ids) <= set(policy.allowed_target_ids):
            raise ResponseDeniedError("Response targets exceed trusted incident scope")
        for target_id in effect.target_ids:
            row = self.db.fetchone(
                "SELECT payload_json FROM response_targets WHERE org_id=? AND incident_id=? AND policy_version=? AND target_id=?",
                (
                    proposal.org_id,
                    proposal.incident_id,
                    proposal.policy_version,
                    target_id,
                ),
            )
            if row is None:
                raise ResponseDeniedError("Unregistered response target")
            target = RegisteredTarget.model_validate_json(row["payload_json"])
            if (
                target.protected
                or target.management
                or (
                    target.org_id,
                    target.incident_id,
                    target.provider_connection_id,
                    target.target_id,
                )
                != (
                    proposal.org_id,
                    proposal.incident_id,
                    proposal.provider_connection_id,
                    target_id,
                )
            ):
                raise ResponseDeniedError(
                    "Protected, management, or mismatched response target"
                )

    def _parameters(self, proposal: ResponseProposal, evidence: EvidenceRecord) -> None:
        if (
            evidence.source != "response.parameters"
            or evidence.content_ref is not None
            or not isinstance(evidence.content, dict)
        ):
            raise ResponseDeniedError("Exact inline parameter evidence required")
        parameters = ParameterBinding.model_validate_json(canonical(evidence.content))
        expected = {
            "action": proposal.effect.action,
            "target_ids": list(proposal.effect.target_ids),
            "provider_connection_id": proposal.provider_connection_id,
            "policy_version": proposal.policy_version,
            "duration_seconds": proposal.effect.duration_seconds,
            "undo_strategy": proposal.effect.undo_strategy,
        }
        if parameters.model_dump(mode="json") != expected:
            raise ResponseDeniedError(
                "Proposal parameters differ from canonical parameter evidence"
            )

    def propose(
        self, org_id: str, task_id: str, actor_id: str, draft: ProposalDraft
    ) -> dict[str, Any]:
        draft = ProposalDraft.model_validate(draft.model_dump())
        with self.db.transaction():
            self._member(org_id, actor_id)
            task, run = self._scope(org_id, task_id)
            policy = self._policy(org_id, task.incident_id)
            if draft.approval_ttl_seconds > policy.max_approval_ttl_seconds:
                raise ResponseDeniedError("Approval TTL exceeds trusted policy")
            hashes = {
                eid: self._evidence(org_id, task.incident_id, eid).content_hash
                for eid in draft.evidence_ids
            }
            parameter_hash = hashes[draft.effect.parameter_evidence_id]
            proposal = ResponseProposal(
                proposal_id=f"proposal:{uuid4()}",
                org_id=org_id,
                incident_id=task.incident_id,
                task_id=task_id,
                run_id=run.run_id,
                provider_connection_id=policy.provider_connection_id,
                policy_version=policy.policy_version,
                effect=draft.effect,
                evidence_ids=draft.evidence_ids,
                prerequisites=(
                    *draft.prerequisites,
                    f"Parameter evidence {draft.effect.parameter_evidence_id} sha256 {parameter_hash}",
                ),
                expected_effect=draft.expected_effect,
                anticipated_impact=draft.anticipated_impact,
                verification_requirements=draft.verification_requirements,
                health_requirements=draft.health_requirements,
                approval_expires_at=self._now()
                + timedelta(seconds=draft.approval_ttl_seconds),
            )
            self._effect(proposal, policy)
            self._parameters(
                proposal,
                self._evidence(
                    org_id, task.incident_id, draft.effect.parameter_evidence_id
                ),
            )
            _ = self.db.execute(
                "INSERT INTO response_proposals VALUES(?,?,?,?,?,?,?,?)",
                (
                    org_id,
                    task.incident_id,
                    proposal.proposal_id,
                    actor_id,
                    proposal.digest(),
                    proposal.model_dump_json(),
                    canonical(hashes),
                    self._now().isoformat(),
                ),
            )
            self._event(
                org_id,
                proposal.proposal_id,
                None,
                "proposed",
                "Immutable fixture-only proposal; no effect executed",
            )
            return self.inspect(org_id, proposal.proposal_id)

    def _proposal(
        self, org_id: str, proposal_id: str
    ) -> tuple[ResponseProposal, dict[str, Any]]:
        row = self.store.proposal(org_id, proposal_id)
        proposal = ResponseProposal.model_validate_json(row["payload_json"])
        if (
            proposal.org_id != org_id
            or proposal.proposal_id != proposal_id
            or proposal.incident_id != row["incident_id"]
            or proposal.digest() != row["digest"]
        ):
            raise ResponseDeniedError("Immutable proposal digest or identity changed")
        return proposal, row

    def _admit(
        self, org_id: str, proposal_id: str
    ) -> tuple[ResponseProposal, dict[str, Any]]:
        proposal, row = self._proposal(org_id, proposal_id)
        self._member(org_id, row["creator_id"])
        task, run = self._scope(org_id, proposal.task_id)
        if (task.incident_id, run.run_id) != (proposal.incident_id, proposal.run_id):
            raise ResponseDeniedError("Proposal planner task/run no longer matches")
        self._effect(proposal, self._policy(org_id, proposal.incident_id))
        if self._now() >= proposal.approval_expires_at:
            raise ResponseDeniedError("Response approval has expired")
        snapshot = json.loads(row["evidence_hashes_json"])
        hashes = {
            eid: self._evidence(org_id, proposal.incident_id, eid).content_hash
            for eid in proposal.evidence_ids
        }
        if snapshot != hashes:
            raise ResponseDeniedError("Approved response evidence snapshot changed")
        self._parameters(
            proposal,
            self._evidence(
                org_id, proposal.incident_id, proposal.effect.parameter_evidence_id
            ),
        )
        expected = f"Parameter evidence {proposal.effect.parameter_evidence_id} sha256 {hashes[proposal.effect.parameter_evidence_id]}"
        if expected not in proposal.prerequisites:
            raise ResponseDeniedError(
                "Parameter evidence hash is absent from the immutable approval digest"
            )
        return proposal, row

    def decide(
        self,
        org_id: str,
        proposal_id: str,
        actor_id: str,
        decision: Literal["approve", "deny"],
    ) -> dict[str, Any]:
        if decision not in {"approve", "deny"}:
            raise ResponseDeniedError("Unknown response decision")
        with self.db.transaction():
            self._member(org_id, actor_id, admin=True)
            proposal, row = self._proposal(org_id, proposal_id)
            prior = self.db.fetchone(
                "SELECT * FROM response_decisions WHERE org_id=? AND proposal_id=?",
                (org_id, proposal_id),
            )
            if prior:
                if prior["decision"] != decision or prior["actor_id"] != actor_id:
                    raise ResponseConflictError("Response decision is immutable")
                return self.inspect(org_id, proposal_id)
            binding = None
            if decision == "approve":
                proposal, row = self._admit(org_id, proposal_id)
                if actor_id == row["creator_id"]:
                    raise ResponseDeniedError(
                        "A proposal creator cannot approve their own response"
                    )
                binding = ApprovalBinding(
                    approval_id=f"approval:{uuid4()}",
                    org_id=org_id,
                    incident_id=proposal.incident_id,
                    proposal_id=proposal_id,
                    proposal_digest=proposal.digest(),
                    approver_id=actor_id,
                    approver_role="admin",
                    issued_at=self._now(),
                    approval_expires_at=proposal.approval_expires_at,
                )
            _ = self.db.execute(
                "INSERT INTO response_decisions VALUES(?,?,?,?,?,?)",
                (
                    org_id,
                    proposal_id,
                    actor_id,
                    decision,
                    binding.model_dump_json() if binding else None,
                    self._now().isoformat(),
                ),
            )
            self._event(
                org_id,
                proposal_id,
                None,
                "approved" if binding else "denied",
                "Human decision recorded; no dispatch occurred",
            )
            return self.inspect(org_id, proposal_id)

    def _binding(self, proposal: ResponseProposal) -> ApprovalBinding:
        row = self.db.fetchone(
            "SELECT * FROM response_decisions WHERE org_id=? AND proposal_id=?",
            (proposal.org_id, proposal.proposal_id),
        )
        if row is None or row["decision"] != "approve" or not row["binding_json"]:
            raise ResponseDeniedError(
                "An exact human approval is required before intent"
            )
        binding = ApprovalBinding.model_validate_json(row["binding_json"])
        self._member(proposal.org_id, binding.approver_id, admin=True)
        if (
            binding.org_id,
            binding.incident_id,
            binding.proposal_id,
            binding.proposal_digest,
            binding.approval_expires_at,
            binding.approver_id,
        ) != (
            proposal.org_id,
            proposal.incident_id,
            proposal.proposal_id,
            proposal.digest(),
            proposal.approval_expires_at,
            row["actor_id"],
        ):
            raise ResponseDeniedError(
                "Approval does not exactly bind the immutable proposal"
            )
        creator = self.store.proposal(proposal.org_id, proposal.proposal_id)[
            "creator_id"
        ]
        if (
            binding.approver_id == creator
            or not binding.issued_at <= self._now() < binding.approval_expires_at
        ):
            raise ResponseDeniedError(
                "Self, future, or expired approval cannot authorize intent"
            )
        return binding

    def _reserve(self, org_id: str, proposal_id: str) -> dict[str, Any]:  # pyright: ignore[reportUnusedFunction]
        """Persist a unique intent atomically before any fixture I/O can occur."""
        with self.db.transaction():
            proposal, _ = self._admit(org_id, proposal_id)
            _ = self._binding(proposal)
            prior = self.db.fetchone(
                "SELECT * FROM response_intents WHERE org_id=? AND proposal_id=?",
                (org_id, proposal_id),
            )
            if prior:
                if (
                    prior["incident_id"],
                    prior["proposal_digest"],
                    prior["idempotency_key"],
                ) != (
                    proposal.incident_id,
                    proposal.digest(),
                    f"response:{proposal_id}",
                ):
                    raise ResponseDeniedError(
                        "Existing durable response intent has an altered identity"
                    )
                return prior
            intent_id = f"intent:{uuid4()}"
            _ = self.db.execute(
                "INSERT INTO response_intents(org_id,incident_id,intent_id,proposal_id,proposal_digest,idempotency_key,state,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    org_id,
                    proposal.incident_id,
                    intent_id,
                    proposal_id,
                    proposal.digest(),
                    f"response:{proposal_id}",
                    "reserved",
                    self._now().isoformat(),
                ),
            )
            self._event(
                org_id,
                proposal_id,
                intent_id,
                "reserved",
                "Durable fixture intent admitted before simulated I/O",
            )
            return self.store.intent(org_id, intent_id)

    def inspect(self, org_id: str, proposal_id: str) -> dict[str, Any]:
        proposal, row = self._proposal(org_id, proposal_id)
        decision = self.db.fetchone(
            "SELECT * FROM response_decisions WHERE org_id=? AND proposal_id=?",
            (org_id, proposal_id),
        )
        intent = self.db.fetchone(
            "SELECT * FROM response_intents WHERE org_id=? AND proposal_id=?",
            (org_id, proposal_id),
        )
        state = (
            intent["state"]
            if intent
            else "denied"
            if decision and decision["decision"] == "deny"
            else "expired"
            if self._now() >= proposal.approval_expires_at
            else "approved"
            if decision
            else "proposed"
        )
        return {
            "fixture_only": True,
            "live_executed": False,
            "live_verified": False,
            "state": state,
            "proposal": proposal.model_dump(mode="json"),
            "proposal_digest": row["digest"],
            "creator_id": row["creator_id"],
            "evidence_hashes": json.loads(row["evidence_hashes_json"]),
            "approval": json.loads(decision["binding_json"])
            if decision and decision["binding_json"]
            else None,
            "intent": intent,
            "verification": {
                "fixture_only": True,
                "report": json.loads(intent["verification_json"]),
            }
            if intent and intent["verification_json"]
            else None,
            "verification_current": state == "fixture_verified",
            "events": self.db.fetchall(
                "SELECT state,timestamp,detail FROM response_events WHERE org_id=? AND proposal_id=? ORDER BY event_id",
                (org_id, proposal_id),
            ),
        }

    def list_proposals(self, org_id: str, incident_id: str) -> list[dict[str, Any]]:
        self._incident(org_id, incident_id)
        return [
            self.inspect(org_id, row["proposal_id"])
            for row in self.db.fetchall(
                "SELECT proposal_id FROM response_proposals WHERE org_id=? AND incident_id=? ORDER BY created_at LIMIT 100",
                (org_id, incident_id),
            )
        ]

    def _event(
        self,
        org_id: str,
        proposal_id: str,
        intent_id: str | None,
        state: str,
        detail: str,
    ) -> None:
        _ = self.db.execute(
            "INSERT INTO response_events(org_id,proposal_id,intent_id,state,timestamp,detail) VALUES(?,?,?,?,?,?)",
            (org_id, proposal_id, intent_id, state, self._now().isoformat(), detail),
        )
