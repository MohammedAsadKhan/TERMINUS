# pyright: reportAny=false, reportExplicitAny=false, reportPrivateUsage=false
"""Internal deterministic fixture transitions. No transport or live adapter.

This module is deliberately absent from the public API and package exports.
Its receipts, resources, checks and undo outcomes always describe fixtures.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, final
from uuid import uuid4

from terminus.response.service import FixtureOutcome, ResponseContractService
from terminus.response.storage import ResponseConflictError, ResponseDeniedError
from terminus.toolkit.models import (
    ResponseProposal,
    VerificationObservation,
    VerificationReport,
)


@final
class FixtureResponseDriver:
    def __init__(self, service: ResponseContractService) -> None:
        self.service = service
        self.db = service.db

    def reserve(self, org_id: str, proposal_id: str) -> dict[str, Any]:
        return self.service._reserve(org_id, proposal_id)  # noqa: SLF001

    def dispatch(
        self, org_id: str, proposal_id: str, outcome: FixtureOutcome = "acknowledged"
    ) -> dict[str, Any]:
        """Commit intent and an attempt before touching a simulated provider."""
        if outcome not in {
            "acknowledged",
            "failed",
            "unknown_before_apply",
            "unknown_after_apply",
            "crash_before_apply",
            "crash_after_apply",
        }:
            raise ResponseDeniedError("Unknown fixture outcome")
        intent = self.reserve(org_id, proposal_id)
        with self.db.transaction():
            intent = self.service.store.intent(org_id, intent["intent_id"])
            if intent["state"] != "reserved":
                # Ambiguous/in-flight attempts are read, never blindly retried.
                return self.service.inspect(org_id, proposal_id)
            proposal, _ = self.service._admit(org_id, proposal_id)  # noqa: SLF001
            _ = self.service._binding(proposal)  # noqa: SLF001
            run = self.service.records.create_agent_run(
                org_id, proposal.task_id, agent_id="response-fixture"
            )
            _ = self.service.records.transition_agent_run(
                org_id, run.run_id, "queued", "running"
            )
            _ = self.db.execute(
                "UPDATE response_intents SET state='in_flight',dispatch_run_id=?,dispatched_at=? WHERE org_id=? AND intent_id=? AND state='reserved'",
                (
                    run.run_id,
                    self.service._now().isoformat(),  # noqa: SLF001
                    org_id,
                    intent["intent_id"],
                ),
            )
            self.service._event(  # noqa: SLF001
                org_id,
                proposal_id,
                intent["intent_id"],
                "in_flight",
                "Fixture attempt committed before simulated I/O; live_executed=false",
            )
        # The transaction has committed. A crash at this point cannot erase the
        # intent or authorize a second attempt after restart.
        if outcome in {"acknowledged", "unknown_after_apply", "crash_after_apply"}:
            self._apply(org_id, intent["intent_id"])
        if outcome.startswith("crash"):
            return self.service.inspect(org_id, proposal_id)
        state = (
            "acknowledged"
            if outcome == "acknowledged"
            else "failed"
            if outcome == "failed"
            else "unknown"
        )
        with self.db.transaction():
            self._state(
                org_id,
                intent["intent_id"],
                "in_flight",
                state,
                "Simulated provider acknowledgement is not independent verification"
                if state == "acknowledged"
                else "Simulated outcome requires reconciliation"
                if state == "unknown"
                else "Simulated provider rejected the effect",
            )
            _ = self.service.records.transition_agent_run(
                org_id,
                run.run_id,
                "running",
                "completed",
                result={
                    "fixture_only": True,
                    "live_executed": False,
                    "outcome": state,
                    "intent_id": intent["intent_id"],
                },
            )
        return self.service.inspect(org_id, proposal_id)

    def _apply(self, org_id: str, intent_id: str) -> None:
        """Pure SQLite fixture I/O; creates only a uniquely owned fixture resource."""
        with self.db.transaction():
            intent = self.service.store.intent(org_id, intent_id)
            if intent["state"] != "in_flight":
                raise ResponseConflictError(
                    "Fixture I/O requires an admitted in-flight intent"
                )
            proposal, _ = self.service._admit(org_id, intent["proposal_id"])  # noqa: SLF001
            _ = self.service._binding(proposal)  # noqa: SLF001
            if proposal.digest() != intent["proposal_digest"]:
                raise ResponseDeniedError("Fixture intent digest changed")
            prior = self.db.fetchone(
                "SELECT 1 FROM response_fixture_receipts WHERE org_id=? AND intent_id=?",
                (org_id, intent_id),
            )
            if prior:
                raise ResponseConflictError(
                    "A fixture resource already exists; reconcile instead of replaying"
                )
            resource_id = f"fixture-resource:{uuid4()}"
            now = self.service._now()  # noqa: SLF001
            expiry = datetime.fromisoformat(intent["dispatched_at"]) + timedelta(
                seconds=proposal.effect.duration_seconds
            )
            _ = self.db.execute(
                "INSERT INTO response_fixture_receipts VALUES(?,?,?,?,?,?)",
                (
                    org_id,
                    intent_id,
                    proposal.digest(),
                    resource_id,
                    "acknowledged",
                    now.isoformat(),
                ),
            )
            _ = self.db.execute(
                "INSERT INTO response_owned_resources VALUES(?,?,?,?,?,?,?)",
                (
                    org_id,
                    proposal.incident_id,
                    resource_id,
                    intent_id,
                    proposal.digest(),
                    expiry.isoformat(),
                    "owned",
                ),
            )
            self.service._event(  # noqa: SLF001
                org_id,
                proposal.proposal_id,
                intent_id,
                "fixture_applied",
                "Only an owned SQLite fixture resource was created; no endpoint action ran",
            )

    def _state(
        self, org_id: str, intent_id: str, expected: str, state: str, detail: str
    ) -> None:
        intent = self.service.store.intent(org_id, intent_id)
        cursor = self.db.execute(
            "UPDATE response_intents SET state=?,detail=? WHERE org_id=? AND intent_id=? AND state=?",
            (state, detail, org_id, intent_id, expected),
        )
        if cursor.rowcount != 1:
            raise ResponseConflictError("Response lifecycle state changed")
        self.service._event(org_id, intent["proposal_id"], intent_id, state, detail)  # noqa: SLF001

    def recover_interrupted(self, org_id: str) -> int:
        """Mark abandoned attempts unknown; recovery never dispatches again."""
        recovered = 0
        with self.db.transaction():
            for intent in self.db.fetchall(
                "SELECT * FROM response_intents WHERE org_id=? AND state='in_flight' LIMIT 100",
                (org_id,),
            ):
                self._state(
                    org_id,
                    intent["intent_id"],
                    "in_flight",
                    "unknown",
                    "Fixture restart found an interrupted attempt; reconcile before any further action",
                )
                run = self.service.records.get_agent_run(
                    org_id, intent["dispatch_run_id"]
                )
                if run.status == "running":
                    _ = self.service.records.transition_agent_run(
                        org_id,
                        run.run_id,
                        "running",
                        "failed",
                        error="Fixture attempt interrupted; effect outcome unknown",
                    )
                recovered += 1
        return recovered

    def reconcile(self, org_id: str, intent_id: str) -> dict[str, Any]:
        """Read an authoritative fixture receipt, with no simulated redispatch."""
        with self.db.transaction():
            intent = self.service.store.intent(org_id, intent_id)
            proposal, _ = self.service._proposal(org_id, intent["proposal_id"])  # noqa: SLF001
            if intent["state"] != "unknown":
                return self.service.inspect(org_id, intent["proposal_id"])
            try:
                _ = self._ownership(proposal, intent)
            except (ResponseDeniedError, ValueError, KeyError):
                owned = False
            else:
                owned = True
            if owned:
                self._state(
                    org_id,
                    intent_id,
                    "unknown",
                    "acknowledged",
                    "Reconciled owned fixture resource; acknowledgement remains unverified",
                )
            else:
                self.service._event(  # noqa: SLF001
                    org_id,
                    proposal.proposal_id,
                    intent_id,
                    "unknown",
                    "No conclusive matching fixture receipt; ambiguity retained and replay denied",
                )
        return self.service.inspect(org_id, intent["proposal_id"])

    def verify(
        self, org_id: str, intent_id: str, report: VerificationReport
    ) -> dict[str, Any]:
        """Validate independent, canonical persisted observations; fixture-only."""
        report = VerificationReport.model_validate(report.model_dump())
        with self.db.transaction():
            intent = self.service.store.intent(org_id, intent_id)
            proposal, _ = self.service._proposal(org_id, intent["proposal_id"])  # noqa: SLF001
            if intent["state"] not in {
                "acknowledged",
                "verification_failed",
                "fixture_verified",
            }:
                raise ResponseDeniedError(
                    "Verification requires a reconciled acknowledgement"
                )
            resource = self._ownership(proposal, intent)
            if datetime.fromisoformat(resource["expires_at"]) <= self.service._now():  # noqa: SLF001
                raise ResponseDeniedError(
                    "An expired fixture resource cannot establish current verification"
                )
            if (
                report.org_id,
                report.incident_id,
                report.proposal_digest,
                report.dispatch_run_id,
                report.dispatched_at.isoformat(),
            ) != (
                org_id,
                intent["incident_id"],
                intent["proposal_digest"],
                intent["dispatch_run_id"],
                intent["dispatched_at"],
            ):
                raise ResponseDeniedError(
                    "Verification report does not bind the actual dispatch record"
                )
            dispatch = self.service.records.get_agent_run(
                org_id, report.dispatch_run_id
            )
            if (
                dispatch.org_id,
                dispatch.incident_id,
                dispatch.task_id,
                dispatch.agent_id,
            ) != (org_id, proposal.incident_id, proposal.task_id, "response-fixture"):
                raise ResponseDeniedError(
                    "Verification dispatch run does not match the fixture"
                )
            for observation in report.observations:
                self._observation(proposal, intent, observation)
            state = (
                "fixture_verified"
                if report.status == "verified"
                else "verification_failed"
                if report.status == "failed"
                else "acknowledged"
            )
            _ = self.db.execute(
                "UPDATE response_intents SET verification_json=? WHERE org_id=? AND intent_id=?",
                (report.model_dump_json(), org_id, intent_id),
            )
            self._state(
                org_id,
                intent_id,
                intent["state"],
                state,
                "Independent fixture checks recorded; live_verified=false",
            )
        return self.service.inspect(org_id, intent["proposal_id"])

    def _observation(
        self,
        proposal: ResponseProposal,
        intent: dict[str, Any],
        observation: VerificationObservation,
    ) -> None:
        evidence = self.service._evidence(  # noqa: SLF001
            proposal.org_id, proposal.incident_id, observation.evidence.evidence_id
        )
        if (
            observation.evidence.org_id,
            observation.evidence.incident_id,
            observation.evidence.content_hash,
            observation.source_id,
            observation.source_timestamp,
        ) != (
            evidence.org_id,
            evidence.incident_id,
            evidence.content_hash,
            evidence.source,
            evidence.source_timestamp,
        ):
            raise ResponseDeniedError(
                "Verification observation differs from persisted source/hash/timestamp"
            )
        collector = self.service.records.get_agent_run(
            proposal.org_id, observation.collector_run_id
        )
        collector_task = self.service.records.get_task(
            proposal.org_id, collector.task_id
        )
        dispatched_at = datetime.fromisoformat(intent["dispatched_at"])
        if (
            (
                collector.org_id,
                collector.incident_id,
                collector_task.incident_id,
                evidence.task_id,
            )
            != (
                proposal.org_id,
                proposal.incident_id,
                proposal.incident_id,
                collector.task_id,
            )
            or collector.status != "completed"
            or collector_task.status != "completed"
        ):
            raise ResponseDeniedError(
                "Verification collector does not match canonical evidence/task/incident"
            )
        if observation.kind != "provider_ack" and (
            collector_task.role != "verification"
            or collector.run_id == intent["dispatch_run_id"]
            or collector.task_id == proposal.task_id
        ):
            raise ResponseDeniedError(
                "Effect and health observations require an independent verification task/run"
            )
        expiry = dispatched_at + timedelta(seconds=proposal.effect.duration_seconds)
        if (
            evidence.source_timestamp < dispatched_at
            or evidence.collected_at < dispatched_at
            or evidence.source_timestamp > evidence.collected_at
            or collector.started_at is None
            or evidence.source_timestamp >= expiry
            or collector.completed_at is None
            or not collector.started_at
            <= evidence.collected_at
            <= collector.completed_at
        ):
            raise ResponseDeniedError(
                "Verification evidence must be collected after dispatch within the real collector run"
            )
        if not isinstance(evidence.content, dict) or any(
            evidence.content.get(key) != value
            for key, value in {
                "intent_id": intent["intent_id"],
                "proposal_digest": proposal.digest(),
                "kind": observation.kind,
                "passed": observation.passed,
                "fixture_only": True,
            }.items()
        ):
            raise ResponseDeniedError(
                "Recorded fixture evidence does not support the claimed observation"
            )

    def undo(self, org_id: str, intent_id: str, actor_id: str) -> dict[str, Any]:
        """Remove only this intent's owned fixture resource, never an arbitrary rule."""
        with self.db.transaction():
            self.service._member(org_id, actor_id, admin=True)  # noqa: SLF001
            self._remove_owned(org_id, intent_id, expired=False)
        intent = self.service.store.intent(org_id, intent_id)
        return self.service.inspect(org_id, intent["proposal_id"])

    def expire_owned_resources(self, org_id: str) -> int:
        """Apply the originally approved owned-resource expiry to fixtures only."""
        expired = 0
        with self.db.transaction():
            for resource in self.db.fetchall(
                "SELECT * FROM response_owned_resources WHERE org_id=? AND state='owned' LIMIT 100",
                (org_id,),
            ):
                if (
                    datetime.fromisoformat(resource["expires_at"])
                    <= self.service._now()  # noqa: SLF001
                ):
                    self._remove_owned(org_id, resource["intent_id"], expired=True)
                    expired += 1
        return expired

    def _remove_owned(self, org_id: str, intent_id: str, *, expired: bool) -> None:
        intent = self.service.store.intent(org_id, intent_id)
        proposal, _ = self.service._proposal(org_id, intent["proposal_id"])  # noqa: SLF001
        if intent["state"] in {"undone", "expired"}:
            return
        if not expired and intent["state"] not in {
            "acknowledged",
            "verification_failed",
            "fixture_verified",
        }:
            raise ResponseDeniedError(
                "Manual undo requires reconciliation of an ambiguous effect"
            )
        resource = self._ownership(proposal, intent)
        if (
            expired
            and datetime.fromisoformat(resource["expires_at"]) > self.service._now()  # noqa: SLF001
        ):
            raise ResponseDeniedError("Resource has not reached its approved expiry")
        state = "expired" if expired else "undone"
        _ = self.db.execute(
            "UPDATE response_owned_resources SET state=? WHERE org_id=? AND intent_id=? AND state='owned'",
            (state, org_id, intent_id),
        )
        _ = self.db.execute(
            "UPDATE response_fixture_receipts SET state=? WHERE org_id=? AND intent_id=?",
            (state, org_id, intent_id),
        )
        self._state(
            org_id,
            intent_id,
            intent["state"],
            state,
            "Only the originally owned fixture resource was removed; no live undo ran",
        )

    def _ownership(
        self, proposal: ResponseProposal, intent: dict[str, Any]
    ) -> dict[str, Any]:
        resource = self.db.fetchone(
            "SELECT * FROM response_owned_resources WHERE org_id=? AND intent_id=?",
            (proposal.org_id, intent["intent_id"]),
        )
        receipt = self.db.fetchone(
            "SELECT * FROM response_fixture_receipts WHERE org_id=? AND intent_id=?",
            (proposal.org_id, intent["intent_id"]),
        )
        if not resource or not receipt or not intent["dispatched_at"]:
            raise ResponseDeniedError(
                "An authoritative owned fixture resource is required"
            )
        expiry = datetime.fromisoformat(intent["dispatched_at"]) + timedelta(
            seconds=proposal.effect.duration_seconds
        )
        if (
            proposal.effect.undo_strategy != "owned_resource_only"
            or intent["incident_id"] != proposal.incident_id
            or intent["proposal_id"] != proposal.proposal_id
            or resource["state"] != "owned"
            or receipt["state"] != "acknowledged"
            or resource["resource_id"] != receipt["resource_id"]
            or resource["incident_id"] != proposal.incident_id
            or resource["proposal_digest"] != receipt["proposal_digest"]
            or resource["proposal_digest"] != intent["proposal_digest"]
            or resource["proposal_digest"] != proposal.digest()
            or datetime.fromisoformat(resource["expires_at"]) != expiry
        ):
            raise ResponseDeniedError(
                "Only the exact originally owned fixture resource and approved expiry are valid"
            )
        return resource
