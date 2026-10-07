"""Explicit local admin request for a new read-only triage attempt."""
# ruff: noqa: INP001 -- trusted local deployment command

import argparse
from uuid import uuid4

from terminus.core.ids import OrgId, UserId
from terminus.orchestration.coordination import CoordinationService
from terminus.orgs.models import OrganizationRole
from terminus.orgs.storage import SqliteMembershipStore
from terminus.storage.db import Database
from terminus.toolkit.context import ToolReadPolicyStore


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("database", "org", "actor", "incident"):
        _ = parser.add_argument("--" + key, required=True)
    args = parser.parse_args()
    db = Database(args.database)
    try:
        if (
            SqliteMembershipStore(db).role_of(OrgId(args.org), UserId(args.actor))
            != OrganizationRole.ADMIN
        ):
            raise ValueError("Current organization administrator required")
        _ = ToolReadPolicyStore(db).get_policy(args.org, args.incident)
        service = CoordinationService(db)
        parents = [
            task
            for task in service.records.list_tasks(args.org, incident_id=args.incident)
            if task.role == "area_orchestrator" and task.area == "alert_handling"
        ]
        if len(parents) != 1:
            raise ValueError("Expected existing alert-handling coordinator")
        task = service.records.create_incident_task(
            args.org,
            args.incident,
            "alert_handling",
            "triage",
            "Recollect bounded authentication evidence; models and response actions disabled by lab worker.",
            parent_task_id=parents[0].task_id,
            idempotency_key="lab-read-retry:" + str(uuid4()),
        )
        _ = service.scheduler.enqueue_task(args.org, task.task_id)
        print("Queued triage task: " + task.task_id)
    finally:
        db.close()


if __name__ == "__main__":
    main()
