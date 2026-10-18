"""Save an evidence-backed review plan; never approve or execute a response."""
# ruff: noqa: INP001
import argparse
import json

from terminus.core.ids import OrgId, UserId
from terminus.orchestration.storage import OrchestrationStore
from terminus.orgs.models import OrganizationRole
from terminus.orgs.storage import SqliteMembershipStore
from terminus.response.lab_plan import build_lab_response_plan
from terminus.storage.db import Database


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "org", "actor", "incident", "source-task"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    db = Database(args.database)
    try:
        if SqliteMembershipStore(db).role_of(OrgId(args.org), UserId(args.actor)) != OrganizationRole.ADMIN:
            raise ValueError("Current organization administrator required")
        store = OrchestrationStore(db)
        source = store.get_task(args.org, args.source_task)
        if source.incident_id != args.incident:
            raise ValueError("Source task must belong to this incident")
        records = store.list_evidence(args.org, task_id=args.source_task)
        plan = build_lab_response_plan(records, args.incident)
        record = store.create_evidence(args.org, source.task_id, "terminus-lab-response-review", source.created_at, content=plan)
        print("Saved review plan evidence: " + record.evidence_id)
        print(json.dumps(plan, indent=2))
    finally:
        db.close()


if __name__ == "__main__":
    main()
