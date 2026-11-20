# File name: analyze_wazuh_lab_evidence.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Run one approved Gemini triage turn over saved lab evidence, without response tools.

"""Run one approved Gemini triage turn over saved lab evidence, without response tools."""
# ruff: noqa: INP001

import argparse
import asyncio
import json
import os
from dataclasses import replace
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from terminus.core.ids import OrgId, UserId
from terminus.model_gateway.fixture_client import FixtureModelClient
from terminus.model_gateway.ledger import ModelBudgetStore, window_key_for
from terminus.model_gateway.live import ProductionModelTransport
from terminus.model_gateway.models import ModelConnectionView
from terminus.model_gateway.policy import ModelPolicyStore, ModelPolicyWrite
from terminus.orchestration.coordination import CoordinationService
from terminus.orchestration.scheduler import SchedulerRuntime
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.orchestration.specialists.deploy import build_deployment_deps
from terminus.orchestration.specialists.runtime import make_saved_evidence_handler
from terminus.orgs.models import OrganizationRole
from terminus.orgs.storage import SqliteMembershipStore
from terminus.storage.db import Database


class LocalSecrets(BaseSettings):
    """Read the local model-credentials key from ``.env`` so it is never a CLI argument."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    terminus_model_credentials_key: SecretStr


async def run(args: argparse.Namespace) -> None:  # noqa: C901, PLR0912, PLR0915 -- ordered local admission and lifecycle
    """Check admission, then run one triage task over saved evidence and print its result.

    Every admission check runs before any state change or model call, so a failed check
    leaves the database untouched. ``--check`` stops after the read-only checks.
    """
    db = Database(args.database)
    runtime = None
    runner = None
    try:
        # Authorization first: only a current organization administrator may start a
        # lab model run, before any evidence is read.
        if (
            SqliteMembershipStore(db).role_of(OrgId(args.org), UserId(args.actor))
            != OrganizationRole.ADMIN
        ):
            raise ValueError("Current organization administrator required")
        service = CoordinationService(db)
        # Bound the input to one incident's saved records so the model never sees
        # evidence from another incident or an unbounded set.
        records = service.records.list_evidence(args.org, task_id=args.source_task)
        if (
            not records
            or len(records) > 16
            or any(r.incident_id != args.incident for r in records)
        ):
            raise ValueError("Select one to sixteen saved records from this incident")
        # Coverage embeds the same alerts. Preserve its warning in the result,
        # rather than sending a second copy of the observations to the model.
        records = [
            record
            for record in records
            if not isinstance(record.content, dict)
            or record.content.get("tool_id") != "collection.coverage"
        ]
        if not records:
            raise ValueError(
                "No investigation evidence remains after removing duplicated coverage"
            )
        # Require the single approved zero-price Gemini Flash Lite triage route; any other
        # grant or a non-zero price is refused so the lab cannot incur spend.
        policy_store = ModelPolicyStore(db)
        policy = policy_store.get(args.org, args.actor)
        grants = [g for g in policy.grants if g.role == "triage"]
        if (
            not policy.enabled
            or len(grants) != 1
            or grants[0].models != ("gemini-3.5-flash-lite",)
        ):
            raise ValueError(
                "Exactly one enabled Gemini Flash Lite triage grant required"
            )
        price = ModelBudgetStore(db).get_price(
            args.org, args.actor, grants[0].connection_id, grants[0].models[0]
        )
        if price.input_per_mtok_micro_usd != 0 or price.output_per_mtok_micro_usd != 0:
            raise ValueError("Lab run requires the configured zero-price route")
        # Readiness mode exits here, before any classification change or API call.
        if args.check:
            print(
                f"Ready: {len(records)} saved evidence records; exact triage grant configured. No model call made."
            )
            return
        # An unexpired scheduler lease means another worker owns the queue; refuse
        # rather than run two coordinators against the same database.
        coordinator = db.fetchone(
            "SELECT lease_expires_at FROM orchestration_scheduler_coordinator WHERE singleton=1"
        )
        if coordinator and datetime.fromisoformat(
            coordinator["lease_expires_at"]
        ) > datetime.now(UTC):
            raise ValueError(
                "Stop the existing lab worker with Ctrl+C, then rerun this command"
            )
        # The new triage task must hang under the incident's existing alert-handling
        # coordinator so it appears in the same task tree.
        parents = [
            t
            for t in service.records.list_tasks(args.org, incident_id=args.incident)
            if t.role == "area_orchestrator" and t.area == "alert_handling"
        ]
        if len(parents) != 1:
            raise ValueError("Expected existing alert-handling coordinator")
        # Deployment settings are passed through a copied environment, not process-wide
        # state; the credentials key comes from the local ``.env`` file.
        env = os.environ.copy()
        env.update(
            {
                "TERMINUS_SPECIALIST_DATABASE": args.database,
                "TERMINUS_SPECIALIST_ACTOR_USER_ID": args.actor,
                "TERMINUS_SPECIALIST_LIVE_MODELS": "true",
                "TERMINUS_SPECIALIST_MODEL_EVIDENCE_BYTES": str(args.evidence_limit_bytes),
                "TERMINUS_MODEL_CREDENTIALS_KEY": LocalSecrets().terminus_model_credentials_key.get_secret_value(),
            }
        )
        deps = build_deployment_deps(env)
        original_factory = deps.client_for
        if original_factory is None:
            raise ValueError("Live model transport is unavailable")

        def diagnostic_client(
            connection: ModelConnectionView,
        ) -> FixtureModelClient | ProductionModelTransport | None:
            """Wrap the deployment client factory to apply a 75 second live-call timeout."""
            client = original_factory(connection)
            if isinstance(client, ProductionModelTransport):
                client.timeout_seconds = 75
            return client

        deps = replace(deps, client_for=diagnostic_client)
        # The lab budget must already be zero dollars. A new window copies the previous
        # token limit and never raises the dollar limit.
        window = window_key_for(datetime.now(UTC))
        budgets = ModelBudgetStore(db)
        if (
            db.fetchone(
                "SELECT 1 FROM model_budgets WHERE org_id=? AND window_key=?",
                (args.org, window),
            )
            is None
        ):
            previous = db.fetchone(
                "SELECT limit_micro_usd, limit_tokens FROM model_budgets WHERE org_id=? ORDER BY window_key DESC LIMIT 1",
                (args.org,),
            )
            if previous is None or previous["limit_micro_usd"] != 0:
                raise ValueError("An existing zero-dollar lab budget is required")
            budgets.put_budget(
                args.org,
                args.actor,
                window,
                limit_micro_usd=0,
                limit_tokens=previous["limit_tokens"],
            )
        # Only redacted evidence may leave for the cloud route: grant that
        # classification to the model and mark each selected record with it.
        grant = grants[0]
        if "redacted_cloud" not in grant.classifications:
            updated = grant.model_copy(
                update={"classifications": (*grant.classifications, "redacted_cloud")}
            )
            policy_store.put(
                args.org,
                args.actor,
                ModelPolicyWrite(
                    expected_version=policy.version,
                    grants=tuple(updated if g == grant else g for g in policy.grants),
                    enabled=policy.enabled,
                ),
            )
        for record in records:
            existing = policy_store.get_classification(
                args.org, args.actor, record.evidence_id
            )
            policy_store.classify_evidence(
                args.org,
                args.actor,
                record.evidence_id,
                "redacted_cloud",
                expected_version=existing.version if existing else 0,
            )
        # A random idempotency key makes every run a new task rather than a replay.
        task = service.records.create_incident_task(
            args.org,
            args.incident,
            "alert_handling",
            "triage",
            "Analyze saved historical source evidence with approved Gemini; no response actions.",
            parent_task_id=parents[0].task_id,
            idempotency_key="lab-gemini:" + str(uuid4()),
        )
        handler = make_saved_evidence_handler(
            deps, args.org, args.incident, tuple(r.evidence_id for r in records)
        )
        # A dedicated runtime owns the scheduler; admission still fences every call.
        runtime = SchedulerRuntime(
            SchedulerStore(Database(args.database)),
            {"triage": handler},
            worker_count=1,
            run_timeout_seconds=90,
        )
        runner = asyncio.create_task(runtime.run())
        # Give the scheduler a moment to start; if it already exited, surface its error.
        await asyncio.sleep(0.2)
        if runner.done():
            await runner
        _ = service.scheduler.enqueue_task(args.org, task.task_id)
        print("Gemini analysis task: " + task.task_id, flush=True)
        # Poll the durable task tree for up to about two minutes. A run error is raised
        # as a failure instead of being retried, and a timeout is reported as unknown
        # so the operator inspects the durable run first.
        for _ in range(240):
            tree = service.get_incident_tree(args.org, args.incident)
            nodes = list(tree["roots"])
            while nodes:
                node = nodes.pop()
                nodes.extend(node.get("children", []))
                if node["task_id"] == task.task_id:
                    for attempt in node.get("runs", []):
                        if attempt.get("result"):
                            print(json.dumps(attempt["result"], indent=2))
                            return
                        if attempt.get("error"):
                            raise ValueError(
                                "Analysis task failed; inspect its durable run before retrying"
                            )
            if runner.done():
                await runner
            await asyncio.sleep(0.5)
        raise ValueError(
            "Analysis did not produce a result within the bounded wait; inspect task before retrying"
        )
    finally:
        # Always stop the scheduler and wait for it before closing the database.
        if runtime:
            runtime.request_stop()
        if runner:
            await runner
        db.close()


def main() -> None:
    """Parse arguments, run the analysis, and exit with the error text on a refusal."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "org", "actor", "incident", "source-task"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument(
        "--evidence-limit-bytes", type=int, default=65536,
        help="Redacted model evidence bound for this lab run (default: 64 KiB)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Read-only readiness check; no classification changes or API calls",
    )
    try:
        asyncio.run(run(parser.parse_args()))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
