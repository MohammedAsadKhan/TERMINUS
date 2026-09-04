"""Offline simulation runner for Terminus.

Runs the complete pipeline end-to-end against a sample Wazuh alert using
in-memory stores and deterministic scripted LLM responses. Zero network required.
"""

from __future__ import annotations

import json
from pathlib import Path

import anyio

from terminus.agent.investigator import InvestigationAgent
from terminus.agent.tools import InvestigationTools
from terminus.core.ids import OrgId
from terminus.llm.client import ScriptedLlm
from terminus.models import SiemAlert
from terminus.notifiers.log import LogNotifier
from terminus.pipeline.deployment import PipelineDeployment
from terminus.pipeline.runner import PipelineRunner
from terminus.policies.engine import PolicyEngine
from terminus.siem.static import StaticSiemClient
from terminus.ticketing.memory import MemoryTickets


async def run_simulation(sample_path: Path | None = None) -> None:
    """Execute offline simulation run with sample alert."""
    if sample_path is None:
        sample_path = Path(__file__).parent.parent.parent / "data" / "sample_alert.json"

    with sample_path.open("r", encoding="utf-8") as f:
        raw_alert = json.load(f)

    alert = SiemAlert.model_validate(raw_alert)

    llm = ScriptedLlm()
    siem = StaticSiemClient({alert.id: alert})
    tools = InvestigationTools(siem)
    agent = InvestigationAgent(llm, tools)
    policy_engine = PolicyEngine()
    ticket_store = MemoryTickets()
    notifier = LogNotifier()

    deployment = PipelineDeployment(
        policy_engine=policy_engine,
        agent=agent,
        notifier=notifier,
        ticket_store=ticket_store,
    )

    runner = PipelineRunner(deployment)
    org_id = OrgId("org_simulated")

    print("=== Starting Terminus Offline Simulation ===")
    print(
        f"Ingesting Alert ID: {alert.id} | Rule: {alert.rule_id} | Level: {alert.level}"
    )

    report = await runner.process_alert(alert, org_id)

    print("\n=== Investigation Completed ===")
    print(f"Severity: {report.verdict.severity.value.upper()}")
    print(f"Confidence: {report.verdict.confidence.value}")
    print(f"Summary: {report.verdict.summary}")
    print(f"Recommended Actions: {', '.join(report.verdict.recommended_actions)}")
    print(
        f"Evidence Items: Agent={report.evidence.agent_name}, TI={report.evidence.threat_intel}"
    )
    print("==========================================")


def main() -> None:
    """Entry point for terminus-simulate script."""
    anyio.run(run_simulation)


if __name__ == "__main__":
    main()
