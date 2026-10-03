"""Interactive Incident Analyst Copilot Endpoint for TERMINUS 2.0.

Enables human SOC analysts to query incident context, run on-demand forensics,
and interrogate the autonomous agent regarding root cause and mitigation strategies.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from terminus.core.ids import OrgId
from terminus.llm.base import LlmClient
from terminus.llm.client import OpenAiCompatibleLlm
from terminus.server.copilot_tools import IncidentTools, TOOL_SCHEMAS
from terminus.server.deps import get_current_org, get_llm_client, get_pipeline_runner

copilot_router = APIRouter(prefix="/incidents", tags=["Analyst Copilot"])
logger = logging.getLogger("terminus.server.copilot")


class CopilotChatRequest(BaseModel):
    prompt: str = Field(min_length=1)


class CopilotChatResponse(BaseModel):
    ticket_id: str
    response: str
    tools_consulted: list[str] = Field(default_factory=list)


@copilot_router.post("/{ticket_id}/chat")
async def chat_with_incident_copilot(
    ticket_id: str,
    req: CopilotChatRequest,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    runner: Annotated[Any, Depends(get_pipeline_runner)],
    llm: Annotated[LlmClient, Depends(get_llm_client)],
) -> CopilotChatResponse:
    """Interactively interrogate the AI SOC Copilot regarding a specific incident."""
    ticket = await runner.deployment.ticket_store.get_ticket(ticket_id, org_id)
    if not ticket:
        raise HTTPException(status_code=404, detail="Incident not found")

    system_prompt = (
        "You are the Terminus Senior Forensic Copilot. An analyst is reviewing an active security ticket "
        "and asking follow-up questions. Answer using only the incident data provided. "
        "If evidence is missing, say so. Do not claim an action was executed."
    )

    from terminus.privacy.redactor import SecretRedactor
    from terminus.privacy.sanitizer import PromptInjectionSanitizer

    raw_log = str(ticket.get("full_log") or "")
    sanitized_log = PromptInjectionSanitizer.wrap_untrusted_data(
        "untrusted_incident_log", SecretRedactor.redact(raw_log)
    )

    user_prompt = f"""INCIDENT CONTEXT:
- Ticket ID: {ticket.get('id')}
- Summary: {ticket.get('summary')}
- Target Host: {ticket.get('agent_name')}
- Severity: {ticket.get('severity')}
- Evidence: {ticket.get('threat_intel')}
- Full Log:
{sanitized_log}

ANALYST QUESTION: {req.prompt}

Provide a direct, authoritative forensic response:"""

    consulted = ["Incident record"]
    try:
        if isinstance(llm, OpenAiCompatibleLlm):
            incident_tools = IncidentTools(runner.deployment.ticket_store, org_id)
            res_text, consulted = await llm.chat_with_tools(system_prompt, user_prompt, TOOL_SCHEMAS, incident_tools.execute)
        else:
            raw_res = await llm.respond_json(system_prompt, user_prompt)
            res_text = str(raw_res.get("summary") or raw_res.get("response") or raw_res.get("message") or "No answer returned.")
    except Exception as exc:
        logger.warning("Incident copilot model request failed: %s", exc)
        res_text = (
            "The model is unavailable. Here is the recorded incident context:\n"
            f"- Incident: {ticket.get('id')} — {ticket.get('rule_description') or 'Unclassified alert'}\n"
            f"- Host: {ticket.get('agent_name') or 'Unknown'}\n"
            f"- Assessment: {ticket.get('summary') or 'No assessment recorded.'}\n"
            f"- Raw event: {(ticket.get('full_log') or 'No raw event attached.')[:600]}\n"
            "Review the raw event before taking action."
        )

    return CopilotChatResponse(
        ticket_id=ticket_id,
        response=res_text,
        tools_consulted=consulted,
    )


global_copilot_router = APIRouter(prefix="/copilot", tags=["Global AI Copilot"])


class GlobalChatRequest(BaseModel):
    prompt: str = Field(min_length=1)
    ticket_id: str | None = None


class GlobalChatResponse(BaseModel):
    response: str
    tools_consulted: list[str] = Field(default_factory=list)
    suggested_actions: list[str] = Field(default_factory=list)


@global_copilot_router.post("/chat")
async def chat_with_global_copilot(
    req: GlobalChatRequest,
    org_id: Annotated[OrgId, Depends(get_current_org)],
    runner: Annotated[Any, Depends(get_pipeline_runner)],
    llm: Annotated[LlmClient, Depends(get_llm_client)],
) -> GlobalChatResponse:
    """ChatGPT-style conversational AI assistant for SOC analysts across the organization."""
    tickets = await runner.deployment.ticket_store.list_tickets(org_id)
    open_tickets = [t for t in tickets if t.get("status") != "RESOLVED"]
    critical_tickets = [t for t in open_tickets if t.get("severity") == "critical"]

    context_str = f"""CURRENT SOC ENVIRONMENT OVERVIEW:
- Organization ID: {org_id}
- Open Incidents: {len(open_tickets)}
- Critical Incidents: {len(critical_tickets)}
- Recent Incidents: {', '.join(t.get('rule_description', 'Incident') for t in open_tickets[:5]) or 'No active incidents.'}
"""

    if req.ticket_id:
        target_ticket = await runner.deployment.ticket_store.get_ticket(req.ticket_id, org_id)
        if target_ticket:
            context_str += f"""\nFOCUSED INCIDENT ({req.ticket_id}):
- Description: {target_ticket.get('rule_description')}
- Target Host: {target_ticket.get('agent_name')}
- Severity: {target_ticket.get('severity')}
- Summary: {target_ticket.get('summary')}
- Evidence: {target_ticket.get('threat_intel')}
- Full Log: {target_ticket.get('full_log')}
"""

    system_prompt = (
        "You are the TERMINUS AI SOC Copilot, the embedded expert AI assistant for the Terminus Security Operations Platform.\n\n"
        "PLATFORM CAPABILITIES & ARCHITECTURE KNOWLEDGE:\n"
        "• TERMINUS is an enterprise multi-tenant AI Security Operations Center (SOC) platform built on top of Wazuh SIEM.\n"
        "• Deterministic Policy Triage Engine: Evaluates every incoming alert in sub-milliseconds before calling LLMs using deterministic rules:\n"
        "  - IGNORE (Level < 5): Low-priority noise is suppressed with zero LLM token cost.\n"
        "  - TRIAGE (Level 5–9): Alert is recorded as an incident ticket and sent to autonomous AI investigation agents.\n"
        "  - ESCALATE (Level >= 10 or recognizable MITRE ATT&CK technique): High-priority security incident triggering immediate investigation and containment workflows.\n"
        "• Autonomous Investigation Agents: Reason over alert telemetry, extract IOCs, assign severity (critical/high/medium/low), assess confidence, map MITRE ATT&CK techniques, and suggest response steps.\n"
        "• Attack Relationship Topology: Interactive 7-day canvas correlating attacker source IPs, victim hosts, and MITRE techniques across multi-host attack clusters.\n"
        "• Visual DAG Automation Workflows: Drag-and-drop pipelines connecting triggers (Wazuh webhook, cron), conditions (severity filters), investigation agents, and output/containment actions (Slack notifications, Jira ticketing, firewall drops).\n"
        "• Incident Command Workbench: Unified triage center for reviewing alert evidence, inspecting raw JSON logs, analyzing threat intel, and recording verified resolutions (True positive, False positive, Benign activity, Inconclusive) with analyst notes.\n"
        "• Multi-Tenant SaaS & RBAC: Organization isolation keyed by OrgId with ADMIN, MEMBER, and VIEWER roles, plus HMAC-signed cryptographic licensing.\n"
        "• SOAR Active Containment Guardrails: Multi-domain containment (border firewall IP blocks, host network isolation, IAM credential revocation) with blast radius checks.\n"
        "• Decoy Services: Built-in honeypot and banking simulation services generating synthetic canary tripwire alerts.\n\n"
        "INSTRUCTIONS FOR ANSWERING:\n"
        "1. Platform / Architectural Questions: When asked about Terminus, what it can do, how the deterministic policy triage engine works, how to create workflows, how to configure agents, or how to triage incidents, answer directly and thoroughly using the platform knowledge above. Do NOT search incident records for platform concepts.\n"
        "2. Telemetry / Incident Questions: When asked about active security incidents, queue workload, attack campaigns, specific IP addresses, or victim hosts, use the provided incident tools (list_incidents, get_incident, search_incidents, correlate_sources) to fetch and cite live evidence.\n"
        "3. Answer in concise, professional plain text with short markdown bullets. Do not use Markdown tables. Preserve exact incident IDs and IP addresses."
    )

    user_prompt = f"Analyst question: {req.prompt}\nFocused incident ID: {req.ticket_id or 'none'}"

    consulted = ["Incident records"]
    try:
        if isinstance(llm, OpenAiCompatibleLlm):
            incident_tools = IncidentTools(runner.deployment.ticket_store, org_id)
            res_text, consulted = await llm.chat_with_tools(system_prompt, user_prompt, TOOL_SCHEMAS, incident_tools.execute)
        else:
            raw_res = await llm.respond_json(system_prompt, context_str + "\nAnalyst question: " + req.prompt)
            res_text = str(raw_res.get("summary") or raw_res.get("response") or raw_res.get("message") or "No answer returned.")
    except Exception as exc:
        logger.warning("Global copilot model request failed: %s", exc)
        prompt_upper = req.prompt.upper()
        if "POLICY" in prompt_upper or "TRIAGE" in prompt_upper:
            res_text = (
                "Terminus Deterministic Policy Triage Engine:\n"
                "• IGNORE (Level < 5): Suppresses low-level benign noise with 0 LLM token cost.\n"
                "• TRIAGE (Level 5–9): Evaluated by autonomous AI investigation agents and logged to the incident queue.\n"
                "• ESCALATE (Level >= 10 or recognizable MITRE technique): Immediate high-priority security incident triggering containment workflows."
            )
        elif "WORKFLOW" in prompt_upper or "DAG" in prompt_upper or "AUTOMATION" in prompt_upper:
            res_text = (
                "Terminus Visual DAG Workflows:\n"
                "• Triggers: Wazuh alert webhook ingestion, scheduled cron triggers.\n"
                "• Conditions: Severity filters, threshold comparisons.\n"
                "• Agents: Routing alerts to specialized autonomous investigation agents.\n"
                "• Containment & Outputs: Automated Slack alerts, Jira ticketing, and border firewall drops."
            )
        elif "TERMINUS" in prompt_upper or "WHAT CAN" in prompt_upper or "CAPABILITIES" in prompt_upper:
            res_text = (
                "TERMINUS is an enterprise AI SOC Platform built on top of Wazuh SIEM:\n"
                "• Deterministic Policy Engine: Sub-millisecond triage of incoming alerts.\n"
                "• Autonomous Investigation Agents: Deep LLM forensic reasoning and MITRE ATT&CK mapping.\n"
                "• Attack Relationship Topology: 7-day interactive canvas correlating adversary IPs, victim hosts, and techniques.\n"
                "• Incident Command Center: Unified triage workspace for evidence inspection and verified containment.\n"
                "• Multi-Tenant SaaS: Tenant isolation keyed by OrgId with RBAC and cryptographic licensing."
            )
        else:
            ordered = sorted(open_tickets, key=lambda t: (
                {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(t.get("severity"), 4),
                str(t.get("created_at") or t.get("timestamp") or ""),
            ))
            lines = [
                "Here is the current recorded workload for this organization:",
                f"- Active incidents: {len(open_tickets)} ({len(critical_tickets)} critical)",
            ]
            for ticket in ordered[:5]:
                lines.append(
                    f"- {ticket.get('id')}: {ticket.get('rule_description') or 'Unclassified alert'} "
                    f"on {ticket.get('agent_name') or 'Unknown host'} "
                    f"({ticket.get('severity') or 'unknown'}, {ticket.get('status') or 'unknown'})"
                )
            if req.ticket_id:
                lines.append(f"Focused incident: {req.ticket_id}")
                lines.append(f"Assessment: {target_ticket.get('summary') or 'No assessment recorded.'}")
                lines.append(f"Raw event: {(target_ticket.get('full_log') or 'No raw event attached.')[:600]}")
            elif not open_tickets:
                lines.append("No active incident evidence is recorded in this organization.")
            res_text = "\n".join(lines)

    return GlobalChatResponse(
        response=res_text,
        tools_consulted=consulted,
        suggested_actions=[],
    )
