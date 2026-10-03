"""Node schemas, types, and registry for TERMINUS 2.0 Workflows.

Defines the exact 8 allowed node types (D1), their strict Pydantic config schemas,
and their valid output handles (D8).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field


class NodeType(StrEnum):
    TRIGGER_WAZUH = "trigger_wazuh"
    CONDITION_SEVERITY = "condition_severity"
    CONDITION_APPROVAL = "condition_approval"
    AGENT_LLM = "agent_llm"
    TOOL_SLACK = "tool_slack"
    TOOL_JIRA = "tool_jira"
    TOOL_ISOLATE = "tool_isolate"
    TOOL_FIREWALL = "tool_firewall"


# ─── Node Config Schemas (Strict extra="forbid") ───────────────────────────────────


class TriggerWazuhConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: int | None = None
    rule_ids: list[int] | None = None
    min_level: int = 0
    location: str | None = None
    mitre: str | None = None
    agent_name_match: str | None = None


class ConditionSeverityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_level: int = 0
    min_verdict_severity: str | None = None  # "low", "medium", "high", "critical"


class ConditionApprovalConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    required_role: str = "admin"
    timeout_seconds: int = 3600
    prompt_message: str = "Please review and approve containment action."


class AgentLlmConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str | None = None
    system_prompt_override: str | None = None
    model: str | None = None


class ToolSlackConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    channel: str = "#soc-alerts"
    message_template: str | None = None


class ToolJiraConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_key: str = "SEC"
    issue_type: str = "Incident"
    summary_template: str | None = None


class ToolIsolateConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_agent_id: str | None = None
    force_override: bool = False
    reason: str | None = None


class ToolFirewallConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str | None = None
    direction: str = "both"  # "inbound", "outbound", "both"
    force_override: bool = False
    reason: str | None = None


TYPE_TO_SCHEMA: dict[str, type[BaseModel]] = {
    NodeType.TRIGGER_WAZUH: TriggerWazuhConfig,
    NodeType.CONDITION_SEVERITY: ConditionSeverityConfig,
    NodeType.CONDITION_APPROVAL: ConditionApprovalConfig,
    NodeType.AGENT_LLM: AgentLlmConfig,
    NodeType.TOOL_SLACK: ToolSlackConfig,
    NodeType.TOOL_JIRA: ToolJiraConfig,
    NodeType.TOOL_ISOLATE: ToolIsolateConfig,
    NodeType.TOOL_FIREWALL: ToolFirewallConfig,
}

VALID_OUTPUT_HANDLES: dict[str, set[str]] = {
    NodeType.TRIGGER_WAZUH: {"default", "on_error"},
    NodeType.CONDITION_SEVERITY: {"true", "false", "on_error"},
    NodeType.CONDITION_APPROVAL: {"true", "false", "on_error"},
    NodeType.AGENT_LLM: {"default", "on_error"},
    NodeType.TOOL_SLACK: {"default", "on_error"},
    NodeType.TOOL_JIRA: {"default", "on_error"},
    NodeType.TOOL_ISOLATE: {"default", "on_error"},
    NodeType.TOOL_FIREWALL: {"default", "on_error"},
}

NODE_REGISTRY_METADATA = [
    {
        "type": NodeType.TRIGGER_WAZUH.value,
        "name": "Wazuh Alert Trigger",
        "category": "trigger",
        "description": "Fires when incoming Wazuh SIEM telemetry matches rule and severity filters.",
        "handles": ["default", "on_error"],
        "default_config": TriggerWazuhConfig().model_dump(),
    },
    {
        "type": NodeType.CONDITION_SEVERITY.value,
        "name": "Severity / Level Gate",
        "category": "condition",
        "description": "Evaluates whether alert level or verdict severity meets configured threshold.",
        "handles": ["true", "false", "on_error"],
        "default_config": ConditionSeverityConfig().model_dump(),
    },
    {
        "type": NodeType.CONDITION_APPROVAL.value,
        "name": "Human Approval Gate",
        "category": "condition",
        "description": "Pauses execution until a human analyst or admin approves containment.",
        "handles": ["true", "false", "on_error"],
        "default_config": ConditionApprovalConfig().model_dump(),
    },
    {
        "type": NodeType.AGENT_LLM.value,
        "name": "ReAct SOC Agent Re-Investigation",
        "category": "agent",
        "description": "Executes secondary ReAct reasoning using a specialized persona agent prompt.",
        "handles": ["default", "on_error"],
        "default_config": AgentLlmConfig().model_dump(),
    },
    {
        "type": NodeType.TOOL_SLACK.value,
        "name": "Slack Alert Notifier",
        "category": "tool",
        "description": "Dispatches threat notification card to a dedicated Slack channel.",
        "handles": ["default", "on_error"],
        "default_config": ToolSlackConfig().model_dump(),
    },
    {
        "type": NodeType.TOOL_JIRA.value,
        "name": "Jira Incident Ticket",
        "category": "tool",
        "description": "Opens or updates a security incident ticket in Jira.",
        "handles": ["default", "on_error"],
        "default_config": ToolJiraConfig().model_dump(),
    },
    {
        "type": NodeType.TOOL_ISOLATE.value,
        "name": "Active Host Containment (Isolate)",
        "category": "tool",
        "description": "Isolates the compromised endpoint via Wazuh Active Response.",
        "handles": ["default", "on_error"],
        "default_config": ToolIsolateConfig().model_dump(),
    },
    {
        "type": NodeType.TOOL_FIREWALL.value,
        "name": "Firewall IP Block",
        "category": "tool",
        "description": "Blocks attacker IP on border firewalls / host-level packet filter.",
        "handles": ["default", "on_error"],
        "default_config": ToolFirewallConfig().model_dump(),
    },
]
