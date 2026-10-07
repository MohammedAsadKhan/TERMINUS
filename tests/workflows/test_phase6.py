"""Phase 6 Test Suite: Copilot Tools & System Prompt.

Covers T-COP-1 through T-COP-9:
- T-COP-1: Agent creation and limits validation (D23)
- T-COP-2: Rejection of agents violating limits (D23)
- T-COP-3: Workflow creation defaults to draft mode enabled=False (D22)
- T-COP-4: Auto-layout computation for workflow node placement
- T-COP-5: Enforces force_override=False for Copilot-created nodes (D12)
- T-COP-6: Optimistic concurrency control with expected_version (D18)
- T-COP-7: Structural update of enabled workflow forces enabled=False (D13, D22)
- T-COP-8: Rename-only update of enabled workflow preserves enabled=True (D13)
- T-COP-9: Dry-run test execution does not persist or execute live actions (D17)
"""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock

from terminus.models import Workflow, WorkflowEdge, WorkflowNode
from terminus.server.copilot_tools import IncidentTools, compute_full_layout
from terminus.storage.db import Database
from terminus.storage.repositories import SqliteWorkflowRepository


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_phase6.db"
    db = Database(str(db_file))
    Database._instance = db
    return db


@pytest.fixture
def mock_ticket_store():
    store = MagicMock()
    store.list_tickets = AsyncMock(return_value=[])
    store.get_ticket = AsyncMock(return_value={})
    return store


@pytest.mark.anyio
async def test_t_cop_1_create_soc_agent(temp_db, mock_ticket_store):
    """T-COP-1: Copilot tool creates valid agent within limits."""
    tools = IncidentTools(store=mock_ticket_store, org_id="org-copilot", db=temp_db, actor_role="admin")

    res = await tools.execute(
        "create_soc_agent",
        {
            "name": "Malware Analyst",
            "role_description": "Analyzes binary attachments and PE headers.",
            "master_prompt": "You are a specialized reverse engineering AI agent.",
        },
    )

    assert res.get("success") is True
    agent = res["agent"]
    assert agent["name"] == "Malware Analyst"
    assert agent["status"] == "active"


@pytest.mark.anyio
async def test_t_cop_2_agent_limits_enforced(temp_db, mock_ticket_store):
    """T-COP-2: Rejects agent creation when name, role, or prompt exceeds limits (D23)."""
    tools = IncidentTools(store=mock_ticket_store, org_id="org-copilot", db=temp_db, actor_role="admin")

    # Name too long (>80)
    res_name = await tools.execute(
        "create_soc_agent",
        {
            "name": "A" * 81,
            "role_description": "Valid role",
            "master_prompt": "Valid prompt",
        },
    )
    assert "error" in res_name

    # Role too long (>500)
    res_role = await tools.execute(
        "create_soc_agent",
        {
            "name": "Valid Name",
            "role_description": "B" * 501,
            "master_prompt": "Valid prompt",
        },
    )
    assert "error" in res_role

    # Prompt too long (>4000)
    res_prompt = await tools.execute(
        "create_soc_agent",
        {
            "name": "Valid Name",
            "role_description": "Valid role",
            "master_prompt": "C" * 4001,
        },
    )
    assert "error" in res_prompt


@pytest.mark.anyio
async def test_t_cop_3_create_workflow_defaults_to_draft(temp_db, mock_ticket_store):
    """T-COP-3: Workflows created via Copilot always have enabled=False (D22)."""
    tools = IncidentTools(store=mock_ticket_store, org_id="org-copilot", db=temp_db, actor_role="admin")

    nodes = [
        {"id": "n1", "type": "trigger_wazuh", "config": {"min_level": 5}},
        {"id": "n2", "type": "tool_slack", "config": {"channel": "#alerts"}},
    ]
    edges = [
        {"id": "e1", "source": "n1", "target": "n2", "source_handle": "default"},
    ]

    res = await tools.execute(
        "create_workflow",
        {
            "name": "Slack Alert Playbook",
            "nodes": nodes,
            "edges": edges,
        },
    )

    assert res.get("success") is True
    wf = res["workflow"]
    assert wf["enabled"] is False
    assert wf["version"] == 1


@pytest.mark.anyio
async def test_t_cop_4_auto_layout_computation():
    """T-COP-4: Auto-layout computes coordinates for DAG nodes."""
    nodes = [
        {"id": "n1", "type": "trigger_wazuh", "config": {}},
        {"id": "n2", "type": "condition_severity", "config": {"min_level": 10}},
        {"id": "n3", "type": "tool_slack", "config": {"channel": "#alerts"}},
    ]
    edges = [
        {"id": "e1", "source": "n1", "target": "n2", "source_handle": "default"},
        {"id": "e2", "source": "n2", "target": "n3", "source_handle": "true"},
    ]

    layout_nodes = compute_full_layout(nodes, edges)
    n1 = next(n for n in layout_nodes if n["id"] == "n1")
    n2 = next(n for n in layout_nodes if n["id"] == "n2")
    n3 = next(n for n in layout_nodes if n["id"] == "n3")

    # Layer progression: n1 (root, x=50) -> n2 (x=300) -> n3 (x=550)
    assert n1["x"] < n2["x"] < n3["x"]


@pytest.mark.anyio
async def test_t_cop_5_copilot_cannot_set_force_override(temp_db, mock_ticket_store):
    """T-COP-5: Copilot creation discards force_override=True to False (D12)."""
    tools = IncidentTools(store=mock_ticket_store, org_id="org-copilot", db=temp_db, actor_role="admin")

    nodes = [
        {"id": "n1", "type": "trigger_wazuh", "config": {}},
        {"id": "n2", "type": "condition_approval", "config": {}},
        {"id": "n3", "type": "tool_isolate", "config": {"force_override": True}},  # Attempted force_override
    ]
    edges = [
        {"id": "e1", "source": "n1", "target": "n2", "source_handle": "default"},
        {"id": "e2", "source": "n2", "target": "n3", "source_handle": "true"},
    ]

    res = await tools.execute(
        "create_workflow",
        {
            "name": "Containment Playbook",
            "nodes": nodes,
            "edges": edges,
        },
    )

    assert res.get("success") is True
    isolate_node = next(n for n in res["workflow"]["nodes"] if n["id"] == "n3")
    assert isolate_node["config"]["force_override"] is False
    assert "override_note" in res


@pytest.mark.anyio
async def test_t_cop_6_optimistic_concurrency_expected_version(temp_db, mock_ticket_store):
    """T-COP-6: Updating workflow with wrong expected_version returns conflict (D18)."""
    tools = IncidentTools(store=mock_ticket_store, org_id="org-copilot", db=temp_db, actor_role="admin")
    wf_repo = SqliteWorkflowRepository(temp_db)

    wf = Workflow(
        id="wf-ver-1",
        name="Versioned Playbook",
        version=3,
        nodes=[WorkflowNode(id="n1", type="trigger_wazuh", config={})],
        edges=[],
    )
    wf_repo.save_workflow("org-copilot", wf)

    # Update with wrong expected_version (2 instead of 3)
    res = await tools.execute(
        "update_workflow",
        {
            "workflow_id": "wf-ver-1",
            "expected_version": 2,
            "name": "Updated Name",
        },
    )

    assert "error" in res
    assert "Version conflict" in res["error"]


@pytest.mark.anyio
async def test_t_cop_7_structural_update_forces_disabled(temp_db, mock_ticket_store):
    """T-COP-7: Structural update of enabled workflow forces enabled=False (D13, D22)."""
    tools = IncidentTools(store=mock_ticket_store, org_id="org-copilot", db=temp_db, actor_role="admin")
    wf_repo = SqliteWorkflowRepository(temp_db)

    wf = Workflow(
        id="wf-struct-1",
        name="Active Playbook",
        enabled=True,
        version=1,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={}),
            WorkflowNode(id="n2", type="tool_slack", config={"channel": "#soc"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )
    wf_repo.save_workflow("org-copilot", wf)

    # Add a new node (structural change)
    updated_nodes = [
        {"id": "n1", "type": "trigger_wazuh", "config": {}},
        {"id": "n2", "type": "tool_slack", "config": {"channel": "#soc"}},
        {"id": "n3", "type": "tool_jira", "config": {"project_key": "SEC"}},
    ]
    updated_edges = [
        {"id": "e1", "source": "n1", "target": "n2", "source_handle": "default"},
        {"id": "e2", "source": "n2", "target": "n3", "source_handle": "default"},
    ]

    res = await tools.execute(
        "update_workflow",
        {
            "workflow_id": "wf-struct-1",
            "expected_version": 1,
            "nodes": updated_nodes,
            "edges": updated_edges,
        },
    )

    assert res.get("success") is True
    assert res["workflow"]["enabled"] is False
    assert res["workflow"]["version"] == 2


@pytest.mark.anyio
async def test_t_cop_8_rename_preserves_enabled_status(temp_db, mock_ticket_store):
    """T-COP-8: Rename-only update of enabled workflow preserves enabled=True (D13)."""
    tools = IncidentTools(store=mock_ticket_store, org_id="org-copilot", db=temp_db, actor_role="admin")
    wf_repo = SqliteWorkflowRepository(temp_db)

    wf = Workflow(
        id="wf-rename-1",
        name="Old Name",
        enabled=True,
        version=1,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={}),
        ],
        edges=[],
    )
    wf_repo.save_workflow("org-copilot", wf)

    res = await tools.execute(
        "update_workflow",
        {
            "workflow_id": "wf-rename-1",
            "expected_version": 1,
            "name": "New Renovated Name",
        },
    )

    assert res.get("success") is True
    assert res["workflow"]["name"] == "New Renovated Name"
    assert res["workflow"]["enabled"] is True
    assert res["workflow"]["version"] == 2


@pytest.mark.anyio
async def test_t_cop_9_test_workflow_dry_run(temp_db, mock_ticket_store):
    """T-COP-9: test_workflow runs dry-run trace without persisting or executing side effects (D17)."""
    tools = IncidentTools(store=mock_ticket_store, org_id="org-copilot", db=temp_db, actor_role="admin")
    wf_repo = SqliteWorkflowRepository(temp_db)

    wf = Workflow(
        id="wf-dry-test",
        name="Dry Run Target",
        enabled=False,
        version=1,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5}),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 10}),
            WorkflowNode(id="n3", type="tool_slack", config={"channel": "#live-channel"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )
    wf_repo.save_workflow("org-copilot", wf)

    res = await tools.execute(
        "test_workflow",
        {
            "workflow_id": "wf-dry-test",
            "sample_alert": {"id": "alt-test", "rule_id": "5710", "level": 12},
        },
    )

    assert res.get("dry_run") is True
    assert res.get("status") == "COMPLETED"
    assert res.get("outcome") == "HANDLED"
    assert "n3" in res.get("executed_nodes", [])
