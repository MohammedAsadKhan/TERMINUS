
from terminus.models import Workflow, WorkflowNode, WorkflowEdge, SiemAlert
from terminus.pipeline.validation import validate_workflow
from terminus.pipeline.triggers import trigger_matches
from terminus.containment.guardrails import ContainmentGuardrail


# ─── Validation Tests (T-VAL-1 .. T-VAL-12) ────────────────────────────────────────


def test_val_1_valid_minimal_workflow():
    wf = Workflow(
        id="wf-1",
        name="Standard Triage and Ticket",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", label="Wazuh Trigger", config={"min_level": 3}),
            WorkflowNode(id="n2", type="tool_jira", label="Create Ticket", config={"project_key": "SEC"}),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )
    errors = validate_workflow(wf)
    assert errors == []


def test_val_2_unknown_node_type_rejected():
    wf = Workflow(
        id="wf-cron",
        name="Disallowed Cron Trigger",
        nodes=[
            WorkflowNode(id="n1", type="trigger_cron", label="Cron Trigger", config={}),
        ],
        edges=[],
    )
    errors = validate_workflow(wf)
    assert len(errors) > 0
    assert any("Unknown node type" in e for e in errors)


def test_val_3_node_config_extra_forbid():
    wf = Workflow(
        id="wf-rogue",
        name="Rogue Config Key",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh", config={"min_level": 5, "unknown_field": "disallowed"}),
        ],
        edges=[],
    )
    errors = validate_workflow(wf)
    assert len(errors) > 0
    assert any("Invalid config for node 'n1'" in e for e in errors)


def test_val_4_invalid_edge_endpoints():
    wf = Workflow(
        id="wf-bad-edge",
        name="Broken Edge",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh"),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n999"),
        ],
    )
    errors = validate_workflow(wf)
    assert any("non-existent target node 'n999'" in e for e in errors)


def test_val_5_edge_handles_condition_severity():
    # condition_severity with "default" handle is invalid (must be true/false/on_error)
    wf_invalid = Workflow(
        id="wf-cond-invalid",
        name="Invalid Condition Handle",
        nodes=[
            WorkflowNode(id="n1", type="condition_severity", config={"min_level": 7}),
            WorkflowNode(id="n2", type="tool_slack"),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )
    errors = validate_workflow(wf_invalid)
    assert any("Invalid source_handle 'default'" in e for e in errors)

    # valid condition handle "true"
    wf_valid = Workflow(
        id="wf-cond-valid",
        name="Valid Condition Handle",
        nodes=[
            WorkflowNode(id="n1", type="condition_severity", config={"min_level": 7}),
            WorkflowNode(id="n2", type="tool_slack"),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="true"),
        ],
    )
    assert validate_workflow(wf_valid) == []


def test_val_6_edge_handles_trigger_wazuh():
    # trigger_wazuh with "true" handle is invalid (must be default/on_error)
    wf = Workflow(
        id="wf-trig-bad",
        name="Bad Trigger Handle",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh"),
            WorkflowNode(id="n2", type="tool_slack"),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="true"),
        ],
    )
    errors = validate_workflow(wf)
    assert any("Invalid source_handle 'true'" in e for e in errors)


def test_val_7_cycle_detection():
    wf = Workflow(
        id="wf-cycle",
        name="Cyclic Workflow",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh"),
            WorkflowNode(id="n2", type="agent_llm"),
            WorkflowNode(id="n3", type="tool_slack"),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="default"),
            WorkflowEdge(id="e3", source="n3", target="n2", source_handle="default"),
        ],
    )
    errors = validate_workflow(wf)
    assert any("cycle or loop" in e for e in errors)


def test_val_8_containment_ungated_direct_rejected():
    wf = Workflow(
        id="wf-ungated",
        name="Ungated Isolate",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh"),
            WorkflowNode(id="n2", type="tool_isolate"),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
        ],
    )
    errors = validate_workflow(wf)
    assert any("reachable via ungated path" in e for e in errors)


def test_val_9_containment_gated_by_severity_min_level():
    wf = Workflow(
        id="wf-gated-sev",
        name="Severity Gated Isolate",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh"),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 8}),
            WorkflowNode(id="n3", type="tool_isolate"),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )
    assert validate_workflow(wf) == []


def test_val_10_containment_gated_by_severity_zero_rejected():
    wf = Workflow(
        id="wf-gated-zero",
        name="Zero Level Severity Gate Isolate",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh"),
            WorkflowNode(id="n2", type="condition_severity", config={"min_level": 0}),
            WorkflowNode(id="n3", type="tool_isolate"),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )
    errors = validate_workflow(wf)
    assert any("reachable via ungated path" in e for e in errors)


def test_val_11_containment_gated_by_approval():
    wf = Workflow(
        id="wf-gated-appr",
        name="Approval Gated Firewall",
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh"),
            WorkflowNode(id="n2", type="condition_approval", config={"required_role": "admin"}),
            WorkflowNode(id="n3", type="tool_firewall"),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )
    assert validate_workflow(wf) == []


def test_val_12_enabling_requires_admin_for_containment():
    wf = Workflow(
        id="wf-containment-enable",
        name="Containment Flow",
        enabled=True,
        nodes=[
            WorkflowNode(id="n1", type="trigger_wazuh"),
            WorkflowNode(id="n2", type="condition_approval"),
            WorkflowNode(id="n3", type="tool_isolate"),
        ],
        edges=[
            WorkflowEdge(id="e1", source="n1", target="n2", source_handle="default"),
            WorkflowEdge(id="e2", source="n2", target="n3", source_handle="true"),
        ],
    )
    errors_analyst = validate_workflow(wf, caller_role="analyst", is_enabling=True)
    assert any("requires 'admin' role" in e for e in errors_analyst)

    errors_admin = validate_workflow(wf, caller_role="admin", is_enabling=True)
    assert errors_admin == []


# ─── Trigger Matching Tests ────────────────────────────────────────────────────────


def test_trigger_matches_rules():
    alert = SiemAlert(
        id="a1",
        rule_id=5710,
        level=7,
        description="SSH Auth Failure",
        location="/var/log/auth.log",
        mitre="T1110",
        agent_name="prod-web-01",
    )

    assert trigger_matches({"min_level": 5}, alert) is True
    assert trigger_matches({"min_level": 10}, alert) is False
    assert trigger_matches({"rule_id": 5710}, alert) is True
    assert trigger_matches({"rule_id": 9999}, alert) is False
    assert trigger_matches({"rule_ids": [1000, 5710]}, alert) is True
    assert trigger_matches({"location": "auth.log"}, alert) is True
    assert trigger_matches({"mitre": "t1110"}, alert) is True
    assert trigger_matches({"agent_name_match": "prod-web"}, alert) is True
    assert trigger_matches({"agent_name_match": "dev-box"}, alert) is False


# ─── Guardrails Tests (T-GRD-1 .. T-GRD-6) ─────────────────────────────────────────


def test_grd_1_critical_host_blocked_without_override():
    res = ContainmentGuardrail.assess_target("dc-01.corp.internal", kind="host", force_override=False)
    assert res.allowed is False
    assert "critical asset" in res.reason.lower()


def test_grd_2_critical_host_allowed_with_override():
    res = ContainmentGuardrail.assess_target("dc-01.corp.internal", kind="host", force_override=True)
    assert res.allowed is True
    assert "overridden" in res.reason.lower()


def test_grd_3_protected_ip_blocked_even_with_override():
    res = ContainmentGuardrail.assess_target("127.0.0.1", kind="ip", force_override=True)
    assert res.allowed is False
    assert "protected" in res.reason.lower()

    res_link_local = ContainmentGuardrail.assess_target("169.254.169.254", kind="ip", force_override=True)
    assert res_link_local.allowed is False


def test_grd_4_allowlist_blocked_even_with_override():
    allowlist = {"safe-workstation-99", "192.168.1.100"}
    res = ContainmentGuardrail.assess_target(
        "safe-workstation-99",
        kind="host",
        allowlist_repo=allowlist,
        force_override=True,
    )
    assert res.allowed is False
    assert "allowlist" in res.reason.lower()


def test_grd_5_invalid_target_blocked():
    res_empty = ContainmentGuardrail.assess_target("", kind="host")
    assert res_empty.allowed is False

    res_bad_ip = ContainmentGuardrail.assess_target("999.999.999.999", kind="ip")
    assert res_bad_ip.allowed is False


def test_grd_6_standard_benign_allowed():
    res = ContainmentGuardrail.assess_target("laptop-jane-doe", kind="host", force_override=False)
    assert res.allowed is True
    assert res.reason is None
