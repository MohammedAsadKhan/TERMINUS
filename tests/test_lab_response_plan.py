"""Review plans use exact lab observations and cannot authorize dispatch."""
from datetime import UTC, datetime

import pytest

from terminus.orchestration.models import EvidenceRecord
from terminus.response.lab_plan import build_lab_response_plan


def evidence(org="org", incident="incident", source="10.77.0.10", count=3):
    return EvidenceRecord(
        org_id=org, incident_id=incident, task_id="task", source="wazuh-indexer",
        source_timestamp=datetime.now(UTC), content_hash="a" * 64,
        content={"tool_id": "alerts.search", "observed": [
            {"event_id": str(i), "alert": {"agent": {"id": "001", "ip": "10.77.0.20"},
             "data": {"srcip": source}, "rule": {"groups": ["sshd", "authentication_failed"]},
             "timestamp": "2026-10-17T21:57:36+00:00"}} for i in range(count)
        ]},
    )


def test_exact_scope_is_review_only():
    plan = build_lab_response_plan([evidence()], "incident")
    assert plan["execution_enabled"] is False
    assert plan["approval_state"] == "not_requested"
    assert plan["agent_id"] == "001"
    assert plan["duration_seconds"] == 60
    assert len(plan["source_event_ids"]) == 3


@pytest.mark.parametrize("records", [[], [evidence(incident="other")], [evidence(source="192.168.56.1")], [evidence(count=2)], [evidence(), evidence(org="other")]])
def test_missing_foreign_or_insufficient_evidence_is_rejected(records):
    with pytest.raises(ValueError):
        build_lab_response_plan(records, "incident")


def test_duplicate_events_do_not_meet_threshold():
    record = evidence(count=1)
    with pytest.raises(ValueError):
        build_lab_response_plan([record, record, record], "incident")
