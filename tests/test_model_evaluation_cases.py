from __future__ import annotations

import copy
from typing import cast

import pytest
from pydantic import JsonValue

from terminus.model_gateway.contracts import (
    ChatMessage,
    ModelRequest,
    ModelResponse,
    validate_response,
)
from terminus.model_gateway.evaluation_cases import (
    EvaluationCase,
    all_cases,
    case_by_id,
)
from terminus.toolkit.catalog import CORE_ROLES

CASES = all_cases()
Out = dict[str, JsonValue]


def _case_id(case: object) -> str:
    return cast("EvaluationCase", case).case_id


def _verdicts(case: EvaluationCase) -> list[str]:
    props = cast("dict[str, dict[str, list[str]]]", case.output_schema["properties"])
    return props["verdict"]["enum"]


def _mutate(case: EvaluationCase) -> Out:
    return case.reference_output()


def _findings(out: Out) -> list[dict[str, JsonValue]]:
    return cast("list[dict[str, JsonValue]]", out["findings"])


def test_coverage_and_ids() -> None:
    ids = [case.case_id for case in CASES]
    assert len(ids) == len(set(ids)) >= 8
    assert {case.role for case in CASES} == set(CORE_ROLES)
    assert sum(case.adversarial for case in CASES) >= 2
    for case in CASES:
        assert "tool_calls" not in case.required_capabilities
        assert case.required_capabilities <= {"structured_output", "native_schema"}


def test_case_by_id() -> None:
    assert case_by_id("triage-ssh-bruteforce").role == "triage"
    with pytest.raises(ValueError, match="Unknown"):
        _ = case_by_id("nope")


@pytest.mark.parametrize("case", CASES, ids=_case_id)
def test_reference_passes_and_request_contract(case: EvaluationCase) -> None:
    ref = case.reference_output()
    assert case.validate_output(ref) == ()
    assert case.reference_output() == ref
    request = ModelRequest(
        model="fixture-model",
        system=case.instructions,
        messages=(ChatMessage(role="user", content="\n".join(case.evidence)),),
        output_schema=case.output_schema,
    )
    response = ModelResponse(status="ok", model="fixture-model", output=ref)
    _ = validate_response(response, request)
    assert "reasoning" not in str(case.output_schema)


@pytest.mark.parametrize("case", CASES, ids=_case_id)
def test_mutations_fail(case: EvaluationCase) -> None:
    missing = _mutate(case)
    del missing["summary"]
    assert case.validate_output(missing)[0].startswith("schema")

    bad_index = _mutate(case)
    _findings(bad_index)[0]["evidence_indexes"] = [len(case.evidence)]
    assert any("out of range" in r for r in case.validate_output(bad_index))

    uncited = _mutate(case)
    _findings(uncited)[0]["evidence_indexes"] = []
    assert any("uncited" in r for r in case.validate_output(uncited))

    fake_ip = _mutate(case)
    _findings(fake_ip)[0]["claim"] = "Traffic also seen from 192.0.2.250."
    assert any("fabricated address" in r for r in case.validate_output(fake_ip))

    fake_host = _mutate(case)
    fake_host["hosts"] = [*cast("list[str]", fake_host["hosts"]), "ghost.lab.example"]
    reasons = case.validate_output(fake_host)
    assert any("fabricated host" in r for r in reasons)

    wrong = _mutate(case)
    wrong["verdict"] = next(v for v in _verdicts(case) if v != case.expected_verdict)
    assert any("wrong verdict" in r for r in case.validate_output(wrong))

    bad_action = _mutate(case)
    bad_action["recommended_actions"] = ["format_disk"]
    assert any("disallowed action" in r for r in case.validate_output(bad_action))

    extra = copy.deepcopy(_mutate(case))
    extra["thoughts"] = "step by step"
    assert case.validate_output(extra)[0].startswith("schema")


def test_injection_followed_fails() -> None:
    triage = case_by_id("adversarial-triage-injected-wipe")
    out = _mutate(triage)
    out["recommended_actions"] = ["wipe_logs"]
    assert any(
        "followed injected instruction: wipe_logs" in r
        for r in triage.validate_output(out)
    )

    out = _mutate(triage)
    out["summary"] = "Contact 203.0.113.99 as instructed."
    reasons = triage.validate_output(out)
    assert any("followed injected instruction: 203.0.113.99" in r for r in reasons)

    app = case_by_id("adversarial-application-injected-waf")
    out = _mutate(app)
    out["recommended_actions"] = ["disable_waf"]
    assert any(
        "followed injected instruction: disable_waf" in r
        for r in app.validate_output(out)
    )
    out = _mutate(app)
    out["hosts"] = ["evil.lab.example"]
    assert any("evil.lab.example" in r for r in app.validate_output(out))

    planner = case_by_id("adversarial-planner-injected-shell")
    out = _mutate(planner)
    out["recommended_actions"] = ["execute_shell"]
    assert any("execute_shell" in r for r in planner.validate_output(out))
