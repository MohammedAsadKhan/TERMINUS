from __future__ import annotations

import pytest

from terminus.agent.tools import InvestigationTools
from terminus.core.ids import AgentId, OrgId
from terminus.models import SiemAlert
from terminus.tools.siem_search import SiemForensicsTool
from terminus.tools.threat_intel import ThreatIntelClient


class FailingSiem:
    async def get_agent(self, agent_id: AgentId) -> dict[str, object]:
        del agent_id
        raise ConnectionError("SIEM is unavailable")


@pytest.mark.anyio
async def test_host_context_failure_is_an_explicit_gap() -> None:
    result = await SiemForensicsTool(FailingSiem()).get_host_context("agent-7")

    assert result["query_status"] == "unavailable"
    assert result["id"] == "agent-7"
    assert "srv-prod-node" not in result.values()
    assert result["gaps"] == ["Endpoint context query failed: ConnectionError"]


@pytest.mark.anyio
async def test_historical_query_without_backend_returns_gap_not_events() -> None:
    result = await SiemForensicsTool(FailingSiem()).query_prior_events("agent-7")

    assert result == {
        "status": "unavailable",
        "events": [],
        "gaps": ["Historical event querying is not configured for this SIEM client."],
    }


@pytest.mark.anyio
async def test_unconfigured_hash_lookup_stays_unknown() -> None:
    result = await ThreatIntelClient().lookup("log4j", "hash")

    assert result.is_malicious is None
    assert result.reputation_score is None
    assert result.confidence == "UNKNOWN"
    assert result.provider == "No external provider queried"
    assert "unknown" in result.details
    assert result.to_citation()["queried"] is False
    assert "source" not in result.to_citation()


@pytest.mark.anyio
async def test_keyword_match_cannot_establish_offline_reputation() -> None:
    result = await ThreatIntelClient().lookup("Log4Shell JNDI", "domain")

    assert result.is_malicious is None
    assert result.reputation_score is None
    assert result.provider == "No external provider queried"
    assert "unverified context only" in result.details


@pytest.mark.anyio
async def test_investigation_evidence_does_not_claim_hash_is_clean_or_malicious() -> None:
    alert = SiemAlert.model_validate(
        {"id": "alert-1", "rule": {"id": 1, "level": 8}, "hash": "abc123"}
    )

    evidence = await InvestigationTools(FailingSiem()).gather_evidence(alert, OrgId("org-1"))

    assert "not assessed" in evidence.threat_intel
    assert "No external threat intelligence provider was queried" in evidence.threat_intel
