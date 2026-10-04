"""Strict, bounded specialist result contracts.

A result with gaps is explicitly not a security verdict: absence of telemetry
never becomes a finding, and findings must cite evidence collected in the run.
"""

from __future__ import annotations

import json
from typing import Annotated, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_RESULT_BYTES = 32 * 1024
_EVIDENCE_ID = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")]
GapCode = Literal[
    "service_not_configured",
    "context_denied",
    "tool_not_installed",
    "tool_unavailable",
    "coverage_partial",
    "denied",
    "model_unavailable",
    "model_output_invalid",
    "uncited_finding_dropped",
    "role_mismatch",
    "query_unavailable",
    "result_truncated",
]


class _Contract(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", strict=True, frozen=True, allow_inf_nan=False
    )


class Finding(_Contract):
    claim: str = Field(min_length=1, max_length=500)
    evidence_ids: tuple[_EVIDENCE_ID, ...] = Field(min_length=1, max_length=8)


class SpecialistGap(_Contract):
    code: GapCode
    tool_id: str | None = Field(default=None, max_length=200)
    detail: str = Field(default="", max_length=200)


class ToolCallRecord(_Contract):
    tool_id: str = Field(min_length=1, max_length=200)
    status: str = Field(min_length=1, max_length=32)
    error_code: str | None = Field(default=None, max_length=200)
    evidence_count: int = Field(ge=0, le=1000)


class ModelRef(_Contract):
    connection_id: str = Field(min_length=1, max_length=200)
    model: str = Field(min_length=1, max_length=128)


class SpecialistResult(_Contract):
    status: Literal["completed", "partial", "insufficient_telemetry", "error"]
    role: str = Field(min_length=1, max_length=120)
    tool_calls: tuple[ToolCallRecord, ...] = Field(default=(), max_length=20)
    evidence_ids: tuple[_EVIDENCE_ID, ...] = Field(default=(), max_length=60)
    findings: tuple[Finding, ...] = Field(default=(), max_length=8)
    gaps: tuple[SpecialistGap, ...] = Field(default=(), max_length=30)
    model: ModelRef | None = None
    execution_mode: Literal["tools_only", "tools_and_model"] = "tools_only"

    @model_validator(mode="after")
    def bounded(self) -> SpecialistResult:
        size = len(json.dumps(self.model_dump(mode="json"), allow_nan=False).encode())
        if size > MAX_RESULT_BYTES:
            raise ValueError("Specialist result exceeds 32 KiB")
        if (self.model is None) != (self.execution_mode == "tools_only"):
            raise ValueError("Model reference must match execution mode")
        return self


class ModelFindings(_Contract):
    """Exact shape the model may return; nothing else is accepted."""

    findings: tuple[Finding, ...] = Field(max_length=16)
