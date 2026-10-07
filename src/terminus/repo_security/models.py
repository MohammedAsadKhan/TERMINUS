"""Data models for repository security scanning, findings, and components."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field

ScanTrigger = Literal["add", "push", "manual", "rematch"]
ScanStatus = Literal["queued", "running", "completed", "partial", "failed"]
FindingCategory = Literal["secret", "dependency", "suspicious_commit"]
FindingSeverity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal["open", "acknowledged", "false_positive", "resolved"]


class RepoScan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    org_id: str
    asset_id: str
    trigger: ScanTrigger
    commit_sha: str | None = None
    status: ScanStatus = "queued"
    started_at: str | None = None
    finished_at: str | None = None
    error: str | None = None
    stats: dict[str, Any] = Field(default_factory=dict)


class RepoFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    org_id: str
    asset_id: str
    scan_id: str
    category: FindingCategory
    rule: str
    severity: FindingSeverity
    file: str | None = None
    line: int | None = None
    commit_sha: str | None = None
    fingerprint: str
    preview: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    status: FindingStatus = "open"
    first_seen: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    last_seen: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())


class RepoComponent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    org_id: str
    asset_id: str
    commit_sha: str
    ecosystem: str
    name: str
    version: str
    source_file: str


class RepoFindingEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    finding_id: str
    org_id: str
    actor: str
    from_status: FindingStatus
    to_status: FindingStatus
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    details: dict[str, Any] = Field(default_factory=dict)
