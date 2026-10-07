"""Deterministic enterprise demo seed data for assets, guardrails, repositories, and SBOM."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from terminus.model_gateway.contracts import ModelUsage
from terminus.orchestration.collaboration import (
    help_task_key,
    objective_digest,
    task_key,
)
from terminus.orchestration.coordination import CoordinationService
from terminus.orchestration.coordination_models import (
    AreaObjective,
    IncidentObjective,
    MainObjective,
)
from terminus.orchestration.models import (
    ActionAttempt,
    ActionAttemptEvent,
    AgentRun,
    EvidenceRecord,
    HelpRequest,
    Task,
)
from terminus.orchestration.scheduler_models import SchedulerJob
from terminus.orchestration.scheduler_store import (
    _JOB_COLUMNS,
    _bounded_payload,
    _job_data,
)
from terminus.orchestration.specialists.models import (
    Finding,
    ModelRef,
    SpecialistResult,
    ToolCallRecord,
)
from terminus.repo_security.storage import SqliteRepoSecurityRepository
from terminus.storage.assets import SqliteAssetRepository
from terminus.storage.db import Database


def _sha256(val: str) -> str:
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


def seed_presentation_demo_data(db: Database | None = None, org_id: str = "org-default") -> dict[str, Any]:
    """Idempotently populate rich enterprise asset, repository, SBOM, and security finding fixtures."""
    db = db or Database.get_instance()
    asset_repo = SqliteAssetRepository(db)
    sec_repo = SqliteRepoSecurityRepository(db)

    # Ensure organization exists
    now = datetime.now(UTC)
    now_iso = now.isoformat()
    db.execute(
        "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) "
        "VALUES (?, ?, ?, '', '{}')",
        (str(org_id), f"Organization {org_id}", now_iso),
    )

    created_assets: dict[str, dict[str, Any]] = {}

    # 1. Enterprise Infrastructure Assets
    infrastructure_specs = [
        {
            "name": "Active Directory Root Domain Controller",
            "kind": "device",
            "locator": "10.0.0.5",
            "hostname": "dc01.corp.internal",
            "agent_id": "001",
            "criticality": "tier0",
            "owner": "infosec-ad@terminus.bank",
            "environment": "production",
            "exposure": "internal",
            "notes": "Mission-critical identity infrastructure. Guardrails strictly prohibit automated containment (D12).",
        },
        {
            "name": "Primary Settlement Core Ledger",
            "kind": "container",
            "locator": "10.0.0.10",
            "hostname": "ledger-prod-01.internal",
            "agent_id": "002",
            "criticality": "tier0",
            "owner": "fintech-core@terminus.bank",
            "environment": "production",
            "exposure": "internal",
            "notes": "High-throughput core transaction ledger engine. Tier-0 protection enforced.",
        },
        {
            "name": "Public Perimeter Web Gateway",
            "kind": "cloud",
            "locator": "198.51.100.1",
            "hostname": "api-gateway.terminus.bank",
            "agent_id": "003",
            "criticality": "tier1",
            "owner": "appsec-team@terminus.bank",
            "environment": "production",
            "exposure": "internet",
            "notes": "Edge reverse proxy and rate limiting gateway for public banking APIs.",
        },
        {
            "name": "Customer Account API Cluster",
            "kind": "container",
            "locator": "10.0.4.22",
            "hostname": "api-cluster-prod.internal",
            "agent_id": "004",
            "criticality": "tier1",
            "owner": "platform-team@terminus.bank",
            "environment": "production",
            "exposure": "internal",
            "notes": "Microservice handling banking session validation and balance queries.",
        },
        {
            "name": "Enterprise Payroll Database",
            "kind": "device",
            "locator": "10.5.0.100",
            "hostname": "payroll-srv.internal",
            "agent_id": "005",
            "criticality": "tier1",
            "owner": "hr-finance-ops@terminus.bank",
            "environment": "production",
            "exposure": "internal",
            "notes": "Confidential compensation ledger. Guardrail verified non-keyword Tier-1 containment protection.",
        },
        {
            "name": "SecOps Analyst Workstation 88",
            "kind": "device",
            "locator": "10.0.10.88",
            "hostname": "workstation-88.corp.internal",
            "agent_id": "088",
            "criticality": "tier3",
            "owner": "alice.dev@terminus.bank",
            "environment": "corporate",
            "exposure": "internal",
            "notes": "Analyst endpoint. Ransomware detonation simulation target; human-in-the-loop isolation permitted.",
        },
        {
            "name": "Finance Department Laptop 04",
            "kind": "device",
            "locator": "10.0.10.42",
            "hostname": "laptop-fin-04.corp.internal",
            "agent_id": "042",
            "criticality": "tier3",
            "owner": "bob.analyst@terminus.bank",
            "environment": "corporate",
            "exposure": "internal",
            "notes": "Corporate finance analyst laptop.",
        },
    ]

    for spec in infrastructure_specs:
        existing = asset_repo.find_for_target(org_id, spec["hostname"])
        if not existing:
            existing = asset_repo.create(
                org_id=org_id,
                kind=spec["kind"],
                name=spec["name"],
                locator=spec["locator"],
                notes=spec["notes"],
                agent_id=spec["agent_id"],
                hostname=spec["hostname"],
                criticality=spec["criticality"],
                owner=spec["owner"],
                environment=spec["environment"],
                exposure=spec["exposure"],
                source="registered",
            )
        created_assets[spec["hostname"]] = existing

    # 2. Enterprise Software Repositories
    repo_specs = [
        {
            "name": "Core Banking API Service",
            "url": "https://github.com/terminus-sec/core-banking-api",
            "criticality": "tier1",
            "owner": "fintech-dev@terminus.bank",
            "notes": "Primary backend REST and gRPC banking services repository.",
            "scan_status": "completed",
            "scan_age_hours": 2,
            "commit_sha": "d500cdc89f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c",
            "findings": [
                {
                    "category": "secret",
                    "rule": "aws_access_key",
                    "severity": "critical",
                    "file": "infra/terraform/main.tf",
                    "line": 42,
                    "commit_sha": "8f2a1b0c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a",
                    "preview": "AKIA...[REDACTED]",
                    "status": "open",
                    "details": {
                        "description": "AWS Access Key ID committed in Terraform manifest",
                        "source": "git_history",
                        "note": "Detected in previous commit history even after deletion in subsequent patch",
                    },
                },
                {
                    "category": "secret",
                    "rule": "slack_token",
                    "severity": "high",
                    "file": "services/notifications.py",
                    "line": 18,
                    "commit_sha": "d500cdc89f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c",
                    "preview": "xoxb...[REDACTED]",
                    "status": "acknowledged",
                    "details": {
                        "description": "Slack Bot Incident Notification Webhook Token",
                        "matched_rule": "slack_token",
                    },
                },
                {
                    "category": "dependency",
                    "rule": "vulnerable_dependency",
                    "severity": "critical",
                    "file": "requirements.txt",
                    "line": 4,
                    "commit_sha": "d500cdc89f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c",
                    "preview": "requests==2.18.0 (CVE-2018-18074)",
                    "status": "open",
                    "details": {
                        "component": "requests",
                        "version": "2.18.0",
                        "ecosystem": "PyPI",
                        "advisory_id": "GHSA-9hjg-q298-5555",
                        "aliases": ["CVE-2018-18074"],
                        "summary": "Session credential exposure on cross-origin redirect in requests",
                    },
                },
                {
                    "category": "dependency",
                    "rule": "vulnerable_dependency",
                    "severity": "high",
                    "file": "package-lock.json",
                    "line": 128,
                    "commit_sha": "d500cdc89f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c",
                    "preview": "lodash@4.17.20 (CVE-2021-23337)",
                    "status": "open",
                    "details": {
                        "component": "lodash",
                        "version": "4.17.20",
                        "ecosystem": "npm",
                        "advisory_id": "GHSA-35jh-r3h4-6jhm",
                        "aliases": ["CVE-2021-23337"],
                        "summary": "Command injection vulnerability in lodash template engine",
                    },
                },
                {
                    "category": "suspicious_commit",
                    "rule": "ci_workflow_modification",
                    "severity": "medium",
                    "file": ".github/workflows/deploy.yml",
                    "line": 14,
                    "commit_sha": "d500cdc89f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c",
                    "preview": ".github/workflows/deploy.yml modified",
                    "status": "open",
                    "details": {
                        "description": "Production release CI/CD workflow modified",
                        "risk": "Requires two-person maintainer review before merge",
                    },
                },
            ],
            "components": [
                {"ecosystem": "PyPI", "name": "fastapi", "version": "0.115.0", "source_file": "requirements.txt", "pinned": True},
                {"ecosystem": "PyPI", "name": "pydantic", "version": "2.9.2", "source_file": "requirements.txt", "pinned": True},
                {"ecosystem": "PyPI", "name": "uvicorn", "version": "0.30.0", "source_file": "requirements.txt", "pinned": True},
                {"ecosystem": "PyPI", "name": "requests", "version": "2.18.0", "source_file": "requirements.txt", "pinned": True},
                {"ecosystem": "npm", "name": "react", "version": "18.3.1", "source_file": "package-lock.json", "pinned": True},
                {"ecosystem": "npm", "name": "axios", "version": "1.6.0", "source_file": "package-lock.json", "pinned": True},
                {"ecosystem": "npm", "name": "lodash", "version": "4.17.20", "source_file": "package-lock.json", "pinned": True},
            ],
        },
        {
            "name": "Authentication & OAuth Gateway",
            "url": "https://github.com/terminus-sec/auth-service",
            "criticality": "tier0",
            "owner": "identity-team@terminus.bank",
            "notes": "Cryptographic authentication token signer and MFA gateway.",
            "scan_status": "completed",
            "scan_age_hours": 4,
            "commit_sha": "fa78bc901234567890abcdef1234567890abcdef",
            "findings": [],
            "components": [
                {"ecosystem": "PyPI", "name": "fastapi", "version": "0.115.0", "source_file": "requirements.txt", "pinned": True},
                {"ecosystem": "PyPI", "name": "cryptography", "version": "43.0.1", "source_file": "requirements.txt", "pinned": True},
                {"ecosystem": "PyPI", "name": "pyjwt", "version": "2.9.0", "source_file": "requirements.txt", "pinned": True},
                {"ecosystem": "PyPI", "name": "pydantic", "version": "2.9.2", "source_file": "requirements.txt", "pinned": True},
            ],
        },
        {
            "name": "Legacy Web Portal Frontend",
            "url": "https://github.com/terminus-sec/legacy-frontend",
            "criticality": "tier2",
            "owner": "web-team@terminus.bank",
            "notes": "Customer web interface. Last scanned 18 days ago (demonstrates stale coverage).",
            "scan_status": "completed",
            "scan_age_hours": 24 * 18,  # 18 days ago -> stale (>7 days)
            "commit_sha": "34567890abcdef1234567890abcdef1234567890",
            "findings": [],
            "components": [
                {"ecosystem": "npm", "name": "jquery", "version": "3.5.1", "source_file": "package-lock.json", "pinned": True},
            ],
        },
    ]

    for spec in repo_specs:
        existing = asset_repo.find_for_target(org_id, spec["url"])
        if not existing:
            # Check by locator
            rows = db.fetchall(
                "SELECT * FROM assets WHERE org_id = ? AND locator = ?", (str(org_id), spec["url"])
            )
            existing = rows[0] if rows else None

        if not existing:
            existing = asset_repo.create(
                org_id=org_id,
                kind="repository",
                name=spec["name"],
                locator=spec["url"],
                notes=spec["notes"],
                criticality=spec["criticality"],
                owner=spec["owner"],
                environment="production",
                exposure="internal",
                source="registered",
            )
        asset_id = existing["asset_id"]
        created_assets[spec["url"]] = existing

        # Create Seeded Scan
        scan_time = now - timedelta(hours=spec["scan_age_hours"])
        scan_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO repo_scans (scan_id, org_id, asset_id, trigger, commit_sha, status, started_at, finished_at, stats_json) "
            "VALUES (?, ?, ?, 'manual', ?, ?, ?, ?, ?)",
            (
                scan_id,
                str(org_id),
                asset_id,
                spec["commit_sha"],
                spec["scan_status"],
                scan_time.isoformat(),
                scan_time.isoformat(),
                json.dumps({
                    "findings_count": len(spec["findings"]),
                    "components_count": len(spec["components"]),
                }),
            ),
        )

        # Record findings
        if spec["findings"]:
            findings_to_insert = []
            for f in spec["findings"]:
                fingerprint = _sha256(f"{f['rule']}:{f['file']}:{f['preview']}")
                findings_to_insert.append({
                    "category": f["category"],
                    "rule": f["rule"],
                    "severity": f["severity"],
                    "file": f["file"],
                    "line": f["line"],
                    "commit_sha": f["commit_sha"],
                    "preview": f["preview"],
                    "fingerprint": fingerprint,
                    "details": f["details"],
                })
            sec_repo.record_findings(org_id, asset_id, scan_id, findings_to_insert)

        # Record components
        if spec["components"]:
            sec_repo.record_components(org_id, asset_id, spec["commit_sha"], spec["components"])

    # 3. Seed multi-specialist orchestration workflows, runs, evidence, and actions
    orch_res = seed_demo_orchestration_tasks(db, org_id)

    return {
        "status": "seeded",
        "org_id": org_id,
        "assets_count": len(created_assets),
        "assets": list(created_assets.keys()),
        "orchestration": orch_res,
    }


def seed_demo_orchestration_tasks(db: Database, org_id: str = "org-default") -> dict[str, Any]:
    """Populate realistic multi-specialist orchestration workflows, subagent runs, and evidence."""
    now = datetime.now(UTC)
    now_iso = now.isoformat()

    # Ensure org exists
    db.execute(
        "INSERT OR IGNORE INTO organizations (org_id, name, created_at, license_ref, settings_json) "
        "VALUES (?, ?, ?, '', '{}')",
        (str(org_id), f"Organization {org_id}", now_iso),
    )

    # Initialize coordination service (creates collaboration tables)
    _ = CoordinationService(db)

    # 1. Canonical Demo Incidents
    incidents_data = [
        {
            "ticket_id": "INC-8821",
            "alert_id": "ALT-8821",
            "rule_id": "100201",
            "rule_description": "Volume Shadow Copy Deletion (vssadmin.exe)",
            "severity": "critical",
            "confidence": "high",
            "summary": "Ransomware detonation detected on workstation-88.corp.internal with Volume Shadow Copy deletion",
            "recommended_actions": [
                "Authorize emergency host network isolation for workstation-88.corp.internal",
                "Revoke Kerberos session tokens and terminate PID 4912 lineage",
            ],
            "agent_name": "workstation-88.corp.internal",
            "threat_intel": "Known LockBit 3.0 ransomware IOC lineage",
            "context_notes": "High-confidence process execution; parent powershell.exe (PID 3108)",
            "full_log": "vssadmin.exe delete shadows /all /quiet",
            "policy_tier": "tier3",
            "policy_reason": "Tier-3 analyst endpoint containment policy permits human-in-the-loop isolation.",
            "status": "OPEN",
            "asset_criticality": "tier3",
            "kill_chain_stage": "Impact & Defense Evasion",
            "threat_intel_score": "94/100 (Malicious)",
            "time_to_decision": 1.25,
            "mitigation_status": "PENDING_APPROVAL",
            "citations": ["ev-ws88-proc-4912", "ev-ws88-wazuh-100201"],
            "raw_payload": {
                "agent": {"id": "088", "name": "workstation-88.corp.internal", "ip": "10.0.10.88"},
                "process": {"pid": 4912, "cmdline": "vssadmin.exe delete shadows /all /quiet"},
            },
        },
        {
            "ticket_id": "INC-8819",
            "alert_id": "ALT-8819",
            "rule_id": "99010",
            "rule_description": "Perimeter API Gateway SQL Injection & C2 Beaconing",
            "severity": "high",
            "confidence": "high",
            "summary": "External SQL injection probe on /api/v1/customers followed by C2 beacon to 198.51.100.42",
            "recommended_actions": [
                "Apply ingress boundary firewall drop on attacker IP 198.51.100.42",
                "Sanitize customer query parameters at API gateway tier",
            ],
            "agent_name": "api-gateway.terminus.bank",
            "threat_intel": "IP 198.51.100.42 listed on AbuseIPDB (92/100) and VirusTotal C2 blocklist",
            "context_notes": "Target is Tier-1 reverse proxy gateway (198.51.100.1)",
            "full_log": "GET /api/v1/customers?id=1%27%20OR%201=1-- HTTP/1.1 from 198.51.100.42",
            "policy_tier": "tier1",
            "policy_reason": "Tier-1 gateway protection enforced (D12). Ingress attacker IP blocked; gateway host isolation prohibited.",
            "status": "OPEN",
            "asset_criticality": "tier1",
            "kill_chain_stage": "Initial Access & Command and Control",
            "threat_intel_score": "92/100 (Malicious C2)",
            "time_to_decision": 0.85,
            "mitigation_status": "CONTAINED",
            "citations": ["ev-gw-suricata-9901", "ev-gw-vt-intel"],
            "raw_payload": {
                "agent": {"id": "003", "name": "api-gateway.terminus.bank", "ip": "198.51.100.1"},
                "network": {"src_ip": "198.51.100.42", "dst_ip": "198.51.100.1", "port": 443},
            },
        },
        {
            "ticket_id": "INC-8825",
            "alert_id": "ALT-8825",
            "rule_id": "60112",
            "rule_description": "Active Directory Kerberoasting (TGS Request with RC4-HMAC)",
            "severity": "critical",
            "confidence": "high",
            "summary": "Kerberos ticket-granting service request with weak RC4 encryption targeting MSSQLSvc on dc01.corp.internal",
            "recommended_actions": [
                "Disable RC4 encryption types on service account SPNs",
                "Rotate MSSQLSvc service account password",
                "Observe lateral authentication flows from 10.0.10.42",
            ],
            "agent_name": "dc01.corp.internal",
            "threat_intel": "Internal credential harvesting signature MITRE T1558.003",
            "context_notes": "Tier-0 Domain Controller. Host isolation strictly forbidden by safety guardrail D12.",
            "full_log": "Event 4769: A Kerberos service ticket was requested. Service: MSSQLSvc/db-prod.internal:1433, Ticket Options: 0x40810000, Ticket Encryption: 0x17 (RC4-HMAC)",
            "policy_tier": "tier0",
            "policy_reason": "Tier-0 identity asset. Automated host containment strictly prohibited by guardrail D12.",
            "status": "OPEN",
            "asset_criticality": "tier0",
            "kill_chain_stage": "Credential Access",
            "threat_intel_score": "88/100 (High Risk)",
            "time_to_decision": 1.10,
            "mitigation_status": "NOT_EXECUTED",
            "citations": ["ev-dc01-ad-4769", "ev-dc01-wazuh-kerb"],
            "raw_payload": {
                "agent": {"id": "001", "name": "dc01.corp.internal", "ip": "10.0.0.5"},
                "auth": {"service": "MSSQLSvc/db-prod.internal:1433", "encryption": "0x17"},
            },
        },
    ]

    for inc in incidents_data:
        db.execute(
            """
            INSERT OR REPLACE INTO incidents (
                ticket_id, org_id, alert_id, rule_id, rule_description, severity, confidence,
                summary, recommended_actions, agent_name, threat_intel, context_notes, full_log,
                policy_tier, policy_reason, status, asset_criticality, kill_chain_stage,
                threat_intel_score, time_to_decision_sec, mitigation_status, evidence_citations_json,
                raw_payload_json, report_json, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                inc["ticket_id"],
                str(org_id),
                inc["alert_id"],
                inc["rule_id"],
                inc["rule_description"],
                inc["severity"],
                inc["confidence"],
                inc["summary"],
                json.dumps(inc["recommended_actions"]),
                inc["agent_name"],
                inc["threat_intel"],
                inc["context_notes"],
                inc["full_log"],
                inc["policy_tier"],
                inc["policy_reason"],
                inc["status"],
                inc["asset_criticality"],
                inc["kill_chain_stage"],
                inc["threat_intel_score"],
                inc["time_to_decision"],
                inc["mitigation_status"],
                json.dumps(inc["citations"]),
                json.dumps(inc["raw_payload"]),
                json.dumps({"status": "triaged"}),
                now_iso,
                now_iso,
            ),
        )

    # Low-level helpers to insert orchestration records
    def insert_task(
        task_id: str,
        incident_id: str,
        area: str,
        role: str,
        objective: str,
        status: str = "completed",
        parent_task_id: str | None = None,
        priority: int = 100,
        idempotency_key: str | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ) -> Task:
        t = Task(
            org_id=str(org_id),
            incident_id=incident_id,
            task_id=task_id,
            parent_task_id=parent_task_id,
            area=area,
            role=role,
            objective=objective,
            status=status,  # type: ignore
            priority=priority,
            idempotency_key=idempotency_key,
            created_at=now - timedelta(minutes=10),
            updated_at=now,
            started_at=started_at or (now - timedelta(minutes=10)),
            completed_at=completed_at,
        )
        req_hash = _sha256(f"{org_id}:{incident_id}:{area}:{role}:{task_id}")
        db.execute(
            """
            INSERT OR REPLACE INTO orchestration_tasks
            (org_id, task_id, incident_id, parent_task_id, status, idempotency_key, request_hash, created_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(org_id),
                t.task_id,
                t.incident_id,
                t.parent_task_id,
                t.status,
                t.idempotency_key,
                req_hash,
                t.created_at.isoformat(),
                t.model_dump_json(),
            ),
        )
        return t

    def insert_scheduler_job(
        task: Task,
        status: str = "completed",
        attempt: int = 1,
        worker_id: str | None = "worker-01",
        run_id: str | None = None,
        recovery_reason: str | None = None,
    ) -> SchedulerJob:
        job = SchedulerJob(
            job_id=f"job-{task.task_id[:8]}",
            org_id=str(org_id),
            incident_id=task.incident_id,
            task_id=task.task_id,
            role=task.role,
            priority=task.priority,
            status=status,  # type: ignore
            attempt=attempt,
            max_attempts=3,
            available_at=now - timedelta(minutes=10),
            worker_id=worker_id,
            run_id=run_id,
            recovery_reason=recovery_reason,
            created_at=now - timedelta(minutes=10),
            updated_at=now,
        )
        data = _job_data(job)
        columns = ("job_id", *_JOB_COLUMNS, "payload_json")
        values = [data[c] for c in columns[:-1]]
        values.append(_bounded_payload(job))
        db.execute(
            f"INSERT OR REPLACE INTO orchestration_scheduler_jobs ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            tuple(values),
        )
        return job

    def insert_agent_run(
        run_id: str,
        task: Task,
        status: str = "completed",
        model_name: str | None = "claude-3-5-sonnet",
        model_connection_id: str | None = "conn-anthropic-prod",
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> AgentRun:
        run = AgentRun(
            org_id=str(org_id),
            incident_id=task.incident_id,
            task_id=task.task_id,
            run_id=run_id,
            agent_id=f"agent-{task.role}",
            model_name=model_name,
            model_connection_id=model_connection_id,
            status=status,  # type: ignore
            created_at=now - timedelta(minutes=9),
            started_at=now - timedelta(minutes=9),
            updated_at=now,
            completed_at=now - timedelta(minutes=1) if status == "completed" else None,
            result=result,
            error=error,
        )
        db.execute(
            """
            INSERT OR REPLACE INTO orchestration_agent_runs
            (org_id, run_id, incident_id, task_id, status, created_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(org_id),
                run.run_id,
                run.incident_id,
                run.task_id,
                run.status,
                run.created_at.isoformat(),
                run.model_dump_json(),
            ),
        )
        return run

    def insert_evidence(
        evidence_id: str,
        task: Task,
        source: str,
        content: dict[str, Any],
        content_ref: str | None = None,
    ) -> EvidenceRecord:
        content_hash = _sha256(json.dumps(content, sort_keys=True))
        ev = EvidenceRecord(
            org_id=str(org_id),
            incident_id=task.incident_id,
            task_id=task.task_id,
            evidence_id=evidence_id,
            source=source,
            source_timestamp=now - timedelta(minutes=15),
            collected_at=now - timedelta(minutes=8),
            content=content,
            content_ref=content_ref,
            content_hash=content_hash,
        )
        db.execute(
            """
            INSERT OR IGNORE INTO orchestration_evidence
            (org_id, evidence_id, incident_id, task_id, created_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(org_id),
                ev.evidence_id,
                ev.incident_id,
                ev.task_id,
                ev.created_at.isoformat(),
                ev.model_dump_json(),
            ),
        )
        return ev

    def insert_action(
        attempt_id: str,
        task: Task,
        action: str,
        targets: list[str],
        status: str = "proposed",
        inputs: dict[str, Any] | None = None,
        actor: str = "response_planner_agent",
        outputs: dict[str, Any] | None = None,
    ) -> ActionAttempt:
        attempt = ActionAttempt(
            org_id=str(org_id),
            incident_id=task.incident_id,
            task_id=task.task_id,
            attempt_id=attempt_id,
            action=action,
            targets=targets,
            status=status,  # type: ignore
            inputs=inputs or {},
            created_at=now - timedelta(minutes=5),
            updated_at=now,
            completed_at=now if status in {"verified", "failed", "rejected"} else None,
        )
        db.execute(
            """
            INSERT OR REPLACE INTO orchestration_action_attempts
            (org_id, attempt_id, incident_id, task_id, status, created_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(org_id),
                attempt.attempt_id,
                attempt.incident_id,
                attempt.task_id,
                attempt.status,
                attempt.created_at.isoformat(),
                attempt.model_dump_json(),
            ),
        )
        ev_id = f"evt-{attempt_id[:8]}-1"
        event = ActionAttemptEvent(
            org_id=str(org_id),
            incident_id=task.incident_id,
            event_id=ev_id,
            attempt_id=attempt.attempt_id,
            status=status,  # type: ignore
            timestamp=now - timedelta(minutes=5),
            actor=actor,
            outputs=outputs or {},
        )
        db.execute(
            """
            INSERT OR IGNORE INTO orchestration_action_events
            (org_id, event_id, incident_id, attempt_id, created_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                str(org_id),
                event.event_id,
                event.incident_id,
                event.attempt_id,
                event.created_at.isoformat(),
                event.model_dump_json(),
            ),
        )
        return attempt

    # =========================================================================
    # TREE 1: INC-8821 (Ransomware Detonation on workstation-88)
    # =========================================================================
    inc1 = "INC-8821"
    inc1_obj = IncidentObjective(
        objective="Contain ransomware detonation and lateral SMB propagation on workstation-88.corp.internal",
        areas=["alert_handling", "investigation", "response_improvement", "applications_data"],
        idempotency_key="inc-8821-root",
    )
    main_plan_1 = MainObjective(
        request=inc1_obj,
        plans=[
            AreaObjective(area="alert_handling", objective="", roles=["triage"]),
            AreaObjective(area="investigation", objective="", roles=["endpoint", "network", "identity"]),
            AreaObjective(area="response_improvement", objective="", roles=["response_planner", "verification", "evidence_reporting"]),
            AreaObjective(area="applications_data", objective="", roles=["application_api"]),
        ],
    )
    root_task_1_id = "task-8821-root"
    root_key_1 = task_key(str(org_id), inc1, inc1_obj.idempotency_key)
    root_1 = insert_task(
        root_task_1_id, inc1, "main", "main_orchestrator",
        main_plan_1.model_dump_json(), status="completed",
        idempotency_key=root_key_1,
        completed_at=now - timedelta(minutes=9),
    )
    insert_scheduler_job(root_1, status="completed")

    # --- Area 1: alert_handling ---
    area_1_plan = AreaObjective(area="alert_handling", objective=inc1_obj.objective, roles=["triage"])
    area_1_task = insert_task(
        "task-8821-area-alert", inc1, "alert_handling", "area_orchestrator",
        area_1_plan.model_dump_json(), status="completed",
        parent_task_id=root_1.task_id,
        idempotency_key=task_key(root_1.task_id, "alert_handling"),
        completed_at=now - timedelta(minutes=8),
    )
    insert_scheduler_job(area_1_task, status="completed")

    # Specialist 1: triage
    triage_task = insert_task(
        "task-8821-spec-triage", inc1, "alert_handling", "triage",
        inc1_obj.objective, status="completed",
        parent_task_id=area_1_task.task_id,
        idempotency_key=task_key(area_1_task.task_id, "triage"),
        completed_at=now - timedelta(minutes=7),
    )
    insert_evidence(
        "ev-ws88-wazuh-100201", triage_task, "wazuh_siem",
        {
            "rule_id": "100201",
            "description": "Volume Shadow Copy Deletion via vssadmin.exe",
            "level": 12,
            "agent": "workstation-88.corp.internal",
            "src_ip": "10.0.10.88",
            "mitre": ["T1490"],
        },
        content_ref="wazuh://alerts/ALT-8821",
    )
    triage_result = SpecialistResult(
        status="completed",
        role="triage",
        tool_calls=(
            ToolCallRecord(tool_id="wazuh_alert_parser", status="success", evidence_count=1),
            ToolCallRecord(tool_id="mitre_technique_mapper", status="success", evidence_count=1),
        ),
        evidence_ids=("ev-ws88-wazuh-100201",),
        findings=(
            Finding(
                claim="Wazuh rule 100201 confirmed malicious shadow copy deletion on workstation-88 (MITRE T1490)",
                evidence_ids=("ev-ws88-wazuh-100201",),
            ),
        ),
        gaps=(),
        model=ModelRef(
            connection_id="conn-openai-direct",
            model="gpt-4o-mini",
            usage=ModelUsage(input_tokens=850, output_tokens=210, total_tokens=1060),
            cost_known=True,
            cost_micro_usd=318,
        ),
        execution_mode="tools_and_model",
    )
    triage_run = insert_agent_run(
        "run-8821-triage", triage_task, status="completed",
        model_name="gpt-4o-mini", model_connection_id="conn-openai-direct",
        result=triage_result.model_dump(mode="json"),
    )
    insert_scheduler_job(triage_task, status="completed", run_id=triage_run.run_id)

    # --- Area 2: investigation ---
    area_2_plan = AreaObjective(area="investigation", objective=inc1_obj.objective, roles=["endpoint", "network", "identity"])
    area_2_task = insert_task(
        "task-8821-area-inv", inc1, "investigation", "area_orchestrator",
        area_2_plan.model_dump_json(), status="completed",
        parent_task_id=root_1.task_id,
        idempotency_key=task_key(root_1.task_id, "investigation"),
        completed_at=now - timedelta(minutes=7),
    )
    insert_scheduler_job(area_2_task, status="completed")

    # Specialist 2: endpoint (completed)
    endpoint_task = insert_task(
        "task-8821-spec-endpoint", inc1, "investigation", "endpoint",
        inc1_obj.objective, status="completed",
        parent_task_id=area_2_task.task_id,
        idempotency_key=task_key(area_2_task.task_id, "endpoint"),
        completed_at=now - timedelta(minutes=5),
    )
    _ = insert_evidence(
        "ev-ws88-proc-4912", endpoint_task, "osquery_endpoint",
        {
            "pid": 4912,
            "name": "vssadmin.exe",
            "cmdline": "vssadmin.exe delete shadows /all /quiet",
            "parent_pid": 3108,
            "parent_name": "powershell.exe",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "user": "CORP\\alice.dev",
        },
        content_ref="osquery://workstation-88/processes/4912",
    )
    _ = insert_evidence(
        "ev-ws88-yara-lockbit", endpoint_task, "yara_memory_scanner",
        {
            "rule": "Ransomware_LockBit_Strings",
            "matched_strings": ["LockBit3.0", "All your files are encrypted", "restore-my-files.txt"],
            "target_pid": 3108,
        },
        content_ref="yara://workstation-88/memory/3108",
    )
    endpoint_result = SpecialistResult(
        status="completed",
        role="endpoint",
        tool_calls=(
            ToolCallRecord(tool_id="osquery_process_lineage", status="success", evidence_count=1),
            ToolCallRecord(tool_id="yara_memory_scanner", status="success", evidence_count=1),
        ),
        evidence_ids=("ev-ws88-proc-4912", "ev-ws88-yara-lockbit"),
        findings=(
            Finding(
                claim="Process lineage confirms malicious PowerShell (PID 3108) spawned vssadmin.exe (PID 4912) with LockBit 3.0 detonation payload",
                evidence_ids=("ev-ws88-proc-4912", "ev-ws88-yara-lockbit"),
            ),
        ),
        gaps=(),
        model=ModelRef(
            connection_id="conn-anthropic-prod",
            model="claude-3-5-sonnet",
            usage=ModelUsage(input_tokens=2340, output_tokens=580, total_tokens=2920),
            cost_known=True,
            cost_micro_usd=8760,
        ),
        execution_mode="tools_and_model",
    )
    endpoint_run = insert_agent_run(
        "run-8821-endpoint", endpoint_task, status="completed",
        model_name="claude-3-5-sonnet", model_connection_id="conn-anthropic-prod",
        result=endpoint_result.model_dump(mode="json"),
    )
    insert_scheduler_job(endpoint_task, status="completed", run_id=endpoint_run.run_id)

    # Peer Help Request: endpoint -> network
    help_req_1_id = "help-8821-net-smb"
    help_reason = "Correlate SMB egress traffic from workstation-88 (10.0.10.88) to Domain Controller DC01 (10.0.0.5) for lateral movement"
    db.execute(
        """
        INSERT OR REPLACE INTO orchestration_help_requests
        (org_id, help_request_id, incident_id, task_id, status, created_at, payload_json)
        VALUES (?, ?, ?, ?, 'assigned', ?, ?)
        """,
        (
            str(org_id),
            help_req_1_id,
            inc1,
            endpoint_task.task_id,
            (now - timedelta(minutes=4)).isoformat(),
            HelpRequest(
                org_id=str(org_id),
                incident_id=inc1,
                help_request_id=help_req_1_id,
                task_id=endpoint_task.task_id,
                requested_role="network",
                reason=help_reason,
                status="assigned",
                created_at=now - timedelta(minutes=4),
                updated_at=now,
            ).model_dump_json(),
        ),
    )
    db.execute(
        """
        INSERT OR REPLACE INTO orchestration_help_collaboration
        (org_id, help_request_id, incident_id, requester_task_id, target_role, objective_digest,
         expected_kinds_json, evidence_ids_json, created_at)
        VALUES (?, ?, ?, ?, 'network', ?, ?, ?, ?)
        """,
        (
            str(org_id),
            help_req_1_id,
            inc1,
            endpoint_task.task_id,
            objective_digest(help_reason),
            json.dumps(["network_pcap", "zeek_flow"]),
            json.dumps(["ev-ws88-proc-4912"]),
            (now - timedelta(minutes=4)).isoformat(),
        ),
    )

    # Delegated Area Orchestrator for Help Request
    help_area_key = help_task_key(root_1.task_id, help_req_1_id)
    help_area_plan = AreaObjective(
        area="investigation",
        objective=help_reason,
        roles=["network"],
        help_request_id=help_req_1_id,
    )
    help_area_task = insert_task(
        "task-8821-help-area-net", inc1, "investigation", "area_orchestrator",
        help_area_plan.model_dump_json(), status="completed",
        parent_task_id=root_1.task_id,
        idempotency_key=help_area_key,
        completed_at=now - timedelta(minutes=3),
    )
    insert_scheduler_job(help_area_task, status="completed")

    # Specialist 3: network (running)
    net_task = insert_task(
        "task-8821-spec-network", inc1, "investigation", "network",
        help_reason, status="running",
        parent_task_id=help_area_task.task_id,
        idempotency_key=task_key(help_area_task.task_id, "network"),
        started_at=now - timedelta(minutes=3),
    )
    insert_evidence(
        "ev-ws88-zeek-smb", net_task, "zeek_network_monitor",
        {
            "src_ip": "10.0.10.88",
            "dst_ip": "10.0.0.5",
            "dst_port": 445,
            "proto": "smb",
            "auth_account": "alice.dev",
            "named_pipe": "srvsvc",
            "bytes_out": 418290,
            "bytes_in": 12044,
        },
        content_ref="zeek://pcaps/flow-ws88-dc01-smb",
    )
    net_run = insert_agent_run(
        "run-8821-network", net_task, status="running",
        model_name="claude-3-5-sonnet", model_connection_id="conn-anthropic-prod",
    )
    insert_scheduler_job(net_task, status="running", run_id=net_run.run_id)

    # Specialist 4: identity (running)
    id_task = insert_task(
        "task-8821-spec-identity", inc1, "investigation", "identity",
        inc1_obj.objective, status="running",
        parent_task_id=area_2_task.task_id,
        idempotency_key=task_key(area_2_task.task_id, "identity"),
        started_at=now - timedelta(minutes=2),
    )
    insert_evidence(
        "ev-ws88-ad-logon", id_task, "windows_security_events",
        {
            "event_id": 4624,
            "logon_type": 3,
            "account": "CORP\\alice.dev",
            "workstation": "workstation-88",
            "auth_package": "Kerberos",
        },
        content_ref="winevt://security/4624/ws88",
    )
    id_run = insert_agent_run(
        "run-8821-identity", id_task, status="running",
        model_name="gpt-4o-mini", model_connection_id="conn-openai-direct",
    )
    insert_scheduler_job(id_task, status="running", run_id=id_run.run_id)

    # --- Area 3: response_improvement ---
    area_3_plan = AreaObjective(area="response_improvement", objective=inc1_obj.objective, roles=["response_planner", "verification", "evidence_reporting"])
    area_3_task = insert_task(
        "task-8821-area-resp", inc1, "response_improvement", "area_orchestrator",
        area_3_plan.model_dump_json(), status="completed",
        parent_task_id=root_1.task_id,
        idempotency_key=task_key(root_1.task_id, "response_improvement"),
        completed_at=now - timedelta(minutes=4),
    )
    insert_scheduler_job(area_3_task, status="completed")

    # Specialist 5: response_planner (waiting on human approval)
    resp_task = insert_task(
        "task-8821-spec-resp", inc1, "response_improvement", "response_planner",
        inc1_obj.objective, status="waiting",
        parent_task_id=area_3_task.task_id,
        idempotency_key=task_key(area_3_task.task_id, "response_planner"),
        started_at=now - timedelta(minutes=4),
    )
    insert_action(
        "act-8821-isolate", resp_task, "TOOL_ISOLATE",
        ["workstation-88.corp.internal"], status="proposed",
        inputs={
            "hostname": "workstation-88.corp.internal",
            "ip": "10.0.10.88",
            "reason": "Active LockBit 3.0 detonation and VSS shadow deletion. D14 human authorization requested.",
        },
        actor="response_planner_agent",
    )
    resp_run = insert_agent_run(
        "run-8821-response", resp_task, status="running",
        model_name="claude-3-5-sonnet", model_connection_id="conn-anthropic-prod",
    )
    insert_scheduler_job(resp_task, status="waiting", run_id=resp_run.run_id, recovery_reason="Awaiting human approval for host isolation")

    # Specialist 6: evidence_reporting (completed)
    rep_task = insert_task(
        "task-8821-spec-rep", inc1, "response_improvement", "evidence_reporting",
        inc1_obj.objective, status="completed",
        parent_task_id=area_3_task.task_id,
        idempotency_key=task_key(area_3_task.task_id, "evidence_reporting"),
        completed_at=now - timedelta(minutes=2),
    )
    insert_evidence(
        "ev-ws88-report", rep_task, "forensic_compiler",
        {
            "incident": "INC-8821",
            "target": "workstation-88.corp.internal",
            "status": "containment_proposed",
            "executive_summary": "High-confidence ransomware detonation on analyst endpoint. Network isolation proposed pending SOC operator approval.",
        },
        content_ref="terminus://reports/INC-8821-summary.json",
    )
    rep_result = SpecialistResult(
        status="completed",
        role="evidence_reporting",
        tool_calls=(
            ToolCallRecord(tool_id="forensic_report_compiler", status="success", evidence_count=1),
        ),
        evidence_ids=("ev-ws88-report",),
        findings=(
            Finding(
                claim="Incident executive brief compiled with forensic citations for SOC operator review",
                evidence_ids=("ev-ws88-report",),
            ),
        ),
        gaps=(),
        model=ModelRef(
            connection_id="conn-openai-direct",
            model="gpt-4o-mini",
            usage=ModelUsage(input_tokens=1100, output_tokens=320, total_tokens=1420),
            cost_known=True,
            cost_micro_usd=426,
        ),
        execution_mode="tools_and_model",
    )
    rep_run = insert_agent_run(
        "run-8821-reporting", rep_task, status="completed",
        model_name="gpt-4o-mini", model_connection_id="conn-openai-direct",
        result=rep_result.model_dump(mode="json"),
    )
    insert_scheduler_job(rep_task, status="completed", run_id=rep_run.run_id)

    # --- Area 4: applications_data ---
    area_4_plan = AreaObjective(area="applications_data", objective=inc1_obj.objective, roles=["application_api"])
    area_4_task = insert_task(
        "task-8821-area-app", inc1, "applications_data", "area_orchestrator",
        area_4_plan.model_dump_json(), status="completed",
        parent_task_id=root_1.task_id,
        idempotency_key=task_key(root_1.task_id, "applications_data"),
        completed_at=now - timedelta(minutes=4),
    )
    insert_scheduler_job(area_4_task, status="completed")

    # Specialist 7: application_api (completed)
    app_task = insert_task(
        "task-8821-spec-app", inc1, "applications_data", "application_api",
        inc1_obj.objective, status="completed",
        parent_task_id=area_4_task.task_id,
        idempotency_key=task_key(area_4_task.task_id, "application_api"),
        completed_at=now - timedelta(minutes=3),
    )
    insert_evidence(
        "ev-ws88-oauth-tokens", app_task, "oauth_gateway",
        {
            "user": "CORP\\alice.dev",
            "active_tokens": 2,
            "session_ids": ["sess-corp-9918", "sess-corp-9924"],
            "revocation_status": "queued_for_post_containment",
        },
        content_ref="oauth://sessions/alice.dev",
    )
    app_result = SpecialistResult(
        status="completed",
        role="application_api",
        tool_calls=(
            ToolCallRecord(tool_id="oauth_token_inspector", status="success", evidence_count=1),
        ),
        evidence_ids=("ev-ws88-oauth-tokens",),
        findings=(
            Finding(
                claim="Identified 2 active OAuth bearer tokens for alice.dev staged for automatic revocation",
                evidence_ids=("ev-ws88-oauth-tokens",),
            ),
        ),
        gaps=(),
        model=ModelRef(
            connection_id="conn-openai-direct",
            model="gpt-4o-mini",
            usage=ModelUsage(input_tokens=780, output_tokens=190, total_tokens=970),
            cost_known=True,
            cost_micro_usd=291,
        ),
        execution_mode="tools_and_model",
    )
    app_run = insert_agent_run(
        "run-8821-app", app_task, status="completed",
        model_name="gpt-4o-mini", model_connection_id="conn-openai-direct",
        result=app_result.model_dump(mode="json"),
    )
    insert_scheduler_job(app_task, status="completed", run_id=app_run.run_id)

    # =========================================================================
    # TREE 2: INC-8819 (Perimeter API Gateway Intrusion & Firewall Containment)
    # =========================================================================
    inc2 = "INC-8819"
    inc2_obj = IncidentObjective(
        objective="Investigate external SQL injection exploit and enforce perimeter boundary firewall drop on attacker C2 IP 198.51.100.42",
        areas=["investigation", "response_improvement"],
        idempotency_key="inc-8819-root",
    )
    main_plan_2 = MainObjective(
        request=inc2_obj,
        plans=[
            AreaObjective(area="investigation", objective="", roles=["network"]),
            AreaObjective(area="response_improvement", objective="", roles=["response_planner", "verification"]),
        ],
    )
    root_2 = insert_task(
        "task-8819-root", inc2, "main", "main_orchestrator",
        main_plan_2.model_dump_json(), status="completed",
        idempotency_key=task_key(str(org_id), inc2, inc2_obj.idempotency_key),
        completed_at=now - timedelta(minutes=25),
    )
    insert_scheduler_job(root_2, status="completed")

    # Area: investigation
    area_2_1_plan = AreaObjective(area="investigation", objective=inc2_obj.objective, roles=["network"])
    area_2_1_task = insert_task(
        "task-8819-area-inv", inc2, "investigation", "area_orchestrator",
        area_2_1_plan.model_dump_json(), status="completed",
        parent_task_id=root_2.task_id,
        idempotency_key=task_key(root_2.task_id, "investigation"),
        completed_at=now - timedelta(minutes=24),
    )
    insert_scheduler_job(area_2_1_task, status="completed")

    # Specialist: network
    gw_net_task = insert_task(
        "task-8819-spec-net", inc2, "investigation", "network",
        inc2_obj.objective, status="completed",
        parent_task_id=area_2_1_task.task_id,
        idempotency_key=task_key(area_2_1_task.task_id, "network"),
        completed_at=now - timedelta(minutes=22),
    )
    insert_evidence(
        "ev-gw-suricata-9901", gw_net_task, "suricata_ids",
        {
            "src_ip": "198.51.100.42",
            "dst_ip": "198.51.100.1",
            "dst_port": 443,
            "http_uri": "/api/v1/customers?id=1%27%20OR%201=1--",
            "alert_signature": "ET WEB_SPECIFIC_APPS SQL Injection in Customers API",
        },
        content_ref="suricata://eve/ALT-8819",
    )
    insert_evidence(
        "ev-gw-vt-intel", gw_net_task, "virustotal_threat_intel",
        {
            "indicator": "198.51.100.42",
            "reputation_score": 92,
            "category": "c2_server",
            "tags": ["cobalt_strike", "scanner", "tor_exit"],
        },
        content_ref="cti://virustotal/ip/198.51.100.42",
    )
    gw_net_result = SpecialistResult(
        status="completed",
        role="network",
        tool_calls=(
            ToolCallRecord(tool_id="suricata_flow_inspector", status="success", evidence_count=1),
            ToolCallRecord(tool_id="threat_intel_virustotal", status="success", evidence_count=1),
        ),
        evidence_ids=("ev-gw-suricata-9901", "ev-gw-vt-intel"),
        findings=(
            Finding(
                claim="Attacker IP 198.51.100.42 executed active SQLi probe against /api/v1/customers; verified CobaltStrike C2 reputation (92/100)",
                evidence_ids=("ev-gw-suricata-9901", "ev-gw-vt-intel"),
            ),
        ),
        gaps=(),
        model=ModelRef(
            connection_id="conn-deepseek-direct",
            model="deepseek-r1",
            usage=ModelUsage(input_tokens=1890, output_tokens=450, total_tokens=2340, reasoning_tokens=310),
            cost_known=True,
            cost_micro_usd=2100,
        ),
        execution_mode="tools_and_model",
    )
    gw_net_run = insert_agent_run(
        "run-8819-network", gw_net_task, status="completed",
        model_name="deepseek-r1", model_connection_id="conn-deepseek-direct",
        result=gw_net_result.model_dump(mode="json"),
    )
    insert_scheduler_job(gw_net_task, status="completed", run_id=gw_net_run.run_id)

    # Area: response_improvement
    area_2_2_plan = AreaObjective(area="response_improvement", objective=inc2_obj.objective, roles=["response_planner", "verification"])
    area_2_2_task = insert_task(
        "task-8819-area-resp", inc2, "response_improvement", "area_orchestrator",
        area_2_2_plan.model_dump_json(), status="completed",
        parent_task_id=root_2.task_id,
        idempotency_key=task_key(root_2.task_id, "response_improvement"),
        completed_at=now - timedelta(minutes=20),
    )
    insert_scheduler_job(area_2_2_task, status="completed")

    # Specialist: response_planner (containment verified)
    gw_resp_task = insert_task(
        "task-8819-spec-resp", inc2, "response_improvement", "response_planner",
        inc2_obj.objective, status="completed",
        parent_task_id=area_2_2_task.task_id,
        idempotency_key=task_key(area_2_2_task.task_id, "response_planner"),
        completed_at=now - timedelta(minutes=18),
    )
    insert_action(
        "act-8819-firewall", gw_resp_task, "TOOL_FIREWALL",
        ["198.51.100.42"], status="verified",
        inputs={
            "ip": "198.51.100.42",
            "direction": "ingress",
            "action": "DROP",
            "reason": "Verified C2 and SQLi attack source. Tier-1 perimeter gateway isolation avoided; IP block verified.",
        },
        actor="auto_containment_engine",
        outputs={"rule_id": "fw-block-198-51-100-42", "status": "active", "drop_count": 142},
    )
    gw_resp_run = insert_agent_run(
        "run-8819-response", gw_resp_task, status="completed",
        model_name="gpt-4o-mini", model_connection_id="conn-openai-direct",
    )
    insert_scheduler_job(gw_resp_task, status="completed", run_id=gw_resp_run.run_id)

    # =========================================================================
    # TREE 3: INC-8825 (Kerberoasting on DC01 - Active Directory)
    # =========================================================================
    inc3 = "INC-8825"
    inc3_obj = IncidentObjective(
        objective="Investigate Kerberoasting SPN ticket request on Active Directory Root Domain Controller dc01.corp.internal",
        areas=["alert_handling", "investigation"],
        idempotency_key="inc-8825-root",
    )
    main_plan_3 = MainObjective(
        request=inc3_obj,
        plans=[
            AreaObjective(area="alert_handling", objective="", roles=["triage"]),
            AreaObjective(area="investigation", objective="", roles=["identity"]),
        ],
    )
    root_3 = insert_task(
        "task-8825-root", inc3, "main", "main_orchestrator",
        main_plan_3.model_dump_json(), status="completed",
        idempotency_key=task_key(str(org_id), inc3, inc3_obj.idempotency_key),
        completed_at=now - timedelta(minutes=30),
    )
    insert_scheduler_job(root_3, status="completed")

    # Area: investigation
    area_3_1_plan = AreaObjective(area="investigation", objective=inc3_obj.objective, roles=["identity"])
    area_3_1_task = insert_task(
        "task-8825-area-inv", inc3, "investigation", "area_orchestrator",
        area_3_1_plan.model_dump_json(), status="completed",
        parent_task_id=root_3.task_id,
        idempotency_key=task_key(root_3.task_id, "investigation"),
        completed_at=now - timedelta(minutes=28),
    )
    insert_scheduler_job(area_3_1_task, status="completed")

    # Specialist: identity (running)
    dc_id_task = insert_task(
        "task-8825-spec-id", inc3, "investigation", "identity",
        inc3_obj.objective, status="running",
        parent_task_id=area_3_1_task.task_id,
        idempotency_key=task_key(area_3_1_task.task_id, "identity"),
        started_at=now - timedelta(minutes=25),
    )
    insert_evidence(
        "ev-dc01-ad-4769", dc_id_task, "active_directory_security_events",
        {
            "event_id": 4769,
            "service_name": "MSSQLSvc/db-prod.internal:1433",
            "ticket_encryption_type": "0x17 (RC4-HMAC)",
            "client_address": "10.0.10.42",
            "client_name": "bob.analyst",
            "status": "0x0",
        },
        content_ref="winevt://dc01/security/4769",
    )
    dc_id_run = insert_agent_run(
        "run-8825-identity", dc_id_task, status="running",
        model_name="claude-3-5-sonnet", model_connection_id="conn-anthropic-prod",
    )
    insert_scheduler_job(dc_id_task, status="running", run_id=dc_id_run.run_id)

    return {
        "status": "seeded",
        "org_id": org_id,
        "incidents_seeded": [inc1, inc2, inc3],
    }
