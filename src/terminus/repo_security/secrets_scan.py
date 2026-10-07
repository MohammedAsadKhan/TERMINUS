"""Secret scanning engine across repository trees and commit history with zero raw secret storage."""

from __future__ import annotations

import hashlib
import math
import re
import subprocess
from pathlib import Path
from typing import Any

from terminus.repo_security.sandbox import safe_walk_files

# Regex Rules for Secret Detection
_SECRET_RULES: list[tuple[str, str, re.Pattern[str], str]] = [
    # (rule_id, description, pattern, severity)
    (
        "aws_access_key",
        "AWS Access Key ID",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "critical",
    ),
    (
        "github_token",
        "GitHub Personal Access Token",
        re.compile(r"\b(?:ghp_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{22,})\b"),
        "critical",
    ),
    (
        "slack_token",
        "Slack Bot/User/Webhook Token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
        "high",
    ),
    (
        "google_api_key",
        "Google API Key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "high",
    ),
    (
        "private_key_block",
        "Unencrypted Private Key Block",
        re.compile(r"-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----"),
        "critical",
    ),
    (
        "jwt_token",
        "JSON Web Token (JWT)",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "medium",
    ),
    (
        "generic_high_entropy_secret",
        "Generic High-Entropy Credential Assignment",
        re.compile(r"(?i)\b(?:api[_-]?key|client[_-]?secret|secret|password|passwd|auth[_-]?token)\s*[:=]\s*[\"']([A-Za-z0-9+/=_-]{16,})[\"']"),
        "high",
    ),
]

_IGNORE_MARKER = "terminus:ignore"
_IGNORED_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot",
    ".zip", ".tar", ".gz", ".7z", ".pdf", ".exe", ".dll", ".so", ".dylib", ".pyc",
}


def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


def _redacted_preview(raw_value: str) -> str:
    cleaned = raw_value.strip()
    if len(cleaned) <= 4:
        return "[REDACTED]"
    return f"{cleaned[:4]}...[REDACTED]"


def _compute_fingerprint(rule_id: str, file_path: str, raw_value: str) -> str:
    val_hash = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
    combined = f"{rule_id}:{file_path}:{val_hash}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def scan_line(
    line: str,
    file_path: str,
    line_number: int | None = None,
    commit_sha: str | None = None,
) -> list[dict[str, Any]]:
    """Scan a single text line against secret rules, honoring suppression markers."""
    if _IGNORE_MARKER in line:
        return []

    findings: list[dict[str, Any]] = []

    for rule_id, desc, pattern, severity in _SECRET_RULES:
        for match in pattern.finditer(line):
            raw_match = match.group(1) if match.groups() else match.group(0)

            # Filter low entropy false positives for generic matches
            if rule_id == "generic_high_entropy_secret":
                if _shannon_entropy(raw_match) < 3.2:
                    continue

            preview = _redacted_preview(raw_match)
            fingerprint = _compute_fingerprint(rule_id, file_path, raw_match)

            findings.append({
                "category": "secret",
                "rule": rule_id,
                "severity": severity,
                "file": file_path,
                "line": line_number,
                "commit_sha": commit_sha,
                "fingerprint": fingerprint,
                "preview": preview,
                "details": {
                    "description": desc,
                    "matched_rule": rule_id,
                    "suppression_available": f"Add '{_IGNORE_MARKER}' to this line to suppress",
                },
            })

    return findings


def scan_tree_secrets(root: Path, current_commit: str) -> list[dict[str, Any]]:
    """Scan all files in the current working tree."""
    all_findings: list[dict[str, Any]] = []

    for rel_path, file_path in safe_walk_files(root):
        if file_path.suffix.lower() in _IGNORED_EXTENSIONS:
            continue

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_idx, line in enumerate(f, start=1):
                    findings = scan_line(line, rel_path, line_number=line_idx, commit_sha=current_commit)
                    all_findings.extend(findings)
        except (OSError, UnicodeError):
            continue

    return all_findings


def scan_history_secrets(root: Path, max_commits: int = 500) -> list[dict[str, Any]]:
    """Scan git history for added lines containing secrets in past commits."""
    history_findings: list[dict[str, Any]] = []

    cmd = [
        "git",
        "-C", str(root),
        "log",
        f"-n{max_commits}",
        "-p",
        "--unified=0",
        "--no-color",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=60,
            check=False,
        )
        if proc.returncode != 0:
            return []
    except (subprocess.TimeoutExpired, OSError):
        return []

    current_commit: str | None = None
    current_file: str | None = None

    for raw_line in proc.stdout.splitlines():
        if raw_line.startswith("commit "):
            current_commit = raw_line.split()[1]
            current_file = None
            continue

        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:].strip()
            continue

        if raw_line.startswith("+") and not raw_line.startswith("+++"):
            line_content = raw_line[1:]
            if current_file:
                findings = scan_line(line_content, current_file, commit_sha=current_commit)
                for f in findings:
                    f["details"]["source"] = "git_history"
                history_findings.extend(findings)

    return history_findings


def scan_repository_secrets(root: Path, current_commit: str) -> list[dict[str, Any]]:
    """Scan both current tree and past git history, deduplicating findings."""
    tree_findings = scan_tree_secrets(root, current_commit)
    history_findings = scan_history_secrets(root)

    seen_fingerprints = set()
    combined: list[dict[str, Any]] = []

    for f in tree_findings + history_findings:
        fp = f["fingerprint"]
        if fp not in seen_fingerprints:
            seen_fingerprints.add(fp)
            combined.append(f)

    return combined
