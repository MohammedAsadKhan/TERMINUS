"""Suspicious commit and repository anomaly inspection rules."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from terminus.repo_security.sandbox import safe_walk_files

_BASE64_LONG_BLOB = re.compile(r"(?:[A-Za-z0-9+/]{4}){125,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
_SUSPICIOUS_HOOKS = {"preinstall", "postinstall", "preuninstall", "postuninstall"}
_BINARY_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".elf", ".bin", ".wasm"}


def scan_suspicious_patterns(root: Path, current_commit: str) -> list[dict[str, Any]]:
    """Scan repository for suspicious workflow changes, install hooks, binaries, and obfuscation."""
    findings: list[dict[str, Any]] = []

    for rel_path, file_path in safe_walk_files(root):
        rel_posix = rel_path.replace("\\", "/")
        ext = file_path.suffix.lower()

        # 1. CI/CD workflow modification
        if rel_posix.startswith(".github/workflows/") or rel_posix in (".gitlab-ci.yml", ".circleci/config.yml"):
            fp = hashlib.sha256(f"suspicious_commit:workflow:{rel_posix}:{current_commit}".encode("utf-8")).hexdigest()
            findings.append({
                "category": "suspicious_commit",
                "rule": "ci_workflow_modification",
                "severity": "medium",
                "file": rel_posix,
                "line": None,
                "commit_sha": current_commit,
                "fingerprint": fp,
                "preview": f"CI/CD workflow configured in {rel_posix}",
                "details": {
                    "review_needed": True,
                    "description": "CI/CD workflow modified or introduced; verify build steps and secret permissions",
                },
            })

        # 2. Package install lifecycle hooks
        if file_path.name.lower() == "package.json":
            try:
                pkg_data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
                scripts = pkg_data.get("scripts", {})
                if isinstance(scripts, dict):
                    for hook in _SUSPICIOUS_HOOKS:
                        if hook in scripts:
                            hook_cmd = str(scripts[hook])
                            fp = hashlib.sha256(
                                f"suspicious_commit:install_hook:{rel_posix}:{hook}:{hook_cmd}".encode("utf-8")
                            ).hexdigest()
                            findings.append({
                                "category": "suspicious_commit",
                                "rule": f"suspicious_install_script_{hook}",
                                "severity": "medium",
                                "file": rel_posix,
                                "line": None,
                                "commit_sha": current_commit,
                                "fingerprint": fp,
                                "preview": f"npm lifecycle hook '{hook}': {hook_cmd[:50]}",
                                "details": {
                                    "review_needed": True,
                                    "hook_name": hook,
                                    "hook_command": hook_cmd,
                                    "description": f"Package declares '{hook}' script that executes automatically on install",
                                },
                            })
            except Exception:
                pass

        # 3. Binary executable file added
        if ext in _BINARY_EXTENSIONS:
            fp = hashlib.sha256(f"suspicious_commit:binary:{rel_posix}:{current_commit}".encode("utf-8")).hexdigest()
            findings.append({
                "category": "suspicious_commit",
                "rule": "binary_file_in_tree",
                "severity": "medium",
                "file": rel_posix,
                "line": None,
                "commit_sha": current_commit,
                "fingerprint": fp,
                "preview": f"Compiled binary {rel_posix} present in repository",
                "details": {
                    "review_needed": True,
                    "file_extension": ext,
                    "description": "Compiled binary or shared library committed to repository",
                },
            })

        # 4. Large Base64 blobs (possible payload obfuscation)
        if ext in (".py", ".js", ".ts", ".sh", ".ps1", ".php", ".rb"):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                for match in _BASE64_LONG_BLOB.finditer(content):
                    blob = match.group(0)
                    if len(blob) >= 500:
                        fp = hashlib.sha256(
                            f"suspicious_commit:base64_blob:{rel_posix}:{hashlib.sha256(blob.encode()).hexdigest()}".encode("utf-8")
                        ).hexdigest()
                        findings.append({
                            "category": "suspicious_commit",
                            "rule": "large_base64_blob",
                            "severity": "medium",
                            "file": rel_posix,
                            "line": None,
                            "commit_sha": current_commit,
                            "fingerprint": fp,
                            "preview": f"Large Base64 blob ({len(blob)} chars) in {rel_posix}",
                            "details": {
                                "review_needed": True,
                                "blob_length": len(blob),
                                "description": "Large contiguous base64 string detected in source code",
                            },
                        })
            except Exception:
                pass

    return findings
