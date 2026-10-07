"""Dependency scanning and OSV vulnerability resolution engine."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from terminus.http import create_async_client
from terminus.repo_security.sandbox import safe_walk_files

_PINNED_REQ_PATTERN = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.-]+)")
_UNPINNED_REQ_PATTERN = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*([><=~!].*)?$")


def parse_requirements_txt(file_path: Path, rel_path: str) -> list[dict[str, Any]]:
    """Parse python requirements.txt into component records."""
    components: list[dict[str, Any]] = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    for line in content.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue

        pinned = _PINNED_REQ_PATTERN.match(line)
        if pinned:
            name, version = pinned.group(1), pinned.group(2)
            components.append({
                "ecosystem": "PyPI",
                "name": name,
                "version": version,
                "source_file": rel_path,
                "pinned": True,
            })
        else:
            unpinned = _UNPINNED_REQ_PATTERN.match(line)
            if unpinned:
                name = unpinned.group(1)
                components.append({
                    "ecosystem": "PyPI",
                    "name": name,
                    "version": "unpinned",
                    "source_file": rel_path,
                    "pinned": False,
                })

    return components


def parse_package_lock_json(file_path: Path, rel_path: str) -> list[dict[str, Any]]:
    """Parse npm package-lock.json (v2/v3 packages map and v1 dependencies map)."""
    components: list[dict[str, Any]] = []
    try:
        data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
    except (OSError, json.JSONDecodeError):
        return []

    # v2 / v3 packages map
    if "packages" in data and isinstance(data["packages"], dict):
        for pkg_path, pkg_info in data["packages"].items():
            if not pkg_path or not isinstance(pkg_info, dict):
                continue
            name = pkg_info.get("name")
            if not name and "node_modules/" in pkg_path:
                name = pkg_path.split("node_modules/")[-1]
            version = pkg_info.get("version")
            if name and version:
                components.append({
                    "ecosystem": "npm",
                    "name": str(name),
                    "version": str(version),
                    "source_file": rel_path,
                    "pinned": True,
                })

    # v1 fallback dependencies map
    elif "dependencies" in data and isinstance(data["dependencies"], dict):
        for name, info in data["dependencies"].items():
            if isinstance(info, dict) and "version" in info:
                components.append({
                    "ecosystem": "npm",
                    "name": str(name),
                    "version": str(info["version"]),
                    "source_file": rel_path,
                    "pinned": True,
                })

    return components


def extract_repo_components(root: Path) -> list[dict[str, Any]]:
    """Find and parse all manifest files in the repository."""
    all_components: list[dict[str, Any]] = []

    for rel_path, file_path in safe_walk_files(root):
        name = file_path.name.lower()
        if name == "requirements.txt" or name.endswith("-requirements.txt"):
            all_components.extend(parse_requirements_txt(file_path, rel_path))
        elif name == "package-lock.json":
            all_components.extend(parse_package_lock_json(file_path, rel_path))

    return all_components


async def query_osv_vulnerabilities(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Query OSV batch API for vulnerabilities in pinned dependencies."""
    pinned_comps = [c for c in components if c.get("pinned") and c.get("version") != "unpinned"]
    if not pinned_comps:
        return []

    offline_fixture = os.getenv("TERMINUS_OSV_OFFLINE_FIXTURE")
    if offline_fixture and os.path.exists(offline_fixture):
        try:
            with open(offline_fixture, "r", encoding="utf-8") as f:
                fixture_data = json.load(f)
                return fixture_data.get("findings", [])
        except Exception:
            pass

    queries = [
        {
            "package": {"name": c["name"], "ecosystem": c["ecosystem"]},
            "version": c["version"],
        }
        for c in pinned_comps
    ]

    findings: list[dict[str, Any]] = []

    try:
        async with create_async_client(timeout=15.0) as client:
            resp = await client.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": queries},
            )
            if resp.status_code != 200:
                return []

            results = resp.json().get("results", [])
            for comp, res in zip(pinned_comps, results):
                vulns = res.get("vulns", [])
                for vuln in vulns:
                    vuln_id = vuln.get("id", "UNKNOWN-VULN")
                    aliases = vuln.get("aliases", [])
                    summary = vuln.get("summary", "")
                    details = vuln.get("details", "")

                    cve_aliases = [a for a in aliases if a.startswith("CVE-")]
                    rule_label = cve_aliases[0] if cve_aliases else vuln_id

                    # Derive severity
                    severity = "high"
                    database_specific = vuln.get("database_specific", {})
                    if "severity" in database_specific:
                        raw_sev = str(database_specific["severity"]).lower()
                        if raw_sev in ("critical", "high", "medium", "low"):
                            severity = raw_sev

                    fingerprint = hashlib.sha256(
                        f"dependency:{comp['name']}:{comp['version']}:{vuln_id}".encode("utf-8")
                    ).hexdigest()

                    findings.append({
                        "category": "dependency",
                        "rule": f"vulnerable_dependency_{rule_label}",
                        "severity": severity,
                        "file": comp["source_file"],
                        "line": None,
                        "commit_sha": None,
                        "fingerprint": fingerprint,
                        "preview": f"{comp['name']}=={comp['version']} affected by {rule_label}",
                        "details": {
                            "vulnerability_id": vuln_id,
                            "cve_aliases": cve_aliases,
                            "summary": summary,
                            "package_name": comp["name"],
                            "package_version": comp["version"],
                            "ecosystem": comp["ecosystem"],
                            "advisory_url": f"https://osv.dev/vulnerability/{vuln_id}",
                        },
                    })

    except Exception:
        # Fail gracefully on network isolation / timeouts
        return []

    return findings


async def scan_repository_dependencies(root: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract components and scan for vulnerable dependencies via OSV."""
    components = extract_repo_components(root)
    findings = await query_osv_vulnerabilities(components)

    # Also add info findings for unpinned dependencies
    for comp in components:
        if not comp.get("pinned"):
            fp = hashlib.sha256(
                f"unpinned_dependency:{comp['source_file']}:{comp['name']}".encode("utf-8")
            ).hexdigest()
            findings.append({
                "category": "dependency",
                "rule": "unpinned_dependency",
                "severity": "info",
                "file": comp["source_file"],
                "line": None,
                "commit_sha": None,
                "fingerprint": fp,
                "preview": f"Unpinned dependency '{comp['name']}' in {comp['source_file']}",
                "details": {
                    "package_name": comp["name"],
                    "ecosystem": comp["ecosystem"],
                    "recommendation": "Pin exact dependency version to prevent supply chain drift",
                },
            })

    return components, findings
