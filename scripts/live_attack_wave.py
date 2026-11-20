# File name: live_attack_wave.py
# Author: Team LARP
# Revision date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Stream a staged multi-host attack wave into a local loopback TERMINUS instance for live demos.

"""Stream a staged multi-host attack wave into a local loopback TERMINUS server.

Usage (from the repository root while TERMINUS is running on http://127.0.0.1:8000):

    uv run --frozen python scripts/live_attack_wave.py

Options:
    --base-url URL       Loopback TERMINUS base URL (default: http://127.0.0.1:8000)
    --seed-baseline      Configure the high-priority containment gate and send 2 baseline alerts
    --stream             Stream the 6-stage attack wave over ~34 seconds (fires approval gates)
    --all                Run --seed-baseline followed by --stream (default when no mode is passed)
    --delay-scale FLOAT  Scale pacing between wave alerts (default: 1.0)
"""

# ruff: noqa: INP001, S310 -- standalone loopback-only demo script

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_ORG_ID = "org-terminus-demo"
DEFAULT_EMAIL = "admin@terminus.local"
DEFAULT_PASSWORD = "Password123!"  # noqa: S105 -- documented local loopback evaluation account


def validate_loopback(base_url: str) -> str:
    """Restrict demo traffic to loopback origins so credentials never leave localhost."""
    parsed = urllib.parse.urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or not parsed.port
    ):
        raise ValueError("Demo --base-url must be a loopback origin with an explicit port (e.g. http://127.0.0.1:8000)")
    return f"{parsed.scheme}://{parsed.netloc}"


def api_req(
    base_url: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    """Send one JSON request and return the status with the decoded body.

    An HTTP error status is returned with its raw text instead of raising, so callers can
    report it and continue. Connection failures and timeouts still raise.
    """
    url = f"{base_url}{path}"
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        return exc.code, raw


def login_headers(base_url: str, email: str, password: str, org_id: str) -> dict[str, str]:
    """Sign in and return the bearer and organization headers; fail if no token comes back."""
    code, resp = api_req(base_url, "POST", "/auth/login", {"email": email, "password": password})
    if code != 200 or not isinstance(resp, dict) or "session_token" not in resp:
        raise RuntimeError(f"Login failed ({code}): {resp}")
    return {"Authorization": f"Bearer {resp['session_token']}", "X-Org-ID": org_id}


def configure_containment_gate(base_url: str, headers: dict[str, str]) -> None:
    """Ensure the gated containment workflow evaluates ahead of Slack-only triage on critical alerts."""
    # Isolation sits behind the human approval node, so containment waits for an admin
    # decision instead of running automatically.
    wf_body = {
        "id": "wf-ransomware-containment",
        "name": "Critical Threat Containment Gate",
        "enabled": True,
        "priority": 10,
        "nodes": [
            {"id": "n1", "type": "trigger_wazuh", "label": "Alert Trigger", "config": {"min_level": 12}, "x": 0, "y": 0},
            {"id": "n2", "type": "condition_severity", "label": "Severity >= 12", "config": {"min_level": 12}, "x": 280, "y": 0},
            {
                "id": "n3",
                "type": "condition_approval",
                "label": "Human Approval Gate",
                "config": {
                    "required_role": "admin",
                    "prompt_message": "Authorize host containment for critical threat activity on impacted banking endpoint.",
                    "timeout_seconds": 300,
                },
                "x": 560,
                "y": 0,
            },
            {"id": "n4", "type": "tool_isolate", "label": "Isolate Host", "config": {}, "x": 840, "y": 0},
            {"id": "n5", "type": "tool_slack", "label": "Notify #soc-containment", "config": {"channel": "#soc-containment"}, "x": 1120, "y": 0},
        ],
        "edges": [
            {"id": "e1", "source": "n1", "target": "n2", "source_handle": "default"},
            {"id": "e2", "source": "n2", "target": "n3", "source_handle": "true"},
            {"id": "e3", "source": "n3", "target": "n4", "source_handle": "true"},
            {"id": "e4", "source": "n4", "target": "n5", "source_handle": "default"},
        ],
    }
    # Update in place first so a re-run does not create a duplicate; create only if absent.
    code, resp = api_req(base_url, "PUT", "/workflows/wf-ransomware-containment", wf_body, headers)
    if code == 404:
        code, resp = api_req(base_url, "POST", "/workflows", wf_body, headers)
    print(f"[setup] containment gate workflow -> HTTP {code}", flush=True)
    if code not in {200, 201}:
        print(f"[warn] workflow configuration response: {resp}", flush=True)


def send_alert(base_url: str, headers: dict[str, str], alert: dict[str, Any], run_tag: str) -> None:
    """Post one synthetic alert and print its status, severity, and analysis mode.

    The run tag is appended to the alert id so repeating the demo is not rejected as a
    duplicate. A failed post is printed but does not stop the wave.
    """
    payload = dict(alert)
    payload["id"] = f"{alert['id']}-{run_tag}"
    t0 = time.time()
    code, resp = api_req(base_url, "POST", "/wazuh", payload, headers)
    dt = time.time() - t0
    sev = resp.get("verdict", {}).get("severity", "?") if isinstance(resp, dict) else "?"
    mode = resp.get("verdict", {}).get("analysis_mode", "?") if isinstance(resp, dict) else "?"
    print(f"[wave] {payload['id']} -> HTTP {code} ({dt:.1f}s) sev={sev} mode={mode}", flush=True)


# All alerts below are synthetic. Source addresses come from the documentation ranges
# reserved for examples or from private ranges, so none point at a real host.
BASELINE_ALERTS: list[dict[str, Any]] = [
    {
        "id": "bank-base-01",
        "rule_id": 5730,
        "level": 7,
        "description": "External Reconnaissance & SYN Port Sweep on Banking Edge (T1046)",
        "mitre": "T1046",
        "src_ip": "198.51.100.77",
        "agent_name": "vpn-edge-01.corp.internal",
        "full_log": "NOTICE: Sequential TCP SYN sweep across ports 22, 443, 3389, and 8443 from external host 198.51.100.77 targeting vpn-edge-01.corp.internal.",
    },
    {
        "id": "bank-base-02",
        "rule_id": 5710,
        "level": 8,
        "description": "Credential Stuffing Burst Against Retail Banking Gateway (T1110)",
        "mitre": "T1110",
        "src_ip": "198.51.100.42",
        "agent_name": "api-gateway.terminus.bank",
        "full_log": "WARNING: 48 failed authentication attempts in 30 seconds for privileged API accounts from 198.51.100.42 against api-gateway.terminus.bank.",
    },
]

# Each entry is the number of seconds after the wave starts, then the alert to send. Stages
# 3, 5 and 6 are level 15, above the containment gate's minimum level of 12.
LIVE_WAVE: list[tuple[float, dict[str, Any]]] = [
    (
        2.0,
        {
            "id": "bank-wave-01",
            "rule_id": 5715,
            "level": 11,
            "description": "SQL Injection & Account Table Extraction Probe on Banking Portal (T1190)",
            "mitre": "T1190",
            "src_ip": "203.0.113.19",
            "agent_name": "api-gateway.terminus.bank",
            "full_log": "HIGH: Malicious SQL union payload intercepted from 203.0.113.19 targeting /api/v2/accounts/search on api-gateway.terminus.bank.",
        },
    ),
    (
        7.5,
        {
            "id": "bank-wave-02",
            "rule_id": 5720,
            "level": 11,
            "description": "Obfuscated PowerShell Download Cradle & Process Injection (T1059.001)",
            "mitre": "T1059.001",
            "src_ip": "10.0.10.88",
            "agent_name": "workstation-88.corp.internal",
            "full_log": "HIGH: powershell.exe -enc SQBFAFgA executed hidden staging loader on workstation-88.corp.internal connecting outbound to 198.51.100.99.",
        },
    ),
    (
        13.5,
        {
            "id": "bank-wave-03",
            "rule_id": 100201,
            "level": 15,
            "description": "Volume Shadow Copy Deletion & Ransomware Precursor (vssadmin.exe)",
            "mitre": "T1490",
            "src_ip": "198.51.100.99",
            "agent_name": "workstation-88.corp.internal",
            "full_log": "CRITICAL: vssadmin.exe delete shadows /all /quiet spawned by powershell.exe (PID 4912) on workstation-88.corp.internal with active C2 beacon to 198.51.100.99.",
        },
    ),
    (
        20.0,
        {
            "id": "bank-wave-04",
            "rule_id": 5725,
            "level": 10,
            "description": "Active Directory Kerberoasting SPN Ticket Harvest (T1558.003)",
            "mitre": "T1558.003",
            "src_ip": "10.0.10.15",
            "agent_name": "dc01.corp.internal",
            "full_log": "HIGH: Abnormal burst of RC4 Kerberos TGS-REQ ticket requests targeting core banking service principals on dc01.corp.internal.",
        },
    ),
    (
        26.5,
        {
            "id": "bank-wave-05",
            "rule_id": 100202,
            "level": 15,
            "description": "LSASS Credential Dumping & Lateral SMB Pivot Attempt (T1003.001)",
            "mitre": "T1003.001",
            "src_ip": "203.0.113.44",
            "agent_name": "payroll-srv.internal",
            "full_log": "CRITICAL: procdump.exe accessed lsass.exe memory on workstation-88.corp.internal followed by authenticated SMB pivot attempt to payroll-srv.internal (10.5.0.100).",
        },
    ),
    (
        34.0,
        {
            "id": "bank-wave-06",
            "rule_id": 100099,
            "level": 15,
            "description": "Core Treasury Key Access & Exfiltration Staging Alert (T1552)",
            "mitre": "T1552",
            "src_ip": "198.51.100.99",
            "agent_name": "bank-core-ledger-01",
            "full_log": "CRITICAL: Unauthorized access attempt against /bank/api/admin/treasury-keys on bank-core-ledger-01 correlated with external C2 host 198.51.100.99.",
        },
    ),
]


def main() -> None:
    """Parse options, check the target is loopback, sign in, then run the chosen stages."""
    parser = argparse.ArgumentParser(description="Stream a staged attack wave into a local loopback TERMINUS server.")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("TERMINUS_BASE_URL", DEFAULT_BASE_URL),
        help=f"Loopback TERMINUS base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument("--org-id", default=DEFAULT_ORG_ID, help=f"Target organization ID (default: {DEFAULT_ORG_ID})")
    parser.add_argument("--email", default=DEFAULT_EMAIL, help=f"Local admin email (default: {DEFAULT_EMAIL})")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="Local admin password")
    parser.add_argument("--seed-baseline", action="store_true", help="Configure approval gate and send 2 baseline alerts")
    parser.add_argument("--stream", action="store_true", help="Stream the 6-stage attack wave over ~34 seconds")
    parser.add_argument("--all", action="store_true", help="Run baseline setup followed immediately by the live wave")
    parser.add_argument("--delay-scale", type=float, default=1.0, help="Multiply wave delays (e.g. 0.5 for faster, 1.5 for slower)")
    args = parser.parse_args()

    # Validate before any request so the demo password is never sent off this machine.
    try:
        base_url = validate_loopback(args.base_url)
    except ValueError as exc:
        parser.error(str(exc))

    # With no mode flag, both stages run; --all is the explicit spelling of the same thing.
    run_baseline = args.seed_baseline or args.all or (not args.seed_baseline and not args.stream)
    run_stream = args.stream or args.all or (not args.seed_baseline and not args.stream)
    # Short per-run suffix that keeps alert ids unique across repeated demo runs.
    run_tag = str(int(time.time()))[-6:]

    print(f"[connect] Signing in to {base_url} (org={args.org_id})...", flush=True)
    headers = login_headers(base_url, args.email, args.password, args.org_id)

    if run_baseline:
        configure_containment_gate(base_url, headers)
        for alert in BASELINE_ALERTS:
            send_alert(base_url, headers, alert, run_tag)
        print("[setup] Baseline ready. Open the Overview page before starting --stream.", flush=True)

    if run_stream:
        print(f"[wave] Streaming 6-stage attack wave into {base_url}...", flush=True)
        start = time.time()
        for delay_sec, alert in LIVE_WAVE:
            # Delays are measured from the wave start, so slow responses do not accumulate;
            # a negative scale is clamped to zero.
            wait = (delay_sec * max(0.0, args.delay_scale)) - (time.time() - start)
            if wait > 0:
                time.sleep(wait)
            send_alert(base_url, headers, alert, run_tag)
        print("[wave] Attack wave complete. Review Overview, Incidents, Copilot, Workflows, and Reports.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[wave] Interrupted by operator.", file=sys.stderr)
        raise SystemExit(130) from None
