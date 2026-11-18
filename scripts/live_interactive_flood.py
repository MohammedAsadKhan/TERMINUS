# File name: live_interactive_flood.py
# Author: Team LARP
# Revision date: 2026-11-14
# Version: 0.1.0
# Purpose: Synthetic presentation traffic for an isolated loopback rehearsal.

"""Send synthetic presentation traffic only to a loopback TERMINUS service.

The caller must provide a disposable workspace. This script does not clear or
reset existing records and does not establish live adversary or response proof.
"""

# ruff: noqa: INP001 -- this presentation entry point is a standalone script
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, override

# ANSI colors for rich terminal logging
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def loopback_origin(base_url: str) -> str:
    """Reject external, credential-bearing, or path-prefixed demo targets."""
    try:
        parsed = urllib.parse.urlsplit(base_url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid demo URL") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or port is None
        or port is None
        or port == 0
    ):
        raise ValueError("Demo URL must be a loopback origin with an explicit port")
    return f"{parsed.scheme}://{parsed.netloc}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    @override
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        """Keep session tokens and demo requests on the validated origin."""
        return


def banner(text: str, color: str = CYAN) -> None:
    line = "=" * 78
    print(f"\n{color}{BOLD}{line}")
    print(f"  {text}")
    print(f"{line}{RESET}\n")


def http_req(
    base_url: str,
    method: str,
    path: str,
    data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("Demo request path must be local")
    url = f"{loopback_origin(base_url)}{path}"
    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)
    if path == "/wazuh" and data is not None:
        # Presentation alerts reach the operator intake route. Keep their
        # synthetic origin visible in the stored description and raw log.
        data = dict(data)
        for field in ("description", "full_log"):
            value = data.get(field)
            if isinstance(value, str) and not value.startswith("[SYNTHETIC]"):
                data[field] = f"[SYNTHETIC] {value}"
    encoded = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(  # noqa: S310 -- validated loopback origin
        url, data=encoded, headers=req_headers, method=method
    )
    try:
        opener = urllib.request.build_opener(_NoRedirect)
        with opener.open(req, timeout=15) as resp:
            code = resp.status
            body = resp.read().decode("utf-8")
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = body
            return code, parsed
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = body
        return e.code, parsed
    except Exception as e:
        return 0, str(e)


async def req_async(
    base_url: str,
    method: str,
    path: str,
    data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, Any]:
    return await asyncio.to_thread(http_req, base_url, method, path, data, headers)


async def register_heartbeat(base_url: str, status: str = "connected", metrics: dict[str, Any] | None = None) -> None:
    try:
        await req_async(
            base_url,
            "POST",
            "/service/heartbeat",
            {
                "source": "simulated_adversary_stream",
                "status": status,
                "metadata": metrics or {},
            },
        )
    except Exception:
        pass


async def seed_initial_demo_telemetry(base_url: str, headers: dict[str, str]) -> int:
    """Populate the isolated rehearsal with visibly synthetic baseline alerts."""
    print(f"{CYAN}[*] Sending synthetic baseline alerts...{RESET}")
    now_ms = int(time.time() * 1000)

    initial_alerts = [
        {
            "id": f"alt-init-spray-{now_ms}-1",
            "rule_id": 5710,
            "level": 8,
            "description": "Repeated SSH & API authentication failures (Brute Force Anomaly T1110)",
            "mitre": "T1110",
            "src_ip": "198.51.100.42",
            "agent_name": "api-gateway.terminus.bank",
            "full_log": "WARNING: 32 consecutive failed authentication attempts for user 'admin' from 198.51.100.42 on api-gateway.",
        },
        {
            "id": f"alt-init-sqli-{now_ms}-2",
            "rule_id": 5715,
            "level": 11,
            "description": "SQL Injection & Union-Based Data Extraction Probe (T1190)",
            "mitre": "T1190",
            "src_ip": "203.0.113.19",
            "agent_name": "bank-customer-portal.internal",
            "full_log": "CRITICAL: Malicious SQL payload intercepted: ' UNION SELECT username, password_hash FROM core_users -- on customer search endpoint.",
        },
        {
            "id": f"alt-init-ps-{now_ms}-3",
            "rule_id": 5720,
            "level": 12,
            "description": "Obfuscated PowerShell Download Cradle & Process Injection (T1059.001)",
            "mitre": "T1059.001",
            "src_ip": "10.0.10.88",
            "agent_name": "workstation-88.corp.internal",
            "full_log": "CRITICAL: powershell.exe -enc SQBFAFgA... executed with hidden window style invoking remote payload from staging server.",
        },
        {
            "id": f"alt-init-kerb-{now_ms}-4",
            "rule_id": 5725,
            "level": 9,
            "description": "Kerberoasting SPN Ticket Request Anomaly (T1558.003)",
            "mitre": "T1558.003",
            "src_ip": "10.0.10.15",
            "agent_name": "dc01.corp.internal",
            "full_log": "WARNING: Unusual volume of Kerberos TGS-REQ ticket requests with RC4 encryption targeting high-privilege service accounts.",
        },
        {
            "id": f"alt-init-scan-{now_ms}-5",
            "rule_id": 5730,
            "level": 7,
            "description": "Network Service Discovery & SYN Port Sweep (T1046)",
            "mitre": "T1046",
            "src_ip": "198.51.100.77",
            "agent_name": "vpn-edge-01.corp.internal",
            "full_log": "NOTICE: Rapid sequential TCP SYN connection attempts across ports 22, 443, 3389, 8080 from single external IP 198.51.100.77.",
        },
        {
            "id": f"alt-init-stage-{now_ms}-6",
            "rule_id": 5735,
            "level": 8,
            "description": "Suspicious Archive Staging in AppData Directory (T1074.001)",
            "mitre": "T1074.001",
            "src_ip": "10.5.0.100",
            "agent_name": "payroll-srv.internal",
            "full_log": "WARNING: 7z.exe archive created in C:\\Windows\\Temp\\exfil_stage.zip containing 42 sensitive compensation spreadsheets.",
        },
        {
            "id": f"alt-init-honey-{now_ms}-7",
            "rule_id": 100099,
            "level": 15,
            "description": "Canary Honeytoken Access Attempt on Core Treasury (T1552)",
            "mitre": "T1552",
            "src_ip": "198.51.100.99",
            "agent_name": "bank-core-ledger-01",
            "full_log": "HONEYTOKEN TRIPWIRE: Fake AWS key AKIA_CANARY_HONEYTOKEN_9941_REDTEAM and secret accessed from /bank/api/admin/treasury-keys",
        },
    ]

    seeded_count = 0
    for alert in initial_alerts:
        code, _ = await req_async(base_url, "POST", "/wazuh", alert, headers=headers)
        if code == 200:
            seeded_count += 1
        await asyncio.sleep(0.15)

    print(f"{GREEN}[+] API accepted {seeded_count} synthetic baseline alerts.{RESET}\n")
    return seeded_count


async def run_simulation(base_url: str = "http://127.0.0.1:8766", duration_seconds: int = 600) -> None:
    if os.environ.get("TERMINUS_BANK_DEMO_MODE") != "1":
        raise ValueError("Synthetic stream requires the isolated bank demo launcher")
    base_url = loopback_origin(base_url)
    print(f"{BOLD}{CYAN}Connecting synthetic demo stream to {base_url}...{RESET}")

    # 1. Health check with retry loop (up to 15 seconds)
    health_ok = False
    for attempt in range(1, 16):
        code, health_resp = await req_async(base_url, "GET", "/health")
        if code == 200:
            health_ok = True
            break
        bcode, _ = await req_async(base_url, "GET", "/bank/api/demo/status")
        if bcode == 200:
            health_ok = True
            break
        if attempt == 1:
            print(f"{YELLOW}[*] Waiting for Terminus backend service to become ready...{RESET}")
        await asyncio.sleep(1.0)

    if not health_ok:
        print(f"{RED}[!] Server health check failed: unable to connect to {base_url}{RESET}")
        print(f"{YELLOW}[!] Please start the Terminus service first using 'run_service.bat'{RESET}")
        return

    # 2. Authenticate: try standard admin first, then demo presenter, with auto-register fallback
    headers: dict[str, str] = {
        "X-Terminus-Request": "1",
    }
    user_email = "admin@terminus.local"
    login_credentials = [
        ("admin@terminus.local", "Password123!"),
        ("presenter@terminus.example", "DemoOnlyPassword123!"),
        ("admin@acme-corp.com", "Password123!"),
        ("admin@acme.corp", "Password123!"),
    ]

    session_token = None
    for email, pwd in login_credentials:
        code, login_data = await req_async(
            base_url,
            "POST",
            "/auth/login",
            {"email": email, "password": pwd},
        )
        if code == 200 and isinstance(login_data, dict) and "session_token" in login_data:
            session_token = login_data["session_token"]
            user_email = email
            break

    # If login failed, register admin@terminus.local and log in
    if not session_token:
        print(f"{CYAN}[*] Bootstrapping demo administrator account (admin@terminus.local)...{RESET}")
        await req_async(
            base_url,
            "POST",
            "/auth/register",
            {
                "email": "admin@terminus.local",
                "password": "Password123!",
                "display_name": "Terminus Administrator",
            },
        )
        code, login_data = await req_async(
            base_url,
            "POST",
            "/auth/login",
            {"email": "admin@terminus.local", "password": "Password123!"},
        )
        if code == 200 and isinstance(login_data, dict) and "session_token" in login_data:
            session_token = login_data["session_token"]
            user_email = "admin@terminus.local"

    if not session_token:
        print(f"{RED}[!] Login failed: unable to authenticate with {base_url}{RESET}")
        return

    headers["Authorization"] = f"Bearer {session_token}"
    headers["X-Session-Token"] = session_token

    # 3. Retrieve or create user organization
    code, orgs = await req_async(base_url, "GET", "/orgs", headers=headers)
    org_id = "org-terminus-demo"
    if orgs and isinstance(orgs, list) and len(orgs) > 0:
        org_id = orgs[0].get("org_id") or "org-terminus-demo"
    else:
        # Create default demo organization if needed
        create_code, new_org = await req_async(
            base_url,
            "POST",
            "/orgs",
            {"name": "Terminus Security Operations Demo"},
            headers=headers,
        )
        if create_code in (200, 201) and isinstance(new_org, dict):
            org_id = new_org.get("org_id") or "org-terminus-demo"

    headers["X-Org-Id"] = org_id

    # 4. Register initial active connection heartbeat
    await register_heartbeat(base_url, "connected", {"target_org": org_id, "duration": duration_seconds})

    banner("TERMINUS SYNTHETIC BANK AND SOC PRESENTATION STREAM", CYAN)
    print(f"  * Web Console: {BOLD}{base_url}/console/{RESET}")
    print(f"  * Authenticated Operator: {BOLD}{user_email}{RESET}")
    print(f"  * Active Workspace: {BOLD}{org_id}{RESET}")
    print(f"  * Presentation Demo Duration: {duration_seconds}s (~{duration_seconds // 60} minutes)")
    print(f"  * Synthetic traffic stream: {GREEN}RUNNING{RESET}; no live threat or response proof\n")

    # 5. Immediately Seed Initial Telemetry Baseline
    seeded_count = await seed_initial_demo_telemetry(base_url, headers)

    start_time = time.time()
    end_time = start_time + duration_seconds

    wave1_done = False
    wave2_done = False
    wave3_done = False
    wave4_done = False
    wave5_done = False
    wave6_done = False
    wave7_done = False

    normal_requests_count = 0
    noise_suppressed = 0
    triaged_count = seeded_count
    critical_count = 3  # Initial seeded critical count

    # Background periodic rolling threat pool
    rolling_threat_pool = [
        {
            "rule_id": 5740,
            "level": 8,
            "description": "Suspicious Windows Service Created (T1543.003)",
            "mitre": "T1543.003",
            "src_ip": "10.0.10.42",
            "agent_name": "laptop-fin-04.corp.internal",
            "full_log": "WARNING: New service 'TerminusPwnSvc' registered pointing to binary in C:\\Users\\Public\\pwn.exe",
        },
        {
            "rule_id": 5745,
            "level": 11,
            "description": "Process Injection Attempt into lsass.exe (T1055 / T1003)",
            "mitre": "T1055",
            "src_ip": "10.0.5.88",
            "agent_name": "workstation-88.corp.internal",
            "full_log": "CRITICAL: OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE) opened on lsass.exe PID 644 from unverified binary.",
        },
        {
            "rule_id": 5750,
            "level": 9,
            "description": "Unusual SSH Bastion Inbound Session from Anomalous ASN (T1078)",
            "mitre": "T1078",
            "src_ip": "185.220.101.5",
            "agent_name": "dev-jumpbox-01.corp.internal",
            "full_log": "WARNING: Successful SSH key login for 'deploy_bot' from Tor exit node 185.220.101.5 outside business hours.",
        },
        {
            "rule_id": 5755,
            "level": 10,
            "description": "Anomalous Outbound Reverse Shell Connection (T1059.004)",
            "mitre": "T1059.004",
            "src_ip": "10.0.4.22",
            "agent_name": "api-cluster-prod.internal",
            "full_log": "CRITICAL: Outbound TCP socket established from /bin/sh to 198.51.100.199:4444 (Reverse Shell Indicator).",
        },
        {
            "rule_id": 5760,
            "level": 8,
            "description": "Unauthorized Active Directory Object Modification (T1098)",
            "mitre": "T1098",
            "src_ip": "10.0.0.5",
            "agent_name": "dc01.corp.internal",
            "full_log": "WARNING: User 'backup_operator' added to privileged group 'Enterprise Admins' via RPC request.",
        },
    ]

    try:
        while time.time() < end_time:
            elapsed = time.time() - start_time
            progress_ratio = elapsed / duration_seconds
            mins = int(elapsed // 60)
            secs = int(elapsed % 60)
            tot_mins = int(duration_seconds // 60)
            tot_secs = int(duration_seconds % 60)
            time_str = f"[{mins:02d}:{secs:02d} / {tot_mins:02d}:{tot_secs:02d}]"

            # Periodically register streaming sensor heartbeat
            if (normal_requests_count + triaged_count) % 6 == 0:
                await register_heartbeat(base_url, "active", {"normal_traffic": normal_requests_count, "elapsed": elapsed})

            # ─── WAVE 1: Reconnaissance & Credential Stuffing Surge (T ~ 15s or 5% - 15%) ───
            if (elapsed >= 15 or progress_ratio >= 0.05) and not wave1_done:
                wave1_done = True
                banner(f"{time_str} WAVE 1: RECONNAISSANCE & CREDENTIAL STUFFING SURGE (T1110)", YELLOW)
                print(f"  {YELLOW}[*] Ingesting multi-source botnet port scans & brute-force spray against api-gateway...{RESET}")

                for i in range(5):
                    src_ip = f"198.51.100.{random.randint(10, 99)}"
                    alert_payload = {
                        "id": f"alt-spray-{int(time.time() * 1000)}-{i}",
                        "rule_id": 5710 + i,
                        "level": 8,
                        "description": "Repeated SSH & API authentication failures (Brute Force Anomaly T1110)",
                        "mitre": "T1110",
                        "src_ip": src_ip,
                        "agent_name": "api-gateway.terminus.bank",
                        "full_log": f"WARNING: 28 consecutive failed auth attempts for user 'svc_admin' from {src_ip} on api-gateway.",
                    }
                    code, _ = await req_async(base_url, "POST", "/wazuh", alert_payload, headers=headers)
                    if code == 200:
                        triaged_count += 1
                        print(f"    {YELLOW}[+] Synthetic credential alert accepted: {alert_payload['id']}{RESET}")
                    await asyncio.sleep(0.35)

            # ─── WAVE 2: Web App SQLi Exploit & Honeytoken Canary Tripwire (T ~ 45s or 15% - 30%) ───
            elif (elapsed >= 45 or progress_ratio >= 0.15) and not wave2_done:
                wave2_done = True
                banner(f"{time_str} WAVE 2: WEB APP SQL INJECTION & CORE BANKING HONEYTOKEN TRIPWIRE (T1190 / T1552)", RED)
                print(f"  {RED}[*] Sending a synthetic SQL injection query to the demo bank...{RESET}")

                # 1. SQL Injection on Bank Search
                code, search_resp = await req_async(
                    base_url,
                    "GET",
                    "/bank/api/search?q=' UNION SELECT username, password_hash FROM core_users --",
                    headers=headers,
                )
                if code == 200 and isinstance(search_resp, dict) and search_resp.get("threat_detected"):
                    triaged_count += 1
                    print(f"    {GREEN}[+] Demo bank reported threat_detected; ticket: {search_resp.get('ticket_created')}{RESET}")

                await asyncio.sleep(1.0)

                # 2. Canary Treasury Keys Honeytoken Accessed
                print(f"  {RED}[*] Adversary probing hidden honeytoken endpoint /bank/api/admin/treasury-keys...{RESET}")
                code, _ = await req_async(base_url, "GET", "/bank/api/admin/treasury-keys", headers=headers)
                if code == 200:
                    critical_count += 1
                    print(f"    {RED}{BOLD}[!] LEVEL-15 ESCALATE TRIPWIRE FIRED:{RESET} Canary Token Retrieved on bank-core-ledger-01 (T1552)")

                await asyncio.sleep(1.0)

            # ─── WAVE 3: LockBit 3.0 Ransomware Detonation & Human Approval Gate (T ~ 90s or 30% - 50%) ───
            elif (elapsed >= 90 or progress_ratio >= 0.30) and not wave3_done:
                wave3_done = True
                banner(f"{time_str} WAVE 3: SYNTHETIC RANSOMWARE ALERT AND APPROVAL SCENARIO (T1486)", RED)
                critical_count += 1

                ransomware_alert = {
                    "id": f"alt-ransom-{int(time.time() * 1000)}",
                    "rule_id": 99001,
                    "level": 14,
                    "description": "LockBit 3.0 Ransomware Encryptor Execution & VSS Deletion (T1486)",
                    "mitre": "T1486",
                    "src_ip": "10.0.10.88",
                    "agent_name": "workstation-88.corp.internal",
                    "full_log": "CRITICAL: vssadmin.exe delete shadows /all /quiet && lockbit_payload.exe -k CorpKey99 on workstation-88.corp.internal",
                }

                print(f"  {RED}{BOLD}[!] Ingesting Critical Ransomware Alert on workstation-88.corp.internal...{RESET}")
                code, _ = await req_async(base_url, "POST", "/wazuh", ransomware_alert, headers=headers)
                print(f"  {GREEN}[+] Synthetic alert POST returned HTTP {code}; investigation status unverified.{RESET}")

                # A presentation must never approve an action on behalf of an
                # analyst. The queue can be reviewed separately in the console.
                print(f"  {YELLOW}[*] Approval is reserved for an authorized analyst; no action was submitted.{RESET}")

                await asyncio.sleep(1.5)

            # ─── WAVE 4: Active Directory DCSync Attack & Deterministic Guardrails (T ~ 180s or 50% - 70%) ───
            elif (elapsed >= 180 or progress_ratio >= 0.50) and not wave4_done:
                wave4_done = True
                banner(f"{time_str} WAVE 4: SYNTHETIC DCSYNC INDICATOR (T1003.006)", RED)
                critical_count += 1

                dc_alert = {
                    "id": f"alt-dc-{int(time.time() * 1000)}",
                    "rule_id": 99002,
                    "level": 15,
                    "description": "Adversary Mimikatz DCSync & Golden Ticket Forge against Domain Controller (T1003.006)",
                    "mitre": "T1003.006",
                    "src_ip": "10.0.0.5",
                    "agent_name": "dc01.corp.internal",
                    "full_log": "CRITICAL: lsadump::dcsync /domain:corp.internal /user:krbtgt executed against Primary DC dc01.corp.internal",
                }

                print(f"  {RED}{BOLD}[!] Ingesting Active Directory Attack on Tier-0 Domain Controller dc01...{RESET}")
                code, _ = await req_async(base_url, "POST", "/wazuh", dc_alert, headers=headers)

                print(f"  {CYAN}[*] Assessing Deterministic Safety Guardrail (D12/D14) for DC01 Isolation...{RESET}")
                await asyncio.sleep(1.5)

                print(f"  {YELLOW}[*] No containment requested; allowlist effect is not verified by this stream.{RESET}\n")

                await asyncio.sleep(1.5)

            # ─── WAVE 5: AI Copilot Multi-Host Campaign Correlation (T ~ 270s or 70% - 85%) ───
            elif (elapsed >= 270 or progress_ratio >= 0.70) and not wave5_done:
                wave5_done = True
                banner(f"{time_str} WAVE 5: AI COPILOT CAMPAIGN CORRELATION & MITRE ATT&CK SYNTHESIS", MAGENTA)
                print(f"  {MAGENTA}[*] Querying AI Copilot for Multi-Host Attack Campaign Summary...{RESET}")
                code, copilot_res = await req_async(
                    base_url,
                    "POST",
                    "/copilot/query",
                    {"query": "Summarize the active adversary campaign across workstation-88 and dc01.corp.internal"},
                    headers=headers,
                )
                if code == 200 and isinstance(copilot_res, dict):
                    answer = copilot_res.get("response") or copilot_res.get("summary") or "No campaign answer returned."
                    print(f"  {BOLD}Demo copilot response (unverified):{RESET} {answer[:220]}...\n")

                await asyncio.sleep(1.5)

            # ─── WAVE 6: Lateral Movement via PsExec & WMI (T ~ 360s or 85% - 92%) ───
            elif (elapsed >= 360 or progress_ratio >= 0.85) and not wave6_done:
                wave6_done = True
                banner(f"{time_str} WAVE 6: LATERAL MOVEMENT VIA PSEXEC & WMI HIJACKING (T1021.002)", RED)
                critical_count += 1
                lat_alert = {
                    "id": f"alt-lat-{int(time.time() * 1000)}",
                    "rule_id": 99003,
                    "level": 13,
                    "description": "Lateral Movement via Remote PsExec & Service Injection (T1021.002)",
                    "mitre": "T1021.002",
                    "src_ip": "10.0.10.88",
                    "agent_name": "app-backend-04.corp.internal",
                    "full_log": "CRITICAL: Remote service PSEXESVC spawned on app-backend-04 initiated from compromised workstation-88.",
                }
                print(f"  {RED}{BOLD}[!] Ingesting Lateral Movement Indicator on app-backend-04...{RESET}")
                code, _ = await req_async(base_url, "POST", "/wazuh", lat_alert, headers=headers)
                triaged_count += 1
                await asyncio.sleep(1.5)

            # ─── WAVE 7: DNS Tunneling C2 Exfiltration & Quarantine (T ~ 450s or 92%+) ───
            elif (elapsed >= 450 or progress_ratio >= 0.92) and not wave7_done:
                wave7_done = True
                banner(f"{time_str} WAVE 7: C2 DNS TUNNELING & AUTOMATED EGRESS CONTAINMENT (T1071.001)", RED)
                critical_count += 1
                c2_alert = {
                    "id": f"alt-c2-{int(time.time() * 1000)}",
                    "rule_id": 99004,
                    "level": 14,
                    "description": "Adversary C2 Beaconing via High-Entropy DNS Subdomain Tunneling (T1071.001)",
                    "mitre": "T1071.001",
                    "src_ip": "10.0.10.42",
                    "agent_name": "laptop-fin-04.corp.internal",
                    "full_log": "CRITICAL: 1,420 high-entropy base64 TXT queries detected to evil-c2-tunnel.example.com from laptop-fin-04.",
                }
                print(f"  {RED}{BOLD}[!] Ingesting C2 Exfiltration Incident on laptop-fin-04...{RESET}")
                code, _ = await req_async(base_url, "POST", "/wazuh", c2_alert, headers=headers)
                triaged_count += 1
                await asyncio.sleep(1.5)

            # ─── CONTINUOUS BACKGROUND NORMAL SERVICE TRAFFIC & REGULAR THREAT INJECTIONS ───
            else:
                normal_requests_count += 1

                # Every fourth cycle, add another synthetic alert to the demo UI.
                if normal_requests_count % 4 == 0:
                    threat_template = random.choice(rolling_threat_pool)
                    now_ms = int(time.time() * 1000)
                    alert_payload = {
                        "id": f"alt-roll-{now_ms}-{normal_requests_count}",
                        "rule_id": threat_template["rule_id"],
                        "level": threat_template["level"],
                        "description": threat_template["description"],
                        "mitre": threat_template["mitre"],
                        "src_ip": threat_template["src_ip"],
                        "agent_name": threat_template["agent_name"],
                        "full_log": threat_template["full_log"],
                    }
                    try:
                        code, _ = await req_async(base_url, "POST", "/wazuh", alert_payload, headers=headers)
                        if code == 200:
                            triaged_count += 1
                            if threat_template["level"] >= 10:
                                critical_count += 1
                            sys.stdout.write(f"\r{DIM}{time_str}{RESET} {YELLOW}[SYNTHETIC ALERT]{RESET} {threat_template['mitre']} on {threat_template['agent_name']} (intake accepted)")
                            sys.stdout.flush()
                    except Exception:
                        pass

                # Benign bank web actions
                elif normal_requests_count % 4 == 1:
                    b_user = random.choice(["sarah.jenkins", "customer", "operator"])
                    b_pass = "BankPass2026!" if b_user == "sarah.jenkins" else "password"
                    try:
                        await req_async(
                            base_url,
                            "POST",
                            "/bank/api/login",
                            {"username": b_user, "password": b_pass},
                            headers=headers,
                        )
                    except Exception:
                        pass
                    sys.stdout.write(f"\r{DIM}{time_str}{RESET} {GREEN}[SYNTHETIC BANK TRAFFIC]{RESET} Customer login request attempted")
                    sys.stdout.flush()

                elif normal_requests_count % 4 == 2:
                    q_term = random.choice(["downtown", "checking", "hours", "routing", "atm", "branch"])
                    try:
                        await req_async(base_url, "GET", f"/bank/api/search?q={q_term}", headers=headers)
                    except Exception:
                        pass
                    sys.stdout.write(f"\r{DIM}{time_str}{RESET} {GREEN}[SYNTHETIC BANK TRAFFIC]{RESET} Public branch search '{q_term}' requested")
                    sys.stdout.flush()

                else:
                    # Low-level benign infrastructure noise -> Sub-millisecond Tier-0 filter
                    level = random.choice([2, 3, 4])
                    desc = random.choice([
                        "ICMP Echo Request probe from external health checker",
                        "TCP SYN scan on closed test port 8443",
                        "Outbound DNS resolution for internal NTP time server",
                        "HTTP 404 Not Found on static asset /favicon.ico",
                    ])
                    src_ip = f"192.168.1.{random.randint(10, 200)}"
                    alert_payload = {
                        "id": f"alt-bg-{int(time.time() * 1000)}-{normal_requests_count}",
                        "rule_id": 2000 + (normal_requests_count % 10),
                        "level": level,
                        "description": desc,
                        "src_ip": src_ip,
                        "agent_name": f"host-srv-{random.randint(1, 10):02d}.corp.internal",
                        "full_log": f"{desc} from {src_ip}",
                    }
                    try:
                        code, rep = await req_async(base_url, "POST", "/wazuh", alert_payload, headers=headers)
                        if code == 200 and isinstance(rep, dict) and rep.get("policy", {}).get("tier") == "ignore":
                            noise_suppressed += 1
                    except Exception:
                        pass
                    sys.stdout.write(f"\r{DIM}{time_str}{RESET} {CYAN}[SYNTHETIC ALERT]{RESET} Low-level event #{normal_requests_count:03d} submitted")
                    sys.stdout.flush()

                await asyncio.sleep(2.0)

    finally:
        # Register disconnected heartbeat
        await register_heartbeat(base_url, "disconnected", {"synthetic_cycles": normal_requests_count})

    # Final presentation summary
    banner("SYNTHETIC PRESENTATION STREAM COMPLETE", GREEN)
    print(f"  * Synthetic bank-traffic cycles attempted: {normal_requests_count}")
    print(f"  * Synthetic low-level alerts returned ignore tier: {noise_suppressed}")
    print("  * No live attack, containment effect, or analyst benefit was verified.")
    print(f"  * Terminus Web Console: {BOLD}{base_url}/console/{RESET}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="TERMINUS synthetic loopback presentation stream")
    parser.add_argument(
        "--base-url",
        "--base_url",
        dest="base_url",
        type=str,
        default=os.environ.get("TERMINUS_BASE_URL", "http://127.0.0.1:8766"),
        help="Base URL of the isolated bank demo (default: http://127.0.0.1:8766)",
    )
    parser.add_argument(
        "--duration",
        "--duration-seconds",
        dest="duration_seconds",
        type=int,
        default=int(os.environ.get("SIMULATION_DURATION", "600")),
        help="Duration of simulation in seconds (default: 600s / 10 minutes)",
    )
    args = parser.parse_args()
    try:
        args.base_url = loopback_origin(args.base_url)
        if os.environ.get("TERMINUS_BANK_DEMO_MODE") != "1":
            raise ValueError("Synthetic stream requires the isolated bank demo launcher")
    except ValueError as exc:
        parser.error(str(exc))

    try:
        asyncio.run(run_simulation(base_url=args.base_url, duration_seconds=args.duration_seconds))
    except KeyboardInterrupt:
        print("\n[!] Simulation interrupted by operator. Registering disconnect heartbeat...")
        try:
            asyncio.run(register_heartbeat(args.base_url, "disconnected"))
        except Exception:
            pass
        print("[+] Disconnected cleanly.")


if __name__ == "__main__":
    main()
