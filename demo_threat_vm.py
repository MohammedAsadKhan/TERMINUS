"""Simulated Threat Emitter VM & Security Incident Generator.

Simulates a compromised endpoint / cloud environment posting high-severity Wazuh SIEM alerts
to the live Terminus REST API at http://localhost:8000/wazuh.
"""

from __future__ import annotations

import sys
import time
import httpx2

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

BASE_URL = "http://localhost:8000"

# ─── High Threat Wazuh Alert Scenarios ─────────────────────────────────────────────

HIGH_THREAT_SCENARIOS = [
    {
        "name": "🔥 CRITICAL: Ransomware Execution & Volume Shadow Copy Deletion (MITRE T1490)",
        "alert": {
            "id": "alert-ransom-001",
            "rule": {
                "id": 92010,
                "level": 14,
                "description": "Critical Process Anomaly: vssadmin.exe executed to delete volume shadow copies",
                "mitre": {"id": "T1490"},
            },
            "agent": {
                "id": "agent-win-prod-01",
                "name": "WIN-DB-SRV01.ad.acme.corp",
            },
            "data": {
                "srcip": "10.0.4.15",
                "command": "vssadmin.exe delete shadows /all /quiet",
                "process_id": "4912",
                "user": "SYSTEM",
            },
            "timestamp": "2026-09-04T02:44:00Z",
            "location": "C:\\Windows\\System32\\vssadmin.exe",
        },
    },
    {
        "name": "💀 CRITICAL: LSASS Memory Dumping via Comsvcs.dll (MITRE T1003.001)",
        "alert": {
            "id": "alert-lsass-002",
            "rule": {
                "id": 92055,
                "level": 13,
                "description": "LSASS memory dump detected via rundll32 and comsvcs.dll",
                "mitre": {"id": "T1003"},
            },
            "agent": {
                "id": "agent-dc-01",
                "name": "DC-PRIMARY.ad.acme.corp",
            },
            "data": {
                "srcip": "10.0.1.5",
                "command": "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 672 C:\\temp\\lsass.dmp full",
                "process_id": "8104",
                "user": "NT AUTHORITY\\SYSTEM",
            },
            "timestamp": "2026-09-04T02:44:15Z",
            "location": "C:\\Windows\\System32\\rundll32.exe",
        },
    },
    {
        "name": "🚨 HIGH: Distributed SSH Password Brute-Force Campaign (MITRE T1110)",
        "alert": {
            "id": "alert-ssh-003",
            "rule": {
                "id": 5712,
                "level": 11,
                "description": "SSHD: 500+ failed login attempts from external IP 185.220.101.5 in 60s",
                "mitre": {"id": "T1110"},
            },
            "agent": {
                "id": "agent-linux-web-02",
                "name": "web-gateway-02.prod.acme.com",
            },
            "data": {
                "srcip": "185.220.101.5",
                "dstuser": "root",
                "attempts": 512,
            },
            "timestamp": "2026-09-04T02:44:30Z",
            "location": "/var/log/auth.log",
        },
    },
    {
        "name": "⚡ HIGH: AWS Root Account Console Login Without MFA (MITRE T1078)",
        "alert": {
            "id": "alert-aws-004",
            "rule": {
                "id": 80105,
                "level": 12,
                "description": "AWS CloudTrail: Root user ConsoleLogin succeeded without MFA from TOR exit node",
                "mitre": {"id": "T1078"},
            },
            "agent": {
                "id": "agent-aws-cloudtrail",
                "name": "AWS-CloudTrail-Global",
            },
            "data": {
                "srcip": "198.51.100.77",
                "user": "root",
                "mfa_used": "No",
            },
            "timestamp": "2026-09-04T02:44:45Z",
            "location": "us-east-1",
        },
    },
    {
        "name": "🛡️ HIGH: Active Directory Kerberoasting TGS Request Flood (MITRE T1558.003)",
        "alert": {
            "id": "alert-kerb-005",
            "rule": {
                "id": 92120,
                "level": 10,
                "description": "Kerberos TGS request for high-privilege service account using weak RC4 encryption",
                "mitre": {"id": "T1558"},
            },
            "agent": {
                "id": "agent-dc-01",
                "name": "DC-PRIMARY.ad.acme.corp",
            },
            "data": {
                "srcip": "10.0.2.88",
                "service_name": "MSSQLSvc/sql-cluster.acme.corp:1433",
                "ticket_encryption": "0x17 (RC4-HMAC)",
            },
            "timestamp": "2026-09-04T02:45:00Z",
            "location": "ActiveDirectory",
        },
    },
]


def run_demo() -> None:
    """Execute live demonstration of high-threat ingestion and AI investigation."""
    client = httpx2.Client(timeout=10.0)

    print("=================================================================")
    print("      🚀 TERMINUS LIVE DEMONSTRATION & THREAT EMITTER VM         ")
    print("=================================================================")
    print(f"Connecting to Terminus Platform at {BASE_URL}...\n")

    # Step 1: Register Tenant Admin User
    print("1. [Setup] Registering SOC Tenant Admin (demo_admin@targetsoc.com)...")
    reg_res = client.post(
        f"{BASE_URL}/auth/register",
        json={
            "email": "demo_admin@targetsoc.com",
            "password": "DemoAdminPassword123!",
            "display_name": "Demo SOC Manager",
        },
    )
    if reg_res.status_code not in (201, 409):
        print(f"❌ Registration failed: {reg_res.status_code} {reg_res.text}")
        return

    # Step 2: Login to receive Session Token
    print("2. [Setup] Authenticating SOC Tenant Admin...")
    login_res = client.post(
        f"{BASE_URL}/auth/login",
        json={
            "email": "demo_admin@targetsoc.com",
            "password": "DemoAdminPassword123!",
        },
    )
    if login_res.status_code != 200:
        print(f"❌ Login failed: {login_res.status_code} {login_res.text}")
        return

    token = login_res.json()["session_token"]
    print(f"   ✓ Obtained Session Token: {token[:12]}...")

    headers = {"Authorization": f"Bearer {token}"}

    # Step 3: Create Organization
    print("3. [Setup] Creating Tenant Organization ('Enterprise Cyber Defense SOC')...")
    org_res = client.post(
        f"{BASE_URL}/orgs",
        headers=headers,
        json={"name": "Enterprise Cyber Defense SOC"},
    )
    if org_res.status_code not in (201, 200):
        # Or list orgs if already exists
        list_res = client.get(f"{BASE_URL}/orgs", headers=headers)
        org_id = list_res.json()[0]["org_id"]
    else:
        org_id = org_res.json()["org_id"]

    print(f"   ✓ Active Tenant Org ID: {org_id}\n")

    # Step 4: Stream High-Threat Alerts to Webhook
    print("=================================================================")
    print("   🔥 STARTING HIGH-THREAT SECURITY INCIDENT INGESTION SIMULATION  ")
    print("=================================================================\n")

    webhook_headers = {
        "Authorization": f"Bearer {token}",
        "X-Org-ID": org_id,
    }

    for i, scenario in enumerate(HIGH_THREAT_SCENARIOS, 1):
        print(f"[{i}/{len(HIGH_THREAT_SCENARIOS)}] Triggering Attack Event: {scenario['name']}")
        alert_data = scenario["alert"]
        print(f"    ├─ Rule ID: {alert_data['rule']['id']} | Level: {alert_data['rule']['level']} | MITRE: {alert_data['rule']['mitre']['id']}")
        print(f"    ├─ Target Host: {alert_data['agent']['name']} ({alert_data['data'].get('srcip', 'N/A')})")

        t0 = time.time()
        res = client.post(f"{BASE_URL}/wazuh", headers=webhook_headers, json=alert_data)
        elapsed_ms = (time.time() - t0) * 1000

        if res.status_code == 200:
            report = res.json()
            policy = report["policy"]
            verdict = report["verdict"]
            print(f"    ├─ ⚡ Policy Decision: TIER {policy['tier'].upper()} (Investigate: {policy['should_investigate']})")
            print(f"    ├─ 🤖 AI Verdict: SEVERITY {verdict['severity'].upper()} | Confidence: {verdict['confidence']}")
            print(f"    ├─ 📝 Summary: {verdict['summary']}")
            print(f"    ├─ 🛡️ Actions: {', '.join(verdict['recommended_actions'])}")
            print(f"    └─ ⏱️ Ingestion & Investigation Latency: {elapsed_ms:.1f}ms\n")
        else:
            print(f"    └─ ❌ Ingestion error: {res.status_code} {res.text}\n")

        time.sleep(1.5)

    print("=================================================================")
    print("   ✅ ALL HIGH-THREAT INCIDENTS PROCESSED BY TERMINUS ENGINE!    ")
    print("=================================================================")


if __name__ == "__main__":
    run_demo()
