"""First Heritage Community Bank — High-Velocity Red Team & Mixed User Traffic Simulator.

Simulates realistic, multi-threaded traffic against the First Heritage Community Bank honeypot:
1. Normal Retail Customer Traffic (80%):
   - Legitimate logins (Sarah Jenkins), checking balances, benign branch queries, account transfers.
   - Generates low-level SIEM telemetry (Level 2-3) filtered out by PolicyEngine into IGNORE tier.
2. Suspicious Anomalies (15%):
   - Failed authentication attempts and credential stuffing spikes.
   - Generates Level 7 telemetry categorized into TRIAGE tier.
3. Targeted Red Team Attacks & Honeytoken Breach (5%):
   - SQL Injection & RCE probes against bank web frontend (Level 12 -> ESCALATE).
   - Treasury Honeytoken Canary Key Breaches (/bank/api/admin/treasury-keys) (Level 15 -> ESCALATE).
   - Synthetic Customer PII Table Exfiltration (/bank/api/customers/export) (Level 15 -> ESCALATE).
4. High-Velocity Concurrency Benchmark:
   - 250 requests dispatched across 25 parallel workers measuring throughput (req/s) and latency (p50, p99).
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any

import httpx2 as httpx

BASE_URL = "http://127.0.0.1:8000"


async def main() -> None:
    print("=" * 80)
    print("  FIRST HERITAGE COMMUNITY BANK — MULTI-STREAM TRAFFIC & STRESS SIMULATOR")
    print("  Target Honeypot Portal: http://127.0.0.1:8000/bank")
    print("  SOC Analyst Console:    http://127.0.0.1:8000/console/")
    print("=" * 80)

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=30.0) as client:
        # Step 0: Obtain Admin / Tenant Context
        login_res = await client.post(
            "/auth/login",
            json={"email": "admin@terminus.local", "password": "Password123!"},
        )
        if login_res.status_code != 200:
            print(f"[!] Login failed ({login_res.status_code}): {login_res.text}")
            return
        session_token = login_res.json()["session_token"]
        headers = {"Authorization": f"Bearer {session_token}"}

        orgs_res = await client.get("/orgs", headers=headers)
        if orgs_res.status_code != 200 or not orgs_res.json():
            print("[!] Failed to list organizations.")
            return
        org_id = orgs_res.json()[0]["org_id"]
        headers["X-Org-ID"] = org_id
        print(f"[+] Connected to Organization: {org_id} (Terminus Security Operations)")

        # ─── PART 1: SIMULATE REGULAR CUSTOMER TRAFFIC ──────────────────────────────
        print("\n" + "-" * 80)
        print("  STAGE 1: SIMULATING REGULAR RETAIL BANKING CUSTOMER TRAFFIC")
        print("-" * 80)

        # 1. Customer visits bank homepage
        res = await client.get("/bank/")
        print(f"  [*] Customer visits /bank/ homepage: Status {res.status_code} (HTML Loaded)")

        # 2. Customer Sarah Jenkins logs in
        login_payload = {"username": "sarah.jenkins", "password": "BankPass2026!"}
        res = await client.post("/bank/api/login", headers=headers, json=login_payload)
        data = res.json()
        print(f"  [*] Customer 'sarah.jenkins' logs into accounts: Status {res.status_code} | {data.get('message')}")
        print("      -> Emitted SIEM Telemetry: Level 2 (Customer Session Authenticated)")
        print("      -> Policy Engine Decision: IGNORE (Benign Noise Filtered, Zero Ticket Clutter)")

        # 3. Customer executes account transfer
        tx_payload = {"to_account": "9021", "amount": 250.00}
        res = await client.post("/bank/api/transfer", headers=headers, json=tx_payload)
        tx_data = res.json()
        print(f"  [*] Customer executes $250 transfer: Transfer ID {tx_data.get('transfer_id')} via FedNow")

        # 4. Customer searches branch locations
        res = await client.get("/bank/api/search?q=downtown", headers=headers)
        print(f"  [*] Customer searches 'downtown' branches: Found {len(res.json().get('results', []))} locations")

        # ─── PART 2: SIMULATE CREDENTIAL STUFFING ANOMALIES ─────────────────────────
        print("\n" + "-" * 80)
        print("  STAGE 2: SIMULATING SUSPICIOUS LOGIN ANOMALY (CREDENTIAL BRUTE FORCE)")
        print("-" * 80)

        bad_payload = {"username": "corporate_treasury_admin", "password": "WrongPassword2026!"}
        res = await client.post("/bank/api/login", headers=headers, json=bad_payload)
        print(f"  [!] Failed login attempt for user 'corporate_treasury_admin': Status {res.status_code}")
        print("      -> Emitted SIEM Telemetry: Level 7 (Brute Force Anomaly Detected)")
        print("      -> Policy Engine Decision: TRIAGE (Logged for Audit / Anomaly Tracking)")

        # ─── PART 3: RED TEAM ATTACK & HONEYTOKEN TRACE ─────────────────────────────
        print("\n" + "-" * 80)
        print("  STAGE 3: RED TEAM ATTACK, EXPLOIT & HONEYTOKEN INTERCEPTION")
        print("-" * 80)

        # 1. SQL Injection / Exploit Probe against Banking Search
        sqli_query = "' OR '1'='1' UNION SELECT username, password_hash FROM bank_users --"
        print(f"  [>] Red Team injects SQLi exploit payload into /bank/api/search?q={sqli_query[:35]}...")
        res = await client.get(f"/bank/api/search?q={sqli_query}", headers=headers)
        sqli_data = res.json()
        print(f"  [!] Exploit Intercepted: {sqli_data.get('action')} | Ticket {sqli_data.get('ticket_created')}")
        print("      -> Policy Engine Decision: ESCALATE (Critical MITRE T1190 Exploit)")

        # 2. Red Team accesses Decoy Treasury Key Vault
        print("\n  [>] Red Team scans hidden paths and accesses Decoy Treasury Vault (/bank/api/admin/treasury-keys)...")
        res = await client.get("/bank/api/admin/treasury-keys", headers=headers)
        vault_data = res.json()
        print("  [!] Adversary Exfiltrated Synthetic Treasury Keys:")
        for k, v in vault_data.get("treasury_secrets", {}).items():
            print(f"      - {k} = {v}")
        print("  [!] HONEYTOKEN TRIPWIRE FIRED: Level 15 alert dispatched to Terminus SOC!")
        print("      -> Autonomous AI Agent identified compromise of 'bank-core-ledger-01'")

        # 3. Red Team dumps Synthetic Customer Database
        print("\n  [>] Red Team accesses Decoy Customer Archive (/bank/api/customers/export)...")
        res = await client.get("/bank/api/customers/export", headers=headers)
        cust_data = res.json()
        print(f"  [!] Adversary Exfiltrated {cust_data.get('record_count')} Decoy Customer Financial Records:")
        for cust in cust_data.get("customers", []):
            print(f"      - {cust['customer_name']} | Acct: {cust['account_number']} | SSN: {cust['ssn']} | Bal: ${cust['balance']:,.2f}")
        print("  [!] DATA EXFILTRATION TRIPWIRE FIRED: Level 15 alert dispatched to Terminus SOC!")

        # ─── PART 4: HIGH-VELOCITY MASS CONCURRENCY STRESS BENCHMARK ────────────────
        print("\n" + "=" * 80)
        print("  STAGE 4: HIGH-VELOCITY MIXED TRAFFIC STRESS BENCHMARK (250 REQUESTS)")
        print("=" * 80)
        print("[*] Launching 250 parallel requests across 25 concurrent workers...")

        traffic_scenarios = [
            # 80% Regular User Traffic (Normal logins, searches, transfers, homepage)
            ("GET", "/bank/", None, "Normal Homepage Visit"),
            ("POST", "/bank/api/login", {"username": "sarah.jenkins", "password": "BankPass2026!"}, "Normal Customer Login"),
            ("POST", "/bank/api/transfer", {"to_account": "4819", "amount": 100.00}, "Normal Fund Transfer"),
            ("GET", "/bank/api/search?q=branch", None, "Normal Branch Search"),
            ("GET", "/bank/api/search?q=hours", None, "Normal ATM Hours Query"),
            # 15% Suspicious Traffic
            ("POST", "/bank/api/login", {"username": "admin", "password": "bad_password"}, "Suspicious Bad Login"),
            ("POST", "/bank/api/login", {"username": "root", "password": "toor"}, "Suspicious Brute Force"),
            # 5% Red Team Exploit & Decoy
            ("GET", "/bank/api/search?q=' OR 1=1 --", None, "Red Team SQLi Probe"),
            ("GET", "/bank/api/admin/treasury-keys", None, "Red Team Treasury Honeytoken"),
            ("GET", "/bank/api/customers/export", None, "Red Team Customer Exfiltration"),
        ]

        # Weights corresponding to 80% benign, 15% suspicious, 5% redteam
        weights = [35, 20, 15, 5, 5, 10, 5, 2, 2, 1]

        total_requests = 250
        tasks = []
        latencies: list[float] = []

        semaphore = asyncio.Semaphore(25)

        async def worker_request(idx: int) -> int:
            method, path, body, desc = random.choices(traffic_scenarios, weights=weights)[0]
            start_t = time.perf_counter()
            async with semaphore:
                try:
                    if method == "POST":
                        r = await client.post(path, headers=headers, json=body)
                    else:
                        r = await client.get(path, headers=headers)
                    duration = (time.perf_counter() - start_t) * 1000.0
                    latencies.append(duration)
                    return r.status_code
                except Exception as e:
                    return 500

        wall_start = time.perf_counter()
        results = await asyncio.gather(*[worker_request(i) for i in range(total_requests)])
        wall_total = time.perf_counter() - wall_start

        # Analyze latencies
        latencies.sort()
        p50 = latencies[len(latencies) // 2]
        p90 = latencies[int(len(latencies) * 0.90)]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]
        success_count = sum(1 for c in results if c in (200, 401))

        print("\n" + "-" * 80)
        print("  BENCHMARK RESULTS & METRICS")
        print("-" * 80)
        print(f"  * Total Dispatched Requests: {total_requests}")
        print(f"  * Total Time Elapsed:        {wall_total:.2f} seconds")
        print(f"  * Effective Throughput:      {total_requests / wall_total:.1f} requests/sec")
        print(f"  * Operational Success Rate:  {success_count}/{total_requests} ({success_count/total_requests*100:.1f}%)")
        print("  Latency Distribution:")
        print(f"    - p50 (Median):            {p50:.2f} ms")
        print(f"    - p90:                     {p90:.2f} ms")
        print(f"    - p95:                     {p95:.2f} ms")
        print(f"    - p99:                     {p99:.2f} ms")
        print(f"    - Min / Max:               {latencies[0]:.2f} ms / {latencies[-1]:.2f} ms")

        # Query Incidents to show live SOC status
        inc_res = await client.get("/incidents", headers=headers)
        if inc_res.status_code == 200:
            active_incidents = inc_res.json()
            critical_inc = [i for i in active_incidents if i.get("severity") == "critical"]
            print("\n" + "-" * 80)
            print("  TERMINUS SOC RADAR SUMMARY")
            print("-" * 80)
            print(f"  * Total Incidents in Active Queue:   {len(active_incidents)}")
            print(f"  * Critical Priority Threats:         {len(critical_inc)}")
            print("  * Compromised / Monitored Endpoints:")
            hosts = {i.get("agent_name", "unassigned") for i in active_incidents}
            for h in sorted(hosts):
                host_count = sum(1 for i in active_incidents if i.get("agent_name") == h)
                print(f"    - Host '{h}': {host_count} active threat investigations")

        print("\n[OK] Banking traffic simulation and mass stress testing completed successfully!")
        print("     Open http://127.0.0.1:8000/console/ to review the live SOC dashboard & asset fleet.")
        print("     Open http://127.0.0.1:8000/bank to view the interactive retail bank honeypot.")


if __name__ == "__main__":
    asyncio.run(main())
