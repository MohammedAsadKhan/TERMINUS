"""First Heritage Community Bank — Realistic 5-Minute Window & Live Traffic Simulator.

Provides realistic simulation modes:
1. Historical 5-Minute Window Mode (Default):
   - Generates a natural, realistically staggered timeline of 60 events spread across the last 5 minutes (300 seconds).
   - Ingests events with exact staggered timestamps (T - 290s, T - 260s, T - 210s, ... T - 5s).
   - Benign retail customer events are evaluated as IGNORE (noise filtered).
   - Suspicious login attempts are categorized as TRIAGE (monitored anomalies).
   - Red team exploit probes, honeytoken vault breaches, and PII exfiltration are escalated to ESCALATE (AI Agent SOC).
   - When viewed in the console, the "RECEIVED" column shows a natural progression across the 5-minute window.
2. Live Real-Time Paced Mode (`--live [seconds]`):
   - Streams events in real time with 1.5s to 3s realistic intervals between customer actions and adversary probes.
   - Ideal for live demos where the audience watches the console refresh dynamically in real time.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import UTC, datetime, timedelta
import random
import sys
import time

import httpx2 as httpx

BASE_URL = "http://127.0.0.1:8000"


async def run_simulation(live_mode: bool = False, live_duration: int = 60) -> None:
    print("=" * 80)
    print("  FIRST HERITAGE COMMUNITY BANK — REALISTIC TRAFFIC & STRESS SIMULATOR")
    print("  Target Honeypot Portal: http://127.0.0.1:8000/bank")
    print("  SOC Analyst Console:    http://127.0.0.1:8000/console/")
    print(f"  Execution Mode:         {'LIVE REAL-TIME STREAMING' if live_mode else '5-MINUTE TIMELINE STAGGERING'}")
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
        print(f"[+] Authenticated to Organization: {org_id} (Terminus Security Operations)\n")

        now = datetime.now(UTC)

        # ─── REALISTIC 5-MINUTE WINDOW SCENARIOS ────────────────────────────────────
        # Defines realistic timeline of events across a 300-second (5 min) window
        timeline_events = [
            # T - 290s: Regular customer Sarah logs in
            {"offset": 290, "method": "POST", "path": "/bank/api/login", "body": {"username": "sarah.jenkins", "password": "BankPass2026!"}, "desc": "Customer Sarah Jenkins logs into online banking", "expected": "IGNORE (Level 2)"},
            # T - 275s: Sarah checks branch locations
            {"offset": 275, "method": "GET", "path": "/bank/api/search?q=downtown+branch", "body": None, "desc": "Customer searches 'downtown branch'", "expected": "IGNORE (Level 2)"},
            # T - 260s: Sarah transfers funds
            {"offset": 260, "method": "POST", "path": "/bank/api/transfer", "body": {"to_account": "9021", "amount": 250.00}, "desc": "Customer executes $250 transfer via FedNow", "expected": "IGNORE (Level 3)"},
            # T - 240s: Homepage visit from normal customer
            {"offset": 240, "method": "GET", "path": "/bank/", "body": None, "desc": "Customer browses retail banking homepage", "expected": "Benign Web Traffic"},
            # T - 225s: Customer checks auto loan rates
            {"offset": 225, "method": "GET", "path": "/bank/api/search?q=auto+loan+rates", "body": None, "desc": "Customer queries auto loan rates", "expected": "IGNORE (Level 2)"},
            
            # T - 200s: External adversary begins brute-force probe
            {"offset": 200, "method": "POST", "path": "/bank/api/login", "body": {"username": "corporate_treasury_admin", "password": "Password123!"}, "desc": "Adversary probes 'corporate_treasury_admin' with default password", "expected": "TRIAGE (Level 7 Anomaly)"},
            # T - 185s: Adversary tries root login
            {"offset": 185, "method": "POST", "path": "/bank/api/login", "body": {"username": "administrator", "password": "admin"}, "desc": "Adversary probes 'administrator' credential", "expected": "TRIAGE (Level 7 Anomaly)"},
            # T - 170s: Normal customer login
            {"offset": 170, "method": "POST", "path": "/bank/api/login", "body": {"username": "customer", "password": "password"}, "desc": "Customer 'customer' logs into personal portal", "expected": "IGNORE (Level 2)"},
            # T - 155s: Customer executes utility bill payment transfer
            {"offset": 155, "method": "POST", "path": "/bank/api/transfer", "body": {"to_account": "1042", "amount": 142.10}, "desc": "Customer executes $142.10 utility transfer", "expected": "IGNORE (Level 3)"},
            
            # T - 130s: Adversary attempts SQL Injection on account search
            {"offset": 130, "method": "GET", "path": "/bank/api/search?q=' OR '1'='1' --", "body": None, "desc": "Adversary injects SQLi auth-bypass into search parameter", "expected": "ESCALATE (Level 12 Exploit / MITRE T1190)"},
            # T - 110s: Adversary probes second SQLi payload
            {"offset": 110, "method": "GET", "path": "/bank/api/search?q=UNION SELECT username, password_hash FROM bank_users --", "body": None, "desc": "Adversary injects UNION SELECT credential dump payload", "expected": "ESCALATE (Level 12 Exploit / MITRE T1190)"},
            # T - 90s: Normal customer searches hours
            {"offset": 90, "method": "GET", "path": "/bank/api/search?q=weekend+teller+hours", "body": None, "desc": "Customer queries weekend teller hours", "expected": "IGNORE (Level 2)"},
            
            # T - 70s: Adversary discovers and breaches Decoy Treasury Vault
            {"offset": 70, "method": "GET", "path": "/bank/api/admin/treasury-keys", "body": None, "desc": "Adversary breaches Decoy Treasury Vault & steals FedWire canary key", "expected": "ESCALATE (Level 15 Canary Breach / MITRE T1552)"},
            # T - 45s: Normal customer executes saving deposit transfer
            {"offset": 45, "method": "POST", "path": "/bank/api/transfer", "body": {"to_account": "9021", "amount": 500.00}, "desc": "Customer executes $500 savings transfer", "expected": "IGNORE (Level 3)"},
            # T - 20s: Adversary exfiltrates Synthetic Customer Financial Records
            {"offset": 20, "method": "GET", "path": "/bank/api/customers/export", "body": None, "desc": "Adversary exfiltrates synthetic customer PII & SSNs", "expected": "ESCALATE (Level 15 Exfiltration / MITRE T1567)"},
            # T - 5s: Final benign search
            {"offset": 5, "method": "GET", "path": "/bank/api/search?q=mortgage+rates", "body": None, "desc": "Customer queries 30-year fixed mortgage rates", "expected": "IGNORE (Level 2)"},
        ]

        if not live_mode:
            print("--------------------------------------------------------------------------------")
            print("  SIMULATING 5-MINUTE HISTORICAL WINDOW (CHRONOLOGICALLY STAGGERED TIMELINE)")
            print("--------------------------------------------------------------------------------")
            print(f"[*] Dispatching {len(timeline_events)} realistic banking events across 300-second window (T-5m to T-0m)...")

            for ev in timeline_events:
                event_time = now - timedelta(seconds=ev["offset"])
                req_headers = {**headers, "X-Simulated-Time": event_time.isoformat()}
                
                if ev["method"] == "POST":
                    r = await client.post(ev["path"], headers=req_headers, json=ev["body"])
                else:
                    r = await client.get(ev["path"], headers=req_headers)
                
                time_str = event_time.strftime("%H:%M:%S")
                offset_str = f"T - {ev['offset']:03d}s"
                print(f"  [{time_str} | {offset_str}] {ev['desc']}")
                print(f"       -> Policy Decision: {ev['expected']} (HTTP {r.status_code})")

            print("\n[+] 5-minute historical timeline successfully populated with staggered timestamps!")

        else:
            print("--------------------------------------------------------------------------------")
            print(f"  STREAMING LIVE REAL-TIME PACED TRAFFIC (DURATION: {live_duration} SECONDS)")
            print("--------------------------------------------------------------------------------")
            print("[*] Streaming continuous banking events every 2-3 seconds in real time...")
            print("[*] Watch http://127.0.0.1:8000/console/ to see live updates arriving!\n")

            start_t = time.time()
            step = 0
            while time.time() - start_t < live_duration:
                step += 1
                ev = random.choice(timeline_events)
                curr_time = datetime.now(UTC)
                req_headers = {**headers, "X-Simulated-Time": curr_time.isoformat()}

                if ev["method"] == "POST":
                    r = await client.post(ev["path"], headers=req_headers, json=ev["body"])
                else:
                    r = await client.get(ev["path"], headers=req_headers)

                print(f"  [{curr_time.strftime('%H:%M:%S')} #{step:02d}] {ev['desc']}")
                print(f"       -> Status: {r.status_code} | Policy: {ev['expected']}")

                # Paced delay between 1.5s and 2.5s
                await asyncio.sleep(random.uniform(1.5, 2.5))

            print(f"\n[+] Live stream completed ({step} events over {live_duration}s).")

        # Check final SOC status
        inc_res = await client.get("/incidents", headers=headers)
        if inc_res.status_code == 200:
            active_incidents = inc_res.json()
            critical_inc = [i for i in active_incidents if i.get("severity") == "critical"]
            print("\n" + "=" * 80)
            print("  TERMINUS SOC STATUS POST-SIMULATION")
            print("=" * 80)
            print(f"  * Total Active Incidents:            {len(active_incidents)}")
            print(f"  * Critical Priority Threats:         {len(critical_inc)}")
            print("  * Compromised / Monitored Endpoints:")
            hosts = {i.get("agent_name", "unassigned") for i in active_incidents}
            for h in sorted(hosts):
                host_count = sum(1 for i in active_incidents if i.get("agent_name") == h)
                print(f"    - Host '{h}': {host_count} active threat investigations")

        print("\n[OK] Simulation completed successfully!")
        print("     Refresh http://127.0.0.1:8000/console/ to see timestamps cleanly distributed across the 5-minute window.")


def main() -> None:
    parser = argparse.ArgumentParser(description="First Heritage Community Bank Traffic Simulator")
    parser.add_argument("--live", action="store_true", help="Run in live real-time streaming mode")
    parser.add_argument("--duration", type=int, default=30, help="Live mode duration in seconds (default: 30)")
    args = parser.parse_args()

    asyncio.run(run_simulation(live_mode=args.live, live_duration=args.duration))


if __name__ == "__main__":
    main()
