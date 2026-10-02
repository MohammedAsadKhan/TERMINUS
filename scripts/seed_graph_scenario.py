"""Add a clearly synthetic, seven-day cross-host investigation to the local demo."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta

import httpx2


SCENARIO = [
    (6, "graph-lab-01", "203.0.113.77", "auth-gw-01", 8, "Repeated SSH authentication failures", "T1110", "sshd: 37 failed passwords for admin from 203.0.113.77; no success observed"),
    (5, "graph-lab-02", "203.0.113.77", "web-prod-02", 12, "Blocked JNDI lookup probe", "T1190", "nginx: source 203.0.113.77 requested /search?q=${jndi:ldap://example.invalid/probe}; application blocked request"),
    (4, "graph-lab-03", "203.0.113.77", "auth-gw-01", 9, "Second SSH password spray", "T1110", "sshd: 62 failed passwords for service accounts from 203.0.113.77; no success observed"),
    (2, "graph-lab-04", "203.0.113.77", "web-prod-02", 11, "Blocked SQL injection probe", "T1190", "waf: 203.0.113.77 sent UNION SELECT probe to /search; request blocked"),
    (1, "graph-lab-05", "203.0.113.77", "vault-decoy-01", 15, "Synthetic canary vault accessed", "T1552", "canary: 203.0.113.77 requested synthetic decoy credential endpoint"),
    (5, "graph-lab-06", "198.51.100.5", "ops-jump-01", 3, "Approved maintenance login", None, "sshd: maintenance-user logged in from 198.51.100.5 during approved change window"),
    (3, "graph-lab-07", "192.0.2.55", "web-stage-01", 7, "Unrelated staging scan", "T1046", "nginx: 192.0.2.55 scanned staging paths; no connection to the production source recorded"),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="http://127.0.0.1:8002")
    args = parser.parse_args()
    if not args.target.startswith(("http://127.0.0.1:", "http://localhost:")):
        raise ValueError("The scenario may only target loopback")
    with httpx2.Client(base_url=args.target, timeout=60.0) as client:
        login = client.post("/auth/login", json={"email": "admin@terminus.local", "password": "Password123!"})
        login.raise_for_status()
        headers = {"Authorization": "Bearer " + login.json()["session_token"]}
        orgs = client.get("/orgs", headers=headers)
        orgs.raise_for_status()
        headers["X-Org-ID"] = orgs.json()[0]["org_id"]
        for days_ago, alert_id, source, host, level, description, mitre, log in SCENARIO:
            event = {
                "id": alert_id, "rule": {"id": 220000 + int(alert_id[-2:]), "level": level, "description": f"Lab: {description}", "mitre": {"id": mitre} if mitre else {}},
                "agent": {"id": host, "name": host}, "data": {"srcip": source}, "full_log": log,
                "timestamp": (datetime.now(UTC) - timedelta(days=days_ago)).isoformat(),
            }
            response = client.post("/wazuh", headers=headers, json=event)
            response.raise_for_status()
            print(f"{alert_id}: {response.json()['policy']['tier']}")


if __name__ == "__main__":
    main()
