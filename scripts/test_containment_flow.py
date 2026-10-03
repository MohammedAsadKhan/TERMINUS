import requests
import json
import time

BASE_URL = 'http://127.0.0.1:8000'
session = requests.Session()

def test_flow():
    login_resp = session.post(f'{BASE_URL}/auth/login', json={'email': 'admin@terminus.local', 'password': 'Password123!'})
    token = login_resp.json()['session_token']
    headers = {'Authorization': f'Bearer {token}', 'X-Session-Token': token, 'X-Org-ID': 'org-terminus-demo', 'Content-Type': 'application/json'}

    # Ensure allowlist entry
    session.post(f'{BASE_URL}/containment/allowlist', json={
        'kind': 'host',
        'value': 'dc01.corp.internal',
        'note': 'Primary Active Directory Domain Controller - Protected Asset'
    }, headers=headers)

    # 1. Trigger Ransomware Alert on workstation-88
    ransom_alert = {
        'id': f'alt-ransom-ws88-{int(time.time())}',
        'rule_id': 100088,
        'level': 14,
        'description': 'Active Ransomware Mass Encryption (LockBit 3.0)',
        'mitre': 'T1486',
        'src_ip': '198.51.100.99',
        'agent_name': 'workstation-88.corp.internal',
        'full_log': 'C:\\Windows\\Temp\\lockbit.exe encrypting shares. C2: 198.51.100.99'
    }
    wazuh_resp = session.post(f'{BASE_URL}/wazuh', json=ransom_alert, headers=headers)
    print(f"[+] Wazuh Alert Ingestion (ws-88): status={wazuh_resp.status_code}")

    time.sleep(1)
    pending = session.get(f'{BASE_URL}/workflows/approvals/pending', headers=headers).json()
    print(f"[+] Pending Approvals after ws-88 alert: {len(pending)}")
    for item in pending:
        apprv_id = item['approval_id']
        print(f"  -> Approving isolation for {item.get('agent_name', 'workstation-88')} (ID: {apprv_id})...")
        resolve_resp = session.post(f'{BASE_URL}/workflows/approvals/{apprv_id}/resolve', json={'decision': 'approve'}, headers=headers)
        print(f"  -> Approval Resolution result: status={resolve_resp.status_code}, body={resolve_resp.json()}")

    # 2. Trigger Attack targeting Domain Controller dc01.corp.internal
    dc_alert = {
        'id': f'alt-dc01-attack-{int(time.time())}',
        'rule_id': 100099,
        'level': 14,
        'description': 'LSASS Memory Injection on Domain Controller',
        'mitre': 'T1003',
        'src_ip': '198.51.100.99',
        'agent_name': 'dc01.corp.internal',
        'full_log': 'Shellcode injection into lsass.exe on primary DC'
    }
    wazuh_resp2 = session.post(f'{BASE_URL}/wazuh', json=dc_alert, headers=headers)
    print(f"\n[+] Wazuh Alert Ingestion (dc01): status={wazuh_resp2.status_code}")

    time.sleep(1)
    pending_dc = session.get(f'{BASE_URL}/workflows/approvals/pending', headers=headers).json()
    print(f"[+] Pending Approvals after dc01 alert: {len(pending_dc)}")
    for item in pending_dc:
        apprv_id = item['approval_id']
        print(f"  -> Resolving approval for dc01 (ID: {apprv_id})...")
        resolve_resp2 = session.post(f'{BASE_URL}/workflows/approvals/{apprv_id}/resolve', json={'decision': 'approve'}, headers=headers)
        print(f"  -> Approval Resolution result: status={resolve_resp2.status_code}, body={resolve_resp2.json()}")

    # 3. Check all workflow runs and statuses
    time.sleep(1)
    runs = session.get(f'{BASE_URL}/workflows/runs', headers=headers).json()
    print(f"\n[+] Total Workflow Runs Logged: {len(runs)}")
    for r in runs:
        print(f"  * Run ID: {r.get('run_id')} | WF: {r.get('workflow_id')} | Status: {r.get('status')} | Nodes: {list(r.get('node_results', {}).keys())}")
        for n_id, n_res in r.get('node_results', {}).items():
            if n_res.get('error'):
                print(f"    - Node {n_id} ({n_res.get('node_type')}): ERROR -> {n_res.get('error')}")
            else:
                print(f"    - Node {n_id} ({n_res.get('node_type')}): SUCCESS -> status={n_res.get('status')}")

if __name__ == '__main__':
    test_flow()
