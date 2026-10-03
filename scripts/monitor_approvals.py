import requests
import json
import time

BASE_URL = 'http://127.0.0.1:8000'
session = requests.Session()

def monitor_and_act():
    login_resp = session.post(f'{BASE_URL}/auth/login', json={'email': 'admin@terminus.local', 'password': 'Password123!'})
    token = login_resp.json()['session_token']
    headers = {'Authorization': f'Bearer {token}', 'X-Session-Token': token, 'X-Org-ID': 'org-terminus-demo', 'Content-Type': 'application/json'}

    print("[*] Starting monitoring loop for pending approvals and critical events...", flush=True)
    for i in range(15):
        try:
            pending = session.get(f'{BASE_URL}/workflows/approvals/pending', headers=headers).json()
            if pending:
                print(f"[!] Detected {len(pending)} pending approval(s) at iteration {i}:", flush=True)
                for item in pending:
                    apprv_id = item.get('approval_id')
                    prompt = item.get('prompt_message')
                    run_id = item.get('run_id')
                    print(f"  -> Approval ID: {apprv_id} | Run: {run_id} | Prompt: {prompt}", flush=True)
                    res = session.post(f'{BASE_URL}/workflows/approvals/{apprv_id}/resolve', json={'decision': 'approve'}, headers=headers)
                    print(f"  -> Resolved with decision=approve: status={res.status_code}, resp={res.json()}", flush=True)
            else:
                print(f"[-] Check {i+1}/15: No pending approvals", flush=True)
        except Exception as e:
            print(f"[!] Error in check: {e}", flush=True)
        time.sleep(3)

    # Summary of workflow runs
    runs = session.get(f'{BASE_URL}/workflows/runs', headers=headers).json()
    print(f"\n[+] Total Workflow Runs Logged: {len(runs)}", flush=True)
    for r in runs:
        print(f"  * Run {r.get('run_id')} | WF: {r.get('workflow_id')} | Status: {r.get('status')} | Nodes executed: {len(r.get('node_results', {}))}", flush=True)

if __name__ == '__main__':
    monitor_and_act()
