import requests
import json
import time

BASE_URL = 'http://127.0.0.1:8000'
session = requests.Session()

def run_ops():
    # 1. Login
    login_resp = session.post(f'{BASE_URL}/auth/login', json={'email': 'admin@terminus.local', 'password': 'Password123!'})
    login_data = login_resp.json()
    token = login_data['session_token']
    headers = {
        'Authorization': f'Bearer {token}',
        'X-Session-Token': token,
        'Content-Type': 'application/json'
    }

    # Get orgs
    orgs_resp = session.get(f'{BASE_URL}/orgs', headers=headers)
    orgs = orgs_resp.json()
    org_id = orgs[0]['org_id'] if orgs and isinstance(orgs, list) else 'org-terminus-demo'
    headers['X-Org-ID'] = org_id
    print(f"[+] Authenticated successfully as admin@terminus.local. Org: {org_id}")

    # 2. Allowlist Setup
    al_resp = session.post(f'{BASE_URL}/containment/allowlist', json={
        'kind': 'host',
        'value': 'dc01.corp.internal',
        'note': 'Primary Active Directory Domain Controller - Protected Asset'
    }, headers=headers)
    print(f"[+] Allowlist setup status: {al_resp.status_code}")

    # 3. Deploy Agents
    agents_to_deploy = [
        {
            'name': 'Triage Sentinel AI',
            'role_description': 'Rapid triage and MITRE ATT&CK tagging',
            'master_prompt': 'You are Triage Sentinel AI. Your mission is rapid triage, sub-second noise suppression, and MITRE ATT&CK tagging across inbound SIEM telemetry.'
        },
        {
            'name': 'Forensic Hunter',
            'role_description': 'Payload deobfuscation and memory analysis',
            'master_prompt': 'You are Forensic Hunter. Deeply analyze endpoint memory dumps, deobfuscate PowerShell/cradle payloads, extract IOCs, and establish root cause.'
        },
        {
            'name': 'Containment Operator',
            'role_description': 'Boundary enforcement and host isolation',
            'master_prompt': 'You are Containment Operator. Formulate targeted containment boundaries, network isolation, and firewall blocking while enforcing strict safety guardrails.'
        }
    ]

    existing_agents = session.get(f'{BASE_URL}/agents', headers=headers).json()
    existing_names = {a.get('name'): a for a in existing_agents}

    for ag in agents_to_deploy:
        if ag['name'] not in existing_names:
            r = session.post(f'{BASE_URL}/agents', json=ag, headers=headers)
            print(f"[+] Deployed agent {ag['name']}: {r.status_code} -> {r.json().get('id')}")
        else:
            print(f"[=] Agent {ag['name']} already exists with ID: {existing_names[ag['name']]['id']}")

    # 4. Build & Activate Playbooks
    # Playbook 1: wf-slack-triage
    wf1 = {
        'id': 'wf-slack-triage',
        'name': 'High-Severity Slack War Room Notification',
        'priority': 20,
        'nodes': [
            {'id': 'n1', 'type': 'trigger_wazuh', 'config': {'min_level': 8}},
            {'id': 'n2', 'type': 'condition_severity', 'config': {'min_level': 8}},
            {'id': 'n3', 'type': 'tool_slack', 'config': {'channel': '#soc-incident-war-room'}}
        ],
        'edges': [
            {'id': 'e1', 'source': 'n1', 'target': 'n2', 'source_handle': 'default'},
            {'id': 'e2', 'source': 'n2', 'target': 'n3', 'source_handle': 'true'}
        ]
    }

    # Playbook 2: wf-ransomware-containment
    wf2 = {
        'id': 'wf-ransomware-containment',
        'name': 'Ransomware Automated Defense & Human Approval Gate',
        'priority': 10,
        'nodes': [
            {'id': 'n1', 'type': 'trigger_wazuh', 'config': {'min_level': 12}},
            {'id': 'n2', 'type': 'condition_severity', 'config': {'min_level': 12}},
            {'id': 'n3', 'type': 'condition_approval', 'config': {'required_role': 'admin', 'prompt_message': 'Authorize emergency host network isolation'}},
            {'id': 'n4', 'type': 'tool_isolate', 'config': {'force_override': False}},
            {'id': 'n5_err', 'type': 'tool_slack', 'config': {'channel': '#containment-blocked-alerts'}}
        ],
        'edges': [
            {'id': 'e1', 'source': 'n1', 'target': 'n2', 'source_handle': 'default'},
            {'id': 'e2', 'source': 'n2', 'target': 'n3', 'source_handle': 'true'},
            {'id': 'e3', 'source': 'n3', 'target': 'n4', 'source_handle': 'true'},
            {'id': 'e4', 'source': 'n4', 'target': 'n5_err', 'source_handle': 'on_error'}
        ]
    }

    for wf in [wf1, wf2]:
        r = session.post(f'{BASE_URL}/workflows', json=wf, headers=headers)
        print(f"[+] Workflow {wf['id']} create status: {r.status_code}")
        r_patch = session.patch(f'{BASE_URL}/workflows/{wf['id']}/enabled', json={'enabled': True}, headers=headers)
        print(f"[+] Workflow {wf['id']} enable status: {r_patch.status_code}")

    # 5. Query live incident queue
    incidents = session.get(f'{BASE_URL}/incidents', headers=headers).json()
    print(f"\n[+] Total Incidents in Queue: {len(incidents)}")
    
    # Statistical breakdown
    severity_counts = {}
    attack_vectors = {}
    targeted_hosts = {}
    source_ips = {}
    
    for inc in incidents:
        sev = inc.get('severity', 'unknown')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        desc = inc.get('rule_description', 'unknown')
        attack_vectors[desc] = attack_vectors.get(desc, 0) + 1
        
        host = inc.get('agent_name', 'unknown')
        targeted_hosts[host] = targeted_hosts.get(host, 0) + 1
        
        ip = inc.get('source_ip', 'unknown')
        source_ips[ip] = source_ips.get(ip, 0) + 1

    print("\n--- Severity Breakdown ---")
    for sev, cnt in severity_counts.items():
        print(f"  {sev.upper()}: {cnt}")

    print("\n--- Top Attack Vectors ---")
    for vec, cnt in sorted(attack_vectors.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {vec}: {cnt}")

    print("\n--- Top Targeted Hosts ---")
    for host, cnt in sorted(targeted_hosts.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {host}: {cnt}")

    print("\n--- Top Source IPs ---")
    for ip, cnt in sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  {ip}: {cnt}")

    # 6. Check Pending Approvals
    pending = session.get(f'{BASE_URL}/workflows/approvals/pending', headers=headers).json()
    print(f"\n[+] Pending Approvals Count: {len(pending)}")
    for apprv in pending:
        print(f"  Pending Approval: ID={apprv.get('approval_id')} RunID={apprv.get('run_id')} Msg={apprv.get('prompt_message')}")
        # Resolve approval if appropriate
        res = session.post(f"{BASE_URL}/workflows/approvals/{apprv.get('approval_id')}/resolve", json={'decision': 'approve'}, headers=headers)
        print(f"  -> Approval Resolution: {res.status_code} : {res.json()}")

    # 7. Query AI Copilot for Attack Correlation
    copilot_query = {
        'prompt': 'Analyze all active incidents, correlate multi-host attack clusters, identify primary threat actors/IOCs, and provide an executive threat summary.'
    }
    copilot_resp = session.post(f'{BASE_URL}/copilot/chat', json=copilot_query, headers=headers)
    print(f"\n[+] Copilot Chat Response ({copilot_resp.status_code}):")
    if copilot_resp.status_code == 200:
        copilot_data = copilot_resp.json()
        print(copilot_data.get('response', copilot_data))
    else:
        print(copilot_resp.text)

if __name__ == '__main__':
    run_ops()
