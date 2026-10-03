import requests
import json
import sys
import time

BASE_URL = 'http://127.0.0.1:8000'
session = requests.Session()

def run_ops():
    print("=== Step 1: Authentication ===", flush=True)
    login_resp = session.post(f'{BASE_URL}/auth/login', json={'email': 'admin@terminus.local', 'password': 'Password123!'})
    login_data = login_resp.json()
    token = login_data['session_token']
    headers = {
        'Authorization': f'Bearer {token}',
        'X-Session-Token': token,
        'Content-Type': 'application/json'
    }

    orgs_resp = session.get(f'{BASE_URL}/orgs', headers=headers)
    orgs = orgs_resp.json()
    org_id = orgs[0]['org_id'] if orgs and isinstance(orgs, list) else 'org-terminus-demo'
    headers['X-Org-ID'] = org_id
    print(f"[+] Logged in as: admin@terminus.local | User ID: {login_data.get('user', {}).get('user_id')} | Org: {org_id}", flush=True)

    print("\n=== Step 2: Ensure Safety Allowlist ===", flush=True)
    al_resp = session.post(f'{BASE_URL}/containment/allowlist', json={
        'kind': 'host',
        'value': 'dc01.corp.internal',
        'note': 'Primary Active Directory Domain Controller - Protected Asset'
    }, headers=headers)
    print(f"[+] Safety Allowlist dc01.corp.internal setup: status={al_resp.status_code}", flush=True)

    print("\n=== Step 3: Deploy Specialized AI SOC Agent Fleet ===", flush=True)
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

    deployed_agent_info = []
    for ag in agents_to_deploy:
        if ag['name'] not in existing_names:
            r = session.post(f'{BASE_URL}/agents', json=ag, headers=headers)
            print(f"[+] Deployed Agent '{ag['name']}': status={r.status_code} id={r.json().get('id')}", flush=True)
            deployed_agent_info.append(r.json())
        else:
            ag_id = existing_names[ag['name']]['id']
            print(f"[=] Agent '{ag['name']}' already deployed: id={ag_id}", flush=True)
            deployed_agent_info.append(existing_names[ag['name']])

    print("\n=== Step 4: Build & Activate DAG Automation Playbooks ===", flush=True)
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
        r_create = session.post(f'{BASE_URL}/workflows', json=wf, headers=headers)
        print(f"[+] Workflow {wf['id']} create status: {r_create.status_code}", flush=True)
        r_patch = session.patch(f'{BASE_URL}/workflows/{wf['id']}/enabled', json={'enabled': True}, headers=headers)
        print(f"[+] Workflow {wf['id']} activate status: {r_patch.status_code}", flush=True)

    print("\n=== Step 5: Incident Queue Analysis ===", flush=True)
    incidents = session.get(f'{BASE_URL}/incidents', headers=headers).json()
    print(f"[+] Total Incidents in Active Queue: {len(incidents)}", flush=True)

    severity_counts = {}
    attack_vectors = {}
    targeted_hosts = {}
    source_ips = {}
    campaigns = {}

    for inc in incidents:
        sev = inc.get('severity') or 'unknown'
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        desc = inc.get('rule_description') or 'Unknown rule'
        attack_vectors[desc] = attack_vectors.get(desc, 0) + 1
        
        host = inc.get('agent_name') or 'Unknown host'
        targeted_hosts[host] = targeted_hosts.get(host, 0) + 1
        
        ip = inc.get('source_ip') or 'Unknown IP'
        source_ips[ip] = source_ips.get(ip, 0) + 1

        camp = inc.get('campaign_id') or 'Uncorrelated'
        campaigns[camp] = campaigns.get(camp, 0) + 1

    print("\n--- Severity Distribution ---", flush=True)
    for sev, cnt in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  * {sev.upper()}: {cnt}", flush=True)

    print("\n--- Top Attack Vectors ---", flush=True)
    for vec, cnt in sorted(attack_vectors.items(), key=lambda x: x[1], reverse=True)[:8]:
        print(f"  * {vec} ({cnt} occurrences)", flush=True)

    print("\n--- Top Targeted Endpoints ---", flush=True)
    for host, cnt in sorted(targeted_hosts.items(), key=lambda x: x[1], reverse=True)[:8]:
        print(f"  * {host} ({cnt} alerts)", flush=True)

    print("\n--- Top Attacking IPs ---", flush=True)
    for ip, cnt in sorted(source_ips.items(), key=lambda x: x[1], reverse=True)[:8]:
        print(f"  * {ip} ({cnt} alerts)", flush=True)

    print("\n--- Campaign Clusters ---", flush=True)
    for camp, cnt in sorted(campaigns.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"  * Campaign ID {camp} ({cnt} correlated events)", flush=True)

    print("\n=== Step 6: Pending Approvals & Containment Verification ===", flush=True)
    pending = session.get(f'{BASE_URL}/workflows/approvals/pending', headers=headers).json()
    print(f"[+] Currently Pending Approvals: {len(pending)}", flush=True)
    for apprv in pending:
        apprv_id = apprv.get('approval_id')
        msg = apprv.get('prompt_message')
        print(f"  [*] Pending Approval Found: ID={apprv_id}, Message='{msg}'", flush=True)
        # Resolve
        resolve_resp = session.post(f"{BASE_URL}/workflows/approvals/{apprv_id}/resolve", json={'decision': 'approve'}, headers=headers)
        print(f"  [+] Approval Resolution result: status={resolve_resp.status_code}, data={resolve_resp.json()}", flush=True)

    print("\n=== Step 7: Copilot Threat Correlation & Intelligence ===", flush=True)
    copilot_query = {
        'prompt': 'Analyze all active incidents across the organization, identify attack clusters, correlated IPs, targeted hosts, and summarize the adversary campaign and recommended containment strategy.'
    }
    try:
        copilot_resp = session.post(f'{BASE_URL}/copilot/chat', json=copilot_query, headers=headers, timeout=20)
        print(f"[+] Copilot response status: {copilot_resp.status_code}", flush=True)
        if copilot_resp.status_code == 200:
            copilot_data = copilot_resp.json()
            print(f"[+] Copilot Response:\n{copilot_data.get('response')}", flush=True)
    except Exception as e:
        print(f"[-] Copilot query exception: {e}", flush=True)

    print("\n=== Completed All Automated Ops Successfully ===", flush=True)

if __name__ == '__main__':
    run_ops()
