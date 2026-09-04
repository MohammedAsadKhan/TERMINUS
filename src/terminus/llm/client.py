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
        return {
            "severity": "medium",
            "confidence": "high",
            "summary": "Scripted test summary.",
            "recommended_actions": ["Isolate host", "Check logs"],
        }
