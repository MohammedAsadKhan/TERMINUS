# Provider protocol adapters and handoff (M02)

M02 implements pure request/response codecs and an explicitly fixture-only transport harness. It does not introduce a live model gateway, production HTTP transport, credential resolution, model routing or a specialist handler. The server's legacy single-provider pipeline is unchanged. All named connections and provider/model capabilities remain unverified until M06 live evaluation.

## Implemented protocols

| Family | Codec and contract |
| --- | --- |
| OpenAI | Chat Completions messages/function calls, strict JSON-schema request and `max_completion_tokens` |
| OpenRouter | OpenAI-compatible messages, JSON-schema request and `max_tokens`; backing-model capabilities still require evaluation |
| DeepSeek | OpenAI-compatible messages/tools, documented JSON-object mode, explicit schema instruction and local output validation |
| Compatible/private/local | Same compatible codec, with explicit configured endpoint; advertised JSON-schema/tool support is unverified |
| Anthropic | Native Messages, system field, tool_use/tool_result blocks and output_config JSON-schema format |
| Gemini | Native generateContent, function declarations/responses, JSON-schema generation configuration and bounded opaque tool-call signatures |

The DeepSeek branch requests JSON mode explicitly; it does not claim provider-enforced strict JSON Schema. An unsupported request becomes an error, without retry, silent mode switching, model fallback or fabricated success.

Primary references: [OpenAI Chat API](https://developers.openai.com/api/reference/resources/chat), [OpenRouter structured outputs](https://openrouter.ai/docs/guides/features/structured-outputs), [DeepSeek JSON output](https://api-docs.deepseek.com/guides/json_mode), [Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create), [Anthropic structured outputs](https://platform.claude.com/docs/en/build-with-claude/structured-outputs), [Anthropic tools](https://platform.claude.com/docs/en/agents-and-tools/tool-use/handle-tool-calls), [Gemini generateContent](https://ai.google.dev/api/generate-content), [Gemini function calling](https://ai.google.dev/gemini-api/docs/generate-content/function-calling), [Gemini thought signatures](https://ai.google.dev/gemini-api/docs/generate-content/thought-signatures). Codecs target the conservative non-streaming text/function subset documented when implemented; a link or fixture is not live capability verification.

## Shared safety contract

`contracts.py` defines strict ModelRequest, ChatMessage, ToolSpec, ToolCall, ModelResponse and ModelUsage. Model identity, message/tool counts, prompt size, argument size and output tokens are bounded. Request and encoded payload limits are 64 KiB; at most 64 messages, 16 declared tools, eight calls per assistant turn and 4096 requested output tokens are accepted. Copied requests are revalidated by the fixture harness before dispatch.

The initial JSON-schema dialect is deliberately small: object/array/string/integer/number/boolean/null types, properties, required, additionalProperties, items, enum and description. Objects are closed and all declared fields required. Schemas are limited to 16 KiB, eight nesting levels and 32 properties per object. References, unions and unsupported constraint keywords fail before transport rather than being silently ignored. Extend this dialect through explicit contracts and provider fixtures before using new schema features.

Successful findings must be finite JSON objects matching the requested schema. Duplicate JSON keys, fences, malformed JSON, extra properties, unknown tools, invalid tool arguments and reused/unmatched call IDs fail. Tools are declarations and requests only: these codecs execute no tools. Tool results must refer to the exact preceding call and name; missing results cannot be skipped.

Normal provider text prefaces accompanying function calls are discarded. Only validated calls are returned, without promoting commentary into findings. Refusals and truncated outputs cannot publish parsed findings or executable calls. Returned usage reflects the provider's available fields; missing usage, including an unreported total, remains unknown. There are no invented prices or financial reservations. The current usage contract covers aggregate input/output/total fields; provider-specific cache/reasoning billing counters and provider request-ID capture must be added with production transport and M05 reconciliation before financial accounting is claimed.

Gemini tool-call thought signatures are opaque bounded state preserved for continuation. Thought text is discarded and never returned as analyst activity. Synthetic call IDs incorporate prior call count to avoid repeating identities across rounds. Final-text signatures are not represented by this contract. Anthropic extended-thinking blocks, streaming, media and provider/server-side tools remain unsupported. Models needing those features must be excluded until the contracts expand and are evaluated.

## Fixture transport boundary

`FixtureModelClient` requires an exact `httpx2.MockTransport`. There is no default transport, real key parameter, credential lookup or server execution route. It uses a fixed clearly fake authentication value to test provider header shapes. Fixture callbacks are trusted test code, not a sandbox for arbitrary plugins.

The harness has a total deadline of at most ten seconds, a decoded wire ceiling of 1 MiB and a 64 KiB normalized result ceiling. It rejects redirects, suppresses raw error bodies and makes one attempt. Timeout/transport failures leave usage unknown; cancellation propagates. No policy or budget exemption is implied by these test interfaces.

## Team handoff and next work

Done by - Mohammed | Agent - Codex orchestrator and GPT-5.6 Sol compatible/native implementation agents. Tests use synthetic recorded-shape fixtures, temporary databases for the full suite, and no real provider credentials. Verification: 670 tests passed against temporary databases, including 100 new protocol/codec/fixture checks. Targeted Ruff and focused source type checks passed. The [execution checklist](EXECUTION_CHECKLIST.md) records completion and ownership.

M03 is next: tenant/role connection permissions, verified destination locality and redaction before every call or fallback. Then M04 capability-based routing and M05 durable financial admission/reconciliation. Only after those gates should a production transport resolve M01 credentials and connect O05 specialists. M06 must record which exact models/providers passed live schema/tool evaluation. U04 can independently implement the masked connection settings UI. Lab setup and real telemetry acceptance remain separate.
