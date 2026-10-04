# Named model connections: implementation and handoff

M01 adds durable named connection settings and encrypted API credentials. Multiple connections for the same provider are allowed. Provider metadata covers OpenAI, Anthropic, Gemini, OpenRouter, DeepSeek, OpenAI-compatible endpoints and local/private models.

This registry performs no outbound calls, model inference, health checks or credential verification. Every connection remains `unverified`; enabled configuration is not execution permission. The legacy single-provider pipeline is unchanged and does not automatically consume these connections. Native adapters, model/role routing, data-sharing policy, redaction and financial budgets remain M02-M05.

## Secret protection and setup

Set `TERMINUS_MODEL_CREDENTIALS_KEY` to a canonical base64url-encoded random 32-byte key. Generate it once on the deployment host:

```powershell
uv run python -c "from terminus.model_gateway.secrets import CredentialCipher; print(CredentialCipher.generate_key().get_secret_value())"
```

Store that value in a protected environment/secret service, outside SQLite and source control. Do not use the license signing secret or human session secret. No fallback key is generated or saved in SQLite. Missing configuration permits metadata operations but cannot save API keys. A malformed configured key makes the registry API unavailable with a generic error.

Credential envelopes use AES-256-GCM, a fresh random nonce for each encryption, and associated data binding the organization and connection. Authenticated encryption detects changed ciphertext or mismatched bindings; see the [cryptography documentation](https://cryptography.io/en/latest/hazmat/primitives/aead/). The registry master key and write-only API keys use masked representations and are excluded from settings/request serialization. Public responses disclose only a boolean and a constant mask, never key prefixes or suffixes.

Back up the encryption key separately from the database. Losing it prevents recovering stored credentials. Changing it does not migrate existing envelopes; bulk master-key rotation is future work. Connection-level API-key replacement/clear is supported. Changing provider or destination requires an explicit replacement or clear so retained credentials cannot move silently. Do not change the master key as a substitute for rotating a provider API key.

## Authenticated configuration API

The `/model-connections` routes use the existing authenticated server identity and organization selection. Current members may inspect masked configuration; current administrators may create, update and delete. Storage rechecks membership inside transactions, including after demotion. Cross-organization identifiers cannot resolve a connection. The API does not expose plaintext credential retrieval.

- `GET /model-connections`: organization-scoped masked list.
- `GET /model-connections/{connection_id}`: masked detail.
- `POST /model-connections`: strict named configuration; optional write-only `api_key`.
- `PATCH /model-connections/{connection_id}`: include `expected_version`; omitted key retains it, explicit null clears it, a new key replaces it.
- `DELETE /model-connections/{connection_id}?expected_version=N`: delete only the expected version.

Updates and deletion use version checks so a teammate cannot silently overwrite newer settings. Names are unique within an organization. Connections, model lists and credential sizes are bounded. Mutation audit records contain identity, operation and version without raw request bodies or keys. Model names are a configured catalog, not proof of provider support.

Provider endpoints are typed administrative configuration. Fixed providers use their default endpoints; compatible endpoints require HTTPS. Local HTTP endpoints require loopback/private literal IPs; local HTTPS can register a company hostname. A local provider label does not verify destination locality, which remains a required M03 check before data egress. Userinfo, query strings and fragments are rejected. Storing an endpoint grants no egress permission and performs no request; future adapters must separately enforce destination and data policy.

The dedicated API sanitizes validation failures so invalid credentials cannot be echoed in 422 errors. It returns generic authorization/conflict/protection failures without raw exception text. Operators must also keep HTTP body logging disabled in external proxies and monitoring.

## Team ownership and next work

Done by - Mohammed | Agent - Codex orchestrator and GPT-5.6 Sol storage/API agents. Verified: 570 tests passed against temporary databases, including 53 new cipher/storage/API checks; targeted Ruff and focused new-module type checks passed. Live providers remain unverified. See the [execution checklist](EXECUTION_CHECKLIST.md) for shared completion status. Claim a task there before editing the same modules.

Next implement M03 role/model/data-locality and redaction policy, with M05 durable budget reservations. [M02 provider protocol adapters](MODEL_ADAPTERS.md) are now fixture-tested; production transport and live calls remain gated by policy/budgets. U04 console settings can consume these masked endpoints separately. O05 specialist execution follows those gates. Lab setup and telemetry validation remain independent tasks.
