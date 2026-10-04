# Database status

Terminus currently uses Python's built-in `sqlite3` driver and SQL repository classes. Normal service startup opens `terminus.db` relative to its working directory. There is no ORM or active PostgreSQL, MySQL, MongoDB, or Redis backend.

Connections enable WAL journaling, foreign keys, a busy timeout, and `synchronous=NORMAL`. WAL allows readers alongside a writer; SQLite still serializes writes. Use SQLite's backup API for a consistent live backup rather than copying only the main file while WAL is active.

## What persists

The service wires SQLite stores for users, organizations, memberships, sessions, incidents, agent definitions, workflows, workflow and node runs, approval gates, alert claims, containment allowlists, and action logs. Registered asset inventory records also persist in SQLite and are scoped to an organization. Daily report history and the campaign stitcher still live in process memory.

Users, organizations, memberships, incident history, and unexpired sessions now survive service restarts. Logout revocation and expiration are durable. Previously memory-only identities and sessions cannot be recovered from SQLite; the first launch of the updated service requires signing in again or registering the account in the durable store.

## Configuration limitation

The setup tools advertise database URLs, including PostgreSQL. The runtime `Settings` class and database singleton do not consume those URLs. Changing the wizard's URL alone does not switch the running service to PostgreSQL or change its default file. Tests and explicit database initialization can pass a SQLite path directly.

## Legacy key migration

Older databases use globally unique agent and workflow IDs. Current repositories scope those IDs to an organization. Existing databases need their primary keys changed to `(org_id, agent_id)` and `(org_id, workflow_id)` while preserving records. Merely adding a composite unique index does not remove the old global primary key.

SQLite is sufficient for the current local class demonstration. Hosted deployment should account for persistent storage, backups, and the remaining memory-backed service state before relying on restart durability or multiple application workers.

## Orchestration foundation

The additive orchestration schema stores incident-scoped tasks, agent runs, immutable evidence, help requests, action attempts, and append-only action events. Composite references keep child records within their organization and incident. Repository transitions use expected-state checks; task creation supports organization-scoped idempotency keys.

These records are a storage foundation. They do not start workers, invoke models, authorize containment, or schedule work. `create_incident_task` verifies that the incident exists in the same tenant before admitting a task; `create_task` remains a low-level legacy/import interface. No new public task API is exposed by this change.

## Canonical incident service path

The default server pipeline, incident queue/detail, copilot and report generation now use the same SQLite incident repository, including when Jira is configured. Jira is an optional export with its external key stored separately from the permanent Terminus incident ID. Pending or unknown exports stay reserved until reconciled; no automatic retry risks creating duplicate external issues.

Incident creation is atomic and idempotent per organization and alert. Workflow checkpoints, reports, alert claims and graph records carry the same incident ID. Final assessments and citations update the incident without replacing its ID or lifecycle status. Close/reopen actions persist resolution details. Existing duplicate historical records are preserved, while an additive mapping chooses one canonical incident per alert for queue reads.

Restart/upgrade verification uses temporary databases and mocked investigation/Jira calls. Actual Wazuh delivery, model providers and lab response still need live validation. Daily report history remains separate work.

## Identity and deployment modes

Runtime identity services use `SqliteUserStore`, `SqliteSessionStore`, `SqliteOrganizationStore` and `SqliteMembershipStore`. Session tokens are random bearer credentials; only SHA-256 token hashes are stored with UTC expiry and revocation timestamps. Every protected request reads the current membership, so removed or demoted users lose the corresponding access without waiting for session expiration. Users without memberships receive 403 for tenant resources.

Local mode retains first-run demo setup. Bootstrap is atomic and does not overwrite existing passwords or restore removed memberships. A generated local license signing secret is retained in the SQLite `local_runtime_secrets` table so licenses remain valid on restart; treat database files and backups as sensitive. An explicitly configured signing secret takes precedence and must remain stable.

For hosting, set `TERMINUS_DEPLOYMENT_MODE=hosted`, a stable `TERMINUS_LICENSE_SECRET`, and serve HTTPS. Hosted cookies are Secure/HttpOnly/SameSite Strict. Hosted mode creates no demo account and rejects the local demo identity even if a local database is reused. Optional first-run owner credentials use `TERMINUS_BOOTSTRAP_ADMIN_EMAIL` and `TERMINUS_BOOTSTRAP_ADMIN_PASSWORD` together (password at least 12 characters); the configured owner gets a separate organization. Bootstrap settings do not rotate an existing password. See [.env.example](../.env.example).


## Named model connection storage (M01, October 4)

`model_connections` stores organization-scoped provider metadata, versioned settings and authenticated encrypted credential envelopes. `model_connection_audit` stores immutable bounded mutation records without request bodies or credentials. Additive schema installation participates in surrounding SQLite transactions. The separate `TERMINUS_MODEL_CREDENTIALS_KEY` is never stored in SQLite and must be backed up outside the database; no automatic key or legacy credential import is performed. See [model connection setup and handoff](MODEL_CONNECTIONS.md). Configuration is unverified and does not enable provider execution.
