# Database status

Terminus currently uses Python's built-in `sqlite3` driver and SQL repository classes. Normal service startup opens `terminus.db` relative to its working directory. There is no ORM or active PostgreSQL, MySQL, MongoDB, or Redis backend.

Connections enable WAL journaling, foreign keys, a busy timeout, and `synchronous=NORMAL`. WAL allows readers alongside a writer; SQLite still serializes writes. Use SQLite's backup API for a consistent live backup rather than copying only the main file while WAL is active.

## What persists

The service wires SQLite repositories for incidents, agent definitions, workflows, workflow and node runs, approval gates, alert claims, containment allowlists, and action logs. Registered asset inventory records also persist in SQLite and are scoped to an organization. Organization, membership, and user SQL repositories exist, but current authentication and organization services still use memory-backed stores. Sessions, report history, and the campaign stitcher also live in process memory. Creating SQL tables does not make those service paths persistent.

Users, organizations, memberships, sessions, and report history can therefore reset when the service restarts. The default demo administrator and organization are bootstrapped again at startup.

## Configuration limitation

The setup tools advertise database URLs, including PostgreSQL. The runtime `Settings` class and database singleton do not consume those URLs. Changing the wizard's URL alone does not switch the running service to PostgreSQL or change its default file. Tests and explicit database initialization can pass a SQLite path directly.

## Legacy key migration

Older databases use globally unique agent and workflow IDs. Current repositories scope those IDs to an organization. Existing databases need their primary keys changed to `(org_id, agent_id)` and `(org_id, workflow_id)` while preserving records. Merely adding a composite unique index does not remove the old global primary key.

SQLite is sufficient for the current local class demonstration. Hosted deployment should account for persistent storage, backups, and the remaining memory-backed service state before relying on restart durability or multiple application workers.
