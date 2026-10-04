"""Durable operator read grants and contexts issued by trusted server code.

The actor argument comes from an authenticated server session, never model
arguments. Endpoint bindings are explicit operator assertions about an incident;
discovering an endpoint in provider inventory does not grant access to it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Annotated, Literal, cast
from uuid import uuid4

from pydantic import Field, TypeAdapter, model_validator

from terminus.core.ids import OrgId, UserId
from terminus.orchestration.scheduler_models import JobLease
from terminus.orchestration.scheduler_store import SchedulerStore
from terminus.orgs.models import OrganizationRole
from terminus.orgs.storage import SqliteMembershipStore
from terminus.storage.db import Database
from terminus.toolkit.audit import ToolInvocationStore
from terminus.toolkit.catalog import CORE_ROLES, load_catalog
from terminus.toolkit.models import Contract, CoreRole, Id, ToolExecutionContext
from terminus.toolkit.registry import ExecutableToolRegistry

_ID = TypeAdapter[str](Id)
ProviderAgentId = Annotated[str, Field(pattern=r"^[0-9]{3,8}$")]


class ReadContextDeniedError(ValueError):
    """Trusted authorization no longer permits a scoped read."""


class ReadPolicyConflictError(ValueError):
    """Another operator changed the policy; reload before editing."""


class ReadResource(Contract):
    resource_id: Id
    org_id: Id
    incident_id: Id
    kind: Literal["incident", "endpoint"]
    agent_id: ProviderAgentId | None = None

    @model_validator(mode="after")
    def endpoint_identity(self) -> ReadResource:
        if (self.kind == "endpoint") != (self.agent_id is not None):
            raise ValueError("Only endpoint resources require a provider agent ID")
        return self


class ReadPolicy(Contract):
    org_id: Id
    incident_id: Id
    version: int = Field(ge=1)
    enabled: bool = True
    role_tool_ids: dict[CoreRole, tuple[Id, ...]]
    connector_ids: tuple[Id, ...]

    @property
    def policy_version(self) -> str:
        return f"read-policy:{self.version}"


class ToolReadPolicyStore:
    """Admin-edited incident read policy with optimistic version checks."""

    def __init__(self, db: Database) -> None:
        self.db: Database = db
        self.memberships: SqliteMembershipStore = SqliteMembershipStore(db)
        with db.transaction() as conn:
            _ = conn.execute("""CREATE TABLE IF NOT EXISTS toolkit_read_policies (
                org_id TEXT NOT NULL, incident_id TEXT NOT NULL,
                version INTEGER NOT NULL, payload_json TEXT NOT NULL,
                PRIMARY KEY(org_id, incident_id),
                FOREIGN KEY(org_id) REFERENCES organizations(org_id),
                FOREIGN KEY(incident_id) REFERENCES incidents(ticket_id)
            )""")
            _ = conn.execute("""CREATE TABLE IF NOT EXISTS toolkit_read_resources (
                org_id TEXT NOT NULL, incident_id TEXT NOT NULL,
                resource_id TEXT NOT NULL, payload_json TEXT NOT NULL,
                PRIMARY KEY(org_id, incident_id, resource_id),
                FOREIGN KEY(org_id, incident_id)
                    REFERENCES toolkit_read_policies(org_id, incident_id)
            )""")

    def require_operator(self, org_id: str, actor_user_id: str) -> None:
        _ = _ID.validate_python(actor_user_id)
        if self.memberships.role_of(OrgId(org_id), UserId(actor_user_id)) not in {
            OrganizationRole.ADMIN,
            OrganizationRole.MEMBER,
        }:
            raise ReadContextDeniedError("Current organization operator required")

    def _require_admin(self, org_id: str, incident_id: str, actor_user_id: str) -> None:
        for identifier in (org_id, incident_id, actor_user_id):
            _ = _ID.validate_python(identifier)
        if self.memberships.role_of(OrgId(org_id), UserId(actor_user_id)) != (
            OrganizationRole.ADMIN
        ):
            raise ReadContextDeniedError("Current organization admin required")
        if not self.db.fetchone(
            "SELECT 1 FROM incidents WHERE org_id=? AND ticket_id=?",
            (org_id, incident_id),
        ):
            raise ReadContextDeniedError("Canonical incident does not belong to org")

    def get_policy(self, org_id: str, incident_id: str) -> ReadPolicy:
        row = self.db.fetchone(
            "SELECT payload_json FROM toolkit_read_policies WHERE org_id=? AND incident_id=?",
            (org_id, incident_id),
        )
        if row is None:
            raise ReadContextDeniedError("Incident read policy is not configured")
        return ReadPolicy.model_validate_json(cast("str", row["payload_json"]))

    def _version(self, org_id: str, incident_id: str, expected_version: int) -> int:
        if type(expected_version) is not int or expected_version < 0:
            raise ValueError("expected_version must be a nonnegative integer")
        row = self.db.fetchone(
            "SELECT version FROM toolkit_read_policies WHERE org_id=? AND incident_id=?",
            (org_id, incident_id),
        )
        current = 0 if row is None else row["version"]
        if current != expected_version:
            raise ReadPolicyConflictError("Incident read policy version changed")
        return expected_version + 1

    def _save_policy(self, policy: ReadPolicy) -> ReadPolicy:
        _ = self.db.execute(
            """INSERT INTO toolkit_read_policies VALUES(?,?,?,?)
            ON CONFLICT(org_id,incident_id) DO UPDATE SET
            version=excluded.version,payload_json=excluded.payload_json""",
            (
                policy.org_id,
                policy.incident_id,
                policy.version,
                policy.model_dump_json(),
            ),
        )
        return policy

    def put_policy(
        self,
        actor_user_id: str,
        org_id: str,
        incident_id: str,
        role_tool_ids: Mapping[str, Iterable[str]],
        connector_ids: Iterable[str],
        *,
        expected_version: int = 0,
    ) -> ReadPolicy:
        """Install an explicit read policy; no credentials or external egress."""
        catalog = load_catalog()
        tools = {tool.tool_id: tool for tool in catalog.tools}
        connectors = tuple(sorted(set(connector_ids)))
        if not set(connectors) <= {item.connector_id for item in catalog.connectors}:
            raise ValueError("Unknown read connector")
        grants = {role: tuple(sorted(set(ids))) for role, ids in role_tool_ids.items()}
        for role, ids in grants.items():
            if role not in CORE_ROLES:
                raise ValueError("Read policy requires a core role")
            for tool_id in ids:
                tool = tools.get(tool_id)
                if tool is None or (
                    tool.release != "1.0"
                    or tool.effect not in {"read", "local_analysis"}
                    or tool.egress != "none"
                    or tool.input_contract != "read_query"
                ):
                    raise ValueError("Read policy cannot grant effects or future tools")
        with self.db.transaction():
            self._require_admin(org_id, incident_id, actor_user_id)
            version = self._version(org_id, incident_id, expected_version)
            policy = ReadPolicy.model_validate(
                {
                    "org_id": org_id,
                    "incident_id": incident_id,
                    "version": version,
                    "role_tool_ids": grants,
                    "connector_ids": connectors,
                }
            )
            return self._save_policy(policy)

    def bind_resource(
        self, actor_user_id: str, resource: ReadResource, *, expected_version: int
    ) -> ReadPolicy:
        """An admin explicitly verifies this resource belongs to the incident."""
        resource = ReadResource.model_validate(resource.model_dump())
        with self.db.transaction():
            self._require_admin(resource.org_id, resource.incident_id, actor_user_id)
            policy = self.get_policy(resource.org_id, resource.incident_id)
            version = self._version(
                resource.org_id, resource.incident_id, expected_version
            )
            _ = self.db.execute(
                """INSERT INTO toolkit_read_resources VALUES(?,?,?,?)
                ON CONFLICT(org_id,incident_id,resource_id) DO UPDATE SET
                payload_json=excluded.payload_json""",
                (
                    resource.org_id,
                    resource.incident_id,
                    resource.resource_id,
                    resource.model_dump_json(),
                ),
            )
            return self._save_policy(policy.model_copy(update={"version": version}))

    def revoke_resource(
        self,
        actor_user_id: str,
        org_id: str,
        incident_id: str,
        resource_id: str,
        *,
        expected_version: int,
    ) -> ReadPolicy:
        with self.db.transaction():
            self._require_admin(org_id, incident_id, actor_user_id)
            policy = self.get_policy(org_id, incident_id)
            version = self._version(org_id, incident_id, expected_version)
            _ = self.db.execute(
                "DELETE FROM toolkit_read_resources WHERE org_id=? AND incident_id=? AND resource_id=?",
                (org_id, incident_id, resource_id),
            )
            return self._save_policy(policy.model_copy(update={"version": version}))

    def revoke_policy(
        self,
        actor_user_id: str,
        org_id: str,
        incident_id: str,
        *,
        expected_version: int,
    ) -> ReadPolicy:
        with self.db.transaction():
            self._require_admin(org_id, incident_id, actor_user_id)
            policy = self.get_policy(org_id, incident_id)
            version = self._version(org_id, incident_id, expected_version)
            return self._save_policy(
                policy.model_copy(update={"version": version, "enabled": False})
            )

    def resources(self, org_id: str, incident_id: str) -> tuple[ReadResource, ...]:
        rows = self.db.fetchall(
            "SELECT payload_json FROM toolkit_read_resources WHERE org_id=? AND incident_id=? ORDER BY resource_id",
            (org_id, incident_id),
        )
        return tuple(
            ReadResource.model_validate_json(cast("str", row["payload_json"]))
            for row in rows
        )


class TrustedReadContextFactory:
    """Bind server-authenticated actors to canonical live task ownership.

    The opaque read-quota reference binds issued contexts to this factory. It
    grants no financial budget. Context copies made by the gateway preserve the
    binding, while a caller constructing a context independently cannot gain it.
    """

    def __init__(
        self,
        scheduler: SchedulerStore,
        registry: ExecutableToolRegistry,
        policy_store: ToolReadPolicyStore,
        audit: ToolInvocationStore,
    ) -> None:
        if scheduler.db is not policy_store.db or scheduler.db is not audit.db:
            raise ValueError("Trusted read services must share one database")
        self.scheduler: SchedulerStore = scheduler
        self.registry: ExecutableToolRegistry = registry
        self.policy_store: ToolReadPolicyStore = policy_store
        self.audit: ToolInvocationStore = audit
        self._bindings: dict[str, tuple[str, ToolExecutionContext]] = {}

    def _context(
        self, lease: JobLease, actor_user_id: str, quota_ref: str
    ) -> ToolExecutionContext:
        lease = JobLease.model_validate(lease.model_dump())
        if self.scheduler.is_cancel_requested(lease):
            raise ReadContextDeniedError("Task ownership is stale or cancelled")
        task = self.scheduler.records.get_task(lease.org_id, lease.task_id)
        run = self.scheduler.records.get_agent_run(lease.org_id, lease.run_id)
        job = self.scheduler.get_job(lease.org_id, lease.task_id)
        if (
            task.status != "running"
            or run.status != "running"
            or task.incident_id != lease.incident_id
            or run.incident_id != task.incident_id
            or run.task_id != task.task_id
            or job.role != task.role
            or job.attempt != lease.attempt
            or lease.task != task
            or lease.run != run
        ):
            raise ReadContextDeniedError("Lease differs from canonical task/run")
        self.policy_store.require_operator(task.org_id, actor_user_id)
        policy = self.policy_store.get_policy(task.org_id, task.incident_id)
        if not policy.enabled:
            raise ReadContextDeniedError("Incident read policy was revoked")
        grants = self.registry.grants_for(task.role).intersection(
            policy.role_tool_ids.get(cast("CoreRole", task.role), ())
        )
        resources = self.policy_store.resources(task.org_id, task.incident_id)
        return ToolExecutionContext(
            org_id=task.org_id,
            incident_id=task.incident_id,
            task_id=task.task_id,
            run_id=run.run_id,
            role=cast("CoreRole", task.role),
            granted_tool_ids=tuple(sorted(grants)),
            permitted_resource_ids=tuple(item.resource_id for item in resources),
            permitted_connector_ids=policy.connector_ids,
            policy_version=policy.policy_version,
            budget_reservation_id=quota_ref,
            invocation_count=self.audit.count(task.org_id, task.task_id),
            lease=lease,
        )

    def build(self, lease: JobLease, actor_user_id: str) -> ToolExecutionContext:
        """Only trusted composition code supplies the authenticated actor ID."""
        quota_ref = f"read-quota:{uuid4().hex}"
        with self.scheduler.db.transaction():
            context = self._context(lease, actor_user_id, quota_ref)
            # Long-lived services may issue a context for every invocation.
            # Old issuance eviction fails closed and requires a fresh build.
            if len(self._bindings) >= 1024:
                del self._bindings[next(iter(self._bindings))]
            self._bindings[quota_ref] = (actor_user_id, context)
            return context

    def authorize(self, context: ToolExecutionContext) -> None:
        """Recheck live membership, policy/resources and fencing before each read."""
        context = ToolExecutionContext.model_validate(context.model_dump())
        binding = self._bindings.get(context.budget_reservation_id)
        if binding is None:
            raise ReadContextDeniedError("Context was not issued by this factory")
        actor_user_id, issued = binding
        ignored = {"invocation_id", "invocation_count"}
        if context.model_dump(exclude=ignored) != issued.model_dump(exclude=ignored):
            raise ReadContextDeniedError("Issued context grants or ownership changed")
        with self.scheduler.db.transaction():
            current = self._context(
                context.lease, actor_user_id, context.budget_reservation_id
            )
            if current.model_dump(exclude=ignored) != issued.model_dump(
                exclude=ignored
            ):
                raise ReadContextDeniedError("Policy or resource grants changed")

    def resolve_resource(
        self, context: ToolExecutionContext, resource_id: str
    ) -> ReadResource:
        with self.scheduler.db.transaction():
            self.authorize(context)
            if resource_id not in context.permitted_resource_ids:
                raise ReadContextDeniedError(
                    "Resource is outside trusted incident scope"
                )
            for resource in self.policy_store.resources(
                context.org_id, context.incident_id
            ):
                if resource.resource_id == resource_id:
                    return resource
        raise ReadContextDeniedError("Incident resource binding was revoked")
