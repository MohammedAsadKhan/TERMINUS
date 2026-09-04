"""OOP foundations: abstract base classes shared by repositories and domain services.

These establish the layered, class-first structure of the codebase. Repositories own
persistence (one per aggregate); Services own domain rules and depend on repositories
via their abstract interface so they can be tested with in-memory fakes.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from terminus.core.ids import OrgId

_RecordT = TypeVar("_RecordT")


class NotFoundError(LookupError):
    """Raised when a repository cannot find a record by its identity."""


class Repository(ABC, Generic[_RecordT]):
    """Base class for a persistence wrapper of one aggregate type."""

    @abstractmethod
    def create(self, record: _RecordT, org_id: OrgId) -> _RecordT:
        """Persist a new record scoped to an organization and return it."""

    @abstractmethod
    def get(self, record_id: str, org_id: OrgId) -> _RecordT:
        """Return a record scoped to an organization or raise NotFoundError."""

    @abstractmethod
    def list(self, org_id: OrgId) -> list[_RecordT]:
        """Return all records belonging to an organization."""


class MemoryRepository(Repository[_RecordT]):
    """Thread-safe, dict-backed generic repository.

    Records are stored keyed by ``(org_id, record_id)``. All read operations are scoped
    by ``org_id`` — cross-org data access is structurally impossible.

    Subclasses must implement ``_record_id`` to extract the identity string from a record.
    """

    def __init__(self) -> None:
        self._store: dict[tuple[OrgId, str], _RecordT] = {}
        self._lock = threading.Lock()

    @abstractmethod
    def _record_id(self, record: _RecordT) -> str:
        """Extract the unique identifier string from a record."""

    def create(self, record: _RecordT, org_id: OrgId) -> _RecordT:
        """Persist a new record and return it."""
        rid = self._record_id(record)
        key = (org_id, rid)
        with self._lock:
            if key in self._store:
                msg = f"Record {rid} already exists in org {org_id}"
                raise ValueError(msg)
            self._store[key] = record
        return record

    def get(self, record_id: str, org_id: OrgId) -> _RecordT:
        """Return a record scoped to an organization or raise NotFoundError."""
        key = (org_id, record_id)
        with self._lock:
            try:
                return self._store[key]
            except KeyError:
                msg = f"Record {record_id} not found in org {org_id}"
                raise NotFoundError(msg) from None

    def list(self, org_id: OrgId) -> list[_RecordT]:
        """Return all records belonging to an organization."""
        with self._lock:
            return [v for (oid, _), v in self._store.items() if oid == org_id]

    def delete(self, record_id: str, org_id: OrgId) -> None:
        """Remove a record. Raises NotFoundError if missing."""
        key = (org_id, record_id)
        with self._lock:
            try:
                del self._store[key]
            except KeyError:
                msg = f"Record {record_id} not found in org {org_id}"
                raise NotFoundError(msg) from None

    def update(self, record: _RecordT, org_id: OrgId) -> _RecordT:
        """Replace an existing record. Raises NotFoundError if missing."""
        rid = self._record_id(record)
        key = (org_id, rid)
        with self._lock:
            if key not in self._store:
                msg = f"Record {rid} not found in org {org_id}"
                raise NotFoundError(msg)
            self._store[key] = record
        return record


class Service(ABC):
    """Base class for a domain service.

    A service composes one or more repositories and enforces domain rules. It exposes
    narrow, well-named public methods and never leaks persistence internals.
    """
