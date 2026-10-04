"""Build the eight core specialist handlers from one set of dependencies."""

from __future__ import annotations

from terminus.orchestration.scheduler import JobHandler
from terminus.orchestration.specialists.roles import ROLE_SPECS
from terminus.orchestration.specialists.runtime import (
    SpecialistDeps,
    make_specialist_handler,
)


def build_specialist_handlers(deps: SpecialistDeps) -> dict[str, JobHandler]:
    """One handler per core role; each rejects tasks of any other role."""
    return {
        role: make_specialist_handler(spec, deps) for role, spec in ROLE_SPECS.items()
    }
