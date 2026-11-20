# File name: import_wazuh_fim_lab_incident.py
# Author: Team LARP
# Date: 2026-11-19 (comments revised)
# Version: 0.1.0
# Purpose: Import bounded real file-integrity alerts from the dedicated Ubuntu lab folder.

"""Import bounded real file-integrity alerts from the dedicated Ubuntu lab folder."""
# ruff: noqa: INP001
import argparse
import asyncio
import getpass
from datetime import datetime

from pydantic import SecretStr

from terminus.orchestration.storage import OrchestrationStore
from terminus.storage.db import Database
from terminus.toolkit.lab_import import import_file_integrity_incident
from terminus.toolkit.models import ReadQuery
from terminus.toolkit.sources import EndpointResource
from terminus.toolkit.wazuh_readers import WazuhIndexerReader, WazuhIndexerSettings


async def run(args: argparse.Namespace) -> None:
    """Read file-integrity alerts for one time window and save them as an incident.

    Only the local lab indexer on loopback is contacted, and the password is prompted
    for rather than accepted as an argument. Nothing is imported if the read is partial.
    """
    # The lab indexer uses a self-signed certificate, so TLS verification is off; the
    # endpoint is fixed to the loopback address.
    reader = WazuhIndexerReader(WazuhIndexerSettings(
        org_id=args.org, indexer_url="https://127.0.0.1:19200",
        username=SecretStr("admin"), password=SecretStr(getpass.getpass("Indexer password (admin): ")),
        verify_tls=False,
    ))
    db = Database(args.database)
    try:
        collection = await reader.read(ReadQuery(
            resource_id="endpoint-ref", start=datetime.fromisoformat(args.start),
            end=datetime.fromisoformat(args.end), event_kind="file",
        ), EndpointResource(org_id=args.org, resource_id="endpoint-ref", agent_id="001"))
        # An incomplete, gapped, or truncated read is refused: a missing alert must not be
        # mistaken for an absence of activity in the saved incident.
        if collection.status != "ok" or collection.coverage != "complete" or collection.gaps or collection.truncated:
            raise ValueError("Incomplete source collection: "+str(collection.gaps))
        # Keep only alerts under the dedicated lab folder so unrelated endpoint changes
        # never enter the incident.
        selected = tuple(item for item in collection.observations
                         if isinstance(item.data, dict)
                         and isinstance(item.data.get("alert"), dict)
                         and isinstance(item.data["alert"].get("syscheck"), dict)
                         and str(item.data["alert"]["syscheck"].get("path", "")).startswith("/home/labadmin/terminus-fim-lab/"))
        incident = import_file_integrity_incident(db, org_id=args.org, actor=args.actor,
                                                agent_id="001", collection=collection.model_copy(update={"observations": selected}))
        # Report the saved-evidence task so the operator can find the new incident's root.
        roots = [t for t in OrchestrationStore(db).list_tasks(args.org, incident_id=incident) if t.role == "main_orchestrator"]
        print(f"Imported {len(selected)} real file integrity events. Incident: {incident}")
        print("Saved evidence task: "+roots[0].task_id)
    finally:
        # Close the HTTP reader and database even when the import is refused.
        await reader.aclose()
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "org", "actor", "start", "end"):
        parser.add_argument("--"+name, required=True)
    asyncio.run(run(parser.parse_args()))
