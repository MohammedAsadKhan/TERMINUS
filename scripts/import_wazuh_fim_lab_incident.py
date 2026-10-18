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
        if collection.status != "ok" or collection.coverage != "complete" or collection.gaps or collection.truncated:
            raise ValueError("Incomplete source collection: "+str(collection.gaps))
        selected = tuple(item for item in collection.observations
                         if isinstance(item.data, dict)
                         and isinstance(item.data.get("alert"), dict)
                         and isinstance(item.data["alert"].get("syscheck"), dict)
                         and str(item.data["alert"]["syscheck"].get("path", "")).startswith("/home/labadmin/terminus-fim-lab/"))
        incident = import_file_integrity_incident(db, org_id=args.org, actor=args.actor,
                                                agent_id="001", collection=collection.model_copy(update={"observations": selected}))
        roots = [t for t in OrchestrationStore(db).list_tasks(args.org, incident_id=incident) if t.role == "main_orchestrator"]
        print(f"Imported {len(selected)} real file integrity events. Incident: {incident}")
        print("Saved evidence task: "+roots[0].task_id)
    finally:
        await reader.aclose()
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("database", "org", "actor", "start", "end"):
        parser.add_argument("--"+name, required=True)
    asyncio.run(run(parser.parse_args()))
