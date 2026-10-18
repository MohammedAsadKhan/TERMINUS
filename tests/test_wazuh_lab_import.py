"""Recorded real-shaped alert import, admission and replay checks."""
# pyright: basic

import json
from datetime import UTC, datetime

import pytest

from terminus.storage.db import Database
from terminus.toolkit.lab_import import import_authentication_incident
from terminus.toolkit.sources import ReadCollection, ReadObservation


@pytest.fixture
def database(tmp_path):
    db = Database(str(tmp_path / "lab.db"))
    now = datetime.now(UTC).isoformat()
    for org in ("org", "other"):
        db.execute(
            "INSERT INTO organizations(org_id,name,created_at) VALUES(?,?,?)",
            (org, org, now),
        )
    db.execute(
        "INSERT INTO users VALUES(?,?,?,?,?)",
        ("admin", "a@example.test", "hash", "Admin", now),
    )
    db.execute("INSERT INTO memberships VALUES(?,?,?)", ("org", "admin", "admin"))
    yield db
    db.close()


def collection(agent="001"):
    stamp = datetime(2026, 10, 6, 1, 14, tzinfo=UTC)
    return ReadCollection(
        status="ok",
        coverage="complete",
        observations=(
            ReadObservation(
                source_id="wazuh-indexer",
                source_event_id="alert:recorded",
                source_timestamp=stamp,
                data={
                    "index": "wazuh-alerts-4.x-2026.10.06",
                    "event_id": "recorded",
                    "alert": {
                        "id": "1791249292.1209176",
                        "timestamp": stamp.isoformat(),
                        "agent": {"id": agent, "name": "terminus-target-a"},
                        "rule": {
                            "id": "5710",
                            "level": 5,
                            "description": "Invalid user",
                            "groups": ["authentication_failed"],
                        },
                        "data": {"srcip": "10.77.0.10"},
                        "full_log": "recorded SSH failure",
                    },
                },
            ),
        ),
    )


def test_import_preserves_source_grants_and_replay(database):
    kwargs = {"org_id": "org", "actor": "admin", "agent_id": "001", "collection": collection()}
    incident = import_authentication_incident(database, **kwargs)
    row = database.fetchone(
        "SELECT raw_payload_json,summary FROM incidents WHERE ticket_id=?", (incident,)
    )
    assert json.loads(row["raw_payload_json"])["id"] == "1791249292.1209176"
    assert "pending" in row["summary"]
    assert (
        database.fetchone("SELECT COUNT(*) AS n FROM toolkit_read_resources")["n"] == 2
    )
    assert import_authentication_incident(database, **kwargs) == incident
    assert database.fetchone("SELECT COUNT(*) AS n FROM incidents")["n"] == 1


def test_foreign_tenant_and_endpoint_denied(database):
    with pytest.raises(ValueError, match="administrator"):
        import_authentication_incident(
            database,
            org_id="other",
            actor="admin",
            agent_id="001",
            collection=collection(),
        )
    with pytest.raises(ValueError, match="Foreign endpoint"):
        import_authentication_incident(
            database,
            org_id="org",
            actor="admin",
            agent_id="001",
            collection=collection("002"),
        )
    assert database.fetchone("SELECT COUNT(*) AS n FROM incidents")["n"] == 0


def test_missing_or_partial_collection_creates_nothing(database):
    for data in (
        ReadCollection(status="unavailable"),
        ReadCollection(status="partial", truncated=True),
    ):
        with pytest.raises(ValueError):
            import_authentication_incident(
                database, org_id="org", actor="admin", agent_id="001", collection=data
            )
    assert database.fetchone("SELECT COUNT(*) AS n FROM incidents")["n"] == 0


def fim_collection(path="/home/labadmin/terminus-fim-lab/demo.conf"):
    source = collection().model_dump(mode="json")
    alert = source["observations"][0]["data"]["alert"]
    alert["rule"]["groups"] = ["ossec", "syscheck", "syscheck_entry_modified"]
    alert["rule"]["description"] = "Integrity checksum changed"
    alert["syscheck"] = {"path": path, "event": "modified"}
    return ReadCollection.model_validate_json(json.dumps(source))


def test_file_integrity_import_preserves_real_shape_and_replay(database):
    from terminus.toolkit.lab_import import import_file_integrity_incident
    kwargs = {"org_id": "org", "actor": "admin", "agent_id": "001", "collection": fim_collection()}
    incident = import_file_integrity_incident(database, **kwargs)
    row = database.fetchone("SELECT raw_payload_json,summary FROM incidents WHERE ticket_id=?", (incident,))
    assert json.loads(row["raw_payload_json"])["syscheck"]["event"] == "modified"
    assert "file integrity" in row["summary"]
    assert import_file_integrity_incident(database, **kwargs) == incident


@pytest.mark.parametrize("path", ["/etc/passwd", "/home/labadmin/terminus-fim-lab/../secret", "/home/labadmin/terminus-fim-lab-other/demo"])
def test_file_integrity_import_rejects_outside_lab(database, path):
    from terminus.toolkit.lab_import import import_file_integrity_incident
    with pytest.raises(ValueError, match="lab file path"):
        import_file_integrity_incident(database, org_id="org", actor="admin", agent_id="001", collection=fim_collection(path))
    assert database.fetchone("SELECT COUNT(*) AS n FROM incidents")["n"] == 0


def test_fim_and_ssh_admission_stay_separate(database):
    from terminus.toolkit.lab_import import import_file_integrity_incident
    with pytest.raises(ValueError):
        import_authentication_incident(database, org_id="org", actor="admin", agent_id="001", collection=fim_collection())
    with pytest.raises(ValueError):
        import_file_integrity_incident(database, org_id="org", actor="admin", agent_id="001", collection=collection())
