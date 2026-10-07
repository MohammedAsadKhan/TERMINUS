import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

spec = importlib.util.spec_from_file_location(
    "lab_block", Path(__file__).parents[1] / "scripts/lab/terminus_ip_block.py"
)
block = importlib.util.module_from_spec(spec)
spec.loader.exec_module(block)


def message(command="add", **changes):
    data = {
        "srcip": "10.77.0.10",
        "terminus_intent_id": "intent-1",
        "terminus_proposal_digest": "a" * 64,
        "terminus_duration_seconds": 60,
    }
    data.update(changes)
    return {"command": command, "parameters": {"alert": {"data": data}}}


def test_atomic_batch_scoped_with_endpoint_expiry():
    calls = []

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=1 if len(calls) == 1 else 0, stdout=b"")

    result = block.execute(message(), runner)
    assert result["state"] == "accepted"
    assert not result["verified"]
    script = calls[1][1]["input"].decode()
    assert "10.77.0.10 timeout 60s" in script
    assert "hook input" in script
    assert "flush" not in script
    assert calls[1][0] == [block.NFT, "--file", "-"]
    assert "shell" not in calls[1][1]


def test_duplicate_does_not_renew_and_delete_requires_ownership():
    _, table, identity, _ = block.plan(message())
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "nftables": [
                        {
                            "table": {
                                "name": table,
                                "family": "inet",
                                "comment": identity,
                            }
                        }
                    ]
                }
            ).encode(),
        )

    assert block.execute(message(), runner)["state"] == "already_owned"
    assert len(calls) == 1
    block.execute(message("delete"), runner)
    assert calls[-1] == [block.NFT, "delete", "table", "inet", table]


def test_foreign_table_never_deleted():
    def runner(args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=b'{"nftables":[]}')

    with pytest.raises(ValueError, match="Ownership"):
        block.execute(message("delete"), runner)


@pytest.mark.parametrize(
    "changes",
    [
        {"srcip": "192.168.56.1"},
        {"terminus_duration_seconds": True},
        {"terminus_duration_seconds": 901},
        {"terminus_intent_id": ";shell"},
        {"terminus_proposal_digest": "not-a-digest"},
    ],
)
def test_invalid_scope_before_external_io(changes):
    def runner(*args, **kwargs):
        pytest.fail("No external I/O permitted")

    with pytest.raises(ValueError):
        block.execute(message(**changes), runner)
