"""Isolated synthetic demo of intake, durable triage, and honest gaps.

Run from the repository root with ``uv run --frozen python scripts/presentation_rehearsal.py``.
Add ``--serve`` to keep the prepared demo open at http://127.0.0.1:8765/console/.
Add ``--bank-demo`` to start the fictional bank, SOC, and ten-minute local
traffic stream at http://127.0.0.1:8766/.
This creates a fresh database in the OS temporary directory, uses no .env file,
and makes no outbound provider, notification, or response calls.
"""

# ruff: noqa: INP001, PLR0915, S603, C901

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from argparse import ArgumentParser
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[1]


def checked(client: TestClient, method: str, path: str, *, expected: int, **kwargs: Any) -> Any:  # noqa: ANN401
    response = getattr(client, method)(path, **kwargs)
    if response.status_code != expected:
        raise RuntimeError(f"{path}: expected {expected}, got {response.status_code}: {response.text[:300]}")
    return response.json()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def find_role(nodes: list[dict], role: str) -> dict | None:
    for node in nodes:
        if node.get("role") == role:
            return node
        found = find_role(node.get("children", []), role)
        if found:
            return found
    return None


def _start_bank_demo(demo_dir: Path, org_id: str, duration_seconds: int) -> None:
    port = 8766
    base_url = f"http://127.0.0.1:{port}"
    server_env = os.environ.copy()
    server_env["PYTHONPATH"] = str(REPO_ROOT / "src") + os.pathsep + server_env.get("PYTHONPATH", "")
    server_env["TERMINUS_REPO_SCAN_ENABLED"] = "true"
    server_env["TERMINUS_BANK_DEMO_MODE"] = "1"
    server_env["TERMINUS_BANK_DEMO_ORG_ID"] = org_id
    server_env["TERMINUS_BANK_DEMO_DURATION"] = str(duration_seconds)
    server_env["TERMINUS_BANK_DEMO_STARTED_AT"] = str(time.time())
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "terminus.server.app:create_app", "--factory",
         "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],
        cwd=demo_dir, env=server_env,
    )
    flood = None
    try:
        for _ in range(80):
            if server.poll() is not None:
                raise RuntimeError("Demo server stopped during startup")
            try:
                with urllib.request.urlopen(f"{base_url}/bank/api/demo/status", timeout=1) as response:  # noqa: S310 - fixed loopback URL
                    if response.status == 200:
                        break
            except (urllib.error.URLError, TimeoutError):
                time.sleep(0.25)
        else:
            raise RuntimeError(f"Demo server did not become healthy on port {port}")
        print(f"Bank site: {base_url}/bank/", flush=True)
        print(f"SOC console: {base_url}/console/", flush=True)
        print("Login: presenter@terminus.example / DemoOnlyPassword123!", flush=True)
        flood = subprocess.Popen(
            [sys.executable, str(REPO_ROOT / "scripts" / "live_interactive_flood.py"),
             "--base-url", base_url, "--duration-seconds", str(duration_seconds)],
            # The bank demo uses its own port so the earlier rehearsal can stay open.
            cwd=demo_dir, env=server_env,
        )
        while server.poll() is None:
            if flood is not None and flood.poll() is not None:
                if flood.returncode != 0:
                    raise RuntimeError(f"Bank traffic generator failed with exit code {flood.returncode}")
                print(f"{duration_seconds}-second stream complete. Bank and SOC screens remain available; press Ctrl+C to stop.", flush=True)
                flood = None
            time.sleep(0.5)
        raise RuntimeError(f"Demo server exited with code {server.returncode}")
    except KeyboardInterrupt:
        pass
    finally:
        if flood is not None and flood.poll() is None:
            flood.terminate()
            flood.wait(timeout=5)
        if server.poll() is None:
            server.terminate()
            server.wait(timeout=5)


def main(*, serve: bool = False, bank_demo: bool = False, duration_seconds: int = 600) -> None:
    demo_dir = Path(tempfile.mkdtemp(prefix="terminus-presentation-"))
    os.chdir(demo_dir)  # Prevent loading the repository's .env or live SQLite file.
    for key in (
        "TERMINUS_LLM_API_KEY", "TERMINUS_WAZUH_URL", "TERMINUS_SLACK_WEBHOOK",
        "TERMINUS_TWILIO_SID", "TERMINUS_TWILIO_TOKEN", "TERMINUS_JIRA_URL",
        "TERMINUS_JIRA_TOKEN", "TERMINUS_SPECIALIST_LIVE_MODELS",
    ):
        os.environ[key] = ""
    os.environ["TERMINUS_DEPLOYMENT_MODE"] = "local"

    from terminus.server.app import create_app
    from terminus.storage.db import Database
    from terminus.toolkit.context import ReadResource, ToolReadPolicyStore

    db_path = demo_dir / "terminus.db"
    worker = None
    with TestClient(create_app()) as client:
        try:
            user = checked(
                client, "post", "/auth/register", expected=201,
                json={"email": "presenter@terminus.example", "password": "DemoOnlyPassword123!", "display_name": "Presenter"},
            )
            login = checked(
                client, "post", "/auth/login", expected=200,
                json={"email": "presenter@terminus.example", "password": "DemoOnlyPassword123!"},
            )
            headers = {"Authorization": f"Bearer {login['session_token']}"}
            org = checked(client, "post", "/orgs", expected=201, headers=headers, json={"name": "Presentation Lab"})
            org_id = org["org_id"]
            headers["X-Org-ID"] = org_id

            from terminus.demos.seed_data import seed_presentation_demo_data

            seed_presentation_demo_data(db=Database.get_instance(), org_id=org_id)

            alert_id = f"synthetic-presentation-{uuid4()}"
            alert = {
                "id": alert_id,
                "rule": {"id": 100101, "level": 8, "description": "[SYNTHETIC] one failed SSH login", "mitre": {"id": "T1110"}},
                "agent": {"id": "001", "name": "training-linux-01"},
                "full_log": "SYNTHETIC TEST EVENT: single BRUTE login failed; no count supplied",
                "timestamp": datetime.now(UTC).isoformat(),
            }
            report = checked(client, "post", "/wazuh", expected=200, headers=headers, json=alert)
            incident_id = report["incident_id"]
            require(bool(incident_id), "No incident ID returned")
            require("OFFLINE DEMO MODE" in report["verdict"]["summary"], "Offline mode was not disclosed")
            require("45 failed" not in report["verdict"]["summary"], "Verdict invented a failure count")
            incidents = checked(client, "get", "/incidents", expected=200, headers=headers)
            require(any(item["id"] == incident_id for item in incidents), "Incident was not persisted")
            refusal = checked(
                client, "post", f"/incidents/{incident_id}/action", expected=501,
                headers=headers, json={"action_type": "block_ip"},
            )
            connection = checked(
                client, "post", "/settings/test-connection", expected=200,
                headers=headers, json={"service": "wazuh", "target_url": "https://example.invalid"},
            )
            require(connection["success"] is False, "Connection check falsely reported success")

            policy = ToolReadPolicyStore(Database.get_instance())
            policy.put_policy(
                user["user_id"], org_id, incident_id,
                {"triage": ("incident.get", "alerts.search", "collection.coverage")},
                ("terminus_store", "wazuh_indexer"),
            )
            policy.bind_resource(
                user["user_id"],
                ReadResource(resource_id="incident-ref", org_id=org_id, incident_id=incident_id, kind="incident"),
                expected_version=1,
            )
            policy.bind_resource(
                user["user_id"],
                ReadResource(resource_id="endpoint-ref", org_id=org_id, incident_id=incident_id, kind="endpoint", agent_id="001"),
                expected_version=2,
            )
            checked(
                client, "post", f"/orchestration/incidents/{incident_id}/start", expected=202,
                headers=headers,
                json={"objective": "Triage the synthetic SSH alert and report missing telemetry", "areas": ["alert_handling"], "idempotency_key": "presentation-triage-1"},
            )

            worker_env = os.environ.copy()
            worker_env["TERMINUS_SPECIALIST_DATABASE"] = str(db_path)
            worker_env["TERMINUS_SPECIALIST_ACTOR_USER_ID"] = user["user_id"]
            worker_env["TERMINUS_SPECIALIST_ROLES"] = "triage"
            command = [
                sys.executable, "-m", "terminus.orchestration.scheduler_cli",
                "--database", str(db_path), "--coordination",
                "--handler", "triage=terminus.orchestration.specialists.deploy:triage",
            ]
            worker = subprocess.Popen(
                command, cwd=demo_dir, env=worker_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            tree = None
            triage = None
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                if worker.poll() is not None:
                    raise RuntimeError(f"Scheduler stopped early: {worker.stderr.read()[-500:]}")
                tree = checked(client, "get", f"/orchestration/incidents/{incident_id}/tree", expected=200, headers=headers)
                triage = find_role(tree["roots"], "triage")
                if triage and triage["status"] in {"completed", "failed"}:
                    break
                time.sleep(0.25)
            if not triage or triage["status"] != "completed":
                raise RuntimeError(f"Triage did not complete: {tree['aggregate_status'] if tree else 'missing'}")
            require(tree["aggregate_status"] == "incomplete", "Missing telemetry did not mark investigation incomplete")
            require(bool(triage["evidence"]), "incident.get did not persist source evidence")
            require(bool(triage["gaps"]), "Missing Wazuh telemetry was not surfaced")
            run_gaps = triage["runs"][-1]["result"]["gaps"]
            require(bool(run_gaps), "Specialist run did not record missing tool coverage")
            print(json.dumps({
                "result": "PASS — synthetic presentation rehearsal",
                "database": str(db_path),
                "incident_id": incident_id,
                "source": "SYNTHETIC test alert; no live Wazuh connection",
                "offline_verdict": report["verdict"]["summary"],
                "triage_status": triage["status"],
                "triage_evidence_count": len(triage["evidence"]),
                "tree_aggregate": tree["aggregate_status"],
                "triage_gaps": triage["gaps"],
                "specialist_run_gaps": run_gaps,
                "connection_verified": connection["success"],
                "live_block_http_status": 501,
                "live_block_message": refusal["detail"],
            }, indent=2))
        finally:
            if worker is not None:
                worker.terminate()
                try:
                    worker.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    worker.kill()
                    worker.communicate(timeout=5)
    if bank_demo:
        _start_bank_demo(demo_dir, org_id, duration_seconds)
    elif serve:
        import uvicorn

        print("Demo URL: http://127.0.0.1:8765/console/", flush=True)
        print("Login: presenter@terminus.example / DemoOnlyPassword123!", flush=True)
        uvicorn.run("terminus.server.app:create_app", factory=True, host="127.0.0.1", port=8765)


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--serve", action="store_true", help="Serve the prepared demo console")
    parser.add_argument("--bank-demo", action="store_true", help="Serve bank and SOC with continuous synthetic traffic")
    parser.add_argument("--duration-seconds", type=int, default=600, help="Bank stream duration (default 600)")
    args = parser.parse_args()
    if args.bank_demo and not 4 <= args.duration_seconds <= 3600:
        parser.error("bank demo duration must be 4..3600 seconds")
    main(serve=args.serve, bank_demo=args.bank_demo, duration_seconds=args.duration_seconds)
