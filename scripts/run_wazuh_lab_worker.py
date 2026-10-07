"""Prompt locally for lab credentials and launch a read-only specialist worker."""
# ruff: noqa: INP001 -- standalone deployment script

import argparse
import getpass
import os
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", required=True)
    parser.add_argument("--org", required=True)
    parser.add_argument("--actor", required=True)
    args = parser.parse_args()
    env = os.environ.copy()
    prefix = "TERMINUS_SPECIALIST_WAZUH_"
    env.update(
        {
            "TERMINUS_DEPLOYMENT_MODE": "local",
            "TERMINUS_SPECIALIST_DATABASE": args.database,
            "TERMINUS_SPECIALIST_ACTOR_USER_ID": args.actor,
            "TERMINUS_SPECIALIST_LIVE_MODELS": "false",
            prefix + "ORG_ID": args.org,
            prefix + "MANAGER_URL": "https://192.168.56.104:55000",
            prefix + "MANAGER_USER": "wazuh-wui",
            prefix + "MANAGER_PASSWORD": getpass.getpass(
                "Wazuh manager password (wazuh-wui): "
            ),
            prefix + "INDEXER_URL": "https://127.0.0.1:19200",
            prefix + "INDEXER_USER": "admin",
            prefix + "INDEXER_PASSWORD": getpass.getpass(
                "Wazuh indexer password (admin): "
            ),
            prefix + "VERIFY_TLS": "false",
        }
    )
    command = [
        sys.executable,
        "-m",
        "terminus.orchestration.scheduler_cli",
        "--database",
        args.database,
        "--coordination",
    ]
    for role in ("triage", "identity", "endpoint"):
        command.extend(
            ["--handler", f"{role}=terminus.orchestration.specialists.deploy:{role}"]
        )
    print(
        "Starting local read-only worker; keep the SSH tunnel open. Model calls are disabled."
    )
    raise SystemExit(subprocess.call(command, env=env))  # noqa: S603 -- fixed module and handlers, no shell


if __name__ == "__main__":
    main()
