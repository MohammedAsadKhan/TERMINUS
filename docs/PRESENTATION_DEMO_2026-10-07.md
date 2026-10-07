# Wednesday bank and SOC demonstration (October 7, 2026)

## Start both screens and the ten-minute stream

From the repository root in PowerShell:

```powershell
uv run --frozen python scripts/presentation_rehearsal.py --bank-demo
```

On Windows, `launch_presentation_demo.bat` starts the same flow. The older `launch_attack_simulation.bat` now forwards to it.

Wait for the rehearsal `PASS`, the two URLs, and `Synthetic bank traffic: 600s`. Keep the terminal open.

- **Screen 1, TERMINUS:** `http://127.0.0.1:8766/console/`
- **Screen 2, fictional bank:** `http://127.0.0.1:8766/bank/`
- **SOC sign-in:** `presenter@terminus.example` / `DemoOnlyPassword123!`
- **Optional bank customer:** Use **Demo Customer Quick-Fill**, then **Sign In to Accounts**. Transfers are simulated; no money moves.

Each launch creates a fresh SQLite database in the OS temporary directory. The launcher does not load the repository's `.env` or contact configured external providers. It first performs the existing isolated incident and separate scheduler rehearsal, then starts both web screens and the traffic generator. The bank site and SOC remain open after the ten-minute stream finishes; press Ctrl+C to stop them.

## What the audience will see

The generator sends **three normal bank API requests per second** for 600 seconds, plus an attack sequence every four seconds. The local bank gateway records every request and samples ordinary telemetry into the TERMINUS policy pipeline. High-severity attack requests are sent through the same pipeline as synthetic bank alerts and appear as incidents. The gateway denies the triggering request, installs a block for that fictional source IP **only when TERMINUS policy returns `escalate`**, and the generator immediately probes from the same source to verify an HTTP 403 denial. The generator stops with an error if that follow-up gets through.

| Time | Attack campaign | Automatic local control |
|---|---|---|
| 0:00–2:30 | Five failed logins from each rotating fictional source within 60 seconds | Deny the fifth attempt and block that source |
| 2:30–5:00 | SQL injection patterns in branch search | Deny the search and block that source |
| 5:00–7:30 | Treasury canary route probes | Deny access, return no key data, and block that source |
| 7:30–10:00 | Customer export canary and mixed search injection | Deny access, return no customer data, and block that source |

Normal traffic continues during every campaign. The bank screen updates allowed requests, denied attacks, denied follow-ups, active source blocks, and recent control events every two seconds. The TERMINUS overview shows the same gateway counters; **Incidents** shows the source-linked high-severity synthetic alerts. The bank controls are deterministic application gateway rules. They do **not** change a real firewall, IDS, Wazuh manager, endpoint, or production network.

## Suggested five-minute live narration

1. Open the bank on one screen and the TERMINUS **Overview** on the other. Show both counters rising while the terminal names each campaign. State that all sources and accounts are fictional.
2. On the bank, use **Demo Customer Quick-Fill** to sign in and simulate a $250 transfer. The site remains usable for normal customers while attack sources are denied.
3. On the bank's red team panel, press **Dispatch Query**. The first suspicious request is denied and installs a local source block; pressing it again shows the existing block denying the follow-up. The generator independently performs the same two-step check for every campaign source.
4. In TERMINUS **Incidents**, select a `[SYNTHETIC BANK]` incident. Show the source IP, matched rule, raw synthetic event, and the offline assessment. The model did not independently verify compromise.
5. Return to **Overview**. Show normal requests allowed, attack requests denied, and active source blocks. Explain that the control scope is the bank demo API; a real SIEM-to-firewall or endpoint response remains a separate lab milestone.

## Preflight and fallback

- Run `npm run build` from `web` after any UI change. The backend serves the tracked production build.
- Run `uv run --frozen pytest -q tests/test_bank_demo_defense.py tests/test_demo_scope.py` and the short full-flow check `uv run --frozen python scripts/presentation_rehearsal.py --bank-demo --duration-seconds 16` before presenting. The 16-second version traverses all four campaign phases.
- If the live screens fail, the terminal's measured counts and the demo database path provide a fallback record. Do not describe a local block as a Wazuh or firewall action.
- Port 8766 is reserved for the bank demo so the earlier console rehearsal on 8765 can remain open.

## Remaining engineering gates

Authenticate and bind a real Wazuh source to a tenant; evaluate incident conclusions against real source telemetry; implement approved external response adapters; and independently verify their effects and service health in a disposable lab. The bank demo proves only its local application gateway and the incident path it exercises.
