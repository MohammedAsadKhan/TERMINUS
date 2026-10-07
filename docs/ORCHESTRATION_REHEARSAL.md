# Orchestration rehearsal

Noah: launch Terminus using the README quick start and sign in to your own workspace. Open **QA walkthroughs**, section **6. Orchestration and response simulation**, and click **Run orchestration simulation**.

No API key, Wazuh connection, saved incident, or VM is required. The local scripted sequence shows a main coordinator, area coordinator, and three specialists. Click a node to see its activity; expand the full timeline for the whole operation. Pause/resume is available while the investigation runs.

The sequence stops at a recommendation. Edit the duration before approving, or choose further investigation or dismissal. Approval shows simulated execution and verification; undo removes the simulated rule. Reset/replay starts over. Leaving the page clears the rehearsal; it creates no incident or durable task and makes no external calls.

For actual investigations, open **Agents → Activity**, select a recorded task, and inspect the delegation map above the existing operation overview. New nodes animate as they arrive; recorded running tasks pulse. Task, run, and evidence updates are polled every two seconds. Existing tool steps, findings, citations, model provenance, and coverage gaps remain available in the task inspector. This is recorded execution visibility, not a stream of private model reasoning or unrecorded commands.

Live response proposal approval and dispatch are still separate integration work. The rehearsal approval control cannot authorize or execute a real response.

Available scenarios: SSH password guessing, ransomware-like file changes, suspicious remote access, unexpected administrator account changes, application exploit probes, and unusual outbound data transfer. Choose a scenario in the simulation dropdown. Switching scenarios clears the prior rehearsal and its decision. Each has its own sample evidence, investigator, proposal, impact, verification, and undo plan. These scenarios demonstrate recommendations only; they do not enable new live response capabilities.
