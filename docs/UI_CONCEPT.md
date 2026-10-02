# Terminus console UI concept

## Product model

Terminus is a multi-organization security operations console. An analyst monitors incidents and evidence, uses an AI copilot to investigate, records response outcomes, and shares reports. Administrators configure agent definitions, visual workflows, integrations, membership, licensing, and runtime appearance. The console is a React/Vite client over the FastAPI endpoints; the server remains the source of truth for permissions and operational state.

## Design direction: Signal Mint

The interface uses deep ink surfaces, restrained mint highlights, clear severity colors, and readable typography. Mint identifies navigation, focus, and primary action. Red, orange, yellow, and blue are reserved for incident severity. Shared page headers, cards, tables, forms, and empty states give every section the same visual grammar. Alternate color themes remain available in Settings.

## Section map

| Section | Primary question | Main interaction |
| --- | --- | --- |
| Overview | What needs attention now? | Focus an incident and question the copilot alongside live metrics. |
| Incidents | What evidence supports the next decision? | Search and filter the queue, open the dossier, and record action or resolution. |
| Reports | What happened in a defined period? | Generate, inspect, and export an operations summary. |
| Agent fleet | Who performs each investigation role? | Review, edit, and pause agent definitions. |
| Workflows | How does a signal become a response? | Connect and validate trigger, condition, agent, and output nodes. |
| Integrations | Where does telemetry enter and leave? | Inspect configured connectors and submit a test event. |
| Organization | Who can access this workspace? | Review seats and administer members and roles. |
| Settings | What powers this installation? | Inspect runtime, policy, license, account, and appearance. |

## Interaction rules

- The sidebar exposes every section at all viewport sizes; on narrow screens it opens as a dismissible drawer.
- Organization switching remains persistent per user, while route content refreshes for the selected organization.
- Connection labels represent console API availability. Connector cards describe configuration presence rather than claiming verified health.
- Dense tables scroll horizontally on phones, with an explicit swipe cue on the incident queue.
- Existing role restrictions, mutation confirmation dialogs, and API backed behaviors stay in place.

## Implementation

`web/src/design.css` is the new visual layer, loaded after the legacy stylesheet. It centralizes shared colors, layout, component treatments, and breakpoints while the older page rules are gradually retired. `web/src/shell.tsx` owns navigation and global context; individual views retain their data queries and actions.
