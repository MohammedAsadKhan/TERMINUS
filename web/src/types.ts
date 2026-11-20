// File: types.ts
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Define TypeScript shapes for backend console responses, including report verdict provenance.

// Backend response shapes used by the console. Fields marked optional may be absent, and the UI must treat a
// missing value as unknown rather than as a default.
export interface User { user_id: string; email: string; display_name: string; created_at: string }
// An organization the signed-in user belongs to.
export interface Organization { org_id: string; name: string; created_at: string }
// Organization roles as returned by the API.
export type Role = 'admin' | 'member' | 'viewer';
// A user's role in an organization; user is null when the user record cannot be found.
export interface Membership { user_id: string; role: Role; user: User | null }
// The current organization with the caller's role, members and license. license may be null, and license_error, when
// present, is shown to the user.
export interface OrgDetail { organization: Organization; role: Role; members: Membership[]; license: { tier: string; max_seats: number; expires_at: string; features: string[] } | null; license_error: string | null }
// Incident record as returned by the incidents API.
export interface Incident {
  id: string; alert_id: string; rule_description: string; severity: string; confidence: string;
  summary: string; recommended_actions: string[]; agent_name: string; full_log: string;
  policy_tier: string; policy_reason: string; status: string; timestamp: string; created_at: string;
  updated_at?: string; resolved_at?: string; threat_intel: string; context_notes: string;
  mitigation_status: string; kill_chain_stage: string;
  external_export_status?: string; external_ticket_id?: string;
  evidence_citations?: Array<Record<string, unknown>>;
  rule_id?: string | number; mitre?: string | string[] | null; agent_id?: string | null;
  source_ip?: string | null; source_location?: string | null;
  resolution_category?: string | null; resolution_notes?: string;
}
// AI agent configuration and processed-incident count.
export interface Agent { id: string; name: string; role_description: string; master_prompt: string; status: 'active' | 'paused' | 'maintenance'; incidents_processed: number; created_at: string }
// Workflow graph: nodes carry canvas position and per-type config, edges link nodes by id.
export interface WorkflowNode { id: string; type: string; label: string; x: number; y: number; config: Record<string, unknown> }
// Link between two nodes; source_handle names the output used (default, true, false or on_error).
export interface WorkflowEdge { id: string; source: string; target: string; source_handle?: string }
// Saved workflow definition. version supports optimistic concurrency: saves send it back as expected_version.
export interface Workflow { id: string; name: string; agent_id: string | null; enabled: boolean; priority?: number; version?: number; nodes: WorkflowNode[]; edges: WorkflowEdge[] }
// Human-approval request raised by a workflow run; resolved or expired approvals keep their resolution fields.
export interface Approval { approval_id: string; run_id: string; workflow_id: string; org_id: string; node_id: string; required_role: string; prompt_message: string; status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED'; created_at: string; expires_at?: string; resolved_by?: string; resolved_at?: string }
// One workflow execution. unknown_outcome marks a run whose side effects could not be confirmed.
export interface WorkflowRun { run_id: string; workflow_id: string; org_id: string; alert_id?: string; status: string; outcome?: string; side_effects_executed?: boolean; unknown_outcome?: boolean; started_at: string; completed_at?: string }
// Verdict attached to a report, with its provenance.
export interface ReportVerdict {
  severity?: string;
  confidence?: string;
  summary?: string;
  // Provenance of the investigation verdict. 'unknown' or absence means the
  // analysis mode was not recorded, so the console must label it unverified.
  analysis_mode?: 'provider' | 'scripted' | 'offline' | 'fallback' | 'policy' | 'unknown' | string | null;
}
// Generated report with incident metrics, impacted hosts and an optional verdict.
export interface Report { id: string; title: string; report_type: 'quick' | 'daily_24h'; created_at: string; period_start: string; period_end: string; executive_summary: string; metrics: { total_incidents: number; critical_incidents: number; high_incidents: number; medium_incidents: number; low_incidents: number; resolved_incidents: number; contained_incidents: number; avg_mttd_sec: number | null; avg_mttr_sec: number | null }; top_impacted_hosts: { host: string; incident_count: number }[]; recommended_actions: string[]; verdict?: ReportVerdict | null }
// Integration entry from /system; configured only means the setting is present on the server; no connection was tested.
export interface Integration { id: string; name: string; category: string; configured: boolean; description: string; setting: string }
// Platform info from /system: version, storage and transport, analysis mode and the feature flags for live response and workflow execution.
export interface SystemInfo { version: string; storage: string; transport: string; llm_mode: string; llm_model: string; live_response: boolean; workflow_execution: boolean; integrations: Integration[] }
// One audit entry for an action taken by an agent, workflow, guardrail, policy or user. status is open-ended
// so new backend states still render.
export interface AgentAction {
  action_id: string;
  org_id: string;
  timestamp: string;
  actor_type: 'agent' | 'workflow' | 'guardrail' | 'policy' | 'user';
  actor_name: string;
  action_type: string;
  target?: string;
  status: 'COMPLETED' | 'BLOCKED' | 'PENDING' | 'WAITING_APPROVAL' | 'SUPPRESSED' | 'FAILED' | string;
  summary: string;
  details?: Record<string, unknown>;
  incident_id?: string;
  alert_id?: string;
}
