export interface User { user_id: string; email: string; display_name: string; created_at: string }
export interface Organization { org_id: string; name: string; created_at: string }
export type Role = 'admin' | 'member' | 'viewer';
export interface Membership { user_id: string; role: Role; user: User | null }
export interface OrgDetail { organization: Organization; role: Role; members: Membership[]; license: { tier: string; max_seats: number; expires_at: string; features: string[] } | null; license_error: string | null }
export interface Incident {
  id: string; alert_id: string; rule_description: string; severity: string; confidence: string;
  summary: string; recommended_actions: string[]; agent_name: string; full_log: string;
  policy_tier: string; policy_reason: string; status: string; timestamp: string; created_at: string;
  updated_at?: string; resolved_at?: string; threat_intel: string; context_notes: string;
  mitigation_status: string; kill_chain_stage: string;
}
export interface Agent { id: string; name: string; role_description: string; master_prompt: string; status: 'active' | 'paused' | 'maintenance'; incidents_processed: number; created_at: string }
export interface WorkflowNode { id: string; type: string; label: string; x: number; y: number; config: Record<string, unknown> }
export interface Workflow { id: string; name: string; agent_id: string | null; enabled: boolean; nodes: WorkflowNode[]; edges: { id: string; source: string; target: string }[] }
export interface Report { id: string; title: string; report_type: 'quick' | 'daily_24h'; created_at: string; period_start: string; period_end: string; executive_summary: string; metrics: { total_incidents: number; critical_incidents: number; high_incidents: number; medium_incidents: number; low_incidents: number; resolved_incidents: number; contained_incidents: number; avg_mttd_sec: number | null; avg_mttr_sec: number | null }; top_impacted_hosts: { host: string; incident_count: number }[]; recommended_actions: string[] }
export interface Integration { id: string; name: string; category: string; configured: boolean; description: string; setting: string }
export interface SystemInfo { version: string; storage: string; transport: string; llm_mode: string; llm_model: string; live_response: boolean; workflow_execution: boolean; integrations: Integration[] }
