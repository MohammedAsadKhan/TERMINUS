import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  App,
  Button,
  Input,
  Pagination,
  Select,
  Skeleton,
  Tag,
  Tooltip,
} from 'antd';
import {
  BranchesOutlined,
  ClockCircleOutlined,
  CloudServerOutlined,
  PauseCircleOutlined,
  ReloadOutlined,
  StopOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, body } from '../api';
import { date, EmptyPanel, ErrorPanel } from '../components';
import { useSession } from '../context';
import './agent-activity.css';
import OperationMap from './operation-map';

const PAGE_SIZE = 20;
const ACTIVE_STATES = new Set(['queued', 'running', 'waiting']);
const TASK_STATES = ['queued', 'running', 'waiting', 'completed', 'failed', 'cancelled'] as const;

type JsonObject = Record<string, unknown>;

interface ActivityTask {
  task_id: string;
  incident_id: string;
  parent_task_id?: string | null;
  area: string;
  role: string;
  objective: string;
  status: string;
  priority?: number;
  created_at?: string;
  updated_at?: string;
  started_at?: string | null;
  completed_at?: string | null;
  idempotency_key?: string | null;
}

interface SchedulerJob {
  job_id?: string;
  role?: string;
  status?: string;
  attempt?: number;
  max_attempts?: number;
  worker_id?: string | null;
  run_id?: string | null;
  available_at?: string;
  run_after?: string;
  lease_expires_at?: string | null;
  recovery_reason?: string | null;
  attempts?: number;
}

interface TaskRow { task: ActivityTask; scheduler_job: SchedulerJob | null }
interface TaskPage { items: TaskRow[]; limit: number; offset: number }

interface AgentRun {
  run_id: string;
  task_id: string;
  agent_id?: string | null;
  model_connection_id?: string | null;
  model_name?: string | null;
  status: string;
  created_at?: string;
  updated_at?: string;
  started_at?: string | null;
  completed_at?: string | null;
  result?: unknown;
  error?: string | null;
}

interface EvidenceRecord {
  evidence_id: string;
  source: string;
  source_timestamp?: string;
  collected_at?: string;
  content?: unknown;
  content_ref?: string | null;
  content_hash?: string;
}

interface HelpRequest {
  help_request_id: string;
  task_id: string;
  requested_role: string;
  reason: string;
  status: string;
  created_at?: string;
}

interface ActionAttempt {
  attempt_id: string;
  action: string;
  targets: string[];
  status: string;
  created_at?: string;
}

interface TaskDetail {
  task: ActivityTask;
  scheduler_job: SchedulerJob | null;
  runs: AgentRun[];
  evidence: EvidenceRecord[];
  help_requests: HelpRequest[];
  actions: ActionAttempt[];
  child_records_limit: number;
  child_records_may_be_truncated: boolean;
}

interface ToolCallRecord { tool_id: string; status: string; error_code?: string | null; evidence_count: number }
interface Finding { claim: string; evidence_ids: string[] }
interface SpecialistGap { code: string; tool_id?: string | null; detail?: string }
interface ModelUsage {
  input_tokens?: number | null;
  output_tokens?: number | null;
  total_tokens?: number | null;
  cached_input_tokens?: number | null;
  reasoning_tokens?: number | null;
}
interface ModelRef {
  connection_id: string;
  model: string;
  route_id?: string | null;
  reservation_id?: string | null;
  usage?: ModelUsage | null;
  cost_known?: boolean | null;
  cost_micro_usd?: number | null;
}
interface SpecialistResult {
  status: 'completed' | 'partial' | 'insufficient_telemetry' | 'error';
  role: string;
  tool_calls: ToolCallRecord[];
  evidence_ids: string[];
  findings: Finding[];
  gaps: SpecialistGap[];
  model: ModelRef | null;
  execution_mode: 'tools_only' | 'tools_and_model';
}

interface TreeNode extends ActivityTask {
  objective: string;
  children?: TreeNode[];
  runs?: AgentRun[];
  evidence?: EvidenceRecord[];
  help_requests?: HelpRequest[];
  help_ownership?: HelpOwnership[];
  gaps?: string[];
  aggregate_status?: string;
  delegation_only?: boolean;
  help_request_id?: string | null;
  planned_areas?: string[];
  planned_roles?: string[];
}
interface IncidentTree {
  incident_id: string;
  roots: TreeNode[];
  aggregate_status: string;
  incident_closed: boolean;
  planned_areas?: string[];
  gaps?: string[];
}
interface HelpOwnership {
  help_request_id: string;
  state: string;
  reason_code?: string | null;
  requester_task_id: string;
  requester_role: string;
  requester_area: string;
  target_role: string;
  responsible_area?: string | null;
  delegated_task_id?: string | null;
  peer_task_id?: string | null;
  objective: string;
  expected_evidence_kinds?: string[];
  shared_evidence_ids?: string[];
  result?: unknown;
}
interface HelpContext extends HelpOwnership { shared_evidence?: EvidenceRecord[] }

interface CatalogItem {
  specialty_id: string;
  name: string;
  area: string;
  core_role: string | null;
  availability: string;
  release: string;
  execution_available: boolean;
  status_label: string;
}
interface CatalogResponse { items: CatalogItem[]; note?: string }

function asObject(value: unknown): JsonObject | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
}

function specialistResult(value: unknown): SpecialistResult | null {
  const item = asObject(value);
  if (!item || !['completed', 'partial', 'insufficient_telemetry', 'error'].includes(String(item.status))) return null;
  const toolCalls = Array.isArray(item.tool_calls) ? item.tool_calls.flatMap(call => {
    const record = asObject(call);
    return record && typeof record.tool_id === 'string' && typeof record.status === 'string'
      ? [{ tool_id: record.tool_id, status: record.status, error_code: typeof record.error_code === 'string' ? record.error_code : null, evidence_count: typeof record.evidence_count === 'number' ? record.evidence_count : 0 }]
      : [];
  }) : [];
  const findings = Array.isArray(item.findings) ? item.findings.flatMap(finding => {
    const record = asObject(finding);
    return record && typeof record.claim === 'string' ? [{ claim: record.claim, evidence_ids: asStringArray(record.evidence_ids) }] : [];
  }) : [];
  const gaps = Array.isArray(item.gaps) ? item.gaps.flatMap(gap => {
    const record = asObject(gap);
    return record && typeof record.code === 'string'
      ? [{ code: record.code, tool_id: typeof record.tool_id === 'string' ? record.tool_id : null, detail: typeof record.detail === 'string' ? record.detail : '' }]
      : [];
  }) : [];
  const rawModel = asObject(item.model);
  const rawUsage = asObject(rawModel?.usage);
  const model = rawModel && typeof rawModel.connection_id === 'string' && typeof rawModel.model === 'string' ? {
    connection_id: rawModel.connection_id,
    model: rawModel.model,
    route_id: typeof rawModel.route_id === 'string' ? rawModel.route_id : null,
    reservation_id: typeof rawModel.reservation_id === 'string' ? rawModel.reservation_id : null,
    usage: rawUsage ? {
      input_tokens: typeof rawUsage.input_tokens === 'number' ? rawUsage.input_tokens : null,
      output_tokens: typeof rawUsage.output_tokens === 'number' ? rawUsage.output_tokens : null,
      total_tokens: typeof rawUsage.total_tokens === 'number' ? rawUsage.total_tokens : null,
      cached_input_tokens: typeof rawUsage.cached_input_tokens === 'number' ? rawUsage.cached_input_tokens : null,
      reasoning_tokens: typeof rawUsage.reasoning_tokens === 'number' ? rawUsage.reasoning_tokens : null,
    } : null,
    cost_known: typeof rawModel.cost_known === 'boolean' ? rawModel.cost_known : null,
    cost_micro_usd: typeof rawModel.cost_micro_usd === 'number' ? rawModel.cost_micro_usd : null,
  } : null;
  return {
    status: item.status as SpecialistResult['status'],
    role: typeof item.role === 'string' ? item.role : 'unknown',
    tool_calls: toolCalls,
    evidence_ids: asStringArray(item.evidence_ids),
    findings,
    gaps,
    model,
    execution_mode: item.execution_mode === 'tools_and_model' ? 'tools_and_model' : 'tools_only',
  };
}

function objectiveText(value: string): string {
  try {
    const parsed = asObject(JSON.parse(value));
    const request = asObject(parsed?.request);
    if (typeof request?.objective === 'string') return request.objective;
    if (typeof parsed?.objective === 'string') return parsed.objective;
  } catch { /* Plain objectives are expected for specialist tasks. */ }
  return value;
}

function displayStatus(value?: string): string {
  return (value || 'unknown').replaceAll('_', ' ');
}

function stateTone(value?: string): string {
  if (value === 'completed' || value === 'resolved') return 'success';
  if (value === 'failed' || value === 'error') return 'error';
  if (value === 'waiting' || value === 'partial' || value === 'insufficient_telemetry' || value === 'incomplete') return 'warning';
  if (value === 'running' || value === 'assigned') return 'processing';
  return 'default';
}

function analysisLabel(result: SpecialistResult | null): string {
  if (!result) return 'No recorded analysis';
  if (result.status === 'insufficient_telemetry') return 'Insufficient telemetry';
  if (result.status === 'partial') return 'Partial coverage';
  if (result.status === 'error') return 'Analysis error';
  return 'Completed analysis';
}

function findNode(nodes: TreeNode[], taskId: string, lineage: TreeNode[] = []): { node: TreeNode; lineage: TreeNode[] } | null {
  for (const node of nodes) {
    if (node.task_id === taskId) return { node, lineage };
    const found = findNode(node.children || [], taskId, [...lineage, node]);
    if (found) return found;
  }
  return null;
}

function taskUrl(page: number, incident: string, status: string): string {
  const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE), newest_first: 'true' });
  if (incident.trim()) params.set('incident_id', incident.trim());
  if (status) params.set('status', status);
  return `/orchestration/tasks?${params.toString()}`;
}

function Id({ children }: { children: string }) {
  return <code className="activity-id" title={children}>{children}</code>;
}

function StateTag({ value }: { value?: string }) {
  return <Tag color={stateTone(value)}>{displayStatus(value).toUpperCase()}</Tag>;
}

function TreeBranch({ node, selected, onSelect, depth = 0 }: { node: TreeNode; selected: string | null; onSelect: (id: string) => void; depth?: number }) {
  return <li>
    <button className={`activity-tree-node${selected === node.task_id ? ' selected' : ''}`} style={{ '--tree-depth': depth } as React.CSSProperties} onClick={() => onSelect(node.task_id)}>
      <span className="tree-rail" aria-hidden="true" />
      <span><strong>{node.role.replaceAll('_', ' ')}</strong><small>{node.area.replaceAll('_', ' ')}</small></span>
      <StateTag value={node.aggregate_status || node.status} />
    </button>
    {!!node.children?.length && <ul>{node.children.map(child => <TreeBranch key={child.task_id} node={child} selected={selected} onSelect={onSelect} depth={depth + 1} />)}</ul>}
  </li>;
}

function descendants(root: TreeNode): TreeNode[] {
  return [root, ...(root.children || []).flatMap(descendants)];
}

function latestRun(node: TreeNode): AgentRun | null {
  return [...(node.runs || [])].sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''))[0] || null;
}

function duration(start?: string | null, end?: string | null): string {
  if (!start) return 'Not started';
  const seconds = Math.max(0, Math.floor(((end ? Date.parse(end) : Date.now()) - Date.parse(start)) / 1000));
  if (!Number.isFinite(seconds)) return 'Unknown';
  return seconds < 60 ? `${seconds}s` : seconds < 3600 ? `${Math.floor(seconds / 60)}m ${seconds % 60}s` : `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m`;
}

function OperationOverview({ tree, selected, onSelect }: { tree: IncidentTree; selected: string | null; onSelect: (id: string) => void }) {
  const roots = [...tree.roots].sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''));
  const match = selected ? findNode(roots, selected) : null;
  const root = match ? match.lineage[0] || match.node : roots[0];
  if (!root) return null;
  const nodes = descendants(root);
  const specialists = nodes.filter(node => !['main_orchestrator', 'area_orchestrator'].includes(node.role));
  const active = nodes.filter(node => ACTIVE_STATES.has(node.status));
  const lastCompletion = active.length ? null : nodes.map(node => node.completed_at || node.updated_at || '').sort().at(-1);
  return <section className="panel operation-overview" aria-label="Operation overview">
    <header className="operation-heading">
      <div><span className="eyebrow">OPERATION OVERVIEW</span><h2>{objectiveText(root.objective)}</h2><Id>{tree.incident_id}</Id></div>
      <StateTag value={active.some(node => node.status === 'running') ? 'running' : active.length ? 'waiting' : root.status} />
    </header>
    <div className="operation-controls"><Select aria-label="Select orchestration run" value={root.task_id} options={roots.map(item => ({ value: item.task_id, label: `${date(item.created_at)} · ${item.role.replaceAll('_', ' ')}` }))} onChange={onSelect} /><span>Each operation contains its recorded child tasks.</span></div>
    <OperationMap nodes={nodes.map(node => ({ id: node.task_id, parent: node.parent_task_id, label: node.role.replaceAll('_', ' '), status: node.status, activity: node.status === 'running' ? 'Executing admitted task; inspect saved evidence and run output below.' : specialistResult(latestRun(node)?.result)?.tool_calls.at(-1)?.tool_id || objectiveText(node.objective) }))} onSelect={onSelect} />
    <dl className="operation-metrics">
      <div><dt>Elapsed</dt><dd>{duration(root.started_at, lastCompletion)}</dd></div>
      <div><dt>Agents running</dt><dd>{specialists.filter(node => node.status === 'running').length}</dd></div>
      <div><dt>Waiting / queued</dt><dd>{specialists.filter(node => ['queued', 'waiting'].includes(node.status)).length}</dd></div>
      <div><dt>Specialists spawned</dt><dd>{specialists.length}</dd></div>
    </dl>
    <div className="operation-ownership">{nodes.filter(node => ['main_orchestrator', 'area_orchestrator'].includes(node.role)).map(node => <button key={node.task_id} onClick={() => onSelect(node.task_id)}><BranchesOutlined /><span>{node.role.replaceAll('_', ' ')} · {node.area.replaceAll('_', ' ')}</span><StateTag value={node.status} /></button>)}</div>
    {specialists.length ? <div className="operation-agent-grid">{specialists.map(node => {
      const run = latestRun(node);
      const result = specialistResult(run?.result);
      const lastCall = result?.tool_calls.at(-1);
      const observation = [...(node.evidence || [])].sort((a, b) => (b.collected_at || '').localeCompare(a.collected_at || ''))[0];
      const observedTool = asObject(observation?.content)?.tool_id;
      const activity = node.status === 'running' ? (typeof observedTool === 'string' ? `Last recorded: ${observedTool} · ${date(observation.collected_at)}` : 'Executing admitted task; waiting for recorded output') : node.status === 'queued' ? 'Waiting for a scheduler worker' : lastCall ? `${lastCall.tool_id} · ${displayStatus(lastCall.status)}` : result?.model ? `Analysis recorded · ${result.model.model}` : objectiveText(node.objective);
      return <button className={`operation-agent${selected === node.task_id ? ' selected' : ''}`} key={node.task_id} onClick={() => onSelect(node.task_id)}>
        <div className="operation-agent-head"><strong>{node.role.replaceAll('_', ' ')}</strong><StateTag value={node.status} /></div>
        <span className="operation-agent-area">{node.area.replaceAll('_', ' ')}</span>
        <p>{activity}</p>
        <footer><span>{result ? `${result.findings.length} cited findings · ${analysisLabel(result)}` : 'No analysis recorded yet'}</span><span>Inspect activity →</span></footer>
      </button>;
    })}</div> : <p className="operation-empty">No specialist tasks have been spawned under this operation.</p>}
    <p className="operation-footnote">Execution status is separate from investigation coverage. Cards show recorded activity; updates arrive every 2 seconds. Motion indicates recorded running tasks; it does not imply unrecorded tool or model calls.</p>
  </section>;
}

function ActivityTimeline({ task, run, evidence }: { task: ActivityTask; run: AgentRun | null; evidence: EvidenceRecord[] }) {
  const result = specialistResult(run?.result);
  return <section className="activity-subsection"><h4>Activity timeline</h4><ol className="agent-timeline">
    <li><strong>Task admitted</strong><small>{date(task.created_at)}</small><p>{objectiveText(task.objective)}</p></li>
    {run && <li><strong>Execution {run.status === 'running' ? 'started' : 'recorded'}</strong><small>{date(run.started_at || run.created_at)}</small><p>Run <Id>{run.run_id}</Id></p></li>}
    {[...evidence].filter(record => asObject(record.content)?.run_id === run?.run_id).sort((a, b) => (a.collected_at || '').localeCompare(b.collected_at || '')).map(record => <li key={record.evidence_id}><strong>Evidence saved · {String(asObject(record.content)?.tool_id || record.source)}</strong><small>{date(record.collected_at)}</small><Id>{record.evidence_id}</Id></li>)}
    {result?.tool_calls.map((call, index) => <li key={`${call.tool_id}-${index}`}><strong>{call.tool_id}</strong><StateTag value={call.status} /><p>{call.evidence_count} evidence records · recorded call order {index + 1}</p></li>)}
    {result?.model && <li><strong>Model analysis recorded</strong><p>{result.model.model} · {result.findings.length} cited findings</p></li>}
    {run?.completed_at && <li><strong>Execution finished</strong><small>{date(run.completed_at)}</small><p>{analysisLabel(result)}</p></li>}
  </ol><p className="coverage-note">Tool and model steps use their recorded order; individual step timestamps are unavailable in this result.</p></section>;
}

function RunResult({ run, evidence }: { run: AgentRun | null; evidence: EvidenceRecord[] }) {
  const result = specialistResult(run?.result);
  const evidenceById = new Map(evidence.map(item => [item.evidence_id, item]));
  if (!run) return <EmptyPanel title="No agent run recorded" description="The task has not produced a durable run record." />;
  return <div className="activity-result">
    <div className="activity-section-heading"><div><span className="eyebrow">CURRENT RUN</span><h3>Execution and analysis</h3></div><StateTag value={run.status} /></div>
    <dl className="activity-facts">
      <div><dt>Run</dt><dd><Id>{run.run_id}</Id></dd></div>
      <div><dt>Execution</dt><dd>{displayStatus(run.status)}</dd></div>
      <div><dt>Analysis coverage</dt><dd>{analysisLabel(result)}</dd></div>
      <div><dt>Updated</dt><dd>{date(run.updated_at)}</dd></div>
    </dl>
    {run.error && <Alert type="error" showIcon title="Run error" description={run.error} />}
    {!result ? <Alert type="warning" showIcon title="No structured specialist result" description="Execution status is available, but this run has no validated finding record." /> : <>
      <div className="activity-subsection">
        <h4>Actual calls</h4>
        {result.tool_calls.length ? <div className="call-list">{result.tool_calls.map((call, index) => <div className="call-row" key={`${call.tool_id}-${index}`}>
          <CloudServerOutlined /><div><strong>{call.tool_id}</strong><small>{call.evidence_count} evidence record{call.evidence_count === 1 ? '' : 's'}{call.error_code ? ` · ${call.error_code}` : ''}</small></div><StateTag value={call.status} />
        </div>)}</div> : <p className="muted">No tool calls were recorded for this run.</p>}
      </div>
      <div className="activity-subsection">
        <h4>Cited findings</h4>
        {result.findings.length ? result.findings.map((finding, index) => <article className="finding" key={`${finding.claim}-${index}`}>
          <p>{finding.claim}</p><div className="evidence-chips">{finding.evidence_ids.map(id => <Tooltip key={id} title={evidenceById.get(id)?.source || 'Evidence is outside the loaded task page'}><span><Id>{id}</Id></span></Tooltip>)}</div>
        </article>) : <Alert type="info" showIcon title="No finding asserted" description="No evidence-cited security finding was recorded. This is not a clean verdict." />}
      </div>
      {!!result.gaps.length && <div className="activity-subsection"><h4>Coverage gaps</h4><ul className="gap-list">{result.gaps.map((gap, index) => <li key={`${gap.code}-${index}`}><strong>{displayStatus(gap.code)}</strong>{gap.tool_id && <> · {gap.tool_id}</>}{gap.detail && <small>{gap.detail}</small>}</li>)}</ul></div>}
      <ModelAttempt model={result.model} executionMode={result.execution_mode} />
    </>}
  </div>;
}

function SchedulerProgress({ job }: { job: SchedulerJob | null }) {
  if (!job) return <Alert type="info" showIcon title="No scheduler job" description="This task has no durable scheduler assignment." />;
  const worker = job.worker_id
    ? <Id>{job.worker_id}</Id>
    : ['completed', 'failed', 'cancelled'].includes(job.status || '') ? 'Lease released after execution' : 'Awaiting worker assignment';
  return <section className="activity-subsection">
    <div className="activity-section-heading"><div><h4>Scheduler assignment</h4></div><StateTag value={job.status} /></div>
    <dl className="activity-facts compact">
      <div><dt>Job</dt><dd>{job.job_id ? <Id>{job.job_id}</Id> : 'Unknown'}</dd></div>
      <div><dt>Assigned role</dt><dd>{job.role?.replaceAll('_', ' ') || 'Unknown'}</dd></div>
      <div><dt>Attempt</dt><dd>{job.attempt === undefined ? 'Unknown' : `${job.attempt} of ${job.max_attempts ?? '?'}`}</dd></div>
      <div><dt>Worker</dt><dd>{worker}</dd></div>
      <div><dt>Active run</dt><dd>{job.run_id ? <Id>{job.run_id}</Id> : 'None'}</dd></div>
      <div><dt>Available</dt><dd>{date(job.available_at || job.run_after)}</dd></div>
    </dl>
    {job.recovery_reason && <p className="coverage-note">{displayStatus(job.recovery_reason)}</p>}
  </section>;
}

function RunHistory({ runs, selected, onSelect }: { runs: AgentRun[]; selected: string | null; onSelect: (runId: string) => void }) {
  if (runs.length < 2) return null;
  return <section className="activity-subsection">
    <h4>Run attempts</h4>
    <div className="call-list">{runs.map((run, index) => <button type="button" className={`call-row${selected === run.run_id ? ' selected' : ''}`} key={run.run_id} onClick={() => onSelect(run.run_id)}>
      <ClockCircleOutlined /><div><strong>Attempt {index + 1}</strong><small>{date(run.updated_at)}{run.error ? ' · failure recorded' : ''}</small></div><StateTag value={run.status} />
    </button>)}</div>
  </section>;
}

function ModelAttempt({ model, executionMode }: { model: ModelRef | null; executionMode: SpecialistResult['execution_mode'] }) {
  if (!model) return <div className="activity-subsection"><h4>Model provenance</h4><p className="muted">Tools-only execution; no model attempt was recorded.</p></div>;
  const usage = model.usage;
  const tokens = usage?.total_tokens ?? (usage?.input_tokens !== null && usage?.input_tokens !== undefined && usage?.output_tokens !== null && usage?.output_tokens !== undefined
    ? usage.input_tokens + usage.output_tokens : null);
  return <div className="activity-subsection model-attempt">
    <div><h4>Model provenance</h4><Tag>{executionMode.replaceAll('_', ' ')}</Tag></div>
    <dl className="activity-facts compact">
      <div><dt>Connection</dt><dd><Id>{model.connection_id}</Id></dd></div>
      <div><dt>Model</dt><dd>{model.model}</dd></div>
      <div><dt>Route</dt><dd>{model.route_id ? <Id>{model.route_id}</Id> : 'Unknown'}</dd></div>
      <div><dt>Reservation</dt><dd>{model.reservation_id ? <Id>{model.reservation_id}</Id> : 'Unknown'}</dd></div>
      <div><dt>Usage</dt><dd>{tokens === null ? 'Unknown — provider did not report' : `${tokens.toLocaleString()} tokens`}</dd></div>
      <div><dt>Cost</dt><dd>{model.cost_known === true && model.cost_micro_usd !== null && model.cost_micro_usd !== undefined ? `$${(model.cost_micro_usd / 1_000_000).toFixed(6)}` : 'Unknown — provider did not report'}</dd></div>
    </dl>
  </div>;
}

function Catalog({ data, loading }: { data?: CatalogResponse; loading: boolean }) {
  const grouped = useMemo(() => {
    const map = new Map<string, CatalogItem[]>();
    for (const item of data?.items || []) {
      const bundle = item.area;
      map.set(bundle, [...(map.get(bundle) || []), item]);
    }
    return [...map.entries()];
  }, [data]);
  return <section className="panel activity-catalog" aria-labelledby="catalog-title">
    <div className="activity-section-heading"><div><span className="eyebrow">SPECIALIST CATALOG</span><h2 id="catalog-title">Specialist roles</h2></div><Tag>{data?.items.length ?? 0} specialties</Tag></div>
    <p className="muted">Browse the full defensive roster. Roles without execution support are disabled.</p>
    {loading ? <Skeleton active paragraph={{ rows: 3 }} /> : grouped.length ? <div className="catalog-bundles">{grouped.map(([role, items]) => <article key={role} className="catalog-bundle">
      <header><strong>{role.replaceAll('_', ' ')}</strong><span>{items.length}</span></header>
      <ul>{items.map(item => <li key={item.specialty_id}><button className="catalog-role" type="button" disabled={!item.execution_available}>{item.name}</button></li>)}</ul>
    </article>)}</div> : <EmptyPanel title="No catalog metadata" description="The specialist catalog did not return any entries." />}
  </section>;
}

export default function AgentActivity() {
  const { orgId, detail: membership } = useSession();
  const { message } = App.useApp();
  const queryClient = useQueryClient();
  const [page, setPage] = useState(0);
  const [status, setStatus] = useState('');
  const [incident, setIncident] = useState('');
  const [incidentDraft, setIncidentDraft] = useState('');
  const [selection, setSelection] = useState<{ orgId: string; taskId: string } | null>(null);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [grouping, setGrouping] = useState('incident');
  const selectedTaskId = selection?.orgId === orgId ? selection.taskId : null;

  useEffect(() => {
    setPage(0);
    setStatus('');
    setIncident('');
    setIncidentDraft('');
    setSelection(null);
    setSelectedRunId(null);
  }, [orgId]);

  const tasks = useQuery({
    queryKey: ['orchestration-tasks', orgId, page, status, incident],
    queryFn: () => api<TaskPage>(taskUrl(page, incident, status), orgId),
    refetchInterval: 2_000,
  });
  const catalog = useQuery({ queryKey: ['orchestration-catalog', orgId], queryFn: () => api<CatalogResponse>('/orchestration/catalog', orgId) });
  const selectedRow = tasks.data?.items.find(item => item.task.task_id === selectedTaskId) || null;
  const detail = useQuery({
    queryKey: ['orchestration-task', orgId, selectedTaskId],
    queryFn: () => api<TaskDetail>(`/orchestration/tasks/${encodeURIComponent(selectedTaskId!)}`, orgId),
    enabled: !!selectedTaskId,
    refetchInterval: 2_000,
  });
  const selectedIncident = selectedRow?.task.incident_id || detail.data?.task.incident_id;
  const tree = useQuery({
    queryKey: ['orchestration-tree', orgId, selectedIncident],
    queryFn: () => api<IncidentTree>(`/orchestration/incidents/${encodeURIComponent(selectedIncident!)}/tree`, orgId),
    enabled: !!selectedIncident,
    refetchInterval: 2_000,
  });
  const treeMatch = selectedTaskId && tree.data ? findNode(tree.data.roots, selectedTaskId) : null;
  const helpRequestId = treeMatch ? [treeMatch.node, ...treeMatch.lineage.slice().reverse()].find(node => node.help_request_id)?.help_request_id : null;
  const helpContext = useQuery({
    queryKey: ['orchestration-help-context', orgId, selectedTaskId, helpRequestId],
    queryFn: () => api<HelpContext>(`/orchestration/tasks/${encodeURIComponent(selectedTaskId!)}/help-context`, orgId),
    enabled: !!selectedTaskId && !!helpRequestId,
  });
  const cancel = useMutation({
    mutationFn: () => api(`/orchestration/tasks/${encodeURIComponent(selectedTaskId!)}/cancel`, orgId, body('POST')),
    onSuccess: async () => {
      message.success('Cancellation requested');
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['orchestration-tasks', orgId] }),
        queryClient.invalidateQueries({ queryKey: ['orchestration-task', orgId, selectedTaskId] }),
      ]);
    },
    onError: error => message.error(error.message),
  });

  const currentRun = detail.data?.runs.find(run => run.run_id === selectedRunId)
    || (detail.data?.runs.length ? detail.data.runs[detail.data.runs.length - 1] : null);
  const result = specialistResult(currentRun?.result);
  const visibleEvidence = useMemo(() => {
    const incidentEvidence = (tree.data?.roots || []).flatMap(descendants).flatMap(node => node.evidence || []);
    const cited = new Set(result?.evidence_ids || []);
    const records = [...(detail.data?.evidence || []), ...(helpContext.data?.shared_evidence || []), ...incidentEvidence.filter(record => cited.has(record.evidence_id))];
    return [...new Map(records.map(record => [record.evidence_id, record])).values()];
  }, [detail.data?.evidence, helpContext.data?.shared_evidence, tree.data, currentRun]);
  const sortedTasks = [...(tasks.data?.items || [])].sort((a, b) => (b.task.created_at || '').localeCompare(a.task.created_at || ''));
  const taskGroups = grouping === 'time' ? [['Execution history', sortedTasks] as const] : [...sortedTasks.reduce((groups, item) => {
    groups.set(item.task.incident_id, [...(groups.get(item.task.incident_id) || []), item]);
    return groups;
  }, new Map<string, TaskRow[]>()).entries()];
  const canOperate = membership?.role === 'admin' || membership?.role === 'member';
  const canCancel = !!detail.data?.scheduler_job && ACTIVE_STATES.has(detail.data.task.status);
  const waiting = tasks.isFetching || detail.isFetching || tree.isFetching || catalog.isFetching;

  async function refresh() {
    await Promise.all([tasks.refetch(), catalog.refetch(), selectedTaskId ? detail.refetch() : Promise.resolve(), selectedIncident ? tree.refetch() : Promise.resolve(), helpRequestId ? helpContext.refetch() : Promise.resolve()]);
  }

  function applyIncident() {
    setPage(0);
    setIncident(incidentDraft.trim());
    setSelection(null);
  }

  return <div className="agent-activity">
    <section className="activity-summary" aria-label="Activity summary">
      <div><span className="eyebrow">LIVE ORCHESTRATION</span><strong>{tasks.data?.items.length ?? '—'}</strong><small>tasks on this page</small></div>
      <div><ClockCircleOutlined /><strong>{tasks.data?.items.filter(item => ACTIVE_STATES.has(item.task.status)).length ?? '—'}</strong><small>active or waiting</small></div>
      <div><BranchesOutlined /><strong>{selectedIncident ? '1' : '—'}</strong><small>incident in focus</small></div>
      <div className="activity-summary-action"><span>Auto-refreshes every 2 seconds</span><Button icon={<ReloadOutlined spin={waiting} />} onClick={() => void refresh()}>Refresh now</Button></div>
    </section>

    <section className="activity-toolbar" aria-label="Task filters">
      <Select aria-label="Filter by execution status" value={status || undefined} allowClear placeholder="All execution states" options={TASK_STATES.map(value => ({ value, label: displayStatus(value) }))} onChange={value => { setPage(0); setStatus(value || ''); setSelection(null); }} />
      <Input.Search aria-label="Filter by incident ID" value={incidentDraft} allowClear placeholder="Exact incident ID" enterButton="Apply" onChange={event => setIncidentDraft(event.target.value)} onSearch={applyIncident} />
      {(status || incident) && <Button onClick={() => { setStatus(''); setIncident(''); setIncidentDraft(''); setPage(0); setSelection(null); }}>Clear filters</Button>}
    </section>

    <div className="activity-view-options"><Select aria-label="Group agent activity" value={grouping} options={[{ value: 'incident', label: 'Group by incident' }, { value: 'time', label: 'Execution history · newest first' }]} onChange={setGrouping} /><span>Newest first within the loaded page. Select an incident task to open its full operation.</span></div>
    {tree.data && <OperationOverview tree={tree.data} selected={selectedTaskId} onSelect={taskId => { setSelection({ orgId, taskId }); setSelectedRunId(null); }} />}

    <ErrorPanel error={tasks.error} retry={() => void tasks.refetch()} />
    {tasks.isPending ? <div className="panel"><Skeleton active paragraph={{ rows: 8 }} /></div> : tasks.data?.items.length ? <div className="activity-workbench">
      <section className="panel activity-queue" aria-labelledby="activity-queue-title">
        <div className="activity-section-heading"><div><span className="eyebrow">DURABLE QUEUE</span><h2 id="activity-queue-title">Agent tasks</h2></div><Tag>{page * PAGE_SIZE + 1}–{page * PAGE_SIZE + tasks.data.items.length}</Tag></div>
        <div className="task-list">{taskGroups.map(([label, items]) => <section key={label} className="incident-task-group"><header><strong title={label}>{label}</strong><span>{items.length} on this page</span></header>{items.map(item => <button key={item.task.task_id} className={`task-row${selectedTaskId === item.task.task_id ? ' selected' : ''}`} onClick={() => { setSelection({ orgId, taskId: item.task.task_id }); setSelectedRunId(null); }}>
          <div className="task-row-top"><span>{item.task.role.replaceAll('_', ' ')}</span><StateTag value={item.task.status} /></div>
          <p>{objectiveText(item.task.objective)}</p>
          <div className="task-meta"><span>{item.task.area.replaceAll('_', ' ')}</span><Id>{item.task.incident_id}</Id><span>{date(item.task.updated_at)}</span></div>
          {item.scheduler_job?.recovery_reason && <small className="recovery"><PauseCircleOutlined /> {item.scheduler_job.recovery_reason}</small>}
        </button>)}</section>)}</div>
        <Pagination simple current={page + 1} pageSize={PAGE_SIZE} total={(page + 1) * PAGE_SIZE + (tasks.data.items.length === PAGE_SIZE ? 1 : 0)} showSizeChanger={false} onChange={next => { setPage(next - 1); setSelection(null); }} />
      </section>

      <aside className="panel activity-inspector" aria-label="Task inspector">
        {!selectedTaskId ? <EmptyPanel title="Select a task" description="Choose a durable task to inspect its run, evidence, model attempt, and collaboration context." /> : detail.isPending ? <Skeleton active paragraph={{ rows: 10 }} /> : detail.error ? <ErrorPanel error={detail.error} retry={() => void detail.refetch()} /> : detail.data && <>
          <header className="inspector-header"><div><span className="eyebrow">TASK INSPECTOR</span><h2>{detail.data.task.role.replaceAll('_', ' ')}</h2><p>{objectiveText(detail.data.task.objective)}</p></div><StateTag value={detail.data.task.status} /></header>
          <div className="inspector-id"><span>Task</span><Id>{detail.data.task.task_id}</Id><span>Incident</span><Id>{detail.data.task.incident_id}</Id></div>
          <div className="inspector-actions">
            <span>Execution state and finding verdict are reported independently.</span>
            {canCancel && <Tooltip title={canOperate ? 'Request a bounded scheduler cancellation' : 'Operator role required'}><Button danger icon={<StopOutlined />} disabled={!canOperate} loading={cancel.isPending} onClick={() => cancel.mutate()}>Cancel task</Button></Tooltip>}
          </div>
          {detail.data.child_records_may_be_truncated && <Alert type="warning" showIcon title="Bounded detail view" description={`One or more record groups reached the ${detail.data.child_records_limit}-record display limit. Additional records may exist.`} />}
          <SchedulerProgress job={detail.data.scheduler_job} />
          <RunHistory runs={detail.data.runs} selected={currentRun?.run_id || null} onSelect={setSelectedRunId} />
          <ActivityTimeline task={detail.data.task} run={currentRun} evidence={detail.data.evidence} />
          <RunResult run={currentRun} evidence={visibleEvidence} />
          <section className="activity-subsection">
            <h4>Evidence collected</h4>
            {visibleEvidence.length ? <div className="evidence-list">{visibleEvidence.map(record => <article key={record.evidence_id}><div><strong>{record.source}</strong><Id>{record.evidence_id}</Id></div><small>Source time {date(record.source_timestamp)} · collected {date(record.collected_at)}</small>{record.content_ref && <p>{record.content_ref}</p>}</article>)}</div> : <p className="muted">{result?.evidence_ids.length ? 'This task cites saved evidence; its records are outside the loaded detail.' : 'No evidence records are attached to this task.'}</p>}
          </section>
          {!!detail.data.actions.length && <section className="activity-subsection"><h4>Action attempts</h4>{detail.data.actions.map(action => <div className="call-row" key={action.attempt_id}><div><strong>{action.action}</strong><small>{action.targets.length} target{action.targets.length === 1 ? '' : 's'}</small></div><StateTag value={action.status} /></div>)}</section>}
          {(helpContext.data || treeMatch?.node.help_ownership?.length) && <section className="activity-subsection help-context"><h4>Help ownership and context</h4>
            {helpContext.isPending ? <Skeleton active paragraph={{ rows: 3 }} /> : helpContext.data ? <HelpRecord ownership={helpContext.data} /> : treeMatch?.node.help_ownership?.map(record => <HelpRecord key={record.help_request_id} ownership={record} />)}
          </section>}
          {!!result?.evidence_ids.length && <p className="coverage-note">This result cites {result.evidence_ids.length} saved evidence record{result.evidence_ids.length === 1 ? '' : 's'} from this incident.</p>}
        </>}
      </aside>
    </div> : <EmptyPanel title="No orchestration tasks" description={status || incident ? 'No tasks match these exact filters.' : 'No durable agent work has been admitted for this organization.'} action={page > 0 ? <Button onClick={() => setPage(current => Math.max(0, current - 1))}>Previous page</Button> : undefined} />}

    {selectedIncident && <section className="panel activity-tree" aria-labelledby="activity-tree-title">
      <div className="activity-section-heading"><div><span className="eyebrow">INCIDENT OWNERSHIP</span><h2 id="activity-tree-title">Task tree</h2></div>{tree.data && <StateTag value={tree.data.aggregate_status} />}</div>
      {tree.isPending ? <Skeleton active paragraph={{ rows: 4 }} /> : tree.error ? <ErrorPanel error={tree.error} retry={() => void tree.refetch()} /> : tree.data?.roots.length ? <><ul>{tree.data.roots.map(root => <TreeBranch key={root.task_id} node={root} selected={selectedTaskId} onSelect={taskId => { setSelection({ orgId, taskId }); setSelectedRunId(null); }} />)}</ul>{!!tree.data.gaps?.length && <Alert type="warning" showIcon title="Incident coverage gaps" description={<ul>{tree.data.gaps.map(gap => <li key={gap}>{gap}</li>)}</ul>} />}</> : <EmptyPanel title="No coordination tree" description="The selected incident has no admitted coordination root." />}
    </section>}

    <ErrorPanel error={catalog.error} retry={() => void catalog.refetch()} />
    <Catalog data={catalog.data} loading={catalog.isPending} />
  </div>;
}

function HelpRecord({ ownership }: { ownership: HelpOwnership | HelpContext }) {
  const result = specialistResult(ownership.result);
  const sharedEvidence = 'shared_evidence' in ownership ? ownership.shared_evidence : undefined;
  return <article className="help-record">
    <div className="help-record-head"><div><strong>{ownership.requester_role.replaceAll('_', ' ')} → {ownership.target_role.replaceAll('_', ' ')}</strong><Id>{ownership.help_request_id}</Id></div><StateTag value={ownership.state} /></div>
    <p>{ownership.objective}</p>
    <dl className="activity-facts compact"><div><dt>Owner</dt><dd>{ownership.responsible_area?.replaceAll('_', ' ') || 'Unassigned'}</dd></div><div><dt>Result</dt><dd>{analysisLabel(result)}</dd></div></dl>
    {!!ownership.expected_evidence_kinds?.length && <p className="muted">Expected: {ownership.expected_evidence_kinds.join(', ')}</p>}
    {!!ownership.shared_evidence_ids?.length && <div className="evidence-chips">{ownership.shared_evidence_ids.map(id => <span key={id}><Id>{id}</Id></span>)}</div>}
    {sharedEvidence && <small>{sharedEvidence.length} shared evidence record{sharedEvidence.length === 1 ? '' : 's'} loaded in this context.</small>}
    {ownership.reason_code && <p className="coverage-note">{displayStatus(ownership.reason_code)}</p>}
  </article>;
}
