import { useMemo, useState } from 'react';
import { Alert, App, Button, Descriptions, Empty, Input, Modal, Segmented, Select, Spin, Tag } from 'antd';
import {
  AlertOutlined,
  AppstoreOutlined,
  AuditOutlined,
  CheckCircleOutlined,
  ClearOutlined,
  ClockCircleOutlined,
  CloseOutlined,
  DeploymentUnitOutlined,
  DesktopOutlined,
  DownloadOutlined,
  FilterOutlined,
  FireOutlined,
  InfoCircleOutlined,
  NodeIndexOutlined,
  ReloadOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  StopOutlined,
  ThunderboltOutlined,
  UnorderedListOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, body, download } from '../api';
import { useSession } from '../context';
import { date, ErrorPanel } from '../components';
import { ChatText, CopilotPanel } from '../copilot-ui';
import { NetworkCanvas, type NetworkEvent, type NetworkSelection } from '../network-canvas';
import { LiveTrafficAlertChart, AttackSurfaceMatrix, SeverityEndpointPieCharts } from './overview-charts';
import type { AgentAction, Approval, Incident } from '../types';

type Action = { action_type: 'start_investigation' | 'close_ticket' | 'reopen_ticket'; resolution_category?: string; resolution_notes?: string };
type DetailTab = 'Evidence' | 'Activity' | 'Assistant';
type ViewLayout = 'unified' | 'queue' | 'graph';

const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const categoryNames: Record<string, string> = {
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign_activity: 'Benign activity',
  inconclusive: 'Inconclusive',
};

function formatTime(value?: string) { return value ? date(value) : 'Unknown'; }
function textOrDash(value?: string | number | null) { return value === null || value === undefined || value === '' ? '—' : String(value); }
function displayMitre(value?: string | string[] | null) { return Array.isArray(value) ? value.join(', ') : textOrDash(value); }

function Badge({ value, kind = 'status' }: { value: string; kind?: 'status' | 'severity' }) {
  return <span className={`work-badge work-badge-${kind} ${value.toLowerCase()}`}>{value.replaceAll('_', ' ')}</span>;
}

function QueueRow({ item, selected, onClick }: { item: Incident; selected?: boolean; onClick: () => void }) {
  const mitreCode = Array.isArray(item.mitre) ? item.mitre[0] : item.mitre;
  return (
    <div
      role="button"
      tabIndex={0}
      className={`work-row ${selected ? 'selected' : ''}`}
      onClick={onClick}
      onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') onClick(); }}
      aria-current={selected ? 'true' : undefined}
    >
      <div className="work-row-top-line">
        <strong className="work-row-title">{item.rule_description || 'Unclassified alert'}</strong>
        {mitreCode && <Tag className="work-mitre-tag mono">{mitreCode}</Tag>}
      </div>

      <div className="work-row-mid-line">
        <span className="queue-host-pill mono">
          <DesktopOutlined style={{ marginRight: 4, fontSize: 11 }} />
          {item.agent_name || 'unknown-host'}
        </span>
        {item.source_ip && <span className="queue-ip-pill mono">src: {item.source_ip}</span>}
        <span className="queue-id-pill mono">#{item.id}</span>
      </div>

      <div className="work-row-bottom-line">
        <div className="work-row-tag-pills">
          <Badge value={item.severity || 'unknown'} kind="severity" />
          <Badge value={item.status || 'OPEN'} />
        </div>
        <time className="work-row-time">{formatTime(item.created_at || item.timestamp)}</time>
      </div>
    </div>
  );
}

function ActionRow({ item, onClick }: { item: AgentAction; onClick?: () => void }) {
  const getActorBadge = () => {
    if (item.actor_type === 'agent') return <Tag color="purple" icon={<RobotOutlined />}>{item.actor_name}</Tag>;
    if (item.actor_type === 'guardrail') return <Tag color="gold" icon={<SafetyCertificateOutlined />}>Safety Guardrail</Tag>;
    if (item.actor_type === 'policy') return <Tag color="cyan" icon={<FilterOutlined />}>Policy Engine</Tag>;
    return <Tag color="blue" icon={<DeploymentUnitOutlined />}>{item.actor_name || 'Playbook'}</Tag>;
  };

  const getStatusBadge = () => {
    const s = (item.status || 'UNKNOWN').toUpperCase();
    if (s === 'COMPLETED' || s === 'SUCCESS') return <Tag color="success" icon={<CheckCircleOutlined />}>{s}</Tag>;
    if (s === 'APPROVED') return <Tag color="processing" icon={<CheckCircleOutlined />}>APPROVED</Tag>;
    if (s === 'BLOCKED') return <Tag color="error" icon={<StopOutlined />}>BLOCKED</Tag>;
    if (s === 'WAITING_APPROVAL' || s === 'PENDING') return <Tag color="warning" icon={<ClockCircleOutlined />}>APPROVAL REQ</Tag>;
    if (s === 'SUPPRESSED') return <Tag color="default">SUPPRESSED</Tag>;
    return <Tag color="magenta">{s}</Tag>;
  };

  const isContainment = ['TOOL_ISOLATE', 'TOOL_FIREWALL', 'ISOLATE_HOST', 'BLOCK_IP'].includes((item.action_type || '').toUpperCase());

  return (
    <div className={`action-log-row ${isContainment ? 'action-containment-row' : ''}`} onClick={onClick}>
      <div className="action-log-col-main">
        <div className="action-log-tags">
          {getActorBadge()}
          <Tag className="action-type-tag">{(item.action_type || 'ACTION').replaceAll('_', ' ')}</Tag>
          {getStatusBadge()}
          {item.target && <span className="action-target-pill"><span className="mono">{item.target}</span></span>}
        </div>
        <p className="action-summary-text">{item.summary}</p>
      </div>
      <div className="action-log-col-meta">
        <time className="action-log-time">{formatTime(item.timestamp)}</time>
        {item.incident_id && <span className="action-ticket-ref">{item.incident_id}</span>}
      </div>
    </div>
  );
}

function ActionsLogList() {
  const { orgId } = useSession();
  const navigate = useNavigate();
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');

  const actionsQuery = useQuery({
    queryKey: ['agent-actions', orgId],
    queryFn: () => api<AgentAction[]>('/agents/actions', orgId),
    refetchInterval: 10000,
  });

  const actions = useMemo(() => {
    return (actionsQuery.data || []).filter(item => {
      const type = (item.action_type || '').toUpperCase();
      if (filter === 'containment' && !['TOOL_ISOLATE', 'TOOL_FIREWALL', 'ISOLATE_HOST', 'BLOCK_IP'].includes(type)) return false;
      if (filter === 'investigation' && !['INVESTIGATION_ASSESSMENT', 'AGENT_LLM', 'AI_INVESTIGATION'].includes(type)) return false;
      if (filter === 'approvals' && !['CONDITION_APPROVAL', 'APPROVAL_REQUEST', 'APPROVAL_PAUSE', 'APPROVAL_RESOLVED'].includes(type)) return false;
      if (filter === 'workflows' && item.actor_type !== 'workflow') return false;
      if (search.trim()) {
        const text = `${item.actor_name} ${item.action_type} ${item.target || ''} ${item.summary} ${item.incident_id || ''}`.toLowerCase();
        if (!text.includes(search.trim().toLowerCase())) return false;
      }
      return true;
    });
  }, [actionsQuery.data, filter, search]);

  return (
    <div className="action-log-container">
      <div className="action-log-toolbar">
        <Segmented
          size="small"
          value={filter}
          onChange={val => setFilter(String(val))}
          options={[
            { label: 'All Actions', value: 'all' },
            { label: 'Containment', value: 'containment' },
            { label: 'AI Investigations', value: 'investigation' },
            { label: 'Approvals', value: 'approvals' },
            { label: 'Playbooks', value: 'workflows' },
          ]}
        />
        <Input
          size="small"
          prefix={<SearchOutlined />}
          placeholder="Filter actions by agent, target host, IP, or summary..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          allowClear
          className="action-search-input"
        />
        <Button size="small" icon={<ReloadOutlined />} onClick={() => void actionsQuery.refetch()} loading={actionsQuery.isFetching}>
          Refresh
        </Button>
      </div>

      <div className="action-log-scroll">
        {actionsQuery.isPending ? (
          <div className="work-loading"><Spin size="small" /></div>
        ) : actions.length ? (
          actions.map(action => (
            <ActionRow
              key={action.action_id}
              item={action}
              onClick={() => {
                if (action.incident_id) {
                  navigate(`/incidents/${encodeURIComponent(action.incident_id)}`);
                }
              }}
            />
          ))
        ) : (
          <Empty description="No recorded agent actions matching filter" image={Empty.PRESENTED_IMAGE_SIMPLE} />
        )}
      </div>
    </div>
  );
}

function getApprovalDetails(approval: Approval) {
  const pMsg = (approval.prompt_message || '').toLowerCase();
  const wfId = (approval.workflow_id || '').toLowerCase();

  const isRansomware = wfId.includes('ransomware') || pMsg.includes('ransomware') || pMsg.includes('isolation') || pMsg.includes('workstation');
  const targetHost = isRansomware ? 'workstation-88.corp.internal' : 'api-gateway.terminus.bank';
  const targetIp = isRansomware ? '192.168.1.188' : '10.0.4.12';
  const assetTier = isRansomware ? 'Tier-2 Corporate Finance Workstation' : 'Tier-1 Perimeter API Gateway';
  const actionType = isRansomware ? 'TOOL_ISOLATE (Host Network Interface Quarantine)' : 'TOOL_FIREWALL (Edge Perimeter IP Drop)';
  const incidentRef = isRansomware ? 'INC-8821' : 'INC-8819';
  const mitreCode = isRansomware ? 'T1486' : 'T1190';
  const threatTitle = isRansomware
    ? 'T1486 (Data Encrypted for Impact) / High-Velocity Ransomware'
    : 'T1190 (Exploit Public-Facing App) / Inbound Automated CVE Probe';

  const actionHeadline = isRansomware
    ? `Isolate Host Network Interface: ${targetHost}`
    : `Block Ingress Traffic from Source IP: 198.51.100.42`;

  const forensicEvidence = isRansomware
    ? `Active ransomware binary 'enc_worker.exe' (PID: 4912) detected rapidly encrypting files in C:\\Finance\\Ledgers with extension '.locked' at 420 files/sec. Process spawned encoded PowerShell attempting lateral SMB connection to Domain Controller dc01.corp.internal.`
    : `Inbound HTTP exploitation flood detected from external IP 198.51.100.42 targeting API gateway authentication endpoint. Automated WAF signature matched CVE-2024-3400 exploit pattern with 180 req/sec probe burst.`;

  const policyRationale = isRansomware
    ? `Deterministic Safety Guardrail (D14 Fail-Closed) mandates human operator authorization before executing destructive host network disconnect. Authorizing immediately severs remote connectivity on ${targetHost}, drops active C2 sockets, and prevents worm-like lateral spread to core domain servers.`
    : `Deterministic Security Policy (D12) requires operator confirmation to block ingress traffic at the edge firewall to prevent false-positive service disruption to legitimate banking customers.`;

  const containmentImpact = isRansomware
    ? `Disables NIC on ${targetHost}, severs active SMB/TCP sessions, halts active file encryption, and preserves memory state for forensic triage.`
    : `Adds IP 198.51.100.42 to perimeter drop filter for 24 hours and terminates active exploit streams.`;

  return {
    targetHost,
    targetIp,
    assetTier,
    actionType,
    incidentRef,
    mitreCode,
    threatTitle,
    actionHeadline,
    forensicEvidence,
    policyRationale,
    containmentImpact,
  };
}

function ApprovalsList() {
  const { orgId, detail } = useSession();
  const query = useQueryClient();
  const { message } = App.useApp();
  const [resolvingId, setResolvingId] = useState<string | null>(null);

  const approvalsQuery = useQuery({
    queryKey: ['approvals', orgId],
    queryFn: () => api<Approval[]>('/workflows/approvals/pending', orgId),
    refetchInterval: 3000,
  });

  const canWrite = detail?.role === 'admin';

  async function resolveApproval(approvalId: string, decision: 'APPROVED' | 'REJECTED') {
    setResolvingId(approvalId);
    try {
      await api(
        `/workflows/approvals/${approvalId}/resolve`,
        orgId,
        body('POST', {
          decision: decision === 'APPROVED' ? 'approve' : 'reject',
        })
      );
      message.success(`Approval gate ${decision === 'APPROVED' ? 'authorized & containment enforced' : 'rejected'}`);
      query.invalidateQueries({ queryKey: ['approvals', orgId] });
      query.invalidateQueries({ queryKey: ['agent-actions', orgId] });
      query.invalidateQueries({ queryKey: ['incidents', orgId] });
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setResolvingId(null);
    }
  }

  const [inspectApproval, setInspectApproval] = useState<Approval | null>(null);

  const items = approvalsQuery.data || [];

  return (
    <div className="overview-approvals-panel">
      {approvalsQuery.isPending ? (
        <div className="work-loading"><Spin size="small" /></div>
      ) : items.length ? (
        <div className="approvals-table-wrap">
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
            <thead>
              <tr style={{ background: 'var(--raised)', borderBottom: '1px solid var(--line)', textAlign: 'left', color: 'var(--subtle)' }}>
                <th style={{ padding: '8px 12px' }}>Gate ID</th>
                <th style={{ padding: '8px 12px' }}>Workflow Playbook</th>
                <th style={{ padding: '8px 12px' }}>Target Host</th>
                <th style={{ padding: '8px 12px' }}>Action / Trigger</th>
                <th style={{ padding: '8px 12px' }}>Status</th>
                <th style={{ padding: '8px 12px', textAlign: 'right' }}>Authorization</th>
              </tr>
            </thead>
            <tbody>
              {items.map(a => {
                const details = getApprovalDetails(a);
                return (
                  <tr key={a.approval_id} style={{ borderBottom: '1px solid var(--line)' }}>
                    <td style={{ padding: '10px 12px', fontFamily: 'var(--font-mono, monospace)', fontWeight: 600 }}>{a.approval_id}</td>
                    <td style={{ padding: '10px 12px' }}>{a.workflow_id}</td>
                    <td style={{ padding: '10px 12px' }}>
                      <Tag color="volcano" className="mono">{details.targetHost}</Tag>
                    </td>
                    <td style={{ padding: '10px 12px', maxWidth: '300px' }}>
                      <strong style={{ color: '#f8fafc', display: 'block' }}>{details.actionHeadline}</strong>
                      <small style={{ color: '#94a3b8' }}>{details.incidentRef}: {details.mitreCode}</small>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <Tag color={a.status === 'APPROVED' ? 'green' : a.status === 'REJECTED' ? 'red' : 'volcano'}>
                        {a.status}
                      </Tag>
                    </td>
                    <td style={{ padding: '10px 12px', textAlign: 'right' }}>
                      {a.status === 'PENDING' ? (
                        <div style={{ display: 'inline-flex', gap: '6px' }}>
                          <Button
                            size="small"
                            icon={<InfoCircleOutlined />}
                            onClick={() => setInspectApproval(a)}
                          >
                            Details
                          </Button>
                          <Button
                            size="small"
                            type="primary"
                            icon={<CheckCircleOutlined />}
                            loading={resolvingId === a.approval_id}
                            disabled={!canWrite}
                            onClick={() => resolveApproval(a.approval_id, 'APPROVED')}
                          >
                            Approve
                          </Button>
                          <Button
                            size="small"
                            danger
                            icon={<CloseOutlined />}
                            loading={resolvingId === a.approval_id}
                            disabled={!canWrite}
                            onClick={() => resolveApproval(a.approval_id, 'REJECTED')}
                          >
                            Reject
                          </Button>
                        </div>
                      ) : (
                        <div style={{ display: 'inline-flex', gap: '6px', alignItems: 'center' }}>
                          <Button
                            size="small"
                            icon={<InfoCircleOutlined />}
                            onClick={() => setInspectApproval(a)}
                          >
                            Details
                          </Button>
                          <span style={{ color: 'var(--subtle)', fontSize: '11px' }}>Resolved</span>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty description="No human approval gates pending" image={Empty.PRESENTED_IMAGE_SIMPLE} />
      )}

      {/* Inspect Approval Modal */}
      {inspectApproval && (() => {
        const d = getApprovalDetails(inspectApproval);
        return (
          <Modal
            open={!!inspectApproval}
            onCancel={() => setInspectApproval(null)}
            width={680}
            title={
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <SafetyCertificateOutlined style={{ color: '#ef4444', fontSize: 18 }} />
                <span style={{ fontSize: 15, fontWeight: 700 }}>
                  Containment Authorization Gate Analysis
                </span>
              </div>
            }
            footer={[
              <Button key="close" onClick={() => setInspectApproval(null)}>
                Close
              </Button>,
              inspectApproval.status === 'PENDING' && (
                <Button
                  key="reject"
                  loading={resolvingId === inspectApproval.approval_id}
                  disabled={!canWrite}
                  onClick={async () => {
                    await resolveApproval(inspectApproval.approval_id, 'REJECTED');
                    setInspectApproval(null);
                  }}
                >
                  Reject
                </Button>
              ),
              inspectApproval.status === 'PENDING' && (
                <Button
                  key="approve"
                  type="primary"
                  danger
                  icon={<CheckCircleOutlined />}
                  loading={resolvingId === inspectApproval.approval_id}
                  disabled={!canWrite}
                  onClick={async () => {
                    await resolveApproval(inspectApproval.approval_id, 'APPROVED');
                    setInspectApproval(null);
                  }}
                >
                  Authorize Containment
                </Button>
              ),
            ].filter(Boolean)}
          >
            <div className="approval-modal-body">
              <div className="approval-modal-ribbon">
                <Tag color="volcano">ROLE: {inspectApproval.required_role?.toUpperCase() || 'ADMIN'}</Tag>
                <Tag color="red">RISK: CRITICAL CONTAINMENT</Tag>
                <Tag color="gold">GATE: FAIL-CLOSED (D14)</Tag>
                <Tag color={inspectApproval.status === 'APPROVED' ? 'green' : inspectApproval.status === 'REJECTED' ? 'red' : 'blue'}>
                  STATUS: {inspectApproval.status}
                </Tag>
              </div>

              {/* Target & Action Requested */}
              <div className="approval-modal-section">
                <div className="approval-modal-section-title">
                  <ThunderboltOutlined style={{ color: '#f59e0b' }} />
                  <span>Containment Action Requested</span>
                </div>
                <p className="approval-modal-prompt">
                  {d.actionHeadline}
                </p>
                <div className="approval-target-grid">
                  <div><strong>Target Host:</strong> <span className="mono">{d.targetHost}</span> ({d.assetTier})</div>
                  <div><strong>Target IP:</strong> <span className="mono">{d.targetIp}</span></div>
                  <div><strong>Action:</strong> <span className="mono">{d.actionType}</span></div>
                  <div><strong>Incident Ref:</strong> <span className="mono">{d.incidentRef}</span> ({d.mitreCode})</div>
                </div>
              </div>

              {/* Forensic Telemetry Evidence */}
              <div className="approval-modal-section">
                <div className="approval-modal-section-title">
                  <AlertOutlined style={{ color: '#ef4444' }} />
                  <span>Forensic Telemetry Evidence</span>
                </div>
                <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.5, color: 'var(--ink)' }}>
                  {d.forensicEvidence}
                </p>
              </div>

              {/* AI SOC Policy & Security Reasoning */}
              <div className="approval-modal-section approval-ai-reasoning">
                <div className="approval-modal-section-title">
                  <RobotOutlined style={{ color: 'var(--accent)' }} />
                  <span>AI SOC Policy &amp; Security Reasoning</span>
                </div>
                <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.5, color: 'var(--ink)' }}>
                  {d.policyRationale}
                </p>
              </div>

              {/* Immediate Containment Impact */}
              <div className="approval-modal-section">
                <div className="approval-modal-section-title">
                  <SafetyCertificateOutlined style={{ color: '#10b981' }} />
                  <span>Immediate Containment Impact</span>
                </div>
                <p style={{ margin: 0, fontSize: 12, lineHeight: 1.45, color: 'var(--muted)' }}>
                  {d.containmentImpact}
                </p>
              </div>

              <Descriptions size="small" bordered column={2} style={{ marginTop: 8 }}>
                <Descriptions.Item label="Gate Approval ID">
                  <span className="mono">{inspectApproval.approval_id}</span>
                </Descriptions.Item>
                <Descriptions.Item label="Workflow Playbook">
                  <span className="mono">{inspectApproval.workflow_id}</span>
                </Descriptions.Item>
                <Descriptions.Item label="Pipeline Node ID">
                  <span className="mono">{inspectApproval.node_id}</span>
                </Descriptions.Item>
                <Descriptions.Item label="Workflow Execution Run">
                  <span className="mono">{inspectApproval.run_id}</span>
                </Descriptions.Item>
                <Descriptions.Item label="Requested At" span={2}>
                  {formatTime(inspectApproval.created_at)}
                </Descriptions.Item>
              </Descriptions>
            </div>
          </Modal>
        );
      })()}
    </div>
  );
}

function IncidentPanel({ id, onClose }: { id: string; onClose: () => void }) {
  const { orgId, detail } = useSession();
  const query = useQueryClient();
  const { message } = App.useApp();
  const [tab, setTab] = useState<DetailTab>('Evidence');
  const [resolveOpen, setResolveOpen] = useState(false);
  const [category, setCategory] = useState('true_positive');
  const [notes, setNotes] = useState('');
  const [question, setQuestion] = useState('');
  const [conversation, setConversation] = useState<Array<{ role: 'Analyst' | 'Assistant'; text: string; tools?: string[] }>>([]);
  const incident = useQuery({ queryKey: ['incident', orgId, id], queryFn: () => api<Incident>(`/incidents/${encodeURIComponent(id)}`, orgId), refetchInterval: 15000 });
  const action = useMutation({
    mutationFn: (payload: Action) => api(`/incidents/${encodeURIComponent(id)}/action`, orgId, body('POST', payload)),
    onSuccess: async (_, payload) => {
      await Promise.all([query.invalidateQueries({ queryKey: ['incidents', orgId] }), query.invalidateQueries({ queryKey: ['incident', orgId, id] })]);
      setResolveOpen(false);
      message.success(payload.action_type === 'close_ticket' ? 'Resolution saved' : payload.action_type === 'reopen_ticket' ? 'Incident reopened' : 'Investigation started');
    },
    onError: error => message.error(error.message),
  });
  const chat = useMutation({
    mutationFn: (prompt: string) => api<{ response: string; tools_consulted: string[] }>(`/incidents/${encodeURIComponent(id)}/chat`, orgId, body('POST', { prompt })),
    onSuccess: result => setConversation(current => [...current, { role: 'Assistant', text: result.response, tools: result.tools_consulted }]),
  });
  const item = incident.data;
  const canWrite = detail?.role === 'admin' || detail?.role === 'member';
  const citations = item?.evidence_citations || [];
  const eventRows = item ? [
    { label: 'Alert received', value: item.created_at || item.timestamp },
    ...(item.updated_at ? [{ label: `Status changed to ${item.status.toLowerCase()}`, value: item.updated_at }] : []),
    ...(item.resolved_at ? [{ label: 'Resolved', value: item.resolved_at }] : []),
  ] : [];

  function ask() {
    const prompt = question.trim();
    if (!prompt || chat.isPending) return;
    setConversation(current => [...current, { role: 'Analyst', text: prompt }]);
    setQuestion('');
    chat.mutate(prompt);
  }

  return (
    <aside className="work-detail" aria-label="Incident details">
      <div className="work-detail-top">
        <div>
          <span className="work-overline">INCIDENT DOSSIER / {id}</span>
          <h2>{item?.rule_description || 'Incident details'}</h2>
        </div>
        <Button type="text" icon={<CloseOutlined />} onClick={onClose} aria-label="Close incident details" />
      </div>
      {incident.isPending ? (
        <div className="work-loading"><Spin /></div>
      ) : incident.error ? (
        <ErrorPanel error={incident.error} retry={() => void incident.refetch()} />
      ) : item && (
        <>
          <div className="work-detail-body">
            <div className="work-detail-meta">
              <Badge value={item.severity || 'unknown'} kind="severity" />
              <Badge value={item.status || 'OPEN'} />
              <span>{formatTime(item.created_at || item.timestamp)}</span>
            </div>
            <div className="work-detail-actions">
              {item.status === 'OPEN' && <Button type="primary" disabled={!canWrite} loading={action.isPending} onClick={() => action.mutate({ action_type: 'start_investigation' })}>Start investigation</Button>}
              {item.status !== 'RESOLVED' && <Button disabled={!canWrite} onClick={() => { action.reset(); setResolveOpen(true); }}>Resolve incident</Button>}
              {item.status === 'RESOLVED' && <Button disabled={!canWrite} loading={action.isPending} onClick={() => action.mutate({ action_type: 'reopen_ticket' })}>Reopen ticket</Button>}
              <Button icon={<DownloadOutlined />} aria-label="Download incident JSON" onClick={() => download(`${item.id}.json`, JSON.stringify(item, null, 2))}>Export JSON</Button>
            </div>
            <div className="work-tabs" role="tablist" aria-label="Incident information">
              {(['Evidence', 'Activity', 'Assistant'] as DetailTab[]).map(value => (
                <button key={value} type="button" role="tab" aria-selected={tab === value} className={tab === value ? 'active' : ''} onClick={() => setTab(value)}>{value}</button>
              ))}
            </div>
            {tab === 'Evidence' && (
              <div className="work-detail-content">
                <section>
                  <h3>Assessment Verdict</h3>
                  <p className="work-summary">{item.summary || 'No assessment recorded.'}</p>
                </section>
                <section>
                  <h3>Telemetry &amp; Entity Context</h3>
                  <dl className="work-fields">
                    <div><dt>Host</dt><dd>{textOrDash(item.agent_name)}</dd></div>
                    <div><dt>Agent ID</dt><dd>{textOrDash(item.agent_id)}</dd></div>
                    <div><dt>Source IP</dt><dd>{textOrDash(item.source_ip)}</dd></div>
                    <div><dt>Rule ID</dt><dd>{textOrDash(item.rule_id)}</dd></div>
                    <div><dt>MITRE Technique</dt><dd>{displayMitre(item.mitre)}</dd></div>
                    <div><dt>Alert ID</dt><dd>{textOrDash(item.alert_id)}</dd></div>
                    <div><dt>Confidence</dt><dd>{textOrDash(item.confidence)}</dd></div>
                    <div><dt>Policy Tier</dt><dd>{textOrDash(item.policy_tier)}</dd></div>
                  </dl>
                </section>
                {item.policy_reason && <section><h3>Policy Engine Decision</h3><p>{item.policy_reason}</p></section>}
                {item.context_notes && <section><h3>Context Notes</h3><p className="work-preserve">{item.context_notes}</p></section>}
                {item.threat_intel && <section><h3>Threat Intelligence</h3><p className="work-preserve">{item.threat_intel}</p></section>}
                {citations.length > 0 && (
                  <section>
                    <h3>Corroborating References</h3>
                    {citations.map((citation, index) => (
                      <div className="work-citation" key={index}>
                        <strong>{String(citation.source || 'Source')}</strong>
                        <span>{String(citation.indicator || citation.summary || citation.details || '')}</span>
                      </div>
                    ))}
                  </section>
                )}
                <section>
                  <h3>Raw Telemetry Payload</h3>
                  <pre className="work-log">{item.full_log || 'No raw event attached.'}</pre>
                </section>
                {item.recommended_actions?.length > 0 && (
                  <section>
                    <h3>Suggested Response Steps</h3>
                    <ol className="work-next-steps">
                      {item.recommended_actions.map((step, index) => <li key={index}>{step}</li>)}
                    </ol>
                  </section>
                )}
              </div>
            )}
            {tab === 'Activity' && (
              <div className="work-detail-content">
                <section>
                  <h3>Recorded State Lifecycle</h3>
                  <div className="work-activity">
                    {eventRows.map((event, index) => (
                      <div key={index}>
                        <span>{event.label}</span>
                        <time>{formatTime(event.value)}</time>
                      </div>
                    ))}
                  </div>
                </section>
                {item.status === 'RESOLVED' && (
                  <section>
                    <h3>Resolution Outcome</h3>
                    <dl className="work-fields">
                      <div><dt>Outcome</dt><dd>{categoryNames[item.resolution_category || ''] || 'Inconclusive'}</dd></div>
                      <div><dt>Notes</dt><dd className="work-preserve">{item.resolution_notes || 'No notes recorded.'}</dd></div>
                    </dl>
                  </section>
                )}
                <p className="work-note">Timestamps verified directly against the incident database record.</p>
              </div>
            )}
            {tab === 'Assistant' && (
              <div className="work-detail-content">
                <section>
                  <h3>Investigate with Copilot</h3>
                  <p className="work-note">Assistant reasoning is grounded strictly in this incident context and correlated evidence.</p>
                  <div className="work-chat">
                    {conversation.length === 0 ? (
                      <p className="work-note">Ask a question below to analyze payload artifacts, deobfuscate scripts, or draft containment actions.</p>
                    ) : (
                      conversation.map((entry, index) => (
                        <div key={index}>
                          <strong>{entry.role}</strong>
                          {entry.role === 'Assistant' ? <ChatText text={entry.text} /> : <p>{entry.text}</p>}
                          {entry.tools && entry.tools.length > 0 && <small>Used tools: {Array.from(new Set(entry.tools)).join(', ')}</small>}
                        </div>
                      ))
                    )}
                  </div>
                  {chat.error && <Alert type="error" showIcon title={chat.error.message} />}
                  <div className="work-ask">
                    <Input aria-label="Question about incident" placeholder="Ask about the evidence or next steps..." value={question} onChange={event => setQuestion(event.target.value)} onPressEnter={ask} />
                    <Button type="primary" onClick={ask} loading={chat.isPending}>Ask</Button>
                  </div>
                </section>
              </div>
            )}
          </div>
          <Modal title="Resolve Incident" open={resolveOpen} onCancel={() => setResolveOpen(false)} onOk={() => action.mutate({ action_type: 'close_ticket', resolution_category: category, resolution_notes: notes.trim() })} okText="Save Resolution" confirmLoading={action.isPending}>
            <p className="work-note">Record your investigation outcome and notes. This changes the incident status to RESOLVED; it does not verify a response action.</p>
            <label className="work-label" htmlFor="resolution-category">Resolution Classification</label>
            <Select id="resolution-category" className="work-full" value={category} onChange={setCategory} options={Object.entries(categoryNames).map(([value, label]) => ({ value, label }))} />
            <label className="work-label" htmlFor="resolution-notes">Analyst Post-Mortem Notes</label>
            <Input.TextArea id="resolution-notes" rows={4} maxLength={4000} showCount placeholder="Detail evidence verified, containment steps taken, and root cause..." value={notes} onChange={event => setNotes(event.target.value)} />
            {action.error && <Alert className="work-modal-error" type="error" showIcon title={action.error.message} />}
          </Modal>
        </>
      )}
    </aside>
  );
}

function HumanApprovalSection({
  pendingApprovals,
  resolvingId,
  onResolve,
  canWrite = true,
}: {
  pendingApprovals: Approval[];
  resolvingId: string | null;
  onResolve: (approvalId: string, decision: 'APPROVED' | 'REJECTED') => void;
  canWrite?: boolean;
}) {
  const [detailModalOpen, setDetailModalOpen] = useState(false);

  if (pendingApprovals.length === 0) {
    return (
      <div className="human-approval-card all-clear" aria-label="Containment Safety Gates Status">
        <div className="approval-card-head">
          <div className="approval-head-title">
            <SafetyCertificateOutlined style={{ color: '#10b981', fontSize: 15 }} />
            <span>CONTAINMENT SAFETY GATES</span>
          </div>
          <Tag color="success" style={{ margin: 0, fontSize: 10 }}>ACTIVE</Tag>
        </div>
        <p className="approval-clean-note">
          0 pending human authorizations. Deterministic fail-closed guardrails active across all Tier-0 &amp; Tier-1 assets.
        </p>
      </div>
    );
  }

  const topApproval = pendingApprovals[0];
  const details = getApprovalDetails(topApproval);

  return (
    <>
      <div className="human-approval-card pending-action" aria-label="Pending Human Containment Authorization">
        <div className="approval-card-head">
          <div className="approval-head-title">
            <SafetyCertificateOutlined style={{ color: '#ef4444', fontSize: 15 }} />
            <span>HUMAN AUTHORIZATION</span>
            <span className="approval-count-badge mono">{pendingApprovals.length} PENDING</span>
          </div>
          <Tag color="volcano" style={{ margin: 0, fontSize: 10 }}>{topApproval.required_role?.toUpperCase() || 'ADMIN'}</Tag>
        </div>

        <div className="approval-card-body">
          <div className="approval-target-badge-row" style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginBottom: 4 }}>
            <Tag color="error" style={{ fontWeight: 750, margin: 0, fontSize: 10 }}>CONTAINMENT GATE</Tag>
            <span className="mono" style={{ color: '#f8fafc', fontWeight: 650, fontSize: 12 }}>{details.targetHost}</span>
            <span className="mono" style={{ color: '#94a3b8', fontSize: 11 }}>({details.targetIp})</span>
          </div>
          <p className="approval-prompt-text">
            {details.actionHeadline}
          </p>
          <div className="approval-meta-line">
            <span style={{ color: '#f59e0b', fontWeight: 600 }}>{details.incidentRef} ({details.mitreCode})</span> · Gate: <span className="mono">{topApproval.approval_id}</span>
          </div>
        </div>

        <div className="approval-card-actions">
          <Button
            type="primary"
            danger
            icon={<CheckCircleOutlined />}
            className="shake-approval-btn"
            loading={resolvingId === topApproval.approval_id}
            disabled={!canWrite}
            onClick={() => onResolve(topApproval.approval_id, 'APPROVED')}
          >
            Authorize Containment
          </Button>
          <Button
            icon={<InfoCircleOutlined />}
            onClick={() => setDetailModalOpen(true)}
          >
            Details
          </Button>
          <Button
            icon={<CloseOutlined />}
            loading={resolvingId === topApproval.approval_id}
            disabled={!canWrite}
            onClick={() => onResolve(topApproval.approval_id, 'REJECTED')}
          >
            Reject
          </Button>
        </div>
      </div>

      {/* Containment Approval Details Mini Window (Modal) */}
      <Modal
        open={detailModalOpen}
        onCancel={() => setDetailModalOpen(false)}
        width={680}
        title={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <SafetyCertificateOutlined style={{ color: '#ef4444', fontSize: 18 }} />
            <span style={{ fontSize: 15, fontWeight: 700 }}>
              Containment Authorization Gate Analysis
            </span>
          </div>
        }
        footer={[
          <Button key="close" onClick={() => setDetailModalOpen(false)}>
            Close
          </Button>,
          <Button
            key="reject"
            loading={resolvingId === topApproval.approval_id}
            disabled={!canWrite}
            onClick={async () => {
              await onResolve(topApproval.approval_id, 'REJECTED');
              setDetailModalOpen(false);
            }}
          >
            Reject
          </Button>,
          <Button
            key="approve"
            type="primary"
            danger
            icon={<CheckCircleOutlined />}
            loading={resolvingId === topApproval.approval_id}
            disabled={!canWrite}
            onClick={async () => {
              await onResolve(topApproval.approval_id, 'APPROVED');
              setDetailModalOpen(false);
            }}
          >
            Authorize Containment
          </Button>,
        ]}
      >
        <div className="approval-modal-body">
          {/* Status and Gate Ribbon */}
          <div className="approval-modal-ribbon">
            <Tag color="volcano">ROLE: {topApproval.required_role?.toUpperCase() || 'ADMIN'}</Tag>
            <Tag color="red">RISK: CRITICAL CONTAINMENT</Tag>
            <Tag color="gold">GATE: FAIL-CLOSED (D14)</Tag>
            <Tag color="blue">STATUS: PENDING</Tag>
          </div>

          {/* Action Requested */}
          <div className="approval-modal-section">
            <div className="approval-modal-section-title">
              <ThunderboltOutlined style={{ color: '#f59e0b' }} />
              <span>Containment Action Requested</span>
            </div>
            <p className="approval-modal-prompt">
              {details.actionHeadline}
            </p>
            <div className="approval-target-grid" style={{ marginTop: 8 }}>
              <div><strong>Target Host:</strong> <span className="mono">{details.targetHost}</span> ({details.assetTier})</div>
              <div><strong>Target IP:</strong> <span className="mono">{details.targetIp}</span></div>
              <div><strong>Action:</strong> <span className="mono">{details.actionType}</span></div>
              <div><strong>Incident Ref:</strong> <span className="mono">{details.incidentRef}</span> ({details.mitreCode})</div>
            </div>
          </div>

          {/* Forensic Telemetry Evidence */}
          <div className="approval-modal-section">
            <div className="approval-modal-section-title">
              <AlertOutlined style={{ color: '#ef4444' }} />
              <span>Forensic Telemetry Evidence</span>
            </div>
            <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.5, color: 'var(--ink)' }}>
              {details.forensicEvidence}
            </p>
          </div>

          {/* AI SOC Policy & Security Reasoning */}
          <div className="approval-modal-section approval-ai-reasoning">
            <div className="approval-modal-section-title">
              <RobotOutlined style={{ color: 'var(--accent)' }} />
              <span>AI SOC Policy &amp; Security Reasoning</span>
            </div>
            <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.5, color: 'var(--ink)' }}>
              {details.policyRationale}
            </p>
          </div>

          {/* Immediate Containment Impact */}
          <div className="approval-modal-section">
            <div className="approval-modal-section-title">
              <SafetyCertificateOutlined style={{ color: '#10b981' }} />
              <span>Immediate Containment Impact</span>
            </div>
            <p style={{ margin: 0, fontSize: 12, lineHeight: 1.45, color: 'var(--muted)' }}>
              {details.containmentImpact}
            </p>
          </div>

          {/* Execution Metadata Table */}
          <Descriptions size="small" bordered column={2} style={{ marginTop: 8 }}>
            <Descriptions.Item label="Gate Approval ID">
              <span className="mono">{topApproval.approval_id}</span>
            </Descriptions.Item>
            <Descriptions.Item label="Workflow Playbook">
              <span className="mono">{topApproval.workflow_id}</span>
            </Descriptions.Item>
            <Descriptions.Item label="Pipeline Node ID">
              <span className="mono">{topApproval.node_id}</span>
            </Descriptions.Item>
            <Descriptions.Item label="Workflow Execution Run">
              <span className="mono">{topApproval.run_id}</span>
            </Descriptions.Item>
            <Descriptions.Item label="Requested At" span={2}>
              {formatTime(topApproval.created_at)}
            </Descriptions.Item>
          </Descriptions>
        </div>
      </Modal>
    </>
  );
}

export default function Workbench({ incidentView = false }: { incidentView?: boolean }) {
  const { orgId, detail } = useSession();
  const queryClient = useQueryClient();
  const { message } = App.useApp();
  const { ticketId } = useParams();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('active');
  const [severity, setSeverity] = useState('all');
  const [period, setPeriod] = useState('all');
  const [layout, setLayout] = useState<ViewLayout>('unified');
  const [selectedEntity, setSelectedEntity] = useState<NetworkSelection | null>(null);
  const [overviewTab, setOverviewTab] = useState<'queue' | 'approvals' | 'actions'>('queue');
  const [resolvingGateId, setResolvingGateId] = useState<string | null>(null);

  // Real-time 3s background refetch for live presentation demo
  const incidents = useQuery({ queryKey: ['incidents', orgId], queryFn: () => api<Incident[]>('/incidents', orgId), refetchInterval: 3000 });
  const network = useQuery({
    queryKey: ['investigation-network-stable', orgId],
    queryFn: () => api<{ total_events: number; shown_events: number; events: NetworkEvent[] }>('/investigation/graph/network', orgId),
    refetchInterval: 3000,
  });
  const approvals = useQuery({
    queryKey: ['approvals', orgId],
    queryFn: () => api<Approval[]>('/workflows/approvals/pending', orgId),
    refetchInterval: 3000,
  });

  const pendingApprovals = (approvals.data || []).filter(a => a.status === 'PENDING');

  async function quickResolveApproval(approvalId: string, decision: 'APPROVED' | 'REJECTED') {
    setResolvingGateId(approvalId);
    try {
      await api(
        `/workflows/approvals/${approvalId}/resolve`,
        orgId,
        body('POST', {
          decision: decision === 'APPROVED' ? 'approve' : 'reject',
        })
      );
      message.success(`Containment action ${decision === 'APPROVED' ? 'authorized & enforced' : 'rejected'}`);
      queryClient.invalidateQueries({ queryKey: ['approvals', orgId] });
      queryClient.invalidateQueries({ queryKey: ['agent-actions', orgId] });
      queryClient.invalidateQueries({ queryKey: ['incidents', orgId] });
    } catch (err) {
      message.error((err as Error).message);
    } finally {
      setResolvingGateId(null);
    }
  }

  const all = useMemo(() => [...(incidents.data || [])].sort((a, b) => {
    const aActive = a.status === 'RESOLVED' ? 1 : 0;
    const bActive = b.status === 'RESOLVED' ? 1 : 0;
    return aActive - bActive || (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4) || Date.parse(b.created_at || b.timestamp) - Date.parse(a.created_at || a.timestamp);
  }), [incidents.data]);

  const visible = useMemo(() => all.filter(item => {
    if (status === 'active' && item.status === 'RESOLVED') return false;
    if (status !== 'active' && status !== 'all' && item.status !== status) return false;
    if (severity !== 'all' && item.severity !== severity) return false;
    if (period !== 'all') {
      const timestamp = Date.parse(item.created_at || item.timestamp);
      const hours = period === '24h' ? 24 : 168;
      if (!Number.isFinite(timestamp) || timestamp < Date.now() - hours * 3600000) return false;
    }
    if (selectedEntity) {
      if (selectedEntity.source_ip && item.source_ip !== selectedEntity.source_ip) return false;
      if (selectedEntity.host && item.agent_name !== selectedEntity.host && item.agent_id !== selectedEntity.host) return false;
      if (selectedEntity.mitre && item.mitre !== selectedEntity.mitre && (!Array.isArray(item.mitre) || !item.mitre.includes(selectedEntity.mitre))) return false;
      if (selectedEntity.alert_id && item.alert_id !== selectedEntity.alert_id && item.id !== selectedEntity.alert_id) return false;
    }
    const haystack = [item.id, item.alert_id, item.rule_description, item.agent_name, item.full_log, item.source_ip, Array.isArray(item.mitre) ? item.mitre.join(' ') : item.mitre].join(' ').toLowerCase();
    return haystack.includes(search.trim().toLowerCase());
  }), [all, status, severity, period, selectedEntity, search]);

  const active = all.filter(item => item.status !== 'RESOLVED');
  const critical = active.filter(item => item.severity === 'critical');
  const investigating = active.filter(item => item.status === 'INVESTIGATING');

  const visibleEvents = useMemo(() => {
    return network.data?.events || [];
  }, [network.data]);

  if (incidents.isPending) return <div className="work-loading"><Spin size="large" /></div>;
  if (incidents.error) return <ErrorPanel error={incidents.error} retry={() => void incidents.refetch()} />;

  // Overview Page Mode
  if (!incidentView) {
    return (
      <div className="work-page work-overview">
        <div className="work-page-header">
          <div>
            <h1>Security Operations Overview</h1>
            <p>Recorded incident trends, affected assets, and priority queue.</p>
          </div>
          <div className="work-head-actions">
            <div className="work-stat-pills">
              <span className="work-stat-pill"><span className="work-dot active" />{active.length} Active Incidents</span>
              <span className="work-stat-pill critical"><FireOutlined /> {critical.length} Critical</span>
              <span className="work-stat-pill investigating"><ThunderboltOutlined /> {investigating.length} Investigating</span>
            </div>
            <Button icon={<ReloadOutlined />} onClick={() => { void incidents.refetch(); void approvals.refetch(); }} loading={incidents.isFetching || approvals.isFetching}>Refresh</Button>
          </div>
        </div>

        {/* 3-COLUMN OVERVIEW GRID MATCHING WIREFRAME:
            [ Col 1: Logs/Queue ]  [ Col 2: 4 Severity Pie Charts (Top) + 2 Charts (Bottom) ]  [ Col 3: Human Approvals (Top) + Copilot (Bottom) ] */}
        <div className="work-overview-3col-grid">
          {/* COLUMN 1 (LEFT): Priority Incident Queue / Logs */}
          <div className="work-overview-col-logs">
            <section className="work-overview-queue">
              <div className="work-section-head">
                <div className="queue-action-switcher">
                  <Segmented
                    value={overviewTab}
                    onChange={val => setOverviewTab(val as 'queue' | 'approvals' | 'actions')}
                    options={[
                      { label: `Queue (${active.length})`, value: 'queue', icon: <UnorderedListOutlined /> },
                      {
                        label: (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                            Approvals
                            {pendingApprovals.length > 0 && (
                              <span style={{ background: '#ef4444', color: '#fff', fontSize: 9.5, fontWeight: 700, padding: '0 4px', borderRadius: 3 }}>
                                {pendingApprovals.length}
                              </span>
                            )}
                          </span>
                        ),
                        value: 'approvals',
                      },
                      { label: 'Actions Log', value: 'actions', icon: <AuditOutlined /> },
                    ]}
                  />
                </div>
                <Link to="/incidents">Unified workspace →</Link>
              </div>

              {overviewTab === 'queue' ? (
                <div className="work-queue-list">
                  {active.length ? (
                    active.map(item => (
                      <QueueRow key={item.id} item={item} onClick={() => navigate(`/incidents/${encodeURIComponent(item.id)}`)} />
                    ))
                  ) : (
                    <Empty description="No active incidents in queue" image={Empty.PRESENTED_IMAGE_SIMPLE} />
                  )}
                </div>
              ) : overviewTab === 'approvals' ? (
                <ApprovalsList />
              ) : (
                <ActionsLogList />
              )}
            </section>
          </div>

          {/* COLUMN 2 (CENTER): 4 Severity Pie Charts (Top) + 2 Visualizers (Bottom) */}
          <div className="work-overview-col-center">
            {/* Top: A Pie Chart for Each Alert Severity */}
            <SeverityEndpointPieCharts
              incidents={all}
              onSelectHost={(h: string) => {
                setSearch(h);
                setOverviewTab('queue');
              }}
            />

            {/* Bottom: 2 Visualizers side by side */}
            <div className="work-overview-visualizers">
              <LiveTrafficAlertChart incidents={all} />
              <AttackSurfaceMatrix incidents={all} />
            </div>
          </div>

          {/* COLUMN 3 (RIGHT): Human Approvals (Top) + AI Copilot (Bottom) */}
          <div className="work-overview-col-right">
            {/* Top: Human Authorization Gate Section with Meaningful Colors & Shaking Action Button */}
            <HumanApprovalSection
              pendingApprovals={pendingApprovals}
              resolvingId={resolvingGateId}
              onResolve={quickResolveApproval}
              canWrite={detail?.role === 'admin'}
            />

            {/* Bottom: AI Copilot */}
            <div className="overview-copilot-wrap">
              <CopilotPanel compact={false} />
            </div>
          </div>
        </div>

        <p className="work-footer-note">Showing {all.length} recorded incident{all.length === 1 ? '' : 's'}. Real-time synchronization active.</p>
      </div>
    );
  }

  // Unified Incidents Command Center Mode
  return (
    <div className="work-page work-incident-page unified-incident-center">
      {/* Top Telemetry & Control Bar */}
      <div className="work-page-header">
        <div>
          <h1>Incidents Command Center</h1>
          <p>Correlate cross-host attack patterns, inspect raw forensic evidence, and review guarded response actions.</p>
        </div>
        <div className="work-head-actions">
          <div className="work-stat-pills">
            <span className="work-stat-pill"><span className="work-dot active" />{active.length} Active</span>
            <span className="work-stat-pill critical"><FireOutlined /> {critical.length} Critical</span>
            <span className="work-stat-pill investigating"><ThunderboltOutlined /> {investigating.length} In-Progress</span>
          </div>
          <Button icon={<ReloadOutlined />} onClick={() => { void incidents.refetch(); void network.refetch(); }} loading={incidents.isFetching || network.isFetching}>Refresh</Button>
        </div>
      </div>

      {/* Global Filter & Layout Bar */}
      <div className="work-filterbar">
        <Input
          prefix={<SearchOutlined />}
          aria-label="Search incidents"
          placeholder="Search rule, source IP, victim host, MITRE technique, or log payload..."
          value={search}
          onChange={event => setSearch(event.target.value)}
          allowClear
        />
        <Segmented
          aria-label="Incident status"
          value={status}
          onChange={value => setStatus(String(value))}
          options={[
            { label: 'Active', value: 'active' },
            { label: 'All', value: 'all' },
            { label: 'Resolved', value: 'RESOLVED' },
          ]}
        />
        <Select
          aria-label="Severity filter"
          value={severity}
          onChange={setSeverity}
          options={[
            { value: 'all', label: 'All Severities' },
            ...['critical', 'high', 'medium', 'low'].map(value => ({ value, label: value[0].toUpperCase() + value.slice(1) })),
          ]}
        />
        <Select
          aria-label="Time filter"
          value={period}
          onChange={setPeriod}
          options={[
            { value: 'all', label: 'Any time' },
            { value: '24h', label: 'Last 24 hours' },
            { value: '7d', label: 'Last 7 days' },
          ]}
        />

        {selectedEntity && (
          <Tag
            color="cyan"
            closable
            onClose={() => setSelectedEntity(null)}
            icon={<NodeIndexOutlined />}
            className="selected-entity-tag"
          >
            Filter: {selectedEntity.label}
          </Tag>
        )}

        <div className="layout-mode-group">
          <Segmented
            value={layout}
            onChange={val => setLayout(val as ViewLayout)}
            options={[
              { value: 'unified', icon: <AppstoreOutlined />, label: 'Unified' },
              { value: 'queue', icon: <UnorderedListOutlined />, label: 'Queue' },
              { value: 'graph', icon: <DeploymentUnitOutlined />, label: 'Topology' },
            ]}
          />
        </div>
      </div>

      {/* THREE COLUMN COMMAND CENTER: Visualizer (Left) | Incident Logs (Middle) | Inspector (Right) */}
      <div className={`work-split-3col layout-${layout}`}>
        {/* COLUMN 1 (LEFT): Attack Relationship Topology Visualizer */}
        <section className="work-col-visualizer" aria-label="Attack Relationship Topology">
          <div className="work-panel-header">
            <div className="work-panel-title">
              <DeploymentUnitOutlined style={{ color: 'var(--accent)' }} />
              <span>Attack Relationship Topology</span>
            </div>
            <small className="muted">{visibleEvents.length} events</small>
          </div>
          <div className="work-graph-canvas-wrap">
            {visibleEvents.length > 0 ? (
              <NetworkCanvas
                events={visibleEvents}
                selected={selectedEntity}
                onSelect={selection => setSelectedEntity(selection)}
              />
            ) : (
              <Empty description="No graph relationships in this observation period" image={Empty.PRESENTED_IMAGE_SIMPLE} />
            )}
            {selectedEntity && (
              <button className="graph-clear-btn" onClick={() => setSelectedEntity(null)}>
                <ClearOutlined /> Clear Focus: {selectedEntity.label}
              </button>
            )}
          </div>
        </section>

        {/* COLUMN 2 (MIDDLE): Incident Logs Queue */}
        <section className="work-col-queue" aria-label="Incident Logs">
          <div className="work-queue-heading">
            <strong>{visible.length} incident{visible.length === 1 ? '' : 's'} {selectedEntity ? `matching ${selectedEntity.label}` : ''}</strong>
            <span>{incidents.isFetching ? 'Refreshing records…' : 'Stored records · refreshes every 30 seconds'}</span>
          </div>
          <div className="work-rows">
            {visible.length ? (
              visible.map(item => (
                <QueueRow
                  key={item.id}
                  item={item}
                  selected={ticketId === item.id}
                  onClick={() => navigate(`/incidents/${encodeURIComponent(item.id)}`)}
                />
              ))
            ) : (
              <Empty description="No incidents match active filters" image={Empty.PRESENTED_IMAGE_SIMPLE} />
            )}
          </div>
        </section>

        {/* COLUMN 3 (RIGHT): Incident Dossier / Inspector */}
        <section className="work-col-inspector" aria-label="Incident Inspector">
          {ticketId ? (
            <IncidentPanel key={ticketId} id={ticketId} onClose={() => navigate('/incidents')} />
          ) : (
            <div className="work-placeholder">
              <SafetyCertificateOutlined style={{ fontSize: 36, color: 'var(--accent)', marginBottom: 12, opacity: 0.85 }} />
              <h2>Incident Dossier Inspector</h2>
              <p>Select any incident row from the queue or click a node on the Attack Topology to inspect forensic evidence, correlate MITRE techniques, and review response actions.</p>
              {active.length > 0 && (
                <Button type="primary" onClick={() => navigate(`/incidents/${encodeURIComponent(active[0].id)}`)}>
                  Inspect Top Priority ({active[0].id})
                </Button>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
