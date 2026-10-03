import { useCallback, useEffect, useState } from 'react';
import {
  Alert,
  App,
  Badge,
  Button,
  Card,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd';
import {
  CheckCircleOutlined,
  CloseCircleOutlined,
  DeleteOutlined,
  ExperimentOutlined,
  PlayCircleOutlined,
  PlusOutlined,
  SaveOutlined,
} from '@ant-design/icons';
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  addEdge,
  useEdgesState,
  useNodesState,
  useReactFlow,
  type Connection,
  type Edge,
  type Node,
  type NodeProps,
} from '@xyflow/react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import '@xyflow/react/dist/style.css';
import { api, body } from '../api';
import { useSession } from '../context';
import { useTheme } from '../theme';
import { EmptyPanel, ErrorPanel, Loading, PageTitle } from '../components';
import type { Agent, Approval, Workflow } from '../types';

const { Text } = Typography;

// Exactly 8 allowed node types per D1 (trigger_cron permanently removed)
const palette = [
  { type: 'trigger_wazuh', label: 'Wazuh Alert Trigger', group: 'TRIGGER', color: 'green', description: 'Evaluates incoming Wazuh SIEM telemetry' },
  { type: 'condition_severity', label: 'Severity Gate', group: 'CONDITION', color: 'amber', description: 'Deterministic level & verdict severity filter' },
  { type: 'condition_approval', label: 'Human Approval Gate', group: 'APPROVAL', color: 'blue', description: 'Halts execution until analyst authorization' },
  { type: 'agent_llm', label: 'AI Investigation Persona', group: 'AGENT', color: 'blue', description: 'Re-evaluates telemetry with custom persona' },
  { type: 'tool_slack', label: 'Slack Alert', group: 'OUTPUT', color: 'blue', description: 'Broadcasts report to Slack channel' },
  { type: 'tool_jira', label: 'Jira Ticket', group: 'OUTPUT', color: 'blue', description: 'Creates structured tracking incident ticket' },
  { type: 'tool_isolate', label: 'Isolate Host', group: 'CONTAINMENT', color: 'red', description: 'Active containment workstation network cut' },
  { type: 'tool_firewall', label: 'Block IP Address', group: 'CONTAINMENT', color: 'red', description: 'Active perimeter drop firewall rule' },
];

type FlowNode = Node<
  {
    label: string;
    kind: string;
    config: Record<string, unknown>;
    traceStatus?: 'SUCCESS' | 'FAILED' | 'BLOCKED' | 'WAITING_APPROVAL' | 'SKIPPED';
  },
  'operation'
>;

function OperationNode({ data, selected }: NodeProps<FlowNode>) {
  const meta = palette.find(item => item.type === data.kind);
  const isCondition = data.kind === 'condition_severity' || data.kind === 'condition_approval';

  let statusBadge = null;
  if (data.traceStatus) {
    const colorMap: Record<string, string> = {
      SUCCESS: '#22c55e',
      FAILED: '#ef4444',
      BLOCKED: '#f59e0b',
      WAITING_APPROVAL: '#2563c9',
      SKIPPED: '#64748b',
    };
    statusBadge = (
      <div
        style={{
          position: 'absolute',
          top: -8,
          right: -8,
          backgroundColor: colorMap[data.traceStatus] || '#3b82f6',
          color: '#fff',
          fontSize: '9px',
          fontWeight: 700,
          padding: '2px 6px',
          borderRadius: 4,
          textTransform: 'uppercase',
        }}
      >
        {data.traceStatus}
      </div>
    );
  }

  return (
    <div className={`operation-node ${meta?.color || 'blue'} ${selected ? 'selected' : ''}`} style={{ position: 'relative' }}>
      {statusBadge}
      <Handle type="target" position={Position.Left} style={{ background: 'var(--accent)', width: 8, height: 8 }} />
      <div className="node-kind">
        <i />
        {meta?.group || 'STEP'}
      </div>
      <strong>{data.label?.trim() || meta?.label || data.kind}</strong>
      <small>{meta?.description || data.kind}</small>

      {/* Output handles strictly adhering to D8 */}
      {isCondition ? (
        <div style={{ display: 'flex', flexDirection: 'column', position: 'absolute', right: -6, top: 12, gap: 14 }}>
          <Handle
            id="true"
            type="source"
            position={Position.Right}
            style={{ position: 'relative', transform: 'none', background: '#22c55e', width: 8, height: 8 }}
          />
          <Handle
            id="false"
            type="source"
            position={Position.Right}
            style={{ position: 'relative', transform: 'none', background: '#ef4444', width: 8, height: 8 }}
          />
          <Handle
            id="on_error"
            type="source"
            position={Position.Right}
            style={{ position: 'relative', transform: 'none', background: '#f59e0b', width: 8, height: 8 }}
          />
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', position: 'absolute', right: -6, top: 16, gap: 16 }}>
          <Handle
            id="default"
            type="source"
            position={Position.Right}
            style={{ position: 'relative', transform: 'none', background: '#3b82f6', width: 8, height: 8 }}
          />
          <Handle
            id="on_error"
            type="source"
            position={Position.Right}
            style={{ position: 'relative', transform: 'none', background: '#f59e0b', width: 8, height: 8 }}
          />
        </div>
      )}
    </div>
  );
}

const nodeTypes = { operation: OperationNode };

function WorkflowEditor() {
  const { activeTheme } = useTheme();
  const lightCanvas = activeTheme.id === 'workspace';
  const { orgId, detail } = useSession();
  const { message, modal } = App.useApp();
  const query = useQueryClient();
  const flow = useReactFlow<FlowNode>();
  const [params, setParams] = useSearchParams();

  const [activeTab, setActiveTab] = useState<'editor' | 'approvals' | 'dryrun'>('editor');
  const [dryRunTrace, setDryRunTrace] = useState<Record<string, unknown> | null>(null);

  const workflows = useQuery({
    queryKey: ['workflows', orgId],
    queryFn: () => api<Workflow[]>('/workflows', orgId),
    refetchOnWindowFocus: false,
  });

  const agents = useQuery({
    queryKey: ['agents', orgId],
    queryFn: () => api<Agent[]>('/agents', orgId),
  });

  const approvals = useQuery({
    queryKey: ['approvals', orgId],
    queryFn: () => api<Approval[]>('/approvals', orgId),
    refetchInterval: 10000,
  });

  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [active, setActive] = useState('');
  const [name, setName] = useState('');
  const [enabled, setEnabled] = useState(false);
  const [priority, setPriority] = useState<number>(100);
  const [version, setVersion] = useState<number>(1);
  const [agent, setAgent] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState(false);
  const [newOpen, setNewOpen] = useState(false);
  const [newName, setNewName] = useState('');
  const [inspector, setInspector] = useState<string | null>(null);
  const [nodeForm] = Form.useForm();
  const [validation, setValidation] = useState<{ errors: string[]; summary?: string } | null>(null);

  const canWrite = detail?.role === 'admin';
  const requested = params.get('workflow');

  useEffect(() => {
    const selected = workflows.data?.find(w => w.id === requested) || workflows.data?.[0];
    if (!selected || (active === selected.id && dirty)) return;
    setActive(selected.id);
    setName(selected.name);
    setEnabled(selected.enabled);
    setPriority(selected.priority ?? 100);
    setVersion(selected.version ?? 1);
    setAgent(selected.agent_id);
    // Seeded definitions can omit editor coordinates. Spread their nodes out
    // for display while retaining any layout that an analyst has saved.
    const needsInitialLayout = selected.nodes.length > 1 && selected.nodes.every(n => !n.x && !n.y);
    setNodes(
      selected.nodes.map((n, index) => ({
        id: n.id,
        type: 'operation',
        position: needsInitialLayout ? { x: index * 340, y: 60 } : { x: n.x, y: n.y },
        data: { label: n.label, kind: n.type, config: n.config },
      }))
    );
    setEdges(
      selected.edges.map(edge => ({
        ...edge,
        sourceHandle: edge.source_handle || 'default',
        type: 'smoothstep',
      }))
    );
    setDirty(false);
    setInspector(null);
    setValidation(null);
    setDryRunTrace(null);
    requestAnimationFrame(() => void flow.fitView({ padding: 0.2, duration: 200 }));
  }, [workflows.data, requested]);

  const connect = useCallback(
    (connection: Connection) => {
      setEdges(old =>
        addEdge(
          {
            ...connection,
            sourceHandle: connection.sourceHandle || 'default',
            type: 'smoothstep',
          },
          old
        )
      );
      setDirty(true);
    },
    [setEdges]
  );

  function select(id: string) {
    const change = () => {
      setDirty(false);
      setParams({ workflow: id });
    };
    if (dirty) {
      modal.confirm({
        title: 'Discard unsaved changes?',
        content: 'Your saved workflow will remain unchanged.',
        okText: 'Discard changes',
        onOk: change,
      });
    } else {
      change();
    }
  }

  async function save(validate = false) {
    if (!active) return;
    setBusy(true);
    const value: Workflow = {
      id: active,
      name,
      enabled,
      priority,
      version,
      agent_id: agent,
      nodes: nodes.map(n => ({
        id: n.id,
        type: n.data.kind,
        label: n.data.label,
        x: Math.round(n.position.x),
        y: Math.round(n.position.y),
        config: n.data.config,
      })),
      edges: edges.map(e => ({
        id: e.id,
        source: e.source,
        target: e.target,
        source_handle: e.sourceHandle || 'default',
      })),
    };

    try {
      const updated = await api<Workflow>(
        `/workflows/${active}`,
        orgId,
        body('PUT', { ...value, expected_version: version })
      );
      setDirty(false);
      setVersion(updated.version ?? version + 1);
      query.setQueryData<Workflow[]>(['workflows', orgId], old => old?.map(w => (w.id === active ? updated : w)));

      if (validate) {
        const result = await api<{ errors: string[]; summary: string }>(
          `/workflows/${active}/execute`,
          orgId,
          body('POST', { sample_alert: { id: 'sample-1', rule_id: '5710', level: 10 } })
        );
        setValidation(result);
      }
      message.success(validate ? 'Definition validated and saved' : 'Workflow saved');
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function executeDryRun() {
    if (!active) return;
    setBusy(true);
    try {
      const res = await api<{
        dry_run: boolean;
        status: string;
        outcome: string;
        node_statuses: Record<string, string>;
        edge_states: Record<string, string>;
        errors: string[];
      }>(
        `/workflows/${active}/execute`,
        orgId,
        body('POST', {
          sample_alert: {
            id: 'sim-alert-001',
            rule_id: '5710',
            level: 12,
            description: 'SSH Brute Force Simulation Alert',
            src_ip: '198.51.100.42',
          },
        })
      );
      setDryRunTrace(res);

      // Update nodes on canvas with live trace status
      setNodes(old =>
        old.map(n => ({
          ...n,
          data: {
            ...n.data,
            traceStatus: res.node_statuses?.[n.id] as any,
          },
        }))
      );
      message.success(`Dry-run simulation completed: ${res.status} (${res.outcome})`);
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function create() {
    if (!newName.trim()) return;
    setBusy(true);
    try {
      const value = await api<Workflow>(
        '/workflows',
        orgId,
        body('POST', {
          name: newName.trim(),
          enabled: false,
          priority: 100,
          nodes: [
            {
              id: 'n1',
              type: 'trigger_wazuh',
              label: 'Wazuh Alert Ingestion',
              x: 50,
              y: 100,
              config: { min_level: 5 },
            },
          ],
          edges: [],
          agent_id: null,
        })
      );
      setDirty(false);
      await query.invalidateQueries({ queryKey: ['workflows', orgId] });
      setParams({ workflow: value.id });
      setNewOpen(false);
      setNewName('');
      message.success('Playbook created');
    } catch (error) {
      message.error((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function add(type: string) {
    const meta = palette.find(n => n.type === type)!;
    const defaultConfigs: Record<string, Record<string, unknown>> = {
      trigger_wazuh: { min_level: 5 },
      condition_severity: { min_level: 10 },
      condition_approval: { required_role: 'admin', prompt_message: 'Approve containment remediation', timeout_minutes: 30 },
      agent_llm: { persona_instructions: '' },
      tool_slack: { channel: '#soc-alerts' },
      tool_jira: { project_key: 'SEC', issue_type: 'Incident' },
      tool_isolate: { force_override: false },
      tool_firewall: { force_override: false },
    };

    const node: FlowNode = {
      id: `n-${crypto.randomUUID().slice(0, 8)}`,
      type: 'operation',
      position: flow.screenToFlowPosition({ x: window.innerWidth * 0.55, y: window.innerHeight * 0.45 }),
      data: {
        label: meta.label,
        kind: type,
        config: defaultConfigs[type] || {},
      },
    };
    setNodes(old => [...old, node]);
    setDirty(true);
  }

  function inspect(node: FlowNode) {
    setInspector(node.id);
    nodeForm.setFieldsValue({
      label: node.data.label,
      config: JSON.stringify(node.data.config, null, 2),
    });
  }

  function saveNode(values: { label: string; config: string }) {
    try {
      const config: unknown = JSON.parse(values.config);
      if (!config || typeof config !== 'object' || Array.isArray(config)) {
        throw new Error('Configuration must be a JSON object.');
      }
      setNodes(old =>
        old.map(n =>
          n.id === inspector
            ? { ...n, data: { ...n.data, label: values.label, config: config as Record<string, unknown> } }
            : n
        )
      );
      setDirty(true);
      setInspector(null);
    } catch (error) {
      message.error((error as Error).message);
    }
  }

  function removeWorkflow() {
    modal.confirm({
      title: `Delete “${name}”?`,
      content: 'This removes the saved workflow playbook definition.',
      okText: 'Delete playbook',
      okButtonProps: { danger: true },
      onOk: async () => {
        await api(`/workflows/${active}`, orgId, body('DELETE'));
        setDirty(false);
        setActive('');
        setParams({});
        query.invalidateQueries({ queryKey: ['workflows', orgId] });
      },
    });
  }

  async function resolveApproval(approvalId: string, action: 'APPROVED' | 'REJECTED') {
    try {
      await api(
        `/approvals/${approvalId}/resolve`,
        orgId,
        body('POST', {
          status: action,
          notes: `Decision recorded via console (${detail?.role || 'analyst'})`,
        })
      );
      message.success(`Approval gate ${action.toLowerCase()}`);
      query.invalidateQueries({ queryKey: ['approvals', orgId] });
    } catch (error) {
      message.error((error as Error).message);
    }
  }

  const pendingApprovalsCount = approvals.data?.filter(a => a.status === 'PENDING').length ?? 0;

  return (
    <>
      <PageTitle
        eyebrow="AUTOMATION / WORKFLOWS"
        title="SOC Response Playbooks."
        description="Design deterministic gates, AI persona investigations, and active containment workflows."
        actions={
          <Space>
            <Button icon={<ExperimentOutlined />} onClick={() => setActiveTab(activeTab === 'dryrun' ? 'editor' : 'dryrun')}>
              Simulation & Trace
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              disabled={!canWrite}
              onClick={() => setNewOpen(true)}
            >
              New playbook
            </Button>
          </Space>
        }
      />

      <Tabs
        activeKey={activeTab}
        onChange={k => setActiveTab(k as any)}
        items={[
          { key: 'editor', label: 'Playbook Canvas' },
          {
            key: 'approvals',
            label: (
              <span>
                Human Approvals <Badge count={pendingApprovalsCount} overflowCount={99} />
              </span>
            ),
          },
          { key: 'dryrun', label: 'Dry-Run Simulation' },
        ]}
        style={{ marginBottom: 16 }}
      />

      {activeTab === 'approvals' && (
        <section className="panel" style={{ padding: 20 }}>
          <Table<Approval>
            dataSource={approvals.data || []}
            rowKey="approval_id"
            columns={[
              { title: 'Gate ID', dataIndex: 'approval_id', key: 'approval_id' },
              { title: 'Workflow', dataIndex: 'workflow_id', key: 'workflow_id' },
              { title: 'Required Role', dataIndex: 'required_role', key: 'required_role', render: r => <Tag color="purple">{r}</Tag> },
              { title: 'Prompt / Request', dataIndex: 'prompt_message', key: 'prompt_message' },
              {
                title: 'Status',
                dataIndex: 'status',
                key: 'status',
                render: s => (
                  <Tag color={s === 'APPROVED' ? 'green' : s === 'REJECTED' ? 'red' : s === 'EXPIRED' ? 'default' : 'orange'}>
                    {s}
                  </Tag>
                ),
              },
              { title: 'Created', dataIndex: 'created_at', key: 'created_at' },
              {
                title: 'Actions',
                key: 'actions',
                render: (_, record) =>
                  record.status === 'PENDING' ? (
                    <Space>
                      <Button
                        type="primary"
                        size="small"
                        icon={<CheckCircleOutlined />}
                        disabled={!canWrite}
                        onClick={() => resolveApproval(record.approval_id, 'APPROVED')}
                      >
                        Approve
                      </Button>
                      <Button
                        danger
                        size="small"
                        icon={<CloseCircleOutlined />}
                        disabled={!canWrite}
                        onClick={() => resolveApproval(record.approval_id, 'REJECTED')}
                      >
                        Reject
                      </Button>
                    </Space>
                  ) : (
                    <Text type="secondary">Resolved ({record.resolved_by || 'system'})</Text>
                  ),
              },
            ]}
          />
        </section>
      )}

      {activeTab === 'dryrun' && (
        <section className="panel" style={{ padding: 20, marginBottom: 16 }}>
          <Space direction="vertical" style={{ width: '100%' }}>
            <div style={{ display: 'flex', flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <strong>In-Memory Playbook Simulator</strong>
                <p className="muted">Execute the current DAG with sample alert telemetry without firing webhooks or side effects.</p>
              </div>
              <Button type="primary" icon={<PlayCircleOutlined />} loading={busy} onClick={executeDryRun}>
                Run Simulation
              </Button>
            </div>
            {dryRunTrace && (
              <Card title={`Execution Trace — ${dryRunTrace.status} (${dryRunTrace.outcome})`} size="small">
                <pre className="mono" style={{ maxHeight: 220, overflow: 'auto' }}>
                  {JSON.stringify(dryRunTrace, null, 2)}
                </pre>
              </Card>
            )}
          </Space>
        </section>
      )}

      {activeTab === 'editor' && (
        <>
          <ErrorPanel error={workflows.error} retry={() => void workflows.refetch()} />
          {workflows.isPending ? (
            <Loading />
          ) : !workflows.data?.length ? (
            <EmptyPanel title="Start with a blank canvas" description="Create a playbook and connect its first nodes." />
          ) : (
            <section className="workflow-panel panel">
              <div className="workflow-toolbar">
                <Select
                  aria-label="Selected workflow"
                  value={active || undefined}
                  options={workflows.data.map(w => ({ value: w.id, label: `${w.name} (v${w.version || 1})` }))}
                  onChange={select}
                  style={{ minWidth: 260, maxWidth: 450 }}
                />
                <Space>
                  <Tag bordered={false}>{dirty ? 'UNSAVED CHANGES' : `SAVED (V${version})`}</Tag>
                  <Button icon={<CheckCircleOutlined />} disabled={!canWrite} loading={busy} onClick={() => void save(true)}>
                    Validate & save
                  </Button>
                  <Button type="primary" icon={<SaveOutlined />} disabled={!canWrite || !dirty} loading={busy} onClick={() => void save()}>
                    Save
                  </Button>
                  <Tooltip title="Delete playbook">
                    <Button aria-label="Delete workflow" icon={<DeleteOutlined />} disabled={!canWrite} onClick={removeWorkflow} />
                  </Tooltip>
                </Space>
              </div>

              <div className="workflow-meta">
                <Input
                  aria-label="Workflow name"
                  value={name}
                  disabled={!canWrite}
                  onChange={event => {
                    setName(event.target.value);
                    setDirty(true);
                  }}
                  style={{ maxWidth: 300 }}
                />
                <InputNumber
                  aria-label="Priority"
                  value={priority}
                  min={1}
                  max={999}
                  disabled={!canWrite}
                  onChange={val => {
                    setPriority(val ?? 100);
                    setDirty(true);
                  }}
                  addonBefore="Priority"
                  style={{ width: 150 }}
                />
                <Select
                  aria-label="Assigned agent"
                  placeholder="No assigned agent"
                  allowClear
                  value={agent || undefined}
                  options={agents.data?.map(a => ({ value: a.id, label: a.name }))}
                  onChange={value => {
                    setAgent(value || null);
                    setDirty(true);
                  }}
                  disabled={!canWrite}
                  style={{ minWidth: 200 }}
                />
                <Tooltip title="Toggle active autonomous execution for this workflow (enabling requires admin)">
                  <Space>
                    <Switch
                      size="small"
                      checked={enabled}
                      disabled={!canWrite}
                      onChange={value => {
                        setEnabled(value);
                        setDirty(true);
                      }}
                    />
                    <span className="muted">Enabled</span>
                  </Space>
                </Tooltip>
              </div>

              <div className="workflow-body">
                <aside className="node-palette">
                  <div className="eyebrow">NODE REGISTRY (8 TYPES)</div>
                  {palette.map(item => (
                    <button
                      disabled={!canWrite}
                      className={`palette-item ${item.color}`}
                      key={item.type}
                      onClick={() => add(item.type)}
                    >
                      <span className="node-kind">{item.group}</span>
                      <strong>{item.label}</strong>
                      <PlusOutlined />
                    </button>
                  ))}
                </aside>

                <div className="flow-canvas" data-testid="workflow-canvas">
                  <ReactFlow<FlowNode>
                    nodes={nodes}
                    edges={edges}
                    nodeTypes={nodeTypes}
                    onNodesChange={changes => {
                      onNodesChange(changes);
                      if (changes.some(c => c.type !== 'select' && c.type !== 'dimensions')) setDirty(true);
                    }}
                    onEdgesChange={changes => {
                      onEdgesChange(changes);
                      if (changes.some(c => c.type !== 'select')) setDirty(true);
                    }}
                    onConnect={connect}
                    onNodeDoubleClick={(_, node) => inspect(node)}
                    onNodeClick={(_, node) => inspect(node)}
                    nodesDraggable={canWrite}
                    nodesConnectable={canWrite}
                    edgesReconnectable={canWrite}
                    deleteKeyCode={canWrite ? ['Backspace', 'Delete'] : null}
                    fitView
                    minZoom={0.15}
                    maxZoom={2}
                    colorMode={lightCanvas ? 'light' : 'dark'}
                    defaultEdgeOptions={{
                      type: 'smoothstep',
                      style: { stroke: lightCanvas ? '#8093af' : '#7f9dc4', strokeWidth: 1.7 },
                    }}
                  >
                    <Background variant={BackgroundVariant.Dots} gap={22} size={1} color={lightCanvas ? '#cdd5e1' : '#354158'} bgColor={activeTheme.bgBase} />
                    <Controls />
                    <MiniMap pannable zoomable nodeColor={activeTheme.primaryColor} bgColor={activeTheme.bgSurface} maskColor={lightCanvas ? 'rgba(221,229,240,.55)' : 'rgba(15,20,30,.7)'} />
                  </ReactFlow>
                </div>
              </div>

              <div className="workflow-footer">
                <span>
                  {nodes.length} nodes · {edges.length} connections · Priority: {priority}
                </span>
                <span>Handles: Green (true) · Red (false) · Orange (error) · Blue (out)</span>
              </div>
            </section>
          )}

          <Alert
            className="context-alert"
            type={validation?.errors?.length ? 'error' : 'info'}
            showIcon
            title={validation?.errors?.length ? 'Safety Validation Attention' : 'Deterministic Safety Gates (D11)'}
            description={
              validation?.errors?.length
                ? validation.errors.join('; ')
                : 'All containment paths (host isolation, firewall block) are strictly verified to pass through an admin approval gate or deterministic severity threshold before execution.'
            }
          />
        </>
      )}

      <Modal
        title="Create a Playbook"
        open={newOpen}
        onCancel={() => setNewOpen(false)}
        onOk={() => void create()}
        okText="Create playbook"
        confirmLoading={busy}
        okButtonProps={{ disabled: !newName.trim() }}
      >
        <label className="field-label" htmlFor="workflow-name">
          Playbook Name
        </label>
        <Input
          id="workflow-name"
          value={newName}
          onChange={e => setNewName(e.target.value)}
          placeholder="Critical Ransomware Containment Playbook"
          onPressEnter={() => void create()}
        />
      </Modal>

      <Drawer title="Node Configuration" open={!!inspector} onClose={() => setInspector(null)} size={450}>
        <Form form={nodeForm} layout="vertical" onFinish={saveNode}>
          <Form.Item name="label" label="Step Name" rules={[{ required: true, whitespace: true }]}>
            <Input disabled={!canWrite} />
          </Form.Item>
          <Form.Item name="config" label="Configuration JSON" rules={[{ required: true }]}>
            <Input.TextArea rows={14} className="mono" disabled={!canWrite} />
          </Form.Item>
          <Space>
            <Button type="primary" htmlType="submit" disabled={!canWrite}>
              Apply Changes
            </Button>
            <Button
              danger
              icon={<DeleteOutlined />}
              disabled={!canWrite}
              onClick={() => {
                setNodes(old => old.filter(n => n.id !== inspector));
                setEdges(old => old.filter(e => e.source !== inspector && e.target !== inspector));
                setDirty(true);
                setInspector(null);
              }}
            >
              Delete Node
            </Button>
          </Space>
        </Form>
      </Drawer>
    </>
  );
}

export default function Workflows() {
  return (
    <ReactFlowProvider>
      <WorkflowEditor />
    </ReactFlowProvider>
  );
}
