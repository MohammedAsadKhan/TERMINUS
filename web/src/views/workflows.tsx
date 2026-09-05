import { useCallback, useEffect, useState } from 'react';
import { Alert, App, Button, Drawer, Form, Input, Modal, Select, Space, Switch, Tag, Tooltip } from 'antd';
import { CheckCircleOutlined, DeleteOutlined, PlusOutlined, SaveOutlined } from '@ant-design/icons';
import { Background, BackgroundVariant, Controls, Handle, MiniMap, Position, ReactFlow, ReactFlowProvider, addEdge, useEdgesState, useNodesState, useReactFlow, type Connection, type Edge, type Node, type NodeProps } from '@xyflow/react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import '@xyflow/react/dist/style.css';
import { api, body } from '../api';
import { useSession } from '../context';
import { EmptyPanel, ErrorPanel, Loading, PageTitle } from '../components';
import type { Agent, Workflow } from '../types';

const palette = [
  { type: 'trigger_wazuh', label: 'Alert received', group: 'TRIGGER', color: 'green', description: 'Start from a Wazuh alert' },
  { type: 'trigger_cron', label: 'Scheduled trigger', group: 'TRIGGER', color: 'green', description: 'Define a recurring schedule' },
  { type: 'condition_severity', label: 'Severity filter', group: 'CONDITION', color: 'amber', description: 'Branch on an alert threshold' },
  { type: 'agent_llm', label: 'AI investigation', group: 'AGENT', color: 'purple', description: 'Assess the available evidence' },
  { type: 'tool_slack', label: 'Slack notification', group: 'OUTPUT', color: 'blue', description: 'Notify the response team' },
  { type: 'tool_jira', label: 'Create ticket', group: 'OUTPUT', color: 'blue', description: 'Describe a ticketing step' },
  { type: 'tool_isolate', label: 'Isolate host', group: 'RESPONSE', color: 'red', description: 'Requires a response connector' },
  { type: 'tool_firewall', label: 'Block address', group: 'RESPONSE', color: 'red', description: 'Requires a perimeter connector' },
];
type FlowNode = Node<{ label: string; kind: string; config: Record<string, unknown> }, 'operation'>;
function OperationNode({ data, selected }: NodeProps<FlowNode>) {
  const meta = palette.find(item => item.type === data.kind);
  return <div className={`operation-node ${meta?.color || 'blue'} ${selected ? 'selected' : ''}`}><Handle type="target" position={Position.Left} /><div className="node-kind"><i />{meta?.group || 'STEP'}</div><strong>{data.label}</strong><small>{meta?.description || data.kind}</small><Handle type="source" position={Position.Right} /></div>;
}
const nodeTypes = { operation: OperationNode };

function WorkflowEditor() {
  const { orgId, detail } = useSession(); const { message, modal } = App.useApp(); const query = useQueryClient(); const flow = useReactFlow<FlowNode>();
  const [params, setParams] = useSearchParams();
  const workflows = useQuery({ queryKey: ['workflows', orgId], queryFn: () => api<Workflow[]>('/workflows', orgId), refetchOnWindowFocus: false });
  const agents = useQuery({ queryKey: ['agents', orgId], queryFn: () => api<Agent[]>('/agents', orgId) });
  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>([]); const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [active, setActive] = useState(''); const [name, setName] = useState(''); const [enabled, setEnabled] = useState(false); const [agent, setAgent] = useState<string | null>(null);
  const [dirty, setDirty] = useState(false); const [busy, setBusy] = useState(false); const [newOpen, setNewOpen] = useState(false); const [newName, setNewName] = useState('');
  const [inspector, setInspector] = useState<string | null>(null); const [nodeForm] = Form.useForm();
  const [validation, setValidation] = useState<{ errors: string[]; summary: string } | null>(null);
  const canWrite = detail?.role === 'admin';
  const requested = params.get('workflow');
  useEffect(() => {
    const selected = workflows.data?.find(w => w.id === requested) || workflows.data?.[0];
    if (!selected || (active === selected.id && dirty)) return;
    setActive(selected.id); setName(selected.name); setEnabled(selected.enabled); setAgent(selected.agent_id);
    setNodes(selected.nodes.map(n => ({ id: n.id, type: 'operation', position: { x: n.x, y: n.y }, data: { label: n.label, kind: n.type, config: n.config } })));
    setEdges(selected.edges.map(edge => ({ ...edge, type: 'smoothstep' }))); setDirty(false); setInspector(null); setValidation(null);
    requestAnimationFrame(() => void flow.fitView({ padding: 0.2, duration: 200 }));
  }, [workflows.data, requested]);
  useEffect(() => {
    const guard = (event: BeforeUnloadEvent) => { if (dirty) event.preventDefault(); };
    window.addEventListener('beforeunload', guard);
    return () => window.removeEventListener('beforeunload', guard);
  }, [dirty]);
  const connect = useCallback((connection: Connection) => { setEdges(old => addEdge({ ...connection, type: 'smoothstep' }, old)); setDirty(true); }, [setEdges]);
  function select(id: string) {
    const change = () => { setDirty(false); setParams({ workflow: id }); };
    if (dirty) modal.confirm({ title: 'Discard unsaved changes?', content: 'Your saved workflow will remain unchanged.', okText: 'Discard changes', onOk: change }); else change();
  }
  async function save(validate = false) {
    if (!active) return;
    setBusy(true);
    const value: Workflow = { id: active, name, enabled, agent_id: agent, nodes: nodes.map(n => ({ id: n.id, type: n.data.kind, label: n.data.label, x: Math.round(n.position.x), y: Math.round(n.position.y), config: n.data.config })), edges: edges.map(e => ({ id: e.id, source: e.source, target: e.target })) };
    try {
      await api(`/workflows/${active}`, orgId, body('PUT', value)); setDirty(false);
      query.setQueryData<Workflow[]>(['workflows', orgId], old => old?.map(w => w.id === active ? value : w));
      if (validate) { const result = await api<{ errors: string[]; summary: string }>(`/workflows/${active}/execute`, orgId, body('POST')); setValidation(result); }
      message.success(validate ? 'Definition validated and saved' : 'Workflow saved');
    } catch (error) { message.error((error as Error).message); } finally { setBusy(false); }
  }
  async function create() {
    if (!newName.trim()) return;
    setBusy(true);
    try { const value = await api<Workflow>('/workflows', orgId, body('POST', { id: `wf-${crypto.randomUUID()}`, name: newName.trim(), enabled: false, nodes: [], edges: [], agent_id: null })); setDirty(false); await query.invalidateQueries({ queryKey: ['workflows', orgId] }); setParams({ workflow: value.id }); setNewOpen(false); setNewName(''); } catch (error) { message.error((error as Error).message); } finally { setBusy(false); }
  }
  function add(type: string) {
    const meta = palette.find(n => n.type === type)!;
    const node: FlowNode = { id: `n-${crypto.randomUUID().slice(0, 8)}`, type: 'operation', position: flow.screenToFlowPosition({ x: window.innerWidth * 0.6, y: window.innerHeight * 0.55 }), data: { label: meta.label, kind: type, config: type === 'condition_severity' ? { threshold: 10 } : {} } };
    setNodes(old => [...old, node]); setDirty(true);
  }
  function inspect(node: FlowNode) { setInspector(node.id); nodeForm.setFieldsValue({ label: node.data.label, config: JSON.stringify(node.data.config, null, 2) }); }
  function saveNode(values: { label: string; config: string }) {
    try { const config: unknown = JSON.parse(values.config); if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('Configuration must be a JSON object.'); setNodes(old => old.map(n => n.id === inspector ? { ...n, data: { ...n.data, label: values.label, config: config as Record<string, unknown> } } : n)); setDirty(true); setInspector(null); } catch (error) { message.error((error as Error).message); }
  }
  function removeWorkflow() { modal.confirm({ title: `Delete “${name}”?`, content: 'This removes the saved workflow definition.', okText: 'Delete workflow', okButtonProps: { danger: true }, onOk: async () => { await api(`/workflows/${active}`, orgId, body('DELETE')); setDirty(false); setActive(''); setParams({}); query.invalidateQueries({ queryKey: ['workflows', orgId] }); } }); }
  return <><PageTitle eyebrow="CONFIGURE / WORKFLOWS" title="Design the response." description="Connect triggers, decisions, and investigation steps in a visual workflow." actions={<Button type="primary" icon={<PlusOutlined />} disabled={!canWrite} onClick={() => setNewOpen(true)}>New workflow</Button>} />
    <ErrorPanel error={workflows.error} retry={() => void workflows.refetch()} />
    {workflows.isPending ? <Loading /> : !workflows.data?.length ? <EmptyPanel title="Start with a blank canvas" description="Create a workflow and connect its first steps." /> : <section className="workflow-panel panel">
      <div className="workflow-toolbar"><Select aria-label="Selected workflow" value={active || undefined} options={workflows.data.map(w => ({ value: w.id, label: w.name }))} onChange={select} style={{ minWidth: 260, maxWidth: 450 }} /><Space><Tag bordered={false}>{dirty ? 'UNSAVED CHANGES' : 'SAVED DEFINITION'}</Tag><Button icon={<CheckCircleOutlined />} disabled={!canWrite} loading={busy} onClick={() => void save(true)}>Validate & save</Button><Button type="primary" icon={<SaveOutlined />} disabled={!canWrite || !dirty} loading={busy} onClick={() => void save()}>Save</Button><Tooltip title="Delete workflow"><Button aria-label="Delete workflow" icon={<DeleteOutlined />} disabled={!canWrite} onClick={removeWorkflow} /></Tooltip></Space></div>
      <div className="workflow-meta"><Input aria-label="Workflow name" value={name} disabled={!canWrite} onChange={event => { setName(event.target.value); setDirty(true); }} /><Select aria-label="Assigned agent" placeholder="No assigned agent" allowClear value={agent || undefined} options={agents.data?.map(a => ({ value: a.id, label: a.name }))} onChange={value => { setAgent(value || null); setDirty(true); }} disabled={!canWrite} /><Tooltip title="Toggle active autonomous execution for this workflow"><Space><Switch size="small" checked={enabled} disabled={!canWrite} onChange={value => { setEnabled(value); setDirty(true); }} /><span className="muted">Enabled definition</span></Space></Tooltip></div>
      <div className="workflow-body"><aside className="node-palette"><div className="eyebrow">ADD A STEP</div>{palette.map(item => <button disabled={!canWrite} className={`palette-item ${item.color}`} key={item.type} onClick={() => add(item.type)}><span className="node-kind">{item.group}</span><strong>{item.label}</strong><PlusOutlined /></button>)}</aside><div className="flow-canvas" data-testid="workflow-canvas"><ReactFlow<FlowNode> nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodesChange={changes => { onNodesChange(changes); if (changes.some(c => c.type !== 'select' && c.type !== 'dimensions')) setDirty(true); }} onEdgesChange={changes => { onEdgesChange(changes); if (changes.some(c => c.type !== 'select')) setDirty(true); }} onConnect={connect} onNodeDoubleClick={(_, node) => inspect(node)} onNodeClick={(_, node) => inspect(node)} nodesDraggable={canWrite} nodesConnectable={canWrite} edgesReconnectable={canWrite} deleteKeyCode={canWrite ? ['Backspace', 'Delete'] : null} fitView minZoom={0.15} maxZoom={2} colorMode="dark" defaultEdgeOptions={{ type: 'smoothstep', style: { stroke: '#759988', strokeWidth: 1.7 } }}><Background variant={BackgroundVariant.Dots} gap={22} size={1} color="#35423d" /><Controls /><MiniMap pannable zoomable nodeColor="#4e725b" maskColor="rgba(10,18,14,.7)" /></ReactFlow></div></div>
      <div className="workflow-footer"><span>{nodes.length} nodes · {edges.length} connections</span><span>Click a node to inspect · Drag handles to connect · Scroll to zoom</span></div>
    </section>}
    <Alert className="context-alert" type={validation?.errors.length ? 'error' : 'info'} showIcon title={validation?.errors.length ? 'Validation needs attention' : 'Workflow design & validation'} description={validation ? validation.errors.join('; ') || validation.summary : 'Validate DAG node reachability, cycle prevention, and parameter schemas for automated execution.'} />
    <Modal title="Create a workflow" open={newOpen} onCancel={() => setNewOpen(false)} onOk={() => void create()} okText="Create workflow" confirmLoading={busy} okButtonProps={{ disabled: !newName.trim() }}><label className="field-label" htmlFor="workflow-name">Workflow name</label><Input id="workflow-name" value={newName} onChange={e => setNewName(e.target.value)} placeholder="Suspicious sign-in investigation" onPressEnter={() => void create()} /></Modal>
    <Drawer title="Node configuration" open={!!inspector} onClose={() => setInspector(null)} size={430}><Form form={nodeForm} layout="vertical" onFinish={saveNode}><Form.Item name="label" label="Step name" rules={[{ required: true, whitespace: true }]}><Input disabled={!canWrite} /></Form.Item><Form.Item name="config" label="Configuration JSON" rules={[{ required: true }]}><Input.TextArea rows={12} className="mono" disabled={!canWrite} /></Form.Item><Space><Button type="primary" htmlType="submit" disabled={!canWrite}>Apply changes</Button><Button danger icon={<DeleteOutlined />} disabled={!canWrite} onClick={() => { setNodes(old => old.filter(n => n.id !== inspector)); setEdges(old => old.filter(e => e.source !== inspector && e.target !== inspector)); setDirty(true); setInspector(null); }}>Delete node</Button></Space></Form></Drawer>
  </>;
}
export default function Workflows() { return <ReactFlowProvider><WorkflowEditor /></ReactFlowProvider>; }
