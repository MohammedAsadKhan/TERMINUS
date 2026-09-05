import { useState } from 'react';
import { Alert, App, Button, Dropdown, Form, Input, Modal, Select, Space, Tag } from 'antd';
import { ApartmentOutlined, DeleteOutlined, EditOutlined, MoreOutlined, PlusOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api, body } from '../api';
import { useSession } from '../context';
import { date, EmptyPanel, ErrorPanel, Loading, PageTitle, Status } from '../components';
import type { Agent } from '../types';

type AgentFields = Pick<Agent, 'name' | 'role_description' | 'master_prompt' | 'status'>;
export default function Agents() {
  const { orgId, detail } = useSession(); const { message, modal } = App.useApp(); const query = useQueryClient();
  const [editing, setEditing] = useState<Agent | 'new' | null>(null); const [form] = Form.useForm<AgentFields>();
  const agents = useQuery({ queryKey: ['agents', orgId], queryFn: () => api<Agent[]>('/agents', orgId) });
  const canWrite = detail?.role === 'admin';
  const save = useMutation({ mutationFn: (values: AgentFields) => editing === 'new'
    ? api('/agents', orgId, body('POST', { name: values.name, role_description: values.role_description, master_prompt: values.master_prompt }))
    : api(`/agents/${editing!.id}`, orgId, body('PATCH', values)), onSuccess: () => { query.invalidateQueries({ queryKey: ['agents', orgId] }); setEditing(null); message.success('Agent configuration saved'); } });
  const change = useMutation({ mutationFn: ({ agent, status }: { agent: Agent; status: string }) => api(`/agents/${agent.id}`, orgId, body('PATCH', { status })), onSuccess: () => { query.invalidateQueries({ queryKey: ['agents', orgId] }); message.success('Configuration updated'); }, onError: error => message.error(error.message) });
  function edit(agent: Agent | 'new') { save.reset(); setEditing(agent); form.setFieldsValue(agent === 'new' ? { name: '', role_description: '', master_prompt: '', status: 'active' } : agent); }
  function remove(agent: Agent) { modal.confirm({ title: `Delete ${agent.name}?`, content: 'An agent referenced by a workflow must be removed from that workflow first.', okText: 'Delete configuration', okButtonProps: { danger: true }, onOk: async () => { try { await api(`/agents/${agent.id}`, orgId, body('DELETE')); query.invalidateQueries({ queryKey: ['agents', orgId] }); } catch (error) { message.error((error as Error).message); throw error; } } }); }
  return <><PageTitle eyebrow="CONFIGURE / AGENTS" title="Define your investigation team." description="Manage agent descriptions and prompts for your organization's workflow definitions." actions={<Button type="primary" icon={<PlusOutlined />} disabled={!canWrite} onClick={() => edit('new')}>New agent</Button>} />
    <Alert className="context-alert" type="info" showIcon title="Agent Configuration Workspace" description="Manage specialized SOC subagent personas, prompt templates, and execution parameters utilized across multi-stage investigation workflows." />
    <ErrorPanel error={agents.error} retry={() => void agents.refetch()} />{agents.isPending ? <Loading /> : agents.data?.length ? <div className="agent-grid">{agents.data.map((agent, index) => <article className="panel agent-card" key={agent.id}>
      <div className="agent-top"><span className="agent-icon"><ThunderboltOutlined /></span><Tag bordered={false} className="mono">AGENT {String(index + 1).padStart(2, '0')}</Tag><Dropdown menu={{ items: [{ key: 'edit', label: 'Edit configuration', icon: <EditOutlined />, disabled: !canWrite, onClick: () => edit(agent) }, { key: 'delete', label: 'Delete', danger: true, icon: <DeleteOutlined />, disabled: !canWrite, onClick: () => remove(agent) }] }}><Button type="text" aria-label={`Actions for ${agent.name}`} icon={<MoreOutlined />} /></Dropdown></div>
      <h2>{agent.name}</h2><p className="agent-description">{agent.role_description}</p><Status value={agent.status} /><div className="prompt-preview"><div className="eyebrow">SYSTEM PROMPT</div><p>{agent.master_prompt}</p></div>
      <div className="agent-footer"><span className="muted">Created {date(agent.created_at)}</span><Space><Select aria-label={`Status of ${agent.name}`} size="small" value={agent.status} disabled={!canWrite || change.isPending} options={['active', 'paused', 'maintenance'].map(value => ({ value, label: value }))} onChange={status => change.mutate({ agent, status })} /><Button size="small" disabled={!canWrite} onClick={() => edit(agent)}>Edit</Button></Space></div>
    </article>)}</div> : <EmptyPanel title="No agent definitions" description="Create a definition to use in your workflow design." />}
    <div className="related-link"><ApartmentOutlined /><div><strong>Connect the pieces.</strong><p>Use agent definitions to design a workflow.</p></div><Link to="/workflows">Open workflow editor →</Link></div>
    <Modal title={editing === 'new' ? 'New agent definition' : 'Edit agent definition'} open={!!editing} onCancel={() => setEditing(null)} onOk={() => form.submit()} okText="Save configuration" confirmLoading={save.isPending} width={650}>
      <Form form={form} layout="vertical" onFinish={values => save.mutate(values)} requiredMark={false}><Form.Item name="name" label="Name" rules={[{ required: true, whitespace: true, max: 100 }]}><Input placeholder="Forensic investigator" /></Form.Item><Form.Item name="role_description" label="Role" rules={[{ required: true, whitespace: true }]}><Input.TextArea rows={2} placeholder="What this agent is responsible for" /></Form.Item><Form.Item name="master_prompt" label="System prompt" rules={[{ required: true, whitespace: true }]}><Input.TextArea rows={8} placeholder="Describe the evidence to assess and the expected output." /></Form.Item>{editing !== 'new' && <Form.Item name="status" label="Status"><Select options={['active', 'paused', 'maintenance'].map(value => ({ value, label: value }))} /></Form.Item>}{save.error && <Alert type="error" title={save.error.message} />}</Form>
    </Modal></>;
}
