// File: agents.tsx
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Present saved agent definitions and recorded orchestration activity without implying live execution.

import { useEffect, useState } from 'react';
import { Alert, App, Button, Dropdown, Form, Input, Modal, Select, Space, Tabs, Tag } from 'antd';
import { ApartmentOutlined, DeleteOutlined, EditOutlined, MoreOutlined, PlusOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { api, body } from '../api';
import { useSession } from '../context';
import { date, EmptyPanel, ErrorPanel, Loading, PageTitle, Status } from '../components';
import type { Agent } from '../types';
import AgentActivity from './agent-activity';

// Editable agent fields. A create request omits status; updates send it.
type AgentFields = Pick<Agent, 'name' | 'role_description' | 'master_prompt' | 'status'>;
// Tabs of the Agents page; the last one used is remembered per organization in this browser.
type AgentsTab = 'activity' | 'configurations';

// Keyed by organization so switching organizations remounts the workspace and drops any open editor.
export default function Agents() {
  const { orgId } = useSession();
  return <AgentsWorkspace key={orgId} />;
}

// Recorded activity and saved agent definitions for the signed-in organization. Definitions are configuration only:
// they do not start agents or prove execution. Editing controls are enabled only for organization admins.
function AgentsWorkspace() {
  const { orgId, detail } = useSession();
  const { message, modal } = App.useApp();
  const query = useQueryClient();
  const [activeTab, setActiveTab] = useState<AgentsTab>('activity');
  const [editing, setEditing] = useState<Agent | 'new' | null>(null);
  const [form] = Form.useForm<AgentFields>();
  // Definitions load only while the Saved configurations tab is open.
  const agents = useQuery({ queryKey: ['agents', orgId], queryFn: () => api<Agent[]>('/agents', orgId), enabled: activeTab === 'configurations' });
  const canWrite = detail?.role === 'admin';

  // Restore the tab last used in this organization and close any open editor when the organization changes.
  useEffect(() => {
    const saved = localStorage.getItem(`terminus-agent-view-${orgId}`);
    setActiveTab(saved === 'configurations' ? 'configurations' : 'activity');
    setEditing(null);
  }, [orgId]);

  // Creating sends only the name, role and prompt; editing sends every form field, including status.
  const save = useMutation({
    mutationFn: (values: AgentFields) => editing === 'new'
      ? api('/agents', orgId, body('POST', { name: values.name, role_description: values.role_description, master_prompt: values.master_prompt }))
      : api(`/agents/${editing!.id}`, orgId, body('PATCH', values)),
    onSuccess: () => {
      query.invalidateQueries({ queryKey: ['agents', orgId] });
      setEditing(null);
      message.success('Agent configuration saved');
    },
  });
  // Status change from the card dropdown.
  const change = useMutation({
    mutationFn: ({ agent, status }: { agent: Agent; status: string }) => api(`/agents/${agent.id}`, orgId, body('PATCH', { status })),
    onSuccess: () => {
      query.invalidateQueries({ queryKey: ['agents', orgId] });
      message.success('Configuration updated');
    },
    onError: error => message.error(error.message),
  });

  function edit(agent: Agent | 'new') {
    save.reset();
    setEditing(agent);
    form.setFieldsValue(agent === 'new' ? { name: '', role_description: '', master_prompt: '', status: 'active' } : agent);
  }

  // On failure the error is shown and rethrown so the confirmation dialog stays open.
  function remove(agent: Agent) {
    modal.confirm({
      title: `Delete ${agent.name}?`,
      content: 'An agent referenced by a workflow must be removed from that workflow first.',
      okText: 'Delete configuration',
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          await api(`/agents/${agent.id}`, orgId, body('DELETE'));
          query.invalidateQueries({ queryKey: ['agents', orgId] });
        } catch (error) {
          message.error((error as Error).message);
          throw error;
        }
      },
    });
  }

  function selectTab(key: string) {
    const tab = key === 'configurations' ? 'configurations' : 'activity';
    setActiveTab(tab);
    localStorage.setItem(`terminus-agent-view-${orgId}`, tab);
  }

  // Content of the Saved configurations tab.
  const configurations = <>
    <Alert className="context-alert" type="info" showIcon title="Agent Definition Workspace" description="Manage saved agent names, role descriptions, system prompts, and status labels used by workflow definitions. These records do not start agents or prove execution." />
    <ErrorPanel error={agents.error} retry={() => void agents.refetch()} />
    {agents.isPending ? <Loading /> : agents.data?.length ? <div className="agent-grid">{agents.data.map((agent, index) => <article className="panel agent-card" key={agent.id}>
      <div className="agent-top"><span className="agent-icon"><ThunderboltOutlined /></span><Tag bordered={false} className="mono">AGENT {String(index + 1).padStart(2, '0')}</Tag><Dropdown menu={{ items: [{ key: 'edit', label: 'Edit configuration', icon: <EditOutlined />, disabled: !canWrite, onClick: () => edit(agent) }, { key: 'delete', label: 'Delete', danger: true, icon: <DeleteOutlined />, disabled: !canWrite, onClick: () => remove(agent) }] }}><Button type="text" aria-label={`Actions for ${agent.name}`} icon={<MoreOutlined />} /></Dropdown></div>
      <h2>{agent.name}</h2><p className="agent-description">{agent.role_description}</p><Status value={agent.status} /><div className="prompt-preview"><div className="eyebrow">SYSTEM PROMPT</div><p>{agent.master_prompt}</p></div>
      <div className="agent-footer"><span className="muted">Created {date(agent.created_at)}</span><Space><Select aria-label={`Status of ${agent.name}`} size="small" value={agent.status} disabled={!canWrite || change.isPending} options={['active', 'paused', 'maintenance'].map(value => ({ value, label: value }))} onChange={status => change.mutate({ agent, status })} /><Button size="small" disabled={!canWrite} onClick={() => edit(agent)}>Edit</Button></Space></div>
    </article>)}</div> : <EmptyPanel title="No agent definitions" description="Create a definition to use in your workflow design." />}
    <div className="related-link"><ApartmentOutlined /><div><strong>Connect the pieces.</strong><p>Use agent definitions to design a workflow.</p></div><Link to="/workflows">Open workflow editor →</Link></div>
  </>;

  return <>
    <PageTitle
      eyebrow="OPERATE / AGENTS"
      title={activeTab === 'activity' ? 'Inspect recorded orchestration activity.' : 'Maintain agent definitions.'}
      description={activeTab === 'activity' ? 'Review saved orchestration tasks, run details, evidence links, and specialist definitions. Status values come from stored records.' : "Manage saved agent names, role descriptions, and system prompts for your organization's workflow definitions."}
      actions={activeTab === 'configurations' ? <Button type="primary" icon={<PlusOutlined />} disabled={!canWrite} onClick={() => edit('new')}>New agent</Button> : undefined}
    />
    <Tabs
      activeKey={activeTab}
      onChange={selectTab}
      items={[
        { key: 'activity', label: 'Activity', children: <AgentActivity key={orgId} /> },
        { key: 'configurations', label: 'Saved configurations', children: configurations },
      ]}
    />
    <Modal title={editing === 'new' ? 'New agent definition' : 'Edit agent definition'} open={!!editing} onCancel={() => setEditing(null)} onOk={() => form.submit()} okText="Save configuration" confirmLoading={save.isPending} width={650}>
      <Form form={form} layout="vertical" onFinish={values => save.mutate(values)} requiredMark={false}><Form.Item name="name" label="Name" rules={[{ required: true, whitespace: true, max: 100 }]}><Input placeholder="Forensic investigator" /></Form.Item><Form.Item name="role_description" label="Role" rules={[{ required: true, whitespace: true }]}><Input.TextArea rows={2} placeholder="What this agent is responsible for" /></Form.Item><Form.Item name="master_prompt" label="System prompt" rules={[{ required: true, whitespace: true }]}><Input.TextArea rows={8} placeholder="Describe the evidence to assess and the expected output." /></Form.Item>{editing !== 'new' && <Form.Item name="status" label="Status"><Select options={['active', 'paused', 'maintenance'].map(value => ({ value, label: value }))} /></Form.Item>}{save.error && <Alert type="error" title={save.error.message} />}</Form>
    </Modal>
  </>;
}
