import { lazy, Suspense, useEffect, useState } from 'react';
import { App, Alert, Avatar, Button, Dropdown, Form, Input, Menu, Modal, Select, Space, Spin, Tag, Tooltip } from 'antd';
import { ApartmentOutlined, ArrowRightOutlined, DeploymentUnitOutlined, FileTextOutlined, GoldOutlined, LogoutOutlined, MenuOutlined, PlusOutlined, SafetyCertificateOutlined, SettingOutlined, ThunderboltOutlined, UserOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { api, body } from './api';
import { SessionContext } from './context';
import { ErrorPanel, Loading } from './components';
import type { Organization, OrgDetail, SystemInfo, User } from './types';

const Operations = lazy(() => import('./views/operations'));
const Reports = lazy(() => import('./views/reports'));
const Agents = lazy(() => import('./views/agents'));
const Workflows = lazy(() => import('./views/workflows'));
const Settings = lazy(() => import('./views/settings'));

function Brand() { return <div className="brand"><span className="brand-mark"><i /><i /><i /></span><span>TERMINUS<small>SECURITY OPERATIONS</small></span></div>; }

function Login() {
  const [register, setRegister] = useState(false);
  const query = useQueryClient();
  const mutation = useMutation({ mutationFn: async (values: { email: string; password: string; display_name?: string }) => {
    if (register) await api('/auth/register', undefined, body('POST', values));
    return api('/auth/login', undefined, body('POST', { email: values.email, password: values.password }));
  }, onSuccess: () => query.invalidateQueries({ queryKey: ['me'] }) });
  return <div className="login-screen"><aside className="login-story"><Brand /><div className="login-copy"><div className="eyebrow">FROM SIGNAL TO DECISION</div><h1>Clarity at every<br />stage of response.</h1><p>Investigate security alerts, review the evidence, and coordinate your next move from one workspace.</p><div className="pipeline-art"><span>01<small>INGEST</small></span><b /><span>02<small>INVESTIGATE</small></span><b /><span>03<small>RESPOND</small></span></div></div><span className="login-foot">Your evidence. Your decisions.</span></aside>
    <main className="login-form"><div className="login-box"><Tag bordered={false}>ANALYST WORKSPACE</Tag><h2>{register ? 'Create your account' : 'Welcome back'}</h2><p>{register ? 'Create an identity, then set up your organization.' : 'Sign in to your security operations workspace.'}</p>
      <Form layout="vertical" onFinish={values => mutation.mutate(values)} requiredMark={false} key={String(register)}>
        {register && <Form.Item name="display_name" label="Full name" rules={[{ required: true, whitespace: true }]}><Input autoComplete="name" placeholder="Alex Morgan" /></Form.Item>}
        <Form.Item name="email" label="Email address" rules={[{ required: true, type: 'email' }]}><Input autoComplete="email" placeholder="you@organization.com" /></Form.Item>
        <Form.Item name="password" label="Password" rules={[{ required: true, min: register ? 8 : 1 }]}><Input.Password autoComplete={register ? 'new-password' : 'current-password'} placeholder={register ? 'At least 8 characters' : 'Enter your password'} /></Form.Item>
        {mutation.error && <Alert className="form-alert" type="error" showIcon title={mutation.error.message} />}
        <Button type="primary" htmlType="submit" block loading={mutation.isPending} icon={<ArrowRightOutlined />} iconPlacement="end">{register ? 'Create account' : 'Sign in'}</Button>
      </Form><p className="login-toggle">{register ? 'Already have an account?' : 'New to this installation?'} <Button type="link" onClick={() => { setRegister(!register); mutation.reset(); }}>{register ? 'Sign in' : 'Create an account'}</Button></p>
      <div className="quiet-note"><SafetyCertificateOutlined /> Sessions stay in a protected browser cookie.</div>
    </div></main></div>;
}

const nav = [
  { key: '/', icon: <GoldOutlined />, label: 'Overview' },
  { key: '/incidents', icon: <SafetyCertificateOutlined />, label: 'Incidents' },
  { key: '/reports', icon: <FileTextOutlined />, label: 'Reports' },
  { type: 'divider' as const },
  { key: '/agents', icon: <ThunderboltOutlined />, label: 'Agents' },
  { key: '/workflows', icon: <ApartmentOutlined />, label: 'Workflows' },
  { key: '/integrations', icon: <DeploymentUnitOutlined />, label: 'Sources & integrations' },
  { type: 'divider' as const },
  { key: '/organization', icon: <UserOutlined />, label: 'Organization' },
  { key: '/settings', icon: <SettingOutlined />, label: 'Settings & license' },
];

export function ConsoleApp() {
  const query = useQueryClient(); const { message, modal } = App.useApp(); const navigate = useNavigate(); const location = useLocation();
  const [orgId, setOrgId] = useState(''); const [createOpen, setCreateOpen] = useState(false); const [mobileOpen, setMobileOpen] = useState(false);
  const user = useQuery({ queryKey: ['me'], queryFn: () => api<User>('/auth/me'), retry: false, staleTime: 60000 });
  const orgs = useQuery({ queryKey: ['orgs', user.data?.user_id], queryFn: () => api<Organization[]>('/orgs'), enabled: !!user.data });
  const detail = useQuery({ queryKey: ['org', orgId], queryFn: () => api<OrgDetail>('/orgs/current', orgId), enabled: !!orgId && !!user.data });
  const system = useQuery({ queryKey: ['system'], queryFn: () => api<SystemInfo>('/system'), enabled: !!user.data, refetchInterval: 30000 });
  useEffect(() => {
    if (!user.data || !orgs.data) return;
    if (orgs.data.some(org => org.org_id === orgId)) return;
    const saved = localStorage.getItem(`terminus-org-${user.data.user_id}`);
    setOrgId(orgs.data.find(org => org.org_id === saved)?.org_id || orgs.data[0]?.org_id || '');
  }, [orgs.data, orgId, user.data]);
  useEffect(() => {
    const expire = () => { query.clear(); setOrgId(''); void user.refetch(); };
    window.addEventListener('session-expired', expire);
    return () => window.removeEventListener('session-expired', expire);
  }, [query, user.refetch]);
  const create = useMutation({ mutationFn: (values: { name: string }) => api<Organization>('/orgs', undefined, body('POST', values)), onSuccess: async org => {
    await query.invalidateQueries({ queryKey: ['orgs'] }); setOrgId(org.org_id); setCreateOpen(false); message.success('Organization created');
  } });
  async function logout() {
    try { await api('/auth/logout', undefined, body('POST')); } catch { /* Local session state must be cleared even if offline. */ }
    query.clear(); query.setQueryData(['me'], null); setOrgId(''); navigate('/');
  }
  function switchOrg(value: string) {
    query.removeQueries({ predicate: item => !['me', 'orgs', 'system'].includes(String(item.queryKey[0])) });
    setOrgId(value); localStorage.setItem(`terminus-org-${user.data!.user_id}`, value); navigate('/');
  }
  if (user.isPending) return <div className="boot"><Brand /><Spin size="large" /></div>;
  if (!user.data) return <Login />;
  const organization = orgs.data?.find(org => org.org_id === orgId);
  const selected = '/' + location.pathname.split('/')[1];
  const currentPage = nav.find(item => 'key' in item && item.key === selected)?.label || 'Workspace';
  const newOrgForm = <Form layout="vertical" onFinish={values => create.mutate(values)} requiredMark={false}><Form.Item name="name" label="Organization name" rules={[{ required: true, whitespace: true, max: 100 }]}><Input placeholder="Acme Security" autoFocus /></Form.Item>{create.error && <Alert type="error" title={create.error.message} className="form-alert" />}<Button type="primary" htmlType="submit" loading={create.isPending} block>Create organization</Button></Form>;
  return <SessionContext.Provider value={{ user: user.data, orgId, detail: detail.data, system: system.data }}><div className="workspace">
    {mobileOpen && <div className="sidebar-scrim" onClick={() => setMobileOpen(false)} />}
    <aside className={`sidebar ${mobileOpen ? 'open' : ''}`}><Link to="/" aria-label="Terminus overview"><Brand /></Link><div className="workspace-label">WORKSPACE</div><div className="org-switch"><Select aria-label="Active organization" value={orgId || undefined} placeholder="Select organization" options={orgs.data?.map(org => ({ value: org.org_id, label: org.name }))} onChange={switchOrg} /><Tooltip title="Create organization"><Button type="text" aria-label="Create organization" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)} /></Tooltip></div>
      <Menu mode="inline" selectedKeys={[selected]} items={nav} onClick={({ key }) => { navigate(key); setMobileOpen(false); }} />
      <div className="sidebar-bottom"><div className="environment-note"><span className="status-dot" />{system.data?.llm_mode === 'scripted' ? 'Development instance' : 'Connected instance'}<small>In-memory storage · resets on restart</small></div><Dropdown menu={{ items: [{ key: 'account', label: 'Copy my user ID', onClick: () => { void navigator.clipboard.writeText(user.data.user_id); message.success('User ID copied'); } }, { key: 'logout', label: 'Sign out', icon: <LogoutOutlined />, onClick: () => void logout() }] }} trigger={['click']}><button className="user-menu"><Avatar shape="square" size={32}>{user.data.display_name[0]?.toUpperCase()}</Avatar><span>{user.data.display_name}<small>{detail.data?.role || 'Account'}</small></span><span className="user-chevron">⌄</span></button></Dropdown></div>
    </aside><main className="workspace-main"><header className="topbar"><Space><Button className="mobile-menu" type="text" aria-label="Open navigation" icon={<MenuOutlined />} onClick={() => setMobileOpen(true)} /><span className="breadcrumb-org">{organization?.name || 'Welcome'}</span><span className="breadcrumb-slash">/</span><strong>{currentPage}</strong></Space><Space size={16}><Tooltip title={system.isError ? 'Cannot reach the API' : 'API status is checked every 30 seconds. Incident views refresh every 5 seconds.'}><span className="connection"><i className={`status-dot ${system.isError ? 'error' : ''}`} />{system.isError ? 'Connection unavailable' : 'HTTP polling'}</span></Tooltip><Tag bordered={false}>{system.data?.llm_mode === 'scripted' ? 'SCRIPTED AI' : 'REMOTE AI'}</Tag></Space></header>
      <div className="content"><ErrorPanel error={orgs.error} retry={() => void orgs.refetch()} />
        {orgs.isPending ? <Loading /> : !orgId ? <div className="onboarding panel"><span className="eyebrow">YOUR FIRST WORKSPACE</span><h1>Make room for your team.</h1><p>Organizations separate your incidents, reports, and configuration. Create one to start investigating.</p>{newOrgForm}</div> : detail.isError ? <ErrorPanel error={detail.error} retry={() => { void orgs.refetch(); void detail.refetch(); }} /> : <Suspense fallback={<Loading />}><Routes>
          <Route path="/" element={<Operations />} /><Route path="/incidents" element={<Operations incidentView />} /><Route path="/incidents/:ticketId" element={<Operations incidentView />} />
          <Route path="/reports" element={<Reports />} /><Route path="/agents" element={<Agents />} /><Route path="/workflows" element={<Workflows />} />
          <Route path="/integrations" element={<Settings section="integrations" />} /><Route path="/organization" element={<Settings section="organization" />} /><Route path="/settings" element={<Settings section="settings" />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes></Suspense>}
      </div><footer className="workspace-footer"><span>TERMINUS / ANALYST CONSOLE</span><button onClick={() => modal.info({ title: 'About this installation', content: 'This console uses the existing in-memory API. Agent and workflow definitions are editable; workflow validation does not execute tools. Live containment, SSO and durable job processing require the enterprise backend milestones.' })}>Build 0.2 · Capabilities</button></footer>
    </main><Modal title="Create an organization" open={createOpen} onCancel={() => { setCreateOpen(false); create.reset(); }} footer={null} destroyOnHidden>{newOrgForm}</Modal>
  </div></SessionContext.Provider>;
}
