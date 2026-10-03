import { lazy, Suspense, useEffect, useState } from 'react';
import { App, Alert, Avatar, Button, Dropdown, Form, Input, Modal, Spin, Tag } from 'antd';
import { ApartmentOutlined, ArrowRightOutlined, CheckOutlined, CloudOutlined, CodeOutlined, DashboardOutlined, DatabaseOutlined, DesktopOutlined, DownOutlined, FileTextOutlined, GlobalOutlined, LogoutOutlined, MenuOutlined, MessageOutlined, PlusOutlined, SafetyCertificateOutlined, SettingOutlined, ThunderboltOutlined, UserOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import { api, body } from './api';
import { SessionContext } from './context';
import { useTheme } from './theme';
import { ASSET_KINDS, type Asset } from './asset-types';
import { ErrorPanel, Loading } from './components';
import { CopilotPage, CopilotProvider } from './copilot-ui';
import type { Organization, OrgDetail, SystemInfo, User } from './types';
import terminusLogo from './assets/terminus-logo.png';

const Operations = lazy(() => import('./views/workbench'));
const Reports = lazy(() => import('./views/reports'));
const Agents = lazy(() => import('./views/agents'));
const Workflows = lazy(() => import('./views/workflows'));
const Settings = lazy(() => import('./views/settings'));
const Assets = lazy(() => import('./views/assets'));

function Brand() {
  return (
    <div className="brand brand-real-logo">
      <img src={terminusLogo} alt="TERMINUS." className="brand-logo-img" />
    </div>
  );
}

function Login() {
  const [register, setRegister] = useState(false);
  const query = useQueryClient();
  const mutation = useMutation({
    mutationFn: async (values: { email: string; password: string; display_name?: string }) => {
      if (register) await api('/auth/register', undefined, body('POST', values));
      return api('/auth/login', undefined, body('POST', { email: values.email, password: values.password }));
    },
    onSuccess: () => query.invalidateQueries({ queryKey: ['me'] }),
  });
  return (
    <div className="login-screen">
      <aside className="login-story">
        <Brand />
        <div className="login-copy">
          <div className="eyebrow">THE ANALYST WORKSPACE</div>
          <h1>See the signal.<br />Own the response.</h1>
          <p>Bring investigations, evidence, automation, and the people behind them into one focused security workspace.</p>
          <div className="login-steps"><span>01&nbsp; Detect</span><span>02&nbsp; Investigate</span><span>03&nbsp; Respond</span></div>
        </div>
      </aside>
      <main className="login-form">
        <div className="login-box">
          <Tag bordered={false}>SECURE ACCESS</Tag>
          <h2>{register ? 'Create your account' : 'Welcome back'}</h2>
          <p className="login-intro">{register ? 'Set up your analyst identity to begin.' : 'Sign in to continue to your operations center.'}</p>
          <Form layout="vertical" onFinish={values => mutation.mutate(values)} requiredMark={false} key={String(register)}>
            {register && <Form.Item name="display_name" label="Full name" rules={[{ required: true, whitespace: true }]}><Input autoComplete="name" placeholder="Alex Morgan" /></Form.Item>}
            <Form.Item name="email" label="Email address" rules={[{ required: true, type: 'email' }]}><Input autoComplete="email" placeholder="you@organization.com" /></Form.Item>
            <Form.Item name="password" label="Password" rules={[{ required: true, min: register ? 8 : 1 }]}><Input.Password autoComplete={register ? 'new-password' : 'current-password'} placeholder={register ? 'At least 8 characters' : 'Enter your password'} /></Form.Item>
            {mutation.error && <Alert className="form-alert" type="error" showIcon title={mutation.error.message} />}
            <Button type="primary" htmlType="submit" block loading={mutation.isPending} icon={<ArrowRightOutlined />}>{register ? 'Create account' : 'Sign in'}</Button>
          </Form>
          <p className="login-toggle">
            {register ? 'Already have an account?' : 'New to this terminal?'} <Button type="link" onClick={() => { setRegister(!register); mutation.reset(); }}>{register ? 'Sign in' : 'Create an account'}</Button>
          </p>
          <div className="quiet-note"><SafetyCertificateOutlined /> Protected session · Role based access</div>
        </div>
      </main>
    </div>
  );
}

export function ConsoleApp() {
  const { themeId, setThemeId, availableThemes } = useTheme();
  const query = useQueryClient(); const { message } = App.useApp(); const navigate = useNavigate(); const location = useLocation();
  const [orgId, setOrgId] = useState(''); const [createOpen, setCreateOpen] = useState(false);
  const [navOpen, setNavOpen] = useState(false);

  const user = useQuery({ queryKey: ['me'], queryFn: () => api<User>('/auth/me'), retry: false, staleTime: 60000 });
  const orgs = useQuery({ queryKey: ['orgs', user.data?.user_id], queryFn: () => api<Organization[]>('/orgs'), enabled: !!user.data });
  const detail = useQuery({ queryKey: ['org', orgId], queryFn: () => api<OrgDetail>('/orgs/current', orgId), enabled: !!orgId && !!user.data });
  const system = useQuery({ queryKey: ['system'], queryFn: () => api<SystemInfo>('/system'), enabled: !!user.data, refetchInterval: 30000 });
  const assets = useQuery({ queryKey: ['assets', orgId], queryFn: () => api<Asset[]>('/assets', orgId), enabled: !!user.data && !!orgId });

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

  const create = useMutation({
    mutationFn: (values: { name: string }) => api<Organization>('/orgs', undefined, body('POST', values)),
    onSuccess: async org => {
      await query.invalidateQueries({ queryKey: ['orgs'] });
      setOrgId(org.org_id);
      setCreateOpen(false);
      message.success('Organization created');
    },
  });

  async function logout() {
    try { await api('/auth/logout', undefined, body('POST')); } catch { }
    query.clear();
    query.setQueryData(['me'], null);
    setOrgId('');
    navigate('/');
  }

  function switchOrg(value: string) {
    query.removeQueries({ predicate: item => !['me', 'orgs', 'system'].includes(String(item.queryKey[0])) });
    setOrgId(value);
    localStorage.setItem(`terminus-org-${user.data!.user_id}`, value);
    navigate('/');
  }

  if (user.isPending) return <div className="boot"><Brand /><Spin size="large" /></div>;
  if (!user.data) return <Login />;

  const currentPath = '/' + location.pathname.split('/')[1];
  const activePath = currentPath === '/assets' ? location.pathname : currentPath;
  const assetIcons = [<CodeOutlined />, <DatabaseOutlined />, <CloudOutlined />, <DesktopOutlined />, <GlobalOutlined />, <DesktopOutlined />];
  const navigation = [
    { label: 'OPERATIONS', items: [
      { key: '/', label: 'Overview', icon: <DashboardOutlined /> },
      { key: '/incidents', label: 'Incidents', icon: <SafetyCertificateOutlined /> },
      { key: '/copilot', label: 'Copilot', icon: <MessageOutlined /> },
      { key: '/reports', label: 'Reports', icon: <FileTextOutlined /> },
    ] },
    { label: 'ASSETS', items: ASSET_KINDS.map((category, index) => ({ key: `/assets/${category.kind}`, label: category.label, icon: assetIcons[index], count: assets.data ? assets.data.filter(asset => asset.kind === category.kind).length : undefined })) },
    { label: 'AUTOMATION', items: [
      { key: '/agents', label: 'Agents', icon: <ThunderboltOutlined /> },
      { key: '/workflows', label: 'Workflows', icon: <ApartmentOutlined /> },
    ] },
    { label: 'WORKSPACE', items: [
      { key: '/organization', label: 'Organization', icon: <UserOutlined /> },
      { key: '/settings', label: 'Settings', icon: <SettingOutlined /> },
    ] },
  ];
  const currentPage = navigation.flatMap(group => group.items).find(item => item.key === activePath)?.label || 'Overview';

    const currentOrg = orgs.data?.find(o => o.org_id === orgId)?.name || detail.data?.organization.name || 'Workspace';

    return (
    <SessionContext.Provider value={{ user: user.data, orgId, detail: detail.data, system: system.data }}>
      <CopilotProvider orgId={orgId}>
      <div className="hud-layout workspace-layout">
        <a className="skip-link" href="#workspace-content">Skip to content</a>
        {navOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setNavOpen(false)} />}
        <aside className={`console-sidebar ${navOpen ? 'open' : ''}`} aria-label="Workspace navigation">
          <button className="sidebar-brand" onClick={() => { navigate('/'); setNavOpen(false); }} aria-label="Terminus overview"><Brand /></button>
          <div className="sidebar-workspace"><span className="sidebar-workspace-label">Security workspace</span><strong title={currentOrg}>{currentOrg}</strong></div>
          <nav className="sidebar-nav" aria-label="Main navigation">
            {navigation.map(group => <div className="nav-group" key={group.label}>
              <div className="nav-group-label">{group.label}</div>
              {group.items.map(item => <button key={item.key} type="button" className={`nav-item ${activePath === item.key ? 'active' : ''}`} aria-current={activePath === item.key ? 'page' : undefined} onClick={() => { navigate(item.key); setNavOpen(false); }}>{item.icon}<span>{item.label}</span>{'count' in item && <span className="asset-nav-count">{item.count ?? '—'}</span>}</button>)}
            </div>)}
          </nav>
          <div className="sidebar-bottom"><span className="sidebar-product">TERMINUS <span>AI SOC</span></span><small>Investigate. Decide. Respond.</small></div>
        </aside>
        <div className="console-workspace">
        <header className="console-topbar">
          <div className="console-topbar-main">
            <Button className="mobile-nav-toggle" type="text" icon={<MenuOutlined />} aria-label="Open navigation" aria-expanded={navOpen} onClick={() => setNavOpen(!navOpen)} />
            <div className="workspace-breadcrumb"><span>Workspace</span><span>/</span><strong>{currentPage}</strong></div>
            <div className="hud-right-stats">
              <span className="header-connection"><i className={`engine-light ${system.data ? 'online' : ''}`} />{system.data ? 'Connected' : 'Checking'}</span>
              <Dropdown
                menu={{
                  items: [
                    {
                      key: 'profile-header',
                      label: (
                        <div style={{ padding: '4px 0' }}>
                          <div style={{ fontWeight: 600, color: 'var(--ink)', fontSize: 12.5 }}>{user.data.display_name}</div>
                          <div style={{ fontSize: 10.5, color: 'var(--subtle)' }}>{user.data.email} · {detail.data?.role?.toUpperCase() || 'ANALYST'}</div>
                        </div>
                      ),
                      disabled: true,
                    },
                    { type: 'divider' },
                    {
                      key: 'active-org-header',
                      label: (
                        <div style={{ padding: '2px 0' }}>
                          <div style={{ fontSize: 9.5, letterSpacing: '0.06em', color: 'var(--subtle)', fontWeight: 600 }}>CURRENT WORKSPACE</div>
                          <div style={{ fontWeight: 600, color: 'var(--accent)', marginTop: 2, fontSize: 12 }}>{currentOrg}</div>
                        </div>
                      ),
                      disabled: true,
                    },
                    {
                      key: 'switch',
                      label: 'Switch Organization',
                      children: orgs.data?.map(o => ({
                        key: o.org_id,
                        label: (
                          <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
                            <span>{o.name}</span>
                            {o.org_id === orgId && <CheckOutlined style={{ color: 'var(--accent)', fontSize: 11 }} />}
                          </span>
                        ),
                        onClick: () => switchOrg(o.org_id),
                      })),
                    },
                    { key: 'new_org', label: 'Create organization', icon: <PlusOutlined />, onClick: () => setCreateOpen(true) },
                    { type: 'divider' },
                    { key: 'org_settings', label: 'Organization & Team', icon: <UserOutlined />, onClick: () => navigate('/organization') },
                    { key: 'settings', label: 'Platform Settings', icon: <SettingOutlined />, onClick: () => navigate('/settings') },
                    { key: 'appearance', label: 'Appearance', children: availableThemes.map(theme => ({ key: `theme-${theme.id}`, label: <span className="theme-menu-option">{theme.name}{themeId === theme.id && <CheckOutlined />}</span>, onClick: () => setThemeId(theme.id) })) },
                    { type: 'divider' },
                    { key: 'logout', label: 'Sign out', icon: <LogoutOutlined />, danger: true, onClick: () => void logout() },
                  ],
                }}
                trigger={['click']}
                placement="bottomRight"
              >
                <button className="unified-profile-pill" aria-label="Account and organization menu">
                  <Avatar shape="square" size={22} className="profile-pill-avatar">{user.data.display_name[0]?.toUpperCase()}</Avatar>
                  <span className="profile-pill-user">{user.data.display_name}</span>
                  <span className="profile-pill-divider">/</span>
                  <span className="profile-pill-org">{currentOrg}</span>
                  <DownOutlined className="profile-pill-chevron" />
                </button>
              </Dropdown>
            </div>
          </div>
        </header>

        <main className="hud-main" id="workspace-content" tabIndex={-1}>
          <ErrorPanel error={orgs.error} retry={() => void orgs.refetch()} />
          {orgs.isPending ? <Loading /> : !orgId ? (
            <div className="onboarding panel">
              <span className="eyebrow">YOUR FIRST WORKSPACE</span>
              <h1>Welcome to TERMINUS AI SOC.</h1>
              <p>Create an organization to start ingesting and investigating live telemetry.</p>
              <Form layout="vertical" onFinish={values => create.mutate(values)}>
                <Form.Item name="name" label="Organization name" rules={[{ required: true }]}><Input placeholder="Acme Security Operations" /></Form.Item>
                <Button type="primary" htmlType="submit" loading={create.isPending} block>Create Organization</Button>
              </Form>
            </div>
          ) : detail.isError ? (
            <ErrorPanel error={detail.error} retry={() => { void orgs.refetch(); void detail.refetch(); }} />
          ) : (
            <Suspense fallback={<Loading />}>
              <Routes>
                <Route path="/" element={<Operations />} />
                <Route path="/incidents" element={<Operations incidentView />} />
                <Route path="/incidents/graph" element={<Navigate to="/incidents" replace />} />
                <Route path="/incidents/:ticketId" element={<Operations incidentView />} />
                <Route path="/copilot" element={<CopilotPage />} />
                <Route path="/reports" element={<Reports />} />
                <Route path="/agents" element={<Agents />} />
                <Route path="/workflows" element={<Workflows />} />
                <Route path="/integrations" element={<Navigate to="/settings" replace />} />
                <Route path="/organization" element={<Settings section="organization" />} />
                <Route path="/settings" element={<Settings section="settings" />} />
                <Route path="/assets" element={<Navigate to="/assets/repository" replace />} />
                <Route path="/assets/:kind" element={<Assets />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </Suspense>
          )}
        </main>
        </div>

        <Modal
          title="Create an organization"
          open={createOpen}
          onCancel={() => setCreateOpen(false)}
          footer={null}
        >
          <Form layout="vertical" onFinish={values => create.mutate(values)}>
            <Form.Item name="name" label="Organization name" rules={[{ required: true }]}>
              <Input placeholder="Acme Security Operations" autoFocus />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={create.isPending} block>Create organization</Button>
          </Form>
        </Modal>
      </div>
      </CopilotProvider>
    </SessionContext.Provider>
  );
}
