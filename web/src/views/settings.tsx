import { useState } from 'react';
import { Alert, App, Avatar, Button, Descriptions, Form, Input, Modal, Progress, Select, Space, Table, Tag, Typography } from 'antd';
import { ApiOutlined, ArrowRightOutlined, BgColorsOutlined, CheckCircleOutlined, CopyOutlined, DeleteOutlined, ExperimentOutlined, KeyOutlined, PlusOutlined, TeamOutlined } from '@ant-design/icons';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api, body } from '../api';
import { useSession } from '../context';
import { useTheme } from '../theme';
import { Code, date, PageTitle, Stat } from '../components';
import { IngestModal } from './operations';
import type { Integration, Membership } from '../types';

export default function Settings({ section }: { section: 'integrations' | 'organization' | 'settings' }) {
  const { user, orgId, detail, system } = useSession(); const query = useQueryClient(); const { message, modal } = App.useApp();
  const { themeId, activeTheme, setThemeId, availableThemes } = useTheme();
  const [ingest, setIngest] = useState(false); const [connection, setConnection] = useState<Integration | null>(null); const [addOpen, setAddOpen] = useState(false); const [form] = Form.useForm();
  const canWrite = detail?.role === 'admin';
  const add = useMutation({ mutationFn: (values: { user_id: string; role: string }) => api(`/orgs/${orgId}/members`, orgId, body('POST', values)), onSuccess: () => { query.invalidateQueries({ queryKey: ['org', orgId] }); setAddOpen(false); form.resetFields(); message.success('Member added'); } });
  const license = useMutation({ mutationFn: (values: { token: string }) => api(`/orgs/${orgId}/license`, orgId, body('POST', values)), onSuccess: () => { query.invalidateQueries({ queryKey: ['org', orgId] }); message.success('License activated'); }, onError: error => message.error(error.message) });
  async function role(member: Membership, value: string) { try { await api(`/orgs/${orgId}/members/${member.user_id}`, orgId, body('PATCH', { role: value })); query.invalidateQueries({ queryKey: ['org', orgId] }); message.success('Role updated'); } catch (error) { message.error((error as Error).message); } }
  function remove(member: Membership) { modal.confirm({ title: `Remove ${member.user?.display_name || member.user_id}?`, content: 'This removes their access to this organization.', okText: 'Remove member', okButtonProps: { danger: true }, onOk: async () => { try { await api(`/orgs/${orgId}/members/${member.user_id}`, orgId, body('DELETE')); query.invalidateQueries({ queryKey: ['org', orgId] }); } catch (error) { message.error((error as Error).message); throw error; } } }); }

  if (section === 'integrations') return <><PageTitle eyebrow="CONFIGURE / SOURCES & INTEGRATIONS" title="Telemetry & Integrations" description="Inspect security event sources, SIEM connectors, and notification endpoints configured for your SOC." actions={<Button type="primary" icon={<ExperimentOutlined />} disabled={!detail || detail.role === 'viewer'} onClick={() => setIngest(true)}>Simulate Event</Button>} />
    <section className="panel source-banner"><span className="source-icon"><ApiOutlined /></span><div><div className="eyebrow">AUTHENTICATED INGESTION</div><h2>Automated Ingestion Pipeline</h2><p>Wazuh, Syslog, and cloud audit streams are ingested, enriched with MITRE ATT&amp;CK context, and evaluated in real time.</p></div><Tag color="green">POST /wazuh</Tag></section>
    <div className="integration-grid">{system?.integrations.map(item => <article className="panel integration-card" key={item.id}><div className="integration-top"><Avatar shape="square" size={44} className={`provider-icon ${item.id}`}>{item.name.slice(0, 1)}</Avatar><Tag color={item.configured ? 'green' : 'default'}>{item.configured ? 'CONFIGURED' : 'NOT CONFIGURED'}</Tag></div><div className="eyebrow">{item.category}</div><h2>{item.name}</h2><p>{item.description}</p><Button block onClick={() => setConnection(item)}>Configuration details <ArrowRightOutlined /></Button></article>)}</div>
    <div className="settings-grid"><section className="panel"><div className="eyebrow">INGESTION PIPELINE API</div><h2>Direct Alert Dispatch</h2><p className="muted">Authorize inbound alerts via Bearer session tokens with tenant organization headers. Payloads are validated against standard SOC telemetry schemas.</p><Code>{`curl -X POST '${window.location.origin}/wazuh' \\\n  -H 'Authorization: Bearer <SESSION_TOKEN>' \\\n  -H 'X-Org-ID: ${orgId}' \\\n  -H 'Content-Type: application/json' \\\n  -d '{"id":"source-event-001","rule_id":5710,"level":8,"description":"SSH failures","full_log":"sshd: failed password"}'`}</Code></section><section className="panel"><div className="eyebrow">INTEGRATION ARCHITECTURE</div><h2>Security Connectors</h2><p className="muted">Integrations authenticate over encrypted outbound channels. Service credentials are managed centrally via secure environment parameters.</p><Alert type="info" title="Zero-Trust Connector Architecture" description="Outbound actions and ticketing dispatches enforce tenant isolation and cryptographic verification across external integrations." showIcon /></section></div>
    <Modal open={!!connection} title={connection?.name + ' configuration'} onCancel={() => setConnection(null)} footer={<Button onClick={() => setConnection(null)}>Close</Button>}><p>{connection?.description}</p><p className="muted">Set the corresponding TERMINUS environment variables on the server and restart. Secret values are never returned to the console.</p><Code>{`${connection?.setting}=<configured on the server>`}</Code><Alert type={connection?.configured ? 'success' : 'info'} title={connection?.configured ? 'Configuration verified' : 'Connector awaiting credentials'} /></Modal><IngestModal open={ingest} close={() => setIngest(false)} />
  </>;

  if (section === 'organization') return <><PageTitle eyebrow="GOVERN / ORGANIZATION" title="A shared space. Clear access." description="Manage the people who can investigate and administer this organization." actions={<Button type="primary" icon={<PlusOutlined />} disabled={!canWrite} onClick={() => { add.reset(); setAddOpen(true); }}>Add member</Button>} />
    <div className="settings-grid"><section className="panel org-profile"><span className="source-icon"><TeamOutlined /></span><h2>{detail?.organization.name}</h2><Typography.Paragraph className="mono muted" copyable>{orgId}</Typography.Paragraph><Descriptions column={1} size="small" items={[{ key: 'created', label: 'Created', children: date(detail?.organization.created_at) }, { key: 'role', label: 'Your role', children: <Tag>{detail?.role.toUpperCase()}</Tag> }]} /></section><section className="panel"><div className="eyebrow">LICENSED CAPACITY</div><h2>Room for your team.</h2><div className="seat-count">{detail?.members.length || 0}<span> / {detail?.license?.max_seats || '—'} seats</span></div><Progress percent={detail?.license ? Math.min(100, Math.round(detail.members.length / detail.license.max_seats * 100)) : 0} showInfo={false} strokeColor="#a4dfba" /><p className="muted">{detail?.license?.tier.toUpperCase() || 'No valid license'} · {detail?.license ? `Expires ${date(detail.license.expires_at)}` : 'See Settings & license'}</p></section></div>
    <section className="panel table-panel"><div className="panel-heading"><h2>Organization members</h2><Tag>{detail?.members.length || 0} MEMBERS</Tag></div><Table<Membership> rowKey="user_id" dataSource={detail?.members} pagination={false} scroll={{ x: 700 }} columns={[{ title: 'MEMBER', render: (_, person) => <Space><Avatar shape="square">{person.user?.display_name[0]}</Avatar><span className="incident-link"><strong>{person.user?.display_name || person.user_id}{person.user_id === user.user_id && <Tag className="you-tag">YOU</Tag>}</strong><small>{person.user?.email || 'User not found'}</small></span></Space> }, { title: 'ROLE', dataIndex: 'role', render: (value: string, person) => <Select aria-label={`Role of ${person.user?.display_name || person.user_id}`} value={value} disabled={!canWrite} options={['admin', 'member', 'viewer'].map(role => ({ value: role, label: role }))} onChange={value => void role(person, value)} style={{ width: 130 }} /> }, { title: 'USER ID', dataIndex: 'user_id', render: (value: string) => <Typography.Text className="mono" copyable>{value}</Typography.Text> }, { title: '', render: (_, person) => <Button danger type="text" aria-label={`Remove ${person.user?.display_name || person.user_id}`} icon={<DeleteOutlined />} disabled={!canWrite} onClick={() => remove(person)} /> }]} /></section>
    <div className="role-guide"><div><Tag>ADMIN</Tag><p>Manage access, licenses and configuration.</p></div><div><Tag>MEMBER</Tag><p>Submit alerts, investigate and resolve incidents.</p></div><div><Tag>VIEWER</Tag><p>Review incidents, definitions and reports.</p></div></div>
    <Modal title="Add an existing user" open={addOpen} onCancel={() => setAddOpen(false)} onOk={() => form.submit()} okText="Add member" confirmLoading={add.isPending}><p className="muted">Enter the unique User ID of a registered analyst to provision membership and assign access controls.</p><Form form={form} layout="vertical" initialValues={{ role: 'member' }} onFinish={values => add.mutate(values)}><Form.Item name="user_id" label="User ID" rules={[{ required: true, whitespace: true }]}><Input placeholder="usr-…" /></Form.Item><Form.Item name="role" label="Role"><Select options={['member', 'viewer', 'admin'].map(value => ({ value, label: value }))} /></Form.Item>{add.error && <Alert type="error" title={add.error.message} />}</Form></Modal>
  </>;

  return <><PageTitle eyebrow="GOVERN / SETTINGS" title="Platform Configuration" description="Review runtime environment, cryptographic license entitlements, and active SOC triage policies." />
    <div className="stats-grid"><Stat label="STORAGE ENGINE" value="In-Memory" note="Ultra-low latency synchronous write-through" /><Stat label="AI ENGINE" value="Autonomous" note={system?.llm_model || 'TERMINUS AI Engine'} /><Stat label="TELEMETRY BUS" value="HTTPS" note="Encrypted real-time state synchronization" /><Stat label="LICENSE TIER" value={detail?.license?.tier.toUpperCase() || '—'} note={detail?.license ? `Expires ${date(detail.license.expires_at)}` : 'No valid license'} /></div>
    <section className="panel">
      <div className="eyebrow">WORKSPACE APPEARANCE &amp; HUD THEMES</div>
      <div className="panel-heading" style={{ marginBottom: 4 }}>
        <div>
          <h2>Color Scheme &amp; Theme Palette</h2>
          <p className="muted" style={{ margin: '4px 0 0', fontSize: 12 }}>
            Switch between specialized operations center color palettes. Themes apply dynamically across telemetry charts, navigation panels, and action buttons, with profile persistence.
          </p>
        </div>
        <Tag icon={<BgColorsOutlined />} color="cyan" style={{ fontSize: 11, padding: '2px 10px' }}>CURRENT: {activeTheme.name.toUpperCase()}</Tag>
      </div>
      <div className="theme-selector-grid">
        {availableThemes.map(t => {
          const isSelected = t.id === themeId;
          return (
            <div
              key={t.id}
              className={`theme-card ${isSelected ? 'active' : ''}`}
              onClick={() => {
                setThemeId(t.id);
                message.success(`Applied ${t.name} color scheme`);
              }}
            >
              <div>
                <div className="theme-card-header">
                  <h3>{t.name}</h3>
                  {isSelected ? <Tag color="success">ACTIVE</Tag> : <Tag>{t.category}</Tag>}
                </div>
                <p>{t.description}</p>
              </div>
              <div className="theme-swatches">
                <div className="theme-swatch-pill" style={{ background: t.swatches[0] }} title={`Primary: ${t.swatches[0]}`} />
                <div className="theme-swatch-pill" style={{ background: t.swatches[1] }} title={`Surface: ${t.swatches[1]}`} />
                <div className="theme-swatch-pill" style={{ background: t.swatches[2] }} title={`Base: ${t.swatches[2]}`} />
                <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 6 }}>
                  {isSelected ? 'Active Palette' : 'Click to activate'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </section>
    <div className="settings-grid"><section className="panel"><div className="eyebrow">LICENSE MANAGEMENT</div><h2>Enterprise Entitlement</h2>{detail?.license_error && <Alert type="error" title={detail.license_error} />}<p className="muted">Cryptographically signed HMAC license tokens unlock tiered capacity, concurrent analyst seats, and advanced autonomous response capabilities.</p><Space wrap>{detail?.license?.features.map(feature => <Tag key={feature} icon={<CheckCircleOutlined />}>{feature.replaceAll('_', ' ')}</Tag>)}</Space><Form layout="vertical" onFinish={values => license.mutate(values)}><Form.Item name="token" label="Signed license token" rules={[{ required: true }]}><Input.TextArea rows={3} disabled={!canWrite} placeholder="Paste the license token for this organization" /></Form.Item><Button type="primary" htmlType="submit" icon={<KeyOutlined />} disabled={!canWrite} loading={license.isPending}>Activate license</Button></Form></section>
      <section className="panel"><div className="eyebrow">TRIAGE POLICY</div><h2>Signal Prioritization Rules</h2><div className="policy-row"><Tag color="blue">IGNORE</Tag><span>Severity below 5, without a MITRE ATT&amp;CK override</span></div><div className="policy-row"><Tag color="gold">TRIAGE</Tag><span>Severity 5–9, without a MITRE ATT&amp;CK override</span></div><div className="policy-row"><Tag color="red">ESCALATE</Tag><span>Severity 10+ or any verified MITRE technique (Txxxx)</span></div><p className="muted">Autonomous triage rules evaluate incoming signals deterministically before dispatching multi-agent investigation workflows.</p></section></div>
    <section className="panel"><div className="eyebrow">ACTIVE ACCOUNT</div><h2>{user.display_name}</h2><Descriptions column={{ xs: 1, md: 3 }} items={[{ key: 'email', label: 'Email', children: user.email }, { key: 'id', label: 'User ID', children: <Button type="text" icon={<CopyOutlined />} onClick={() => { void navigator.clipboard.writeText(user.user_id); message.success('User ID copied'); }}>{user.user_id}</Button> }, { key: 'session', label: 'Session', children: 'Encrypted bearer token session' }]} /></section>
  </>;
}
