import { useMemo, useState } from 'react';
import { Alert, App, Button, Descriptions, Drawer, Dropdown, Input, Modal, Select, Space, Table, Tag, Timeline, Tooltip } from 'antd';
import { ArrowRightOutlined, CheckOutlined, DownloadOutlined, ExperimentOutlined, MoreOutlined, ReloadOutlined, SearchOutlined, ThunderboltOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api, body, download } from '../api';
import { useSession } from '../context';
import { Code, date, EmptyPanel, ErrorPanel, Loading, PageTitle, Severity, Stat, Status } from '../components';
import type { Incident } from '../types';

const samples = {
  ssh: { name: 'SSH authentication failures', level: 8, description: 'Repeated SSH authentication failures on a monitored host', mitre: 'T1110', log: 'sshd: Failed password for invalid user admin from 192.0.2.10 port 43122 ssh2' },
  log4j: { name: 'Log4Shell lookup attempt', level: 12, description: 'Log4j JNDI lookup pattern detected in application request', mitre: 'T1190', log: 'GET /search?q=${jndi:ldap://example.invalid/test} HTTP/1.1' },
  ransomware: { name: 'Suspicious file encryption', level: 13, description: 'Potential ransomware: rapid file encryption activity', mitre: 'T1486', log: 'File monitor: 250 files renamed to .locked within a 10-second window' },
};

export function IngestModal({ open, close }: { open: boolean; close: () => void }) {
  const { orgId } = useSession(); const query = useQueryClient(); const { message } = App.useApp();
  const [sample, setSample] = useState<keyof typeof samples>('ssh'); const [custom, setCustom] = useState('');
  function payload() { const s = samples[sample]; return { id: `console-${crypto.randomUUID()}`, rule: { id: 100001, level: s.level, description: s.description, mitre: { id: s.mitre } }, agent: { id: 'console-test', name: 'Training endpoint' }, full_log: s.log, timestamp: new Date().toISOString() }; }
  const mutation = useMutation({ mutationFn: async () => {
    let value: unknown; try { value = custom ? JSON.parse(custom) : payload(); } catch { throw new Error('The payload must be valid JSON.'); }
    return api('/wazuh', orgId, body('POST', value));
  }, onSuccess: () => { query.invalidateQueries({ queryKey: ['incidents', orgId] }); message.success('Alert investigated'); close(); setCustom(''); } });
  return <Modal title="Submit a test alert" open={open} onCancel={close} okText="Submit alert" onOk={() => mutation.mutate()} confirmLoading={mutation.isPending} width={660} destroyOnHidden>
    <p className="muted">Creates real investigation data in this organization using your configured pipeline. Configured notification channels may receive this alert.</p>
    <Select aria-label="Test scenario" className="full-width" value={sample} options={Object.entries(samples).map(([value, item]) => ({ value, label: item.name }))} onChange={value => { setSample(value); setCustom(''); mutation.reset(); }} />
    <label className="field-label">Alert payload <span>Optional JSON override</span></label><Input.TextArea aria-label="Alert JSON" rows={9} className="mono" value={custom} placeholder={JSON.stringify(payload(), null, 2)} onChange={e => setCustom(e.target.value)} />
    {mutation.error && <Alert type="error" showIcon title={mutation.error.message} className="form-alert" />}
  </Modal>;
}

function IncidentDetail({ id, close }: { id: string; close: () => void }) {
  const { orgId, detail, system } = useSession(); const query = useQueryClient(); const { message } = App.useApp();
  const incident = useQuery({ queryKey: ['incident', orgId, id], queryFn: () => api<Incident>(`/incidents/${encodeURIComponent(id)}`, orgId), refetchInterval: 5000 });
  const action = useMutation({ mutationFn: (action_type: string) => api(`/incidents/${encodeURIComponent(id)}/action`, orgId, body('POST', { action_type })), onSuccess: () => { query.invalidateQueries({ queryKey: ['incidents', orgId] }); query.invalidateQueries({ queryKey: ['incident', orgId, id] }); message.success('Incident status updated'); }, onError: error => message.error(error.message) });
  const t = incident.data; const canWrite = detail?.role === 'admin' || detail?.role === 'member';
  return <Drawer title={<span className="mono">{id}</span>} size={700} open onClose={close} extra={t && <Button icon={<DownloadOutlined />} onClick={() => download(`${t.id}.json`, JSON.stringify(t, null, 2))}>Export</Button>}>
    {incident.isPending ? <Loading /> : incident.error ? <ErrorPanel error={incident.error} retry={() => void incident.refetch()} /> : t && <div className="detail-stack">
      <Space><Severity value={t.severity} /><Status value={t.status} /></Space><h2 className="detail-title">{t.rule_description || 'Security incident'}</h2>
      <Descriptions size="small" column={2} items={[{ key: 'host', label: 'Host', children: t.agent_name }, { key: 'time', label: 'Received', children: date(t.created_at) }, { key: 'policy', label: 'Policy', children: t.policy_tier }, { key: 'confidence', label: 'Confidence', children: t.confidence }, { key: 'source', label: 'Assessment', children: system?.llm_mode === 'scripted' ? 'Scripted development response' : system?.llm_model }]} />
      <section className="detail-section"><div className="eyebrow">INVESTIGATION SUMMARY</div><p>{t.summary}</p><p className="muted">{t.policy_reason}</p></section>
      <section className="detail-section"><div className="eyebrow">RECOMMENDED NEXT STEPS</div><ol className="recommendations">{t.recommended_actions.map((item, i) => <li key={i}>{item}</li>)}</ol><Alert type="info" showIcon title="Recommendations require analyst review" description="Live host isolation and perimeter blocking are not connected in this build. Changing an incident status does not execute a response." /></section>
      <Space wrap><Button type="primary" icon={<CheckOutlined />} loading={action.isPending} disabled={!canWrite} onClick={() => action.mutate(t.status === 'RESOLVED' ? 'reopen_ticket' : 'close_ticket')}>{t.status === 'RESOLVED' ? 'Reopen incident' : 'Resolve incident'}</Button>{t.status === 'OPEN' && <Button disabled={!canWrite} loading={action.isPending} onClick={() => action.mutate('start_investigation')}>Mark investigating</Button>}<Tooltip title="Requires a verified response connector"><Button disabled>Isolate host</Button></Tooltip></Space>
      <section className="detail-section"><div className="eyebrow">LIFECYCLE</div><Timeline items={[{ content: <><strong>Incident created</strong><p className="muted">{date(t.created_at)}</p></> }, ...(t.updated_at ? [{ color: 'green', content: <><strong>Status: {t.status.toLowerCase()}</strong><p className="muted">{date(t.updated_at)}</p></> }] : [])]} /></section>
      <section className="detail-section"><div className="eyebrow">RAW TELEMETRY</div><Code>{t.full_log || 'No raw log attached to this alert.'}</Code>{t.context_notes && <p className="muted">{t.context_notes}</p>}</section>
    </div>}
  </Drawer>;
}

export default function Operations({ incidentView = false }: { incidentView?: boolean }) {
  const { orgId, detail, system } = useSession(); const [ingest, setIngest] = useState(false); const navigate = useNavigate();
  const { ticketId } = useParams(); const [params, setParams] = useSearchParams();
  const incidents = useQuery({ queryKey: ['incidents', orgId], queryFn: () => api<Incident[]>('/incidents', orgId), refetchInterval: 5000 });
  const data = useMemo(() => [...(incidents.data || [])].sort((a, b) => (b.created_at || b.timestamp).localeCompare(a.created_at || a.timestamp)), [incidents.data]);
  const open = data.filter(t => t.status !== 'RESOLVED'); const critical = open.filter(t => t.severity === 'critical');
  const search = params.get('q') || ''; const severity = params.get('severity') || 'all'; const status = params.get('status') || 'all';
  const filtered = data.filter(t => `${t.id} ${t.rule_description} ${t.agent_name} ${t.summary}`.toLowerCase().includes(search.toLowerCase()) && (severity === 'all' || t.severity === severity) && (status === 'all' || t.status === status));
  const counts = ['critical', 'high', 'medium', 'low'].map(name => ({ name, count: data.filter(t => t.severity === name).length }));
  const canWrite = detail?.role === 'admin' || detail?.role === 'member';
  function filter(key: string, value: string) { const next = new URLSearchParams(params); if (value && value !== 'all') next.set(key, value); else next.delete(key); setParams(next, { replace: true }); }
  const columns = [
    { title: 'INCIDENT', dataIndex: 'rule_description', key: 'incident', render: (_: string, t: Incident) => <Link className="incident-link" to={`/incidents/${t.id}`}><strong>{t.rule_description || 'Security incident'}</strong><small className="mono">{t.id}</small></Link> },
    { title: 'SEVERITY', dataIndex: 'severity', key: 'severity', width: 120, render: (value: string) => <Severity value={value} /> },
    { title: 'HOST', dataIndex: 'agent_name', key: 'host', ellipsis: true, width: 170 },
    { title: 'STATUS', dataIndex: 'status', key: 'status', width: 145, render: (value: string) => <Status value={value} /> },
    { title: 'RECEIVED', dataIndex: 'created_at', key: 'created', width: 150, sorter: (a: Incident, b: Incident) => a.created_at.localeCompare(b.created_at), render: (value: string) => <span className="muted">{date(value)}</span> },
    { title: '', key: 'action', width: 48, render: (_: unknown, t: Incident) => <Dropdown menu={{ items: [{ key: 'open', label: 'View incident', onClick: () => navigate(`/incidents/${t.id}`) }, { key: 'export', label: 'Export JSON', onClick: () => download(`${t.id}.json`, JSON.stringify(t, null, 2)) }] }}><Button type="text" aria-label={`Actions for ${t.id}`} icon={<MoreOutlined />} /></Dropdown> },
  ];
  return <><PageTitle eyebrow={incidentView ? 'INVESTIGATE' : 'OPERATIONS / OVERVIEW'} title={incidentView ? 'Incident queue' : 'Your security, in focus.'} description={incidentView ? 'Review the evidence. Prioritize what needs your attention.' : 'A clear view of incoming threats and the work ahead.'} actions={<Space><Tooltip title="Refresh incidents"><Button aria-label="Refresh incidents" icon={<ReloadOutlined spin={incidents.isFetching} />} onClick={() => void incidents.refetch()} /></Tooltip><Button type="primary" disabled={!canWrite} icon={<ExperimentOutlined />} onClick={() => setIngest(true)}>Submit test alert</Button></Space>} />
    <ErrorPanel error={incidents.error} retry={() => void incidents.refetch()} />
    {!incidentView && <><div className="stats-grid"><Stat label="OPEN INCIDENTS" value={incidents.isPending ? '—' : open.length.toString().padStart(2, '0')} note="Awaiting investigation or resolution" /><Stat label="CRITICAL PRIORITY" value={incidents.isPending ? '—' : critical.length.toString().padStart(2, '0')} note="Unresolved critical assessments" accent="critical" /><Stat label="RESOLVED" value={incidents.isPending ? '—' : data.length - open.length} note="Marked resolved by your team" /><Stat label="TOTAL INVESTIGATED" value={incidents.isPending ? '—' : data.length} note="Incidents in this organization" /></div>
    <div className="overview-grid"><section className="panel signal-panel"><div className="panel-heading"><div><span className="eyebrow">THREAT DISTRIBUTION</span><h2>Know where to look.</h2></div><Tag bordered={false}>CURRENT SESSION</Tag></div><div className="distribution-bar">{data.length ? counts.filter(c => c.count).map(c => <div key={c.name} className={`segment ${c.name}`} style={{ flex: c.count }} title={`${c.name}: ${c.count}`} />) : <div className="segment no-data" />}</div><div className="distribution-legend">{counts.map(c => <div key={c.name}><i className={`legend-dot ${c.name}`} /><span>{c.name}</span><strong>{c.count}</strong></div>)}</div><div className="panel-bottom">{data.length ? `${data.length} incident assessments · ${open.length} still open` : 'Your first alert will bring this view to life.'}</div></section>
    <section className="panel pipeline-panel"><div className="eyebrow">INVESTIGATION PIPELINE</div><h2>Every signal has a path.</h2><div className="pipeline-step"><span>01</span><div><strong>Validate & prioritize</strong><small>Deterministic severity and MITRE policy</small></div><CheckOutlined /></div><div className="pipeline-step"><span>02</span><div><strong>Collect & assess</strong><small>{system?.llm_mode === 'scripted' ? 'Scripted AI · development mode' : system?.llm_model || 'Loading provider'}</small></div><ThunderboltOutlined /></div><div className="pipeline-step"><span>03</span><div><strong>Review & respond</strong><small>Analyst review · live tools not connected</small></div><ArrowRightOutlined /></div></section></div></>}
    <section className="panel table-panel"><div className="panel-heading"><div><span className="eyebrow">{incidentView ? 'ALL INCIDENTS' : 'RECENT ACTIVITY'}</span><h2>{incidentView ? 'Investigation workspace' : 'Latest incidents'}</h2></div>{!incidentView && <Link to="/incidents">View all <ArrowRightOutlined /></Link>}</div>
      {incidentView && <div className="table-toolbar"><Input aria-label="Search incidents" prefix={<SearchOutlined />} placeholder="Search incident, host or evidence…" value={search} onChange={e => filter('q', e.target.value)} allowClear /><Select aria-label="Filter severity" value={severity} onChange={value => filter('severity', value)} options={[{ value: 'all', label: 'All severities' }, ...counts.map(c => ({ value: c.name, label: c.name[0].toUpperCase() + c.name.slice(1) }))]} /><Select aria-label="Filter status" value={status} onChange={value => filter('status', value)} options={[{ value: 'all', label: 'All statuses' }, ...['OPEN', 'INVESTIGATING', 'RESOLVED'].map(value => ({ value, label: value }))]} /></div>}
      <Table<Incident> rowKey="id" columns={columns} dataSource={incidentView ? filtered : data.slice(0, 5)} loading={incidents.isPending} scroll={{ x: 900 }} pagination={incidentView ? { pageSize: 10, showSizeChanger: false, showTotal: total => `${total} incidents` } : false} locale={{ emptyText: <EmptyPanel title={data.length ? 'No matching incidents' : 'No incidents yet'} description={data.length ? 'Try adjusting your filters.' : 'Connect a source or submit a test alert to start an investigation.'} action={!data.length && <Button disabled={!canWrite} onClick={() => setIngest(true)}>Submit test alert</Button>} /> }} />
      <div className="table-foot"><span><i className={`status-dot ${incidents.error ? 'error' : ''}`} />{incidents.error ? 'Updates unavailable' : 'Refreshes every 5 seconds'}</span><span>{incidents.dataUpdatedAt ? `Updated ${new Date(incidents.dataUpdatedAt).toLocaleTimeString()}` : 'Waiting for data'}</span></div>
    </section><IngestModal open={ingest} close={() => setIngest(false)} />{ticketId && <IncidentDetail key={`${orgId}-${ticketId}`} id={ticketId} close={() => navigate('/incidents' + (params.size ? `?${params}` : ''))} />}
  </>;
}
