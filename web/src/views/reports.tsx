import { useState } from 'react';
import { App, Button, Descriptions, Drawer, Input, Select, Space, Table, Tag } from 'antd';
import { DownloadOutlined, FileTextOutlined, PlusOutlined, SearchOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { api, body, download } from '../api';
import { useSession } from '../context';
import { date, EmptyPanel, ErrorPanel, PageTitle, Stat } from '../components';
import type { Report } from '../types';

export default function Reports() {
  const { orgId, detail } = useSession(); const query = useQueryClient(); const { message } = App.useApp();
  const [search, setSearch] = useState(''); const [kind, setKind] = useState('quick'); const [params, setParams] = useSearchParams();
  const reports = useQuery({ queryKey: ['reports', orgId], queryFn: () => api<Report[]>('/reports', orgId), refetchInterval: 15000 });
  const generate = useMutation({ mutationFn: () => api<Report>(`/reports/${kind}`, orgId, body('POST')), onSuccess: report => { query.invalidateQueries({ queryKey: ['reports', orgId] }); setParams({ report: report.id }); message.success('Report generated'); }, onError: error => message.error(error.message) });
  const selected = reports.data?.find(report => report.id === params.get('report'));
  return <><PageTitle eyebrow="INVESTIGATE / REPORTS" title="A record of your response." description="Review incident summaries with explicit reporting windows and measured totals." actions={<Space><Select aria-label="Report window" value={kind} onChange={setKind} options={[{ value: 'quick', label: 'Today · UTC' }, { value: 'daily', label: 'Last 24 hours' }]} /><Button type="primary" icon={<PlusOutlined />} disabled={!detail || detail.role === 'viewer'} loading={generate.isPending} onClick={() => generate.mutate()}>Generate report</Button></Space>} />
    <ErrorPanel error={reports.error} retry={() => void reports.refetch()} /><div className="reports-intro panel"><FileTextOutlined /><div><h2>From incident data to a useful summary.</h2><p>Reports are snapshots of incidents created in the selected period. Missing timing data stays unreported. New reports do not change previous snapshots.</p></div></div>
    <section className="panel table-panel"><div className="panel-heading"><h2>Report library</h2><Input aria-label="Search reports" prefix={<SearchOutlined />} placeholder="Search reports" value={search} onChange={e => setSearch(e.target.value)} style={{ width: 260 }} allowClear /></div>
      <Table<Report> rowKey="id" loading={reports.isPending} dataSource={reports.data?.filter(report => report.title.toLowerCase().includes(search.toLowerCase()))} scroll={{ x: 800 }} columns={[
        { title: 'REPORT', key: 'title', render: (_, report) => <button className="text-link incident-link" onClick={() => setParams({ report: report.id })}><strong>{report.title}</strong><small className="mono">{report.id}</small></button> },
        { title: 'WINDOW', dataIndex: 'report_type', render: (value: string) => <Tag>{value === 'quick' ? 'TODAY · UTC' : '24 HOURS'}</Tag> },
        { title: 'INCIDENTS', render: (_, report) => report.metrics.total_incidents },
        { title: 'GENERATED', dataIndex: 'created_at', render: (value: string) => date(value) },
        { title: '', render: (_, report) => <Button type="text" aria-label={`Export ${report.id}`} icon={<DownloadOutlined />} onClick={() => download(`${report.id}.json`, JSON.stringify(report, null, 2))} /> },
      ]} pagination={{ pageSize: 10, showSizeChanger: false }} locale={{ emptyText: <EmptyPanel title="Your report library starts here" description="Generate a summary for today or the last 24 hours." /> }} />
    </section><Drawer title="Operations report" size={760} open={!!selected} onClose={() => setParams({})} extra={selected && <Button icon={<DownloadOutlined />} onClick={() => download(`${selected.id}.json`, JSON.stringify(selected, null, 2))}>Export JSON</Button>}>
      {selected && <div className="detail-stack"><Tag>{selected.report_type === 'quick' ? 'TODAY · UTC' : 'LAST 24 HOURS'}</Tag><h2>{selected.title}</h2><Descriptions column={1} size="small" items={[{ key: 'window', label: 'Period', children: `${date(selected.period_start)} — ${date(selected.period_end)}` }, { key: 'generated', label: 'Generated', children: date(selected.created_at) }]} />
      <div className="stats-grid report-stats"><Stat label="INCIDENTS" value={selected.metrics.total_incidents} note="In this reporting window" /><Stat label="CRITICAL" value={selected.metrics.critical_incidents} note="Critical assessments" accent="critical" /><Stat label="RESOLVED" value={selected.metrics.resolved_incidents} note="As of report generation" /></div>
      <section className="detail-section"><div className="eyebrow">EXECUTIVE SUMMARY</div><p>{selected.executive_summary}</p></section><section><div className="eyebrow">IMPACTED HOSTS</div><Table size="small" rowKey="host" pagination={false} dataSource={selected.top_impacted_hosts} columns={[{ title: 'Host', dataIndex: 'host' }, { title: 'Incidents', dataIndex: 'incident_count' }]} /></section>
      <section className="detail-section"><div className="eyebrow">RECOMMENDATIONS</div><ul className="recommendations">{selected.recommended_actions.map((action, index) => <li key={index}>{action}</li>)}</ul></section><p className="muted">Detection and response timing are unavailable until the required lifecycle measurements are recorded.</p></div>}
    </Drawer></>;
}
