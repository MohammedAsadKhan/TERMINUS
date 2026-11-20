// File: reports.tsx
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Browse and generate incident and operations reports, labeling verdict provenance.

import { useState } from 'react';
import { App, Button, Descriptions, Drawer, Input, Select, Space, Table, Tag } from 'antd';
import { DownloadOutlined, FileTextOutlined, PlusOutlined, SearchOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { api, body, download } from '../api';
import { useSession } from '../context';
import { date, EmptyPanel, ErrorPanel, PageTitle, Stat } from '../components';
import type { Report } from '../types';

// Display names for the analysis modes a report can record.
const ANALYSIS_MODE_LABELS: Record<string, string> = {
  provider: 'Provider model',
  scripted: 'Scripted / simulated',
  offline: 'Offline mode',
  fallback: 'Fallback / rule-based',
  policy: 'Policy rule only',
  unknown: 'Unknown',
};

// The report payload may not carry verdict provenance yet. Absence is not a
// neutral detail: an unlabeled verdict could be read as model-produced analysis,
// so every report without a recognized analysis_mode is shown as unverified.
function verdictProvenance(report: Report) {
  const mode = (report.verdict?.analysis_mode || '').trim().toLowerCase();
  if (!mode) {
    return { label: 'Unverified (analysis mode not recorded)', color: 'red', summary: 'No analysis mode was recorded for this report.' };
  }
  if (mode === 'unknown') {
    return { label: 'Unknown analysis mode', color: 'red', summary: 'The report records the analysis mode as unknown.' };
  }
  return {
    label: ANALYSIS_MODE_LABELS[mode] ?? `Unverified (unrecognized mode: ${mode})`,
    color: mode === 'provider' ? 'blue' : 'gold',
    summary: `Analysis mode recorded as ${mode}.`,
  };
}

// Report library and detail drawer for the signed-in organization. The selected report is kept in the ?report= URL
// parameter so it can be linked, and generating is disabled while the role is unknown and for viewers.
export default function Reports() {
  const { orgId, detail } = useSession(); const query = useQueryClient(); const { message } = App.useApp();
  const [search, setSearch] = useState(''); const [kind, setKind] = useState('quick'); const [params, setParams] = useSearchParams();
  // Polled every 15 seconds so newly generated reports appear.
  const reports = useQuery({ queryKey: ['reports', orgId], queryFn: () => api<Report[]>('/reports', orgId), refetchInterval: 15000 });
  // The selected window (quick or daily) chooses the endpoint; the new report is opened after it is created.
  const generate = useMutation({ mutationFn: () => api<Report>(`/reports/${kind}`, orgId, body('POST')), onSuccess: report => { query.invalidateQueries({ queryKey: ['reports', orgId] }); setParams({ report: report.id }); message.success('Report generated'); }, onError: error => message.error(error.message) });
  // Looked up in the loaded list, so an unknown id in the URL simply shows no drawer.
  const selected = reports.data?.find(report => report.id === params.get('report'));
  const selectedVerdict = selected ? verdictProvenance(selected) : null;
  return <><PageTitle eyebrow="INVESTIGATE / REPORTS" title="A record of your response." description="Review incident summaries with explicit reporting windows and measured totals." actions={<Space><Select aria-label="Report window" value={kind} onChange={setKind} options={[{ value: 'quick', label: 'Today · UTC' }, { value: 'daily', label: 'Last 24 hours' }]} /><Button type="primary" icon={<PlusOutlined />} disabled={!detail || detail.role === 'viewer'} loading={generate.isPending} onClick={() => generate.mutate()}>Generate report</Button></Space>} />
    <ErrorPanel error={reports.error} retry={() => void reports.refetch()} /><div className="reports-intro panel"><FileTextOutlined /><div><h2>Executive Operations Summaries</h2><p>Stored report snapshots over bounded observation windows, with incident totals and impacted-host counts.</p></div></div>
    <section className="panel table-panel"><div className="panel-heading"><h2>Report library</h2><Input aria-label="Search reports" prefix={<SearchOutlined />} placeholder="Search reports" value={search} onChange={e => setSearch(e.target.value)} style={{ width: 260 }} allowClear /></div>
      <Table<Report> rowKey="id" loading={reports.isPending} dataSource={reports.data?.filter(report => report.title.toLowerCase().includes(search.toLowerCase()))} columns={[
        { title: 'REPORT', key: 'title', render: (_, report) => <button className="text-link incident-link" onClick={() => setParams({ report: report.id })}><strong>{report.title}</strong><small className="mono">{report.id}</small></button> },
        { title: 'WINDOW', dataIndex: 'report_type', width: 140, render: (value: string) => <Tag>{value === 'quick' ? 'TODAY · UTC' : '24 HOURS'}</Tag> },
        { title: 'INCIDENTS', width: 110, render: (_, report) => report.metrics.total_incidents },
        { title: 'VERDICT', width: 180, render: (_, report) => <Tag color={verdictProvenance(report).color}>{verdictProvenance(report).label}</Tag> },
        { title: 'GENERATED', dataIndex: 'created_at', width: 160, render: (value: string) => date(value) },
        { title: '', width: 44, render: (_, report) => <Button type="text" aria-label={`Export ${report.id}`} icon={<DownloadOutlined />} onClick={() => download(`${report.id}.json`, JSON.stringify(report, null, 2))} /> },
      ]} pagination={{ pageSize: 10, showSizeChanger: false }} locale={{ emptyText: <EmptyPanel title="Your report library starts here" description="Generate a summary for today or the last 24 hours." /> }} />
    </section><Drawer title="Operations report" size={760} open={!!selected} onClose={() => setParams({})} extra={selected && <Button icon={<DownloadOutlined />} onClick={() => download(`${selected.id}.json`, JSON.stringify(selected, null, 2))}>Export JSON</Button>}>
      {selected && <div className="detail-stack"><Tag>{selected.report_type === 'quick' ? 'TODAY · UTC' : 'LAST 24 HOURS'}</Tag><h2>{selected.title}</h2><Descriptions column={1} size="small" items={[{ key: 'window', label: 'Period', children: `${date(selected.period_start)} — ${date(selected.period_end)}` }, { key: 'generated', label: 'Generated', children: date(selected.created_at) }]} />
      <div className="stats-grid report-stats"><Stat label="INCIDENTS" value={selected.metrics.total_incidents} note="In this reporting window" /><Stat label="CRITICAL" value={selected.metrics.critical_incidents} note="Critical assessments" accent="critical" /><Stat label="RESOLVED" value={selected.metrics.resolved_incidents} note="As of report generation" /></div>
      <section className="detail-section"><div className="eyebrow">EXECUTIVE SUMMARY</div><p>{selected.executive_summary}</p></section>
      <section className="detail-section"><div className="eyebrow">INVESTIGATION VERDICT</div><Space wrap>{selectedVerdict && <Tag color={selectedVerdict.color}>{selectedVerdict.label}</Tag>}{selected.verdict?.severity && <Tag>{String(selected.verdict.severity).toUpperCase()}</Tag>}{selected.verdict?.confidence && <Tag>CONFIDENCE: {String(selected.verdict.confidence).toUpperCase()}</Tag>}</Space><p>{selected.verdict?.summary || selectedVerdict?.summary}</p></section><section><div className="eyebrow">IMPACTED HOSTS</div><Table size="small" rowKey="host" pagination={false} dataSource={selected.top_impacted_hosts} columns={[{ title: 'Host', dataIndex: 'host' }, { title: 'Incidents', dataIndex: 'incident_count' }]} /></section>
      <section className="detail-section"><div className="eyebrow">RECOMMENDATIONS</div><ul className="recommendations">{selected.recommended_actions.map((action, index) => <li key={index}>{action}</li>)}</ul></section><p className="muted">Metrics are computed from stored incident records at generation time.</p></div>}
    </Drawer></>;
}
