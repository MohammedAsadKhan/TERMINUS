import { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Empty, Input, Select, Slider, Spin } from 'antd';
import { ArrowLeftOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { NetworkCanvas, type NetworkEvent, type NetworkSelection } from '../network-canvas';
import { api } from '../api';
import { date, ErrorPanel } from '../components';
import { useSession } from '../context';

const HOUR = 3600000;
const WEEK = 7 * 24 * HOUR;

interface GraphNode { id: string; kind: 'source' | 'host'; label: string; event_count: number; critical_count: number; local_test?: boolean }
interface GraphEdge { id: string; source: string; target: string; source_ip: string; host: string; event_count: number; critical_count: number; first_seen: string; last_seen: string; techniques: string[]; relationship: string }
interface GraphSnapshot { from: string; until: string; total_events: number; investigated_events: number; nodes: GraphNode[]; edges: GraphEdge[]; daily_counts: Array<{ day: string; event_count: number }>; hidden_relationships: number; note: string }
interface GraphEvent { alert_id: string; incident_id: string | null; occurred_at: string; ingested_at: string; source_ip: string | null; host: string; rule_description: string; mitre: string | null; level: number; severity: string; policy_tier: string; campaign_id: string | null; raw_event: string }
interface EvidencePage { total: number; events: GraphEvent[]; limit: number; offset: number }
interface NetworkPage { total_events: number; shown_events: number; truncated: boolean; events: NetworkEvent[] }

export default function InvestigationGraph() {
  const { orgId } = useSession();
  const [anchor, setAnchor] = useState(() => Date.now());
  const [live, setLive] = useState(true);
  const [hour, setHour] = useState(168);
  const [policy, setPolicy] = useState('all');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<NetworkSelection | null>(null);
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    if (!live) return;
    const timer = window.setInterval(() => setAnchor(Date.now()), 5000);
    return () => window.clearInterval(timer);
  }, [live]);

  const from = new Date(anchor - WEEK).toISOString();
  const until = new Date(live ? anchor : anchor - WEEK + hour * HOUR).toISOString();
  const windowQuery = new URLSearchParams({ from, until, policy });
  const graph = useQuery({ queryKey: ['investigation-graph', orgId, from, until, policy], queryFn: () => api<GraphSnapshot>(`/investigation/graph?${windowQuery}`, orgId), enabled: Boolean(orgId) });
  const network = useQuery({ queryKey: ['investigation-network', orgId, from, until, policy], queryFn: () => api<NetworkPage>(`/investigation/graph/network?${windowQuery}`, orgId), enabled: Boolean(orgId) });
  const evidenceQuery = new URLSearchParams({ from, until, policy, limit: '10', offset: String(offset) });
  if (selected?.source_ip) evidenceQuery.set('source_ip', selected.source_ip);
  if (selected?.host) evidenceQuery.set('host', selected.host);
  if (selected?.mitre) evidenceQuery.set('mitre', selected.mitre);
  if (selected?.alert_id) evidenceQuery.set('alert_id', selected.alert_id);
  const evidence = useQuery({ queryKey: ['graph-evidence', orgId, selected, from, until, policy, offset], queryFn: () => api<EvidencePage>(`/investigation/graph/evidence?${evidenceQuery}`, orgId), enabled: Boolean(orgId && selected) });

  const relationships = useMemo(() => {
    const term = search.trim().toLowerCase();
    return (graph.data?.edges || []).filter(edge => !term || [edge.source_ip, edge.host, ...edge.techniques].some(value => value.toLowerCase().includes(term)));
  }, [graph.data, search]);

  const visibleEvents = useMemo(() => {
    const term = search.trim().toLowerCase();
    return (network.data?.events || []).filter(event => !term || [event.source_ip, event.host, event.mitre, event.rule_description, event.alert_id].some(value => value?.toLowerCase().includes(term)));
  }, [network.data, search]);

  const dayCounts = useMemo(() => {
    const recorded = new Map((graph.data?.daily_counts || []).map(item => [item.day, item.event_count]));
    const first = new Date(from);
    first.setUTCHours(0, 0, 0, 0);
    return Array.from({ length: 8 }, (_, index) => {
      const day = new Date(first.getTime() + index * 24 * HOUR).toISOString().slice(0, 10);
      return { day, event_count: recorded.get(day) || 0 };
    });
  }, [graph.data?.daily_counts, from]);
  const maxDay = Math.max(1, ...dayCounts.map(item => item.event_count));

  function choose(value: NetworkSelection) { setSelected(value); setOffset(0); }
  function scrub(value: number) { setLive(false); setHour(value); setSelected(null); setOffset(0); }
  function goLive() { setAnchor(Date.now()); setHour(168); setLive(true); setSelected(null); setOffset(0); }

  return <div className="graph-page">
    <div className="graph-page-head">
      <div><span className="work-overline">INVESTIGATION / SEVEN-DAY WINDOW</span><h1>Attack network</h1><p>Each dot is an observed alert. Shared sources, hosts, and techniques connect the activity.</p></div>
      <div className="graph-head-actions"><Link to="/incidents"><ArrowLeftOutlined /> Queue</Link><Button icon={<ReloadOutlined />} onClick={() => { void graph.refetch(); void network.refetch(); }} loading={graph.isFetching || network.isFetching}>Refresh</Button></div>
    </div>
    <div className="graph-toolbar">
      <div className="graph-mode"><Link to="/incidents">Queue</Link><strong>Graph</strong></div>
      <Input prefix={<SearchOutlined />} aria-label="Find source, host, or technique" placeholder="Find source, host, technique" value={search} onChange={event => setSearch(event.target.value)} allowClear />
      <Select aria-label="Policy filter" value={policy} onChange={value => { setPolicy(value); setSelected(null); }} options={[{ value: 'all', label: 'All events' }, { value: 'escalate', label: 'Escalated' }, { value: 'triage', label: 'Triaged' }, { value: 'ignore', label: 'Filtered' }]} />
      <span className={`graph-live ${live ? 'on' : ''}`}>{live ? '● Live · 5s' : '● Paused'}</span>
    </div>
    <div className="graph-stats"><div><span>Alert dots shown</span><strong>{visibleEvents.length}</strong></div><div><span>Investigated</span><strong>{graph.data?.investigated_events ?? '—'}</strong></div><div><span>Observed source–host pairs</span><strong>{relationships.length}</strong></div><div><span>As of</span><strong className="graph-asof">{date(until)}</strong></div></div>
    {graph.error && <ErrorPanel error={graph.error} retry={() => void graph.refetch()} />}
    {network.error && <ErrorPanel error={network.error} retry={() => void network.refetch()} />}
    <div className="graph-workspace">
      <aside className="graph-connections" aria-label="Observed connections"><div className="graph-pane-head"><strong>Connections</strong><small>Ranked by event count</small></div><div className="graph-connection-list">
        {relationships.length ? relationships.map(item => <button key={item.id} className={selected?.kind === 'edge' && selected.source_ip === item.source_ip && selected.host === item.host ? 'selected' : ''} onClick={() => choose({ kind: 'edge', label: `${item.source_ip} → ${item.host}`, source_ip: item.source_ip, host: item.host })}><strong>{item.source_ip}</strong><span>→ {item.host}</span><small>{item.event_count} events · {item.critical_count} critical</small></button>) : <p className="graph-muted">No source-to-host connections match this view.</p>}
      </div></aside>
      <section className="graph-canvas" aria-label="Seven-day alert relationship network">
        {network.isPending ? <div className="work-loading"><Spin /></div> : visibleEvents.length ? <NetworkCanvas events={visibleEvents} selected={selected} onSelect={choose} /> : <Empty description="No events with these filters in the selected period" image={Empty.PRESENTED_IMAGE_SIMPLE} />}
        {network.data && <div className="graph-canvas-note">{network.data.truncated ? `Showing ${network.data.shown_events} of ${network.data.total_events} alerts; narrow the window to inspect all. ` : ''}Lines show shared evidence fields, not attacker attribution. Drag to pan; scroll to zoom; click a dot for raw evidence.</div>}
      </section>
      <aside className="graph-evidence" aria-label="Relationship evidence"><div className="graph-pane-head"><strong>{selected ? selected.label : 'Evidence'}</strong><small>{selected ? `${evidence.data?.total ?? '…'} recorded events` : 'Select a source, host, or link'}</small></div>
        {!selected ? <div className="graph-evidence-empty"><h3>Inspect the network</h3><p>Choose an alert dot, entity hub, or connection to see its recorded evidence.</p></div> : <div className="graph-evidence-list">
          {evidence.isPending ? <Spin /> : evidence.error ? <Alert type="error" title={evidence.error.message} /> : evidence.data?.events.length ? evidence.data.events.map(event => <article key={event.alert_id} className="graph-event"><div className="graph-event-top"><time>{date(event.occurred_at)}</time><span className={`graph-event-tier ${event.policy_tier}`}>{event.policy_tier}</span></div><h3>{event.rule_description}</h3><p>{event.source_ip || 'Unknown source'} → {event.host}</p><dl><div><dt>Alert</dt><dd>{event.alert_id}</dd></div>{event.incident_id && <div><dt>Incident</dt><dd>{event.incident_id}</dd></div>}{event.mitre && <div><dt>Technique</dt><dd>{event.mitre}</dd></div>}</dl><pre>{event.raw_event || 'No raw event text recorded.'}</pre></article>) : <Empty description="No events in this time range" image={Empty.PRESENTED_IMAGE_SIMPLE} />}
          {evidence.data && evidence.data.total > 10 && <div className="graph-pager"><Button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 10))}>Previous</Button><span>{offset + 1}–{Math.min(offset + 10, evidence.data.total)} of {evidence.data.total}</span><Button disabled={offset + 10 >= evidence.data.total} onClick={() => setOffset(offset + 10)}>Next</Button></div>}
        </div>}
      </aside>
    </div>
    <div className="graph-timeline"><div className="graph-timeline-head"><strong>Seven-day timeline</strong><span>{date(from)} → {date(until)}</span></div><div className="graph-day-bars" aria-label="Daily event counts">{dayCounts.map(item => <div key={item.day} title={`${item.day}: ${item.event_count} events`}><i style={{ height: `${Math.max(5, item.event_count / maxDay * 100)}%` }} /><span>{item.day.slice(5)}</span></div>)}</div><div className="graph-slider"><span>7 days ago</span><Slider min={0} max={168} step={1} value={live ? 168 : hour} onChange={scrub} tooltip={{ formatter: value => `${value ?? 0}h into window` }} /><span>Now</span><Button size="small" type={live ? 'default' : 'primary'} onClick={goLive}>Go live</Button></div></div>
  </div>;
}
