// File: investigation-graph.tsx
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Render relationships between incident evidence and investigation entities.

import { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Empty, Input, Select, Slider, Spin } from 'antd';
import { ArrowLeftOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { NetworkCanvas, type NetworkEvent, type NetworkSelection } from '../network-canvas';
import { api } from '../api';
import { date, ErrorPanel } from '../components';
import { useSession } from '../context';

// Milliseconds per hour and per week; the graph always covers the seven days before its anchor time.
const HOUR = 3600000;
// One week in milliseconds.
const WEEK = 7 * 24 * HOUR;

// Response shapes for the investigation graph: aggregated nodes and edges, per-alert evidence pages, and the alert dots
// drawn on the canvas.
interface GraphNode { id: string; kind: 'source' | 'host'; label: string; event_count: number; critical_count: number; local_test?: boolean }
// Aggregated source-to-host relationship with its event counts, first and last seen times and techniques.
interface GraphEdge { id: string; source: string; target: string; source_ip: string; host: string; event_count: number; critical_count: number; first_seen: string; last_seen: string; techniques: string[]; relationship: string }
// Graph summary for the window: nodes, edges and daily event counts.
interface GraphSnapshot { from: string; until: string; total_events: number; investigated_events: number; nodes: GraphNode[]; edges: GraphEdge[]; daily_counts: Array<{ day: string; event_count: number }>; hidden_relationships: number; note: string }
// One alert in the evidence pane, including its raw event.
interface GraphEvent { alert_id: string; incident_id: string | null; occurred_at: string; ingested_at: string; source_ip: string | null; host: string; rule_description: string; mitre: string | null; level: number; severity: string; policy_tier: string; campaign_id: string | null; raw_event: string }
// One page of evidence events.
interface EvidencePage { total: number; events: GraphEvent[]; limit: number; offset: number }
// Alert dots for the canvas; truncated is set when the server returned fewer than the total (the page says so).
interface NetworkPage { total_events: number; shown_events: number; truncated: boolean; events: NetworkEvent[] }

// Attack network page for the signed-in organization. Lines connect alerts that share a source, host or technique;
// they show shared evidence fields and are not attacker attribution (the page note says so).
export default function InvestigationGraph() {
  const { orgId } = useSession();
  const [anchor, setAnchor] = useState(() => Date.now());
  const [live, setLive] = useState(true);
  const [hour, setHour] = useState(168);
  const [policy, setPolicy] = useState('all');
  const [search, setSearch] = useState('');
  const [selected, setSelected] = useState<NetworkSelection | null>(null);
  const [offset, setOffset] = useState(0);

  // In live mode the anchor advances every 5 seconds so the window and queries slide forward. A scrubbed (paused)
  // window keeps a fixed anchor, so its time range and cached results stay stable.
  useEffect(() => {
    if (!live) return;
    const timer = window.setInterval(() => setAnchor(Date.now()), 5000);
    return () => window.clearInterval(timer);
  }, [live]);

  // The window starts seven days before the anchor; live mode ends at the anchor, scrubbing ends the chosen number of
  // hours after the window start.
  const from = new Date(anchor - WEEK).toISOString();
  const until = new Date(live ? anchor : anchor - WEEK + hour * HOUR).toISOString();
  const windowQuery = new URLSearchParams({ from, until, policy });
  // Query keys include the window and policy filter so each distinct window is cached separately; both wait for an organization.
  const graph = useQuery({ queryKey: ['investigation-graph', orgId, from, until, policy], queryFn: () => api<GraphSnapshot>(`/investigation/graph?${windowQuery}`, orgId), enabled: Boolean(orgId) });
  const network = useQuery({ queryKey: ['investigation-network', orgId, from, until, policy], queryFn: () => api<NetworkPage>(`/investigation/graph/network?${windowQuery}`, orgId), enabled: Boolean(orgId) });
  // Evidence is paged ten at a time and narrowed by whatever the current selection carries (source, host, technique or alert).
  const evidenceQuery = new URLSearchParams({ from, until, policy, limit: '10', offset: String(offset) });
  if (selected?.source_ip) evidenceQuery.set('source_ip', selected.source_ip);
  if (selected?.host) evidenceQuery.set('host', selected.host);
  if (selected?.mitre) evidenceQuery.set('mitre', selected.mitre);
  if (selected?.alert_id) evidenceQuery.set('alert_id', selected.alert_id);
  const evidence = useQuery({ queryKey: ['graph-evidence', orgId, selected, from, until, policy, offset], queryFn: () => api<EvidencePage>(`/investigation/graph/evidence?${evidenceQuery}`, orgId), enabled: Boolean(orgId && selected) });

  // Search filters the data already loaded in the browser; it does not query the server again.
  const relationships = useMemo(() => {
    const term = search.trim().toLowerCase();
    return (graph.data?.edges || []).filter(edge => !term || [edge.source_ip, edge.host, ...edge.techniques].some(value => value.toLowerCase().includes(term)));
  }, [graph.data, search]);

  const visibleEvents = useMemo(() => {
    const term = search.trim().toLowerCase();
    return (network.data?.events || []).filter(event => !term || [event.source_ip, event.host, event.mitre, event.rule_description, event.alert_id].some(value => value?.toLowerCase().includes(term)));
  }, [network.data, search]);

  // Always eight UTC days from the day of the window start, with zero for days that have no recorded events.
  const dayCounts = useMemo(() => {
    const recorded = new Map((graph.data?.daily_counts || []).map(item => [item.day, item.event_count]));
    const first = new Date(from);
    first.setUTCHours(0, 0, 0, 0);
    return Array.from({ length: 8 }, (_, index) => {
      const day = new Date(first.getTime() + index * 24 * HOUR).toISOString().slice(0, 10);
      return { day, event_count: recorded.get(day) || 0 };
    });
  }, [graph.data?.daily_counts, from]);
  // Never below 1 so the bar heights cannot divide by zero.
  const maxDay = Math.max(1, ...dayCounts.map(item => item.event_count));

  // Selecting a different item restarts evidence paging.
  function choose(value: NetworkSelection) { setSelected(value); setOffset(0); }
  // Moving the timeline pauses live updates and clears the selection so evidence cannot belong to another window.
  function scrub(value: number) { setLive(false); setHour(value); setSelected(null); setOffset(0); }
  // Returns to the live seven-day window and clears the selection and paging.
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
