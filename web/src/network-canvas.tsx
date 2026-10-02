import { useEffect, useMemo, useRef, useState } from 'react';
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY, type SimulationLinkDatum, type SimulationNodeDatum } from 'd3-force';

export interface NetworkEvent {
  alert_id: string; occurred_at: string; source_ip: string | null; host: string;
  mitre: string | null; severity: string; policy_tier: string; rule_description: string;
}
export type NetworkSelection = { kind: 'source' | 'host' | 'technique' | 'event' | 'edge'; label: string; source_ip?: string; host?: string; mitre?: string; alert_id?: string };

type Kind = 'source' | 'host' | 'technique' | 'event';
interface Node extends SimulationNodeDatum {
  id: string;
  kind: Kind;
  label: string;
  count: number;
  event?: NetworkEvent;
  targetX: number;
  targetY: number;
  x: number;
  y: number;
}
interface Link extends SimulationLinkDatum<Node> { source: Node; target: Node }
interface Layout { nodes: Node[]; links: Link[]; adjacency: Map<string, Set<string>>; bounds: { minX: number; minY: number; maxX: number; maxY: number } }

const colors: Record<Kind, string> = {
  source: '#38bdf8',     // Sky cyan for adversary ingress
  technique: '#f59e0b',  // Amber for MITRE ATT&CK tactics
  host: '#10b981',       // Emerald green for protected company hosts
  event: '#94a3b8',      // Slate for event dots
};

const hash = (s: string) => [...s].reduce((n, c) => Math.imul(n ^ c.charCodeAt(0), 16777619) >>> 0, 2166136261);

function buildLayout(events: NetworkEvent[]): Layout {
  const nodes: Node[] = [];
  const links: Link[] = [];
  const entities = new Map<string, Node>();
  const adjacency = new Map<string, Set<string>>();

  function entity(kind: Exclude<Kind, 'event'>, label: string): Node {
    const id = `${kind}:${label}`;
    let node = entities.get(id);
    if (!node) {
      node = { id, kind, label, count: 0, targetX: 0, targetY: 0, x: 0, y: 0 };
      entities.set(id, node);
      nodes.push(node);
    }
    node.count++;
    return node;
  }

  function connect(a: Node, b: Node) {
    links.push({ source: a, target: b });
    if (!adjacency.has(a.id)) adjacency.set(a.id, new Set());
    if (!adjacency.has(b.id)) adjacency.set(b.id, new Set());
    adjacency.get(a.id)!.add(b.id);
    adjacency.get(b.id)!.add(a.id);
  }

  for (const event of events) {
    const dot: Node = {
      id: `event:${event.alert_id}`,
      kind: 'event',
      label: event.rule_description,
      count: 1,
      event,
      targetX: 0,
      targetY: 0,
      x: 0,
      y: 0,
    };
    nodes.push(dot);
    if (event.source_ip) connect(dot, entity('source', event.source_ip));
    connect(dot, entity('host', event.host));
    if (event.mitre) connect(dot, entity('technique', event.mitre));
  }

  // Group entities by kind to assign structured 3-tier coordinates
  const sources = Array.from(entities.values()).filter(n => n.kind === 'source').sort((a, b) => b.count - a.count);
  const techniques = Array.from(entities.values()).filter(n => n.kind === 'technique').sort((a, b) => b.count - a.count);
  const hosts = Array.from(entities.values()).filter(n => n.kind === 'host').sort((a, b) => b.count - a.count);

  // Position sources on Left tier (x: -180) with generous 56px vertical spacing
  const sourceGap = 58;
  sources.forEach((node, idx) => {
    node.targetX = -180;
    node.targetY = (idx - (sources.length - 1) / 2) * sourceGap;
    node.x = node.targetX;
    node.y = node.targetY;
  });

  // Position techniques in Center tier (x: 0) with generous 56px vertical spacing
  const techGap = 58;
  techniques.forEach((node, idx) => {
    node.targetX = 0;
    node.targetY = (idx - (techniques.length - 1) / 2) * techGap;
    node.x = node.targetX;
    node.y = node.targetY;
  });

  // Position company hosts grouped on Right tier (x: +180) with generous 56px vertical spacing
  const hostGap = 58;
  hosts.forEach((node, idx) => {
    node.targetX = 180;
    node.targetY = (idx - (hosts.length - 1) / 2) * hostGap;
    node.x = node.targetX;
    node.y = node.targetY;
  });

  // Position event dots near the pathway between connected entities
  for (const eventNode of nodes) {
    if (eventNode.kind === 'event') {
      const neighbors = Array.from(adjacency.get(eventNode.id) || []).map(id => entities.get(id)).filter(Boolean) as Node[];
      if (neighbors.length > 0) {
        const avgX = neighbors.reduce((sum, n) => sum + n.targetX, 0) / neighbors.length;
        const avgY = neighbors.reduce((sum, n) => sum + n.targetY, 0) / neighbors.length;
        const seed = hash(eventNode.id);
        const jitterX = ((seed % 100) - 50) * 0.35;
        const jitterY = (((seed >>> 8) % 100) - 50) * 0.35;
        eventNode.targetX = avgX + jitterX;
        eventNode.targetY = avgY + jitterY;
        eventNode.x = eventNode.targetX;
        eventNode.y = eventNode.targetY;
      }
    }
  }

  // Run guided force simulation with strict anchor constraints
  const simulation = forceSimulation<Node>(nodes)
    .force('x', forceX<Node>(n => n.targetX).strength(n => n.kind === 'event' ? 0.3 : 0.95))
    .force('y', forceY<Node>(n => n.targetY).strength(n => n.kind === 'event' ? 0.2 : 0.9))
    .force('links', forceLink<Node, Link>(links).id(n => n.id).distance(l => l.target.kind === 'event' ? 20 : 40).strength(0.25))
    .force('charge', forceManyBody<Node>().strength(n => n.kind === 'event' ? -3 : -20).distanceMax(140))
    .force('collide', forceCollide<Node>().radius(n => n.kind === 'event' ? 3.5 : 24).strength(0.85))
    .force('center', forceCenter(0, 0))
    .stop();

  for (let i = 0; i < 80; i++) simulation.tick();

  const xs = nodes.map(n => n.x);
  const ys = nodes.map(n => n.y);
  return {
    nodes,
    links,
    adjacency,
    bounds: {
      minX: Math.min(...xs, -240),
      minY: Math.min(...ys, -180),
      maxX: Math.max(...xs, 240),
      maxY: Math.max(...ys, 180),
    },
  };
}

export function NetworkCanvas({
  events,
  selected,
  onSelect,
}: {
  events: NetworkEvent[];
  selected: NetworkSelection | null;
  onSelect: (value: NetworkSelection) => void;
}) {
  const canvas = useRef<HTMLCanvasElement>(null);
  const wrapper = useRef<HTMLDivElement>(null);
  const transform = useRef({ x: 0, y: 0, scale: 1 });
  const pointer = useRef<{ x: number; y: number; moved: boolean } | null>(null);
  const [hover, setHover] = useState<Node | null>(null);
  const [size, setSize] = useState({ width: 500, height: 600 });
  const [revision, setRevision] = useState(0);

  const signature = events.map(item => item.alert_id).join('|');
  const layout = useMemo(() => buildLayout(events), [signature]);

  useEffect(() => {
    if (!wrapper.current) return;
    const observer = new ResizeObserver(entries => {
      if (entries[0]) {
        setSize({ width: entries[0].contentRect.width, height: entries[0].contentRect.height });
      }
    });
    observer.observe(wrapper.current);
    return () => observer.disconnect();
  }, []);

  function fit() {
    const { minX, minY, maxX, maxY } = layout.bounds;
    const spanX = Math.max(160, maxX - minX + 80);
    const spanY = Math.max(140, maxY - minY + 80);
    const scale = Math.min(1.5, Math.max(0.4, Math.min((size.width - 30) / spanX, (size.height - 50) / spanY)));
    transform.current = {
      x: size.width / 2 - ((minX + maxX) / 2) * scale,
      y: size.height / 2 - ((minY + maxY) / 2) * scale,
      scale,
    };
    setRevision(n => n + 1);
  }

  useEffect(fit, [layout, size.width, size.height]);

  const selectedId =
    selected?.kind === 'event'
      ? `event:${selected.alert_id}`
      : selected?.kind === 'edge'
      ? null
      : selected
      ? `${selected.kind}:${selected.label}`
      : null;

  useEffect(() => {
    const surface = canvas.current;
    if (!surface) return;
    const dpr = window.devicePixelRatio || 1;
    surface.width = Math.round(size.width * dpr);
    surface.height = Math.round(size.height * dpr);
    const ctx = surface.getContext('2d');
    if (!ctx) return;
    ctx.scale(dpr, dpr);

    const { x, y, scale } = transform.current;
    ctx.translate(x, y);
    ctx.scale(scale, scale);

    const active = hover?.id || selectedId;
    const neighbors = active ? layout.adjacency.get(active) : null;

    // Tier Headers
    ctx.save();
    ctx.font = `600 ${9.5 / scale}px Inter, system-ui, sans-serif`;
    ctx.textAlign = 'center';
    ctx.fillStyle = 'rgba(56, 189, 248, 0.4)';
    ctx.fillText('INGRESS SOURCE', -180, layout.bounds.minY - 18);
    ctx.fillStyle = 'rgba(245, 158, 11, 0.4)';
    ctx.fillText('MITRE ATT&CK', 0, layout.bounds.minY - 18);
    ctx.fillStyle = 'rgba(16, 185, 129, 0.4)';
    ctx.fillText('PROTECTED ASSETS', 180, layout.bounds.minY - 18);
    ctx.restore();

    // Draw Links
    for (const link of layout.links) {
      const a = link.source;
      const b = link.target;
      const lit = active && (a.id === active || b.id === active);
      ctx.strokeStyle = lit ? 'rgba(56, 189, 248, 0.85)' : 'rgba(100, 116, 139, 0.22)';
      ctx.lineWidth = lit ? 1.4 / scale : 0.65 / scale;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }

    // Draw Event Dots
    for (const node of layout.nodes) {
      if (node.kind !== 'event') continue;
      const lit = !active || node.id === active || neighbors?.has(node.id);
      const isCritical = node.event?.severity === 'critical';
      const isHigh = node.event?.severity === 'high';
      const radius = isCritical ? 3.8 : isHigh ? 3.0 : 2.4;

      ctx.globalAlpha = lit ? 1 : 0.18;
      ctx.fillStyle = isCritical ? '#f43f5e' : isHigh ? '#fb923c' : '#64748b';
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fill();

      if (node.id === active) {
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.4 / scale;
        ctx.stroke();
      }
    }

    // Draw Major Entity Nodes (Sources, Techniques, Hosts)
    for (const node of layout.nodes) {
      if (node.kind === 'event') continue;
      const lit = !active || node.id === active || neighbors?.has(node.id);
      const radius = Math.min(11, 6 + Math.log2(node.count + 1) * 0.7);

      ctx.globalAlpha = lit ? 1 : 0.25;
      const nodeColor = colors[node.kind];

      // Outer circle
      ctx.fillStyle = nodeColor;
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fill();

      if (node.id === active) {
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 2 / scale;
        ctx.stroke();
      }

      // Draw Badge Label
      const label = `${node.label} (${node.count})`;
      ctx.font = `600 ${10.5 / scale}px Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`;
      ctx.textAlign = 'center';
      const textMetrics = ctx.measureText(label);
      const textWidth = textMetrics.width;
      const badgeHeight = 17 / scale;
      const badgeWidth = textWidth + 12 / scale;
      const badgeX = node.x - badgeWidth / 2;
      const badgeY = node.y + radius + 3.5 / scale;
      const borderRadius = 3.5 / scale;

      // Badge background
      ctx.fillStyle = 'rgba(15, 23, 42, 0.92)';
      ctx.beginPath();
      if (typeof ctx.roundRect === 'function') {
        ctx.roundRect(badgeX, badgeY, badgeWidth, badgeHeight, borderRadius);
      } else {
        ctx.rect(badgeX, badgeY, badgeWidth, badgeHeight);
      }
      ctx.fill();

      // Badge border
      ctx.strokeStyle = lit ? nodeColor : 'rgba(100, 116, 139, 0.35)';
      ctx.lineWidth = 1 / scale;
      ctx.stroke();

      // Badge text
      ctx.fillStyle = lit ? '#f8fafc' : '#94a3b8';
      ctx.fillText(label, node.x, badgeY + 12 / scale);
    }

    ctx.globalAlpha = 1;
  }, [layout, size, revision, hover, selectedId]);

  function hit(clientX: number, clientY: number): Node | null {
    const bounds = canvas.current!.getBoundingClientRect();
    const { x, y, scale } = transform.current;
    const wx = (clientX - bounds.left - x) / scale;
    const wy = (clientY - bounds.top - y) / scale;
    let best: Node | null = null;
    let distance = Infinity;

    for (const node of layout.nodes) {
      const d = Math.hypot(node.x - wx, node.y - wy);
      const threshold = node.kind === 'event' ? Math.max(6, 7 / scale) : Math.max(16, 18 / scale);
      if (d < threshold && d < distance) {
        best = node;
        distance = d;
      }
    }
    return best;
  }

  function select(node: Node) {
    if (node.kind === 'event') {
      onSelect({ kind: 'event', label: node.label, alert_id: node.event!.alert_id });
    } else {
      onSelect({
        kind: node.kind,
        label: node.label,
        ...(node.kind === 'source' ? { source_ip: node.label } : node.kind === 'host' ? { host: node.label } : { mitre: node.label }),
      });
    }
  }

  return (
    <div ref={wrapper} className="graph-network-wrap">
      <canvas
        ref={canvas}
        className="graph-network-surface"
        aria-label="Attack topology network"
        onPointerDown={event => {
          pointer.current = { x: event.clientX, y: event.clientY, moved: false };
          event.currentTarget.setPointerCapture(event.pointerId);
        }}
        onPointerMove={event => {
          if (pointer.current) {
            const dx = event.clientX - pointer.current.x;
            const dy = event.clientY - pointer.current.y;
            if (Math.abs(dx) + Math.abs(dy) > 2) pointer.current.moved = true;
            transform.current.x += dx;
            transform.current.y += dy;
            pointer.current.x = event.clientX;
            pointer.current.y = event.clientY;
            setRevision(n => n + 1);
          } else {
            setHover(hit(event.clientX, event.clientY));
          }
        }}
        onPointerUp={event => {
          if (pointer.current && !pointer.current.moved) {
            const node = hit(event.clientX, event.clientY);
            if (node) select(node);
          }
          pointer.current = null;
        }}
        onPointerLeave={() => setHover(null)}
        onWheel={event => {
          event.preventDefault();
          const bounds = event.currentTarget.getBoundingClientRect();
          const px = event.clientX - bounds.left;
          const py = event.clientY - bounds.top;
          const t = transform.current;
          const next = Math.max(0.3, Math.min(4, t.scale * (event.deltaY < 0 ? 1.12 : 0.89)));
          t.x = px - ((px - t.x) * next) / t.scale;
          t.y = py - ((py - t.y) * next) / t.scale;
          t.scale = next;
          setRevision(n => n + 1);
        }}
      />
      <div className="graph-network-tools">
        <button
          onClick={() => {
            transform.current.scale = Math.min(4, transform.current.scale * 1.25);
            setRevision(n => n + 1);
          }}
          title="Zoom in"
        >
          +
        </button>
        <button
          onClick={() => {
            transform.current.scale = Math.max(0.3, transform.current.scale / 1.25);
            setRevision(n => n + 1);
          }}
          title="Zoom out"
        >
          −
        </button>
        <button onClick={fit} title="Fit network">
          Fit
        </button>
      </div>

      {/* Clean Bottom-Left Legend */}
      <div className="graph-network-legend">
        <span><i className="source" /> Ingress IP</span>
        <span><i className="technique" /> MITRE</span>
        <span><i className="host" /> Host Asset</span>
        <span><i className="critical" /> Critical</span>
      </div>

      {hover && (
        <div className="graph-network-tooltip">
          <strong>{hover.kind.toUpperCase()}</strong> · {hover.label}
          {hover.kind !== 'event' ? ` · ${hover.count} alerts` : ''}
        </div>
      )}
    </div>
  );
}
