// File: network-canvas.tsx
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Draw network topology and its selectable nodes.

import { useEffect, useMemo, useRef, useState } from 'react';
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from 'd3-force';

// One alert from the graph network endpoint; each becomes a dot on the canvas.
export interface NetworkEvent {
  alert_id: string;
  occurred_at: string;
  source_ip: string | null;
  host: string;
  mitre: string | null;
  severity: string;
  policy_tier: string;
  rule_description: string;
}

// What the user picked. The parent page uses the optional fields to filter its evidence query.
export type NetworkSelection = {
  kind: 'source' | 'host' | 'technique' | 'event' | 'edge';
  label: string;
  source_ip?: string;
  host?: string;
  mitre?: string;
  alert_id?: string;
};

// Node kinds: shared hubs (source, host, technique) and one dot per alert (event).
type Kind = 'source' | 'host' | 'technique' | 'event';
// Label modes: all shows every hub label; smart and hover show the active, neighboring or pointer-near hubs, and smart also
// labels the top hubs when nothing is focused.
type LabelDensity = 'smart' | 'hover' | 'all';

// A drawable node. Hubs accumulate counts across every alert that shares them; targetX and targetY are the layout position the
// force simulation pulls toward.
interface Node extends SimulationNodeDatum {
  id: string;
  kind: Kind;
  label: string;
  count: number;
  criticalCount: number;
  highCount: number;
  event?: NetworkEvent;
  targetX: number;
  targetY: number;
  x: number;
  y: number;
  isKeyNode: boolean;
  isTier0?: boolean;
}

// Edge between an alert dot and a hub.
interface Link extends SimulationLinkDatum<Node> {
  source: Node;
  target: Node;
}

// Computed layout plus adjacency (node id to linked node ids) used to highlight neighbors on hover or selection.
interface Layout {
  nodes: Node[];
  links: Link[];
  adjacency: Map<string, Set<string>>;
  bounds: { minX: number; minY: number; maxX: number; maxY: number };
}

// Fill color per node kind.
const colors: Record<Kind, string> = {
  source: '#38bdf8', // Sky cyan for adversary ingress
  technique: '#f59e0b', // Amber for MITRE ATT&CK tactics
  host: '#10b981', // Emerald green for protected enterprise hosts
  event: '#94a3b8', // Slate for event dots
};

// Small deterministic string hash (FNV-1a style) so each dot's jitter is the same on every render.
const hash = (s: string) =>
  [...s].reduce((n, c) => Math.imul(n ^ c.charCodeAt(0), 16777619) >>> 0, 2166136261);

// Name-based heuristic only: hosts whose names contain these markers are drawn as protected tier-0 assets. It is not read
// from the asset inventory.
function isTier0Host(host?: string): boolean {
  if (!host) return false;
  const h = host.toLowerCase();
  return (
    h.includes('dc01') ||
    h.includes('dc-') ||
    h.includes('domain') ||
    h.includes('ledger-prod') ||
    h.includes('bank-core') ||
    h.includes('treasury')
  );
}

// Deterministic layout: sources on the left, techniques in the middle, hosts on the right, each alert dot near the average of
// its hubs. A fixed 70-tick force simulation then relaxes overlaps synchronously; nothing animates.
function buildLayout(events: NetworkEvent[]): Layout {
  const nodes: Node[] = [];
  const links: Link[] = [];
  const entities = new Map<string, Node>();
  const adjacency = new Map<string, Set<string>>();

  // Finds or creates the shared hub for a source, host or technique and adds this alert to its severity counts.
  function entity(kind: Exclude<Kind, 'event'>, label: string, isCritical: boolean, isHigh: boolean): Node {
    const id = `${kind}:${label}`;
    let node = entities.get(id);
    if (!node) {
      node = {
        id,
        kind,
        label,
        count: 0,
        criticalCount: 0,
        highCount: 0,
        targetX: 0,
        targetY: 0,
        x: 0,
        y: 0,
        isKeyNode: false,
        isTier0: kind === 'host' ? isTier0Host(label) : false,
      };
      entities.set(id, node);
      nodes.push(node);
    }
    node.count++;
    if (isCritical) node.criticalCount++;
    if (isHigh) node.highCount++;
    return node;
  }

  // Records an undirected link and the adjacency used for highlighting.
  function connect(a: Node, b: Node) {
    links.push({ source: a, target: b });
    if (!adjacency.has(a.id)) adjacency.set(a.id, new Set());
    if (!adjacency.has(b.id)) adjacency.set(b.id, new Set());
    adjacency.get(a.id)!.add(b.id);
    adjacency.get(b.id)!.add(a.id);
  }

  for (const event of events) {
    const isCritical = event.severity === 'critical';
    const isHigh = event.severity === 'high';

    const dot: Node = {
      id: `event:${event.alert_id}`,
      kind: 'event',
      label: event.rule_description || 'Incident Event',
      count: 1,
      criticalCount: isCritical ? 1 : 0,
      highCount: isHigh ? 1 : 0,
      event,
      targetX: 0,
      targetY: 0,
      x: 0,
      y: 0,
      isKeyNode: false,
    };
    nodes.push(dot);

    if (event.source_ip) {
      connect(dot, entity('source', event.source_ip, isCritical, isHigh));
    }
    connect(dot, entity('host', event.host, isCritical, isHigh));
    if (event.mitre) {
      connect(dot, entity('technique', event.mitre, isCritical, isHigh));
    }
  }

  // Group entities by kind to assign structured compact 2D cluster coordinates
  const sources = Array.from(entities.values())
    .filter(n => n.kind === 'source')
    .sort((a, b) => b.criticalCount * 10 + b.highCount * 3 + b.count - (a.criticalCount * 10 + a.highCount * 3 + a.count));

  const techniques = Array.from(entities.values())
    .filter(n => n.kind === 'technique')
    .sort((a, b) => b.criticalCount * 10 + b.highCount * 3 + b.count - (a.criticalCount * 10 + a.highCount * 3 + a.count));

  const hosts = Array.from(entities.values())
    .filter(n => n.kind === 'host')
    .sort((a, b) => {
      // Prioritize Tier 0 assets at top of hierarchy
      if (a.isTier0 && !b.isTier0) return -1;
      if (!a.isTier0 && b.isTier0) return 1;
      return b.criticalCount * 10 + b.highCount * 3 + b.count - (a.criticalCount * 10 + a.highCount * 3 + a.count);
    });

  // Mark top 3 key nodes per category for smart priority labeling
  sources.slice(0, 3).forEach(n => (n.isKeyNode = true));
  techniques.slice(0, 3).forEach(n => (n.isKeyNode = true));
  hosts.slice(0, 4).forEach(n => (n.isKeyNode = true));

  // ─── 1. Ingress Sources: Multi-Column 2D Compact Cluster (X: -260 .. -140) ───
  const sourceColumns = sources.length > 12 ? 3 : sources.length > 5 ? 2 : 1;
  const sourceRowsPerCol = Math.ceil(sources.length / sourceColumns) || 1;
  const sourceRowHeight = Math.min(42, 240 / Math.max(sourceRowsPerCol, 1));
  const sourceColWidth = 52;

  sources.forEach((node, idx) => {
    const col = idx % sourceColumns;
    const row = Math.floor(idx / sourceColumns);
    const colOffset = (col - (sourceColumns - 1) / 2) * sourceColWidth;
    const rowOffset = (row - (sourceRowsPerCol - 1) / 2) * sourceRowHeight;

    node.targetX = -200 + colOffset;
    node.targetY = rowOffset + ((col % 2) * 8); // subtle staggering
    node.x = node.targetX;
    node.y = node.targetY;
  });

  // ─── 2. MITRE Techniques: Centered 2D Hub (X: -35 .. +35) ───────────────────
  const techColumns = techniques.length > 6 ? 2 : 1;
  const techRowsPerCol = Math.ceil(techniques.length / techColumns) || 1;
  const techRowHeight = Math.min(48, 200 / Math.max(techRowsPerCol, 1));
  const techColWidth = 50;

  techniques.forEach((node, idx) => {
    const col = idx % techColumns;
    const row = Math.floor(idx / techColumns);
    const colOffset = (col - (techColumns - 1) / 2) * techColWidth;
    const rowOffset = (row - (techRowsPerCol - 1) / 2) * techRowHeight;

    node.targetX = 0 + colOffset;
    node.targetY = rowOffset;
    node.x = node.targetX;
    node.y = node.targetY;
  });

  // ─── 3. Target Hosts: Multi-Column 2D Infrastructure Grid (X: +140 .. +260) ──
  const hostColumns = hosts.length > 12 ? 3 : hosts.length > 5 ? 2 : 1;
  const hostRowsPerCol = Math.ceil(hosts.length / hostColumns) || 1;
  const hostRowHeight = Math.min(42, 240 / Math.max(hostRowsPerCol, 1));
  const hostColWidth = 55;

  hosts.forEach((node, idx) => {
    const col = idx % hostColumns;
    const row = Math.floor(idx / hostColumns);
    const colOffset = (col - (hostColumns - 1) / 2) * hostColWidth;
    const rowOffset = (row - (hostRowsPerCol - 1) / 2) * hostRowHeight;

    node.targetX = 200 + colOffset;
    node.targetY = rowOffset + ((col % 2) * 8);
    node.x = node.targetX;
    node.y = node.targetY;
  });

  // ─── 4. Event Dots: Placed along curved transmission pathways ─────────────────
  for (const eventNode of nodes) {
    if (eventNode.kind === 'event') {
      const neighbors = Array.from(adjacency.get(eventNode.id) || [])
        .map(id => entities.get(id))
        .filter(Boolean) as Node[];

      if (neighbors.length > 0) {
        const avgX = neighbors.reduce((sum, n) => sum + n.targetX, 0) / neighbors.length;
        const avgY = neighbors.reduce((sum, n) => sum + n.targetY, 0) / neighbors.length;
        const seed = hash(eventNode.id);
        const jitterX = ((seed % 80) - 40) * 0.45;
        const jitterY = (((seed >>> 8) % 80) - 40) * 0.45;
        eventNode.targetX = avgX + jitterX;
        eventNode.targetY = avgY + jitterY;
        eventNode.x = eventNode.targetX;
        eventNode.y = eventNode.targetY;
      }
    }
  }

  // ─── 5. Run gentle D3 force simulation with 2D balance ─────────────────────────
  const simulation = forceSimulation<Node>(nodes)
    .force('x', forceX<Node>(n => n.targetX).strength(n => (n.kind === 'event' ? 0.35 : 0.85)))
    .force('y', forceY<Node>(n => n.targetY).strength(n => (n.kind === 'event' ? 0.35 : 0.85)))
    .force(
      'links',
      forceLink<Node, Link>(links)
        .id(n => n.id)
        .distance(l => (l.target.kind === 'event' ? 24 : 45))
        .strength(0.2)
    )
    .force('charge', forceManyBody<Node>().strength(n => (n.kind === 'event' ? -2.5 : -25)).distanceMax(180))
    .force('collide', forceCollide<Node>().radius(n => (n.kind === 'event' ? 3.5 : 18)).strength(0.8))
    .force('center', forceCenter(0, 0))
    .stop();

  for (let i = 0; i < 70; i++) simulation.tick();

  const xs = nodes.map(n => n.x);
  const ys = nodes.map(n => n.y);
  return {
    nodes,
    links,
    adjacency,
    bounds: {
      minX: Math.min(...xs, -260),
      minY: Math.min(...ys, -150),
      maxX: Math.max(...xs, 260),
      maxY: Math.max(...ys, 150),
    },
  };
}

// Interactive canvas of alerts and their shared hubs. It only draws and hit-tests the events it is given; selection is
// reported to the parent, which filters the evidence.
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
  // Pan and zoom live in a ref; the revision counter below forces a redraw after they change.
  const transform = useRef({ x: 0, y: 0, scale: 1 });
  const pointer = useRef<{ x: number; y: number; moved: boolean } | null>(null);
  const mouseWorldPos = useRef<{ x: number; y: number } | null>(null);

  const [hover, setHover] = useState<Node | null>(null);
  const [size, setSize] = useState({ width: 500, height: 600 });
  const [revision, setRevision] = useState(0);
  const [labelDensity, setLabelDensity] = useState<LabelDensity>('smart');

  // The layout is rebuilt only when the set of alert ids changes, so hover, selection and label mode never reshuffle nodes.
  const signature = events.map(item => item.alert_id).join('|');
  const layout = useMemo(() => buildLayout(events), [signature]);

  // Keeps the canvas size in sync with its container.
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

  // Centers the layout bounds in the container; the zoom is clamped to 0.45 to 1.4 times.
  function fit() {
    const { minX, minY, maxX, maxY } = layout.bounds;
    const spanX = Math.max(200, maxX - minX + 80);
    const spanY = Math.max(160, maxY - minY + 80);
    const scale = Math.min(1.4, Math.max(0.45, Math.min((size.width - 30) / spanX, (size.height - 50) / spanY)));
    transform.current = {
      x: size.width / 2 - ((minX + maxX) / 2) * scale,
      y: size.height / 2 - ((minY + maxY) / 2) * scale,
      scale,
    };
    setRevision(n => n + 1);
  }

  // Refit when the layout or the container size changes.
  useEffect(fit, [layout, size.width, size.height]);

  // Maps the parent's selection to a node id. A link selection highlights no single node.
  const selectedId =
    selected?.kind === 'event'
      ? `event:${selected.alert_id}`
      : selected?.kind === 'edge'
      ? null
      : selected
      ? `${selected.kind}:${selected.label}`
      : null;

  // Redraws on layout, size, hover, selection, label mode or revision changes (pan and zoom bump the revision).
  // Render Canvas
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

    const activeId = hover?.id || selectedId;
    const neighbors = activeId ? layout.adjacency.get(activeId) : null;
    const mPos = mouseWorldPos.current;
    const proximityRadius = 55 / scale; // Radius in world units for smart label reveal

    // ─── 1. Tier Headings ────────────────────────────────────────────────────────
    ctx.save();
    ctx.font = `700 ${10 / scale}px Inter, -apple-system, system-ui, sans-serif`;
    ctx.textAlign = 'center';

    ctx.fillStyle = 'rgba(56, 189, 248, 0.45)';
    ctx.fillText('INGRESS ADVERSARIES', -200, layout.bounds.minY - 20);

    ctx.fillStyle = 'rgba(245, 158, 11, 0.45)';
    ctx.fillText('MITRE ATT&CK TACTICS', 0, layout.bounds.minY - 20);

    ctx.fillStyle = 'rgba(16, 185, 129, 0.45)';
    ctx.fillText('PROTECTED ASSETS', 200, layout.bounds.minY - 20);
    ctx.restore();

    // ─── 2. Draw Curved Links ───────────────────────────────────────────────────
    for (const link of layout.links) {
      const a = link.source;
      const b = link.target;
      const isLit = activeId && (a.id === activeId || b.id === activeId);

      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      // Smooth organic quadratic curve
      const midX = (a.x + b.x) / 2;
      const midY = (a.y + b.y) / 2 + ((hash(a.id + b.id) % 20) - 10) * 0.3;
      ctx.quadraticCurveTo(midX, midY, b.x, b.y);

      if (isLit) {
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.9)';
        ctx.lineWidth = 1.6 / scale;
        ctx.stroke();
      } else {
        ctx.strokeStyle = 'rgba(100, 116, 139, 0.16)';
        ctx.lineWidth = 0.65 / scale;
        ctx.stroke();
      }
    }

    // ─── 3. Draw Event Dots ─────────────────────────────────────────────────────
    for (const node of layout.nodes) {
      if (node.kind !== 'event') continue;
      const isLit = !activeId || node.id === activeId || neighbors?.has(node.id);
      const isCritical = node.event?.severity === 'critical';
      const isHigh = node.event?.severity === 'high';
      const radius = isCritical ? 3.6 : isHigh ? 2.8 : 2.2;

      ctx.globalAlpha = isLit ? 1 : 0.15;
      ctx.fillStyle = isCritical ? '#f43f5e' : isHigh ? '#fb923c' : '#64748b';
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fill();

      if (node.id === activeId) {
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = 1.4 / scale;
        ctx.stroke();
      }
    }

    // ─── 4. Draw Major Entity Nodes (Sources, Techniques, Hosts) ─────────────────
    for (const node of layout.nodes) {
      if (node.kind === 'event') continue;
      const isLit = !activeId || node.id === activeId || neighbors?.has(node.id);
      const baseRadius = Math.min(12, 6.5 + Math.log2(node.count + 1) * 0.8);
      const nodeColor = colors[node.kind];

      ctx.globalAlpha = isLit ? 1 : 0.22;

      // Outer glow for critical/tier-0
      if (node.criticalCount > 0 || node.isTier0) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, baseRadius + 3 / scale, 0, Math.PI * 2);
        ctx.fillStyle = node.isTier0 ? 'rgba(16, 185, 129, 0.25)' : 'rgba(244, 63, 94, 0.25)';
        ctx.fill();
      }

      // Core circle
      ctx.fillStyle = nodeColor;
      ctx.beginPath();
      ctx.arc(node.x, node.y, baseRadius, 0, Math.PI * 2);
      ctx.fill();

      // Inner stroke
      ctx.strokeStyle = node.id === activeId ? '#ffffff' : 'rgba(15, 23, 42, 0.8)';
      ctx.lineWidth = (node.id === activeId ? 2.2 : 1.2) / scale;
      ctx.stroke();

      // Count numeral inside larger nodes
      if (node.count > 1 && baseRadius >= 8) {
        ctx.font = `700 ${8 / scale}px Inter, sans-serif`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillStyle = '#0f172a';
        ctx.fillText(String(node.count), node.x, node.y + 0.5 / scale);
      }
    }

    // ─── 5. Smart Proximity & Priority Badge Labels ─────────────────────────────
    // Decide which nodes should display full label badge to eliminate overcrowding
    for (const node of layout.nodes) {
      if (node.kind === 'event') continue;

      const isDirectlyActive = node.id === activeId;
      const isNeighborOfActive = neighbors?.has(node.id) ?? false;
      const isSelected = node.id === selectedId;

      // Mouse proximity calculation
      const distToMouse = mPos ? Math.hypot(node.x - mPos.x, node.y - mPos.y) : Infinity;
      const isInProximity = distToMouse <= proximityRadius;

      // Label visibility policy:
      // - Active/Selected/Neighbor nodes always show badge
      // - If mouse is in proximity, show badge
      // - If density is 'all', show badge
      // - If density is 'smart' and no active focus, show top key nodes only
      let shouldShowLabel = false;
      if (labelDensity === 'all') {
        shouldShowLabel = true;
      } else if (isDirectlyActive || isNeighborOfActive || isSelected) {
        shouldShowLabel = true;
      } else if (isInProximity) {
        shouldShowLabel = true;
      } else if (labelDensity === 'smart' && !activeId && node.isKeyNode) {
        shouldShowLabel = true;
      }

      if (!shouldShowLabel) continue;

      const isLit = !activeId || isDirectlyActive || isNeighborOfActive;
      ctx.globalAlpha = isLit ? 1 : 0.35;

      const nodeColor = colors[node.kind];
      const tier0Prefix = node.isTier0 ? '🛡️ ' : '';
      const labelText = `${tier0Prefix}${node.label} (${node.count})`;

      ctx.font = `600 ${10 / scale}px Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'alphabetic';

      const textMetrics = ctx.measureText(labelText);
      const badgeWidth = textMetrics.width + 12 / scale;
      const badgeHeight = 16 / scale;
      const baseRadius = Math.min(12, 6.5 + Math.log2(node.count + 1) * 0.8);
      const badgeX = node.x - badgeWidth / 2;
      const badgeY = node.y + baseRadius + 3.5 / scale;
      const borderRadius = 3.5 / scale;

      // Glassmorphic dark badge background
      ctx.fillStyle = isDirectlyActive ? 'rgba(15, 23, 42, 0.96)' : 'rgba(15, 23, 42, 0.88)';
      ctx.beginPath();
      if (typeof ctx.roundRect === 'function') {
        ctx.roundRect(badgeX, badgeY, badgeWidth, badgeHeight, borderRadius);
      } else {
        ctx.rect(badgeX, badgeY, badgeWidth, badgeHeight);
      }
      ctx.fill();

      // Badge border
      ctx.strokeStyle = isDirectlyActive ? '#ffffff' : isLit ? nodeColor : 'rgba(100, 116, 139, 0.35)';
      ctx.lineWidth = (isDirectlyActive ? 1.5 : 0.8) / scale;
      ctx.stroke();

      // Badge text
      ctx.fillStyle = isDirectlyActive ? '#ffffff' : isLit ? '#f8fafc' : '#94a3b8';
      ctx.fillText(labelText, node.x, badgeY + 11.5 / scale);
    }

    ctx.globalAlpha = 1;
  }, [layout, size, revision, hover, selectedId, labelDensity]);

  // Nearest node under the pointer in world coordinates (pan and zoom undone). Hubs have a larger pick radius than dots, and
  // the radius grows when zoomed out.
  function hit(clientX: number, clientY: number): Node | null {
    const bounds = canvas.current!.getBoundingClientRect();
    const { x, y, scale } = transform.current;
    const wx = (clientX - bounds.left - x) / scale;
    const wy = (clientY - bounds.top - y) / scale;
    let best: Node | null = null;
    let distance = Infinity;

    for (const node of layout.nodes) {
      const d = Math.hypot(node.x - wx, node.y - wy);
      const threshold = node.kind === 'event' ? Math.max(6, 8 / scale) : Math.max(16, 20 / scale);
      if (d < threshold && d < distance) {
        best = node;
        distance = d;
      }
    }
    return best;
  }

  // Tracks the pointer in world coordinates for the proximity label reveal.
  function updateMouseWorld(clientX: number, clientY: number) {
    if (!canvas.current) return;
    const bounds = canvas.current.getBoundingClientRect();
    const { x, y, scale } = transform.current;
    mouseWorldPos.current = {
      x: (clientX - bounds.left - x) / scale,
      y: (clientY - bounds.top - y) / scale,
    };
  }

  // Reports a click to the parent: hubs carry the field it filters on (source_ip, host or mitre), dots carry the alert id.
  function select(node: Node) {
    if (node.kind === 'event') {
      onSelect({ kind: 'event', label: node.label, alert_id: node.event!.alert_id });
    } else {
      onSelect({
        kind: node.kind,
        label: node.label,
        ...(node.kind === 'source'
          ? { source_ip: node.label }
          : node.kind === 'host'
          ? { host: node.label }
          : { mitre: node.label }),
      });
    }
  }

  return (
    <div ref={wrapper} className="graph-network-wrap">
      <canvas
        ref={canvas}
        className="graph-network-surface"
        aria-label="Attack relationship topology network"
        onPointerDown={event => {
          pointer.current = { x: event.clientX, y: event.clientY, moved: false };
          event.currentTarget.setPointerCapture(event.pointerId);
        }}
        onPointerMove={event => {
          updateMouseWorld(event.clientX, event.clientY);
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
            const h = hit(event.clientX, event.clientY);
            setHover(h);
            setRevision(n => n + 1); // trigger proximity highlight
          }
        }}
        onPointerUp={event => {
          if (pointer.current && !pointer.current.moved) {
            const node = hit(event.clientX, event.clientY);
            if (node) select(node);
          }
          pointer.current = null;
        }}
        onPointerLeave={() => {
          pointer.current = null;
          mouseWorldPos.current = null;
          setHover(null);
          setRevision(n => n + 1);
        }}
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

      {/* Top Right Zoom & Smart Label Density Controls */}
      <div className="graph-network-tools">
        <button
          className="graph-density-toggle-btn"
          onClick={() => {
            setLabelDensity(prev => (prev === 'smart' ? 'hover' : prev === 'hover' ? 'all' : 'smart'));
          }}
          title="Toggle label density: Smart (Proximity) / Hover Only / Show All"
        >
          {labelDensity === 'smart' ? '🏷️ Smart' : labelDensity === 'hover' ? '🎯 Proximity' : '📋 All'}
        </button>
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

      {/* Clean Bottom-Left Legend & Interactive Tip */}
      <div className="graph-network-legend">
        <span>
          <i className="source" /> Ingress IP
        </span>
        <span>
          <i className="technique" /> MITRE ATT&amp;CK
        </span>
        <span>
          <i className="host" /> Host Asset
        </span>
        <span>
          <i className="critical" /> Critical
        </span>
        <span className="legend-hover-tip">💡 Hover near nodes to reveal names</span>
      </div>

      {/* Rich Floating Dossier Tooltip */}
      {hover && (
        <div className="graph-network-tooltip">
          <div className="tooltip-badge-row">
            <span className={`tooltip-kind-tag ${hover.kind}`}>{hover.kind.toUpperCase()}</span>
            {hover.isTier0 && <span className="tooltip-tier0-tag">TIER-0 PROTECTED</span>}
          </div>
          <div className="tooltip-title">{hover.label}</div>
          {hover.kind !== 'event' ? (
            <div className="tooltip-stats">
              <span>
                <strong>{hover.count}</strong> total alerts
              </span>
              {hover.criticalCount > 0 && <span className="stat-crit">🔴 {hover.criticalCount} crit</span>}
              {hover.highCount > 0 && <span className="stat-high">🟠 {hover.highCount} high</span>}
            </div>
          ) : (
            <div className="tooltip-stats">
              <span>Severity: {hover.event?.severity?.toUpperCase() || 'INFO'}</span>
              <span>Host: {hover.event?.host}</span>
            </div>
          )}
          <div className="tooltip-action-hint">⚡ Click to filter incident queue</div>
        </div>
      )}
    </div>
  );
}
