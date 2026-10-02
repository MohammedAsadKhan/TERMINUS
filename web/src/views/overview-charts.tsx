import { useMemo, useState } from 'react';
import { Tag, Tooltip } from 'antd';
import { ArrowUpOutlined, DeploymentUnitOutlined, FireOutlined, LineChartOutlined } from '@ant-design/icons';
import type { Incident } from '../types';

interface ChartPoint {
  label: string;
  timeLabel: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  x: number;
  y: number;
}

export function ThreatVelocityChart({ incidents }: { incidents: Incident[] }) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  const { points, totalCritical, totalHigh, totalMedium, totalLow, peakRate } = useMemo(() => {
    const totalCritical = incidents.filter(i => i.severity === 'critical').length;
    const totalHigh = incidents.filter(i => i.severity === 'high').length;
    const totalMedium = incidents.filter(i => i.severity === 'medium').length;
    const totalLow = incidents.filter(i => i.severity === 'low').length;

    // Create 6 continuous time buckets across the observed telemetry
    const bucketCount = 6;
    const buckets: Array<{ label: string; timeLabel: string; count: number; critical: number; high: number; medium: number; low: number }> = [];

    const now = Date.now();
    const times = incidents
      .map(i => Date.parse(i.created_at || i.timestamp))
      .filter(t => Number.isFinite(t))
      .sort((a, b) => a - b);

    const minTime = times.length > 0 ? Math.min(times[0], now - 86400000) : now - 86400000;
    const maxTime = Math.max(now, times.length > 0 ? times[times.length - 1] : now);
    const span = Math.max(maxTime - minTime, 3600000);
    const step = span / bucketCount;

    for (let i = 0; i < bucketCount; i++) {
      const bStart = minTime + i * step;
      const bEnd = bStart + step;
      const d = new Date(bEnd);
      const timeLabel = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
      const label = `T-${bucketCount - i - 1}`;

      const inBucket = incidents.filter(item => {
        const t = Date.parse(item.created_at || item.timestamp);
        if (!Number.isFinite(t)) return i === bucketCount - 1;
        return t >= bStart && (i === bucketCount - 1 ? t <= bEnd : t < bEnd);
      });

      buckets.push({
        label,
        timeLabel,
        count: inBucket.length,
        critical: inBucket.filter(b => b.severity === 'critical').length,
        high: inBucket.filter(b => b.severity === 'high').length,
        medium: inBucket.filter(b => b.severity === 'medium').length,
        low: inBucket.filter(b => b.severity === 'low').length,
      });
    }

    const maxCount = Math.max(...buckets.map(b => b.count), 1);
    const width = 360;
    const height = 90;
    const paddingX = 24;
    const paddingY = 16;

    const chartPoints: ChartPoint[] = buckets.map((b, idx) => {
      const x = paddingX + (idx / (bucketCount - 1)) * (width - paddingX * 2);
      const y = height - paddingY - (b.count / maxCount) * (height - paddingY * 2);
      return { ...b, x, y };
    });

    const peakRate = Math.max(...buckets.map(b => b.count));

    return {
      points: chartPoints,
      totalCritical,
      totalHigh,
      totalMedium,
      totalLow,
      peakRate,
    };
  }, [incidents]);

  // Generate smooth SVG path
  const areaPath = useMemo(() => {
    if (points.length < 2) return '';
    const first = points[0];
    const last = points[points.length - 1];
    let d = `M ${first.x} ${first.y}`;
    for (let i = 1; i < points.length; i++) {
      const p = points[i];
      const prev = points[i - 1];
      const cx1 = prev.x + (p.x - prev.x) / 2;
      const cy1 = prev.y;
      const cx2 = prev.x + (p.x - prev.x) / 2;
      const cy2 = p.y;
      d += ` C ${cx1} ${cy1}, ${cx2} ${cy2}, ${p.x} ${p.y}`;
    }
    const bottom = 90 - 16;
    d += ` L ${last.x} ${bottom} L ${first.x} ${bottom} Z`;
    return d;
  }, [points]);

  const linePath = useMemo(() => {
    if (points.length < 2) return '';
    let d = `M ${points[0].x} ${points[0].y}`;
    for (let i = 1; i < points.length; i++) {
      const p = points[i];
      const prev = points[i - 1];
      const cx1 = prev.x + (p.x - prev.x) / 2;
      const cy1 = prev.y;
      const cx2 = prev.x + (p.x - prev.x) / 2;
      const cy2 = p.y;
      d += ` C ${cx1} ${cy1}, ${cx2} ${cy2}, ${p.x} ${p.y}`;
    }
    return d;
  }, [points]);

  return (
    <div className="overview-graph-card" aria-label="Threat Influx Velocity">
      <div className="graph-card-header">
        <div className="graph-card-title">
          <LineChartOutlined style={{ color: 'var(--accent)' }} />
          <span>Threat Ingestion Velocity</span>
        </div>
        <div className="graph-card-metric">
          <strong>{incidents.length}</strong>
          <small>events</small>
        </div>
      </div>

      <div className="graph-card-stats-row">
        <span className="stat-badge critical"><FireOutlined /> {totalCritical} Critical</span>
        <span className="stat-badge high">{totalHigh} High</span>
        <span className="stat-badge medium">{totalMedium} Medium</span>
        {totalLow > 0 && <span className="stat-badge low">{totalLow} Low</span>}
        <span className="stat-badge peak"><ArrowUpOutlined /> Peak: {peakRate}/bucket</span>
      </div>

      <div className="graph-svg-container">
        <svg viewBox="0 0 360 90" className="velocity-svg" preserveAspectRatio="none">
          <defs>
            <linearGradient id="velocityGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.45" />
              <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line x1="24" y1="16" x2="336" y2="16" stroke="var(--line)" strokeDasharray="3 3" opacity="0.6" />
          <line x1="24" y1="45" x2="336" y2="45" stroke="var(--line)" strokeDasharray="3 3" opacity="0.6" />
          <line x1="24" y1="74" x2="336" y2="74" stroke="var(--line)" opacity="0.9" />

          {/* Area and Line */}
          {areaPath && <path d={areaPath} fill="url(#velocityGrad)" />}
          {linePath && <path d={linePath} fill="none" stroke="var(--accent)" strokeWidth="2.5" strokeLinecap="round" />}

          {/* Interactive points */}
          {points.map((p, idx) => (
            <g key={idx} onMouseEnter={() => setHoveredIndex(idx)} onMouseLeave={() => setHoveredIndex(null)}>
              <circle
                cx={p.x}
                cy={p.y}
                r={hoveredIndex === idx ? 5 : 3.5}
                fill={hoveredIndex === idx ? '#fff' : 'var(--accent)'}
                stroke="var(--surface)"
                strokeWidth="2"
                style={{ cursor: 'pointer', transition: 'r 0.15s ease' }}
              />
              {hoveredIndex === idx && (
                <text x={p.x} y={Math.max(p.y - 8, 12)} textAnchor="middle" fill="var(--ink)" fontSize="10" fontWeight="600">
                  {p.count}
                </text>
              )}
            </g>
          ))}
        </svg>
      </div>

      <div className="graph-time-labels">
        {points.map((p, idx) => (
          <span key={idx} style={{ opacity: hoveredIndex === idx ? 1 : 0.65, color: hoveredIndex === idx ? 'var(--accent)' : 'inherit' }}>
            {p.timeLabel}
          </span>
        ))}
      </div>
    </div>
  );
}

export function AttackSurfaceMatrix({ incidents }: { incidents: Incident[] }) {
  const { techniques, topHosts, totalTagged } = useMemo(() => {
    const techCounts: Record<string, { count: number; name: string; severities: Record<string, number> }> = {};
    const hostCounts: Record<string, { count: number; critical: number; high: number }> = {};

    incidents.forEach(item => {
      // Extract MITRE technique
      const rawMitre = item.mitre || item.rule_description?.match(/T\d{4}/)?.[0] || 'T1190';
      const mList = Array.isArray(rawMitre) ? rawMitre : [rawMitre];

      mList.forEach(m => {
        if (!m) return;
        if (!techCounts[m]) {
          let name = 'Technique';
          if (m === 'T1190') name = 'Exploit Public App';
          else if (m === 'T1110') name = 'Brute Force / Spray';
          else if (m === 'T1562') name = 'Impair Defenses';
          else if (m === 'T1046') name = 'Network Scanning';
          else if (m === 'T1059') name = 'Command Execution';
          else if (m === 'T1486') name = 'Data Encrypted';
          techCounts[m] = { count: 0, name, severities: {} };
        }
        techCounts[m].count++;
        techCounts[m].severities[item.severity] = (techCounts[m].severities[item.severity] || 0) + 1;
      });

      // Host counts
      const host = item.agent_name || 'unknown-host';
      if (!hostCounts[host]) hostCounts[host] = { count: 0, critical: 0, high: 0 };
      hostCounts[host].count++;
      if (item.severity === 'critical') hostCounts[host].critical++;
      if (item.severity === 'high') hostCounts[host].high++;
    });

    const sortedTech = Object.entries(techCounts)
      .map(([code, val]) => ({ code, ...val }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 4);

    const sortedHosts = Object.entries(hostCounts)
      .map(([host, val]) => ({ host, ...val }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 3);

    const totalTagged = sortedTech.reduce((acc, t) => acc + t.count, 0) || 1;

    return {
      techniques: sortedTech,
      topHosts: sortedHosts,
      totalTagged,
    };
  }, [incidents]);

  return (
    <div className="overview-graph-card" aria-label="MITRE ATT&CK and Asset Surface">
      <div className="graph-card-header">
        <div className="graph-card-title">
          <DeploymentUnitOutlined style={{ color: '#fb923c' }} />
          <span>ATT&amp;CK &amp; Surface Exposure</span>
        </div>
        <div className="graph-card-metric">
          <strong>{topHosts.length}</strong>
          <small>target hosts</small>
        </div>
      </div>

      {/* Segmented Proportional Bar */}
      <div className="surface-gauge-wrap">
        <div className="surface-gauge-bar">
          {techniques.map((t, idx) => {
            const pct = Math.round((t.count / totalTagged) * 100);
            const colors = ['#f43f5e', '#fb923c', '#eab308', '#38bdf8'];
            const color = colors[idx % colors.length];
            return (
              <Tooltip key={t.code} title={`${t.code} ${t.name}: ${t.count} incidents (${pct}%)`}>
                <div
                  className="surface-gauge-segment"
                  style={{ width: `${Math.max(pct, 8)}%`, backgroundColor: color }}
                />
              </Tooltip>
            );
          })}
        </div>
      </div>

      {/* MITRE Technique Breakdown Bars */}
      <div className="surface-technique-list">
        {techniques.map((t, idx) => {
          const pct = Math.round((t.count / totalTagged) * 100);
          const colors = ['#f43f5e', '#fb923c', '#eab308', '#38bdf8'];
          const color = colors[idx % colors.length];
          return (
            <div key={t.code} className="surface-tech-row">
              <div className="surface-tech-meta">
                <span className="mono tech-code" style={{ color }}>{t.code}</span>
                <span className="tech-name">{t.name}</span>
                <span className="tech-pct mono">{t.count} ({pct}%)</span>
              </div>
              <div className="surface-tech-track">
                <div className="surface-tech-fill" style={{ width: `${pct}%`, backgroundColor: color }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Impacted Hosts Row */}
      <div className="surface-hosts-bar">
        <small className="muted" style={{ fontSize: 10 }}>IMPACTED HOSTS:</small>
        <div className="surface-host-tags">
          {topHosts.map(h => (
            <Tag key={h.host} className="host-pill mono" color={h.critical > 0 ? 'volcano' : 'default'}>
              {h.host} <span className="host-count">({h.count})</span>
            </Tag>
          ))}
        </div>
      </div>
    </div>
  );
}
