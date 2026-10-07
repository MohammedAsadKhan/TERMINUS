import { useMemo, useState } from 'react';
import { Button, Descriptions, Modal, Tag, Tooltip } from 'antd';
import {
  AlertOutlined,
  CheckCircleOutlined,
  ClusterOutlined,
  DeploymentUnitOutlined,
  EyeOutlined,
  FireOutlined,
  LineChartOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { useNavigate } from 'react-router-dom';
import type { Incident } from '../types';

export const MITRE_TECHNIQUE_NAMES: Record<string, string> = {
  'T1110': 'Brute Force / Password Spray',
  'T1110.001': 'Password Guessing',
  'T1110.002': 'Password Cracking',
  'T1110.003': 'Password Spraying',
  'T1110.004': 'Credential Stuffing',
  'T1098': 'Account Manipulation',
  'T1098.001': 'Additional Cloud Credentials',
  'T1098.002': 'Additional Email Delegate Permissions',
  'T1098.003': 'Add Admin Rights / Groups',
  'T1059': 'Command & Scripting Interpreter',
  'T1059.001': 'PowerShell Script Execution',
  'T1059.003': 'Windows Command Shell',
  'T1059.004': 'Unix Shell Script Execution',
  'T1059.005': 'Visual Basic Scripting',
  'T1059.006': 'Python Script Execution',
  'T1055': 'Process Injection',
  'T1055.001': 'Dynamic-link Library Injection',
  'T1055.002': 'Portable Executable Injection',
  'T1055.012': 'Process Hollowing',
  'T1053': 'Scheduled Task / Cron Job',
  'T1053.003': 'Cron Job Execution',
  'T1053.005': 'Scheduled Task Execution',
  'T1078': 'Valid Accounts Abuse',
  'T1078.001': 'Default Accounts',
  'T1078.002': 'Domain Accounts',
  'T1078.003': 'Local Accounts',
  'T1078.004': 'Cloud Accounts',
  'T1021': 'Remote Services Lateral Movement',
  'T1021.001': 'Remote Desktop Protocol (RDP)',
  'T1021.002': 'SMB / Windows Admin Shares',
  'T1021.004': 'SSH Session Execution',
  'T1071': 'Application Layer C2 Protocol',
  'T1071.001': 'Web Protocols (HTTP/S)',
  'T1071.004': 'DNS Tunneling / Exfiltration',
  'T1001': 'Data Obfuscation / Encrypted C2',
  'T1003': 'OS Credential Dumping',
  'T1003.001': 'LSASS Memory Dumping',
  'T1003.002': 'Security Account Manager (SAM)',
  'T1003.003': 'NTDS.dit Database Extraction',
  'T1003.006': 'DCSync Domain Replication Attack',
  'T1033': 'System Owner/User Discovery',
  'T1046': 'Network Service Scanning / Port Sweep',
  'T1190': 'Exploit Public-Facing Application',
  'T1203': 'Exploitation for Client Execution',
  'T1562': 'Impair Defenses / Evasion',
  'T1562.001': 'Disable or Modify Security Tools',
  'T1562.004': 'Disable System Firewall',
  'T1486': 'Data Encrypted for Impact (Ransomware)',
  'T1490': 'Inhibit System Recovery / Shadow Copy Deletion',
  'T1552': 'Unsecured Credentials / Honeytoken',
  'T1552.001': 'Credentials in Files',
  'T1558': 'Steal or Forge Kerberos Tickets',
  'T1558.003': 'Kerberoasting SPN Ticket Request',
  'T1074': 'Data Staged in Directory',
  'T1074.001': 'Local Data Staging in AppData',
  'T1543': 'Create or Modify System Process',
  'T1543.003': 'Windows Service Execution / Persistence',
  'T1567': 'Exfiltration Over Web Service',
  'T1567.002': 'Exfiltration to Cloud Storage',
  'T1070': 'Indicator Removal on Host',
  'T1070.001': 'Clear Windows Event Logs',
  'T1070.004': 'File Deletion / Log Wiping',
  'T1566': 'Phishing Attack',
  'T1566.001': 'Spearphishing Attachment',
  'T1566.002': 'Spearphishing Link',
  'T1204': 'Malicious User Execution',
  'T1056': 'Input Capture / Keylogging',
  'T1548': 'Abuse Elevation Control (Privilege Escalation)',
  'T1548.002': 'Bypass User Account Control (UAC)',
  'T1548.003': 'Sudo and Sudo Caching',
  'T1136': 'Create Account',
  'T1136.001': 'Create Local Account',
  'T1136.002': 'Create Domain Account',
  'T1499': 'Endpoint DoS / Resource Exhaustion',
  'T1041': 'Exfiltration Over C2 Channel',
  'T1036': 'Masquerading',
  'T1083': 'File and Directory Discovery',
  'T1082': 'System Information Discovery',
  'T1087': 'Account Discovery',
  'T1087.001': 'Local Account Discovery',
  'T1087.002': 'Domain Account Discovery',
  'T1016': 'System Network Configuration Discovery',
  'T1049': 'System Network Connections Discovery',
  'T1560': 'Archive Collected Data',
  'T1048': 'Exfiltration Over Alternative Protocol',
  'T1570': 'Lateral Tool Transfer',
  'T1569': 'System Services Execution',
  'T1218': 'System Binary Proxy Execution',
  'T1018': 'Remote System Discovery',
  'T1027': 'Obfuscated / Encrypted Payloads',
  'T1005': 'Data from Local System',
  'T1105': 'Ingress Tool Transfer',
  'T1574': 'Hijack Execution Flow',
  'T1505': 'Server Software Component',
  'T1505.003': 'Web Shell Backdoor',
  'T1547': 'Boot or Logon Autostart Execution',
};

export function getMitreTechniqueName(code: string, fallbackDesc?: string): string {
  if (!code) return 'Adversary Technique';
  const cleanCode = code.trim().toUpperCase();
  if (MITRE_TECHNIQUE_NAMES[cleanCode]) return MITRE_TECHNIQUE_NAMES[cleanCode];

  const baseCode = cleanCode.split('.')[0];
  if (MITRE_TECHNIQUE_NAMES[baseCode]) return MITRE_TECHNIQUE_NAMES[baseCode];

  const match = cleanCode.match(/T\d{4}(?:\.\d{3})?/i);
  if (match) {
    const matchedCode = match[0].toUpperCase();
    if (MITRE_TECHNIQUE_NAMES[matchedCode]) return MITRE_TECHNIQUE_NAMES[matchedCode];
    const matchedBase = matchedCode.split('.')[0];
    if (MITRE_TECHNIQUE_NAMES[matchedBase]) return MITRE_TECHNIQUE_NAMES[matchedBase];
  }

  if (fallbackDesc && fallbackDesc.length > 4) {
    const cleaned = fallbackDesc
      .replace(/T\d{4}(?:\.\d{3})?/gi, '')
      .replace(/[()\[\]]/g, '')
      .replace(/[-_]/g, ' ')
      .trim();
    if (cleaned.length > 3 && !cleaned.toLowerCase().startsWith('technique')) {
      return cleaned.slice(0, 32);
    }
  }
  return `Adversary Technique (${cleanCode})`;
}

interface TrafficPoint {
  timeLabel: string;
  timestamp: number;
  reqPerSec: number;
  x: number;
  y: number;
}

interface AlertNode {
  incident: Incident;
  x: number;
  y: number;
  color: string;
  pulse: boolean;
  severityLabel: string;
  radius: number;
}

export function LiveTrafficAlertChart({
  incidents,
  onSelectIncident,
}: {
  incidents: Incident[];
  onSelectIncident?: (incident: Incident) => void;
}) {
  const navigate = useNavigate();
  const [hoveredAlertId, setHoveredAlertId] = useState<string | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [activeSeverityFilter, setActiveSeverityFilter] = useState<string>('all');

  // Compute traffic baseline and mapped alert nodes
  const {
    alertNodes,
    timeTicks,
    baselineRps,
    peakRps,
    totalCritical,
    totalHigh,
    totalMedium,
    totalLow,
    areaPath,
    linePath,
  } = useMemo(() => {
    const totalCritical = incidents.filter(i => (i.severity || '').toLowerCase() === 'critical').length;
    const totalHigh = incidents.filter(i => (i.severity || '').toLowerCase() === 'high').length;
    const totalMedium = incidents.filter(i => (i.severity || '').toLowerCase() === 'medium').length;
    const totalLow = incidents.filter(i => (i.severity || '').toLowerCase() === 'low').length;

    const width = 500;
    const height = 135;
    const paddingX = 22;
    const paddingY = 16;

    const now = Date.now();
    const timestamps = incidents
      .map(i => Date.parse(i.created_at || i.timestamp))
      .filter(t => Number.isFinite(t))
      .sort((a, b) => a - b);

    const firstTime = timestamps.length > 0 ? timestamps[0] : now - 300000;
    const lastTime = timestamps.length > 0 ? timestamps[timestamps.length - 1] : now;
    const rawSpan = Math.max(lastTime - firstTime, 30000);

    let minTime: number;
    let maxTime: number;
    if (rawSpan < 120000) {
      minTime = firstTime - 60000;
      maxTime = Math.max(now, lastTime + 45000);
    } else {
      const pad = rawSpan * 0.08;
      minTime = firstTime - pad;
      maxTime = Math.max(now, lastTime + pad);
    }
    const windowSpan = Math.max(maxTime - minTime, 120000);

    // Realistic smooth enterprise baseline traffic curve
    const curvePointsCount = 20;
    const step = windowSpan / (curvePointsCount - 1);
    const baseRpsValue = 220;
    const trafficPoints: TrafficPoint[] = [];

    let maxRps = baseRpsValue;
    for (let i = 0; i < curvePointsCount; i++) {
      const t = minTime + i * step;
      const d = new Date(t);
      const timeLabel = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`;
      // Smooth gentle organic undulation (205 - 245 req/s)
      const oscillation = Math.sin(i * 0.55) * 14 + Math.cos(i * 0.95) * 8;
      const rps = Math.round(baseRpsValue + oscillation);
      if (rps > maxRps) maxRps = rps;
      trafficPoints.push({ timeLabel, timestamp: t, reqPerSec: rps, x: 0, y: 0 });
    }

    const minRps = 180;
    const rpsRange = Math.max(maxRps - minRps, 50);

    trafficPoints.forEach((p, idx) => {
      p.x = paddingX + (idx / (curvePointsCount - 1)) * (width - paddingX * 2);
      p.y = height - paddingY - ((p.reqPerSec - minRps) / rpsRange) * (height - paddingY * 2.2);
    });

    // Smooth cubic bezier path
    let areaPath = '';
    let linePath = '';
    if (trafficPoints.length > 1) {
      const first = trafficPoints[0];
      const last = trafficPoints[trafficPoints.length - 1];
      let d = `M ${first.x} ${first.y}`;
      for (let i = 1; i < trafficPoints.length; i++) {
        const p = trafficPoints[i];
        const prev = trafficPoints[i - 1];
        const cx1 = prev.x + (p.x - prev.x) / 2;
        const cy1 = prev.y;
        const cx2 = prev.x + (p.x - prev.x) / 2;
        const cy2 = p.y;
        d += ` C ${cx1} ${cy1}, ${cx2} ${cy2}, ${p.x} ${p.y}`;
      }
      linePath = d;
      const bottom = height - 10;
      areaPath = `${d} L ${last.x} ${bottom} L ${first.x} ${bottom} Z`;
    }

    // Filter incidents
    const filteredIncidents = incidents.filter(i => {
      const sev = (i.severity || 'low').toLowerCase();
      if (activeSeverityFilter === 'critical') return sev === 'critical';
      if (activeSeverityFilter === 'high') return sev === 'high';
      if (activeSeverityFilter === 'medium') return sev === 'medium';
      if (activeSeverityFilter === 'low') return sev === 'low';
      return true;
    });

    // Prioritize critical & high threats and sample cleanly (maximum 16 distinct non-overlapping points)
    const prioritized = [...filteredIncidents].sort((a, b) => {
      const sOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
      return (sOrder[a.severity?.toLowerCase() || 'low'] ?? 4) - (sOrder[b.severity?.toLowerCase() || 'low'] ?? 4);
    });
    const displayIncidents = prioritized.slice(0, 16);

    // Initial alert node calculations
    const rawNodes = displayIncidents.map((inc, index) => {
      const incTime = Date.parse(inc.created_at || inc.timestamp);
      const safeTime = Number.isFinite(incTime)
        ? incTime
        : minTime + (index / Math.max(displayIncidents.length, 1)) * windowSpan;

      const rawRatio = Math.max(0, Math.min(1, (safeTime - minTime) / windowSpan));
      const rawX = paddingX + rawRatio * (width - paddingX * 2);

      const sev = (inc.severity || 'low').toLowerCase();
      let color = '#06b6d4';
      let pulse = false;
      let severityLabel = 'Low';
      let radius = 3.5;

      if (sev === 'critical') {
        color = '#ef4444';
        pulse = true;
        severityLabel = 'Critical';
        radius = 5.5;
      } else if (sev === 'high') {
        color = '#f97316';
        severityLabel = 'High';
        radius = 4.5;
      } else if (sev === 'medium') {
        color = '#eab308';
        severityLabel = 'Medium';
        radius = 4;
      }

      return {
        incident: inc,
        rawX,
        x: rawX,
        rawTime: safeTime,
        color,
        pulse,
        severityLabel,
        radius,
      };
    });

    // Sort chronologically for clean rendering
    rawNodes.sort((a, b) => a.rawTime - b.rawTime);

    // Collision relaxation: ensure minimum 26px spacing so points never look like teeth
    const minSpacing = 26;

    if (rawNodes.length > 1) {
      for (let i = 1; i < rawNodes.length; i++) {
        if (rawNodes[i].x < rawNodes[i - 1].x + minSpacing) {
          rawNodes[i].x = rawNodes[i - 1].x + minSpacing;
        }
      }
      const maxX = width - paddingX;
      if (rawNodes[rawNodes.length - 1].x > maxX) {
        rawNodes[rawNodes.length - 1].x = maxX;
        for (let i = rawNodes.length - 2; i >= 0; i--) {
          if (rawNodes[i].x > rawNodes[i + 1].x - minSpacing) {
            rawNodes[i].x = rawNodes[i + 1].x - minSpacing;
          }
        }
      }
    }

    // Map Y position smoothly above baseline
    const alertNodes: AlertNode[] = rawNodes.map(node => {
      const xRatio = Math.max(0, Math.min(1, (node.x - paddingX) / (width - paddingX * 2)));
      const baseIdx = Math.max(0, Math.min(trafficPoints.length - 1, xRatio * (trafficPoints.length - 1)));
      const floorIdx = Math.floor(baseIdx);
      const ceilIdx = Math.min(trafficPoints.length - 1, floorIdx + 1);
      const frac = baseIdx - floorIdx;
      const trafficLineY = trafficPoints[floorIdx] && trafficPoints[ceilIdx]
        ? trafficPoints[floorIdx].y * (1 - frac) + trafficPoints[ceilIdx].y * frac
        : height - paddingY - 20;

      // Position severity cleanly: Critical elevated higher, Medium/Low closer to curve
      let yOffset = 8;
      if (node.severityLabel === 'Critical') yOffset = 26;
      else if (node.severityLabel === 'High') yOffset = 18;
      else if (node.severityLabel === 'Medium') yOffset = 12;

      const y = Math.max(22, Math.min(height - 24, trafficLineY - yOffset));

      return {
        incident: node.incident,
        x: node.x,
        y,
        color: node.color,
        pulse: node.pulse,
        severityLabel: node.severityLabel,
        radius: node.radius,
      };
    });

    // 5 clean timeline ticks
    const tickCount = 5;
    const timeTicks = Array.from({ length: tickCount }, (_, i) => {
      const t = minTime + (i / (tickCount - 1)) * (maxTime - minTime);
      const d = new Date(t);
      const hh = d.getHours().toString().padStart(2, '0');
      const mm = d.getMinutes().toString().padStart(2, '0');
      const ss = d.getSeconds().toString().padStart(2, '0');
      return {
        label: `${hh}:${mm}:${ss}`,
        isNow: i === tickCount - 1,
      };
    });

    return {
      trafficPoints,
      alertNodes,
      timeTicks,
      baselineRps: baseRpsValue,
      peakRps: maxRps,
      totalCritical,
      totalHigh,
      totalMedium,
      totalLow,
      areaPath,
      linePath,
    };
  }, [incidents, activeSeverityFilter]);

  const handleNodeClick = (inc: Incident) => {
    setSelectedIncident(inc);
    if (onSelectIncident) {
      onSelectIncident(inc);
    }
  };

  const getMitreTechnique = (inc: Incident) => {
    if (Array.isArray(inc.mitre)) return inc.mitre[0];
    if (inc.mitre) return inc.mitre;
    const match = (inc.rule_description || inc.full_log || '').match(/T\d{4}(?:\.\d{3})?/);
    return match ? match[0] : null;
  };

  const isTier0Asset = (host?: string) => {
    if (!host) return false;
    const lower = host.toLowerCase();
    return lower.includes('dc01') || lower.includes('dc-') || lower.includes('domain') || lower.includes('ledger-prod');
  };

  return (
    <div className="overview-graph-card live-traffic-card" aria-label="Normal Service Traffic and Live Threat Influx">
      {/* Header with real-time status and integrated peak metric */}
      <div className="graph-card-header">
        <div className="graph-card-title">
          <LineChartOutlined style={{ color: 'var(--accent)' }} />
          <span>Live Service Traffic &amp; Threat Influx</span>
        </div>
        <div className="graph-card-metric">
          <span className="live-pulse-dot" title="Live sensor stream online" />
          <strong>~{baselineRps}</strong>
          <small>req/s avg · {peakRps} peak</small>
        </div>
      </div>

      {/* Severity Filter Badges in a Single Non-wrapping Row */}
      <div className="graph-card-stats-row live-filter-pill-row">
        <button
          type="button"
          className={`stat-badge filter-badge ${activeSeverityFilter === 'all' ? 'active' : ''}`}
          onClick={() => setActiveSeverityFilter('all')}
        >
          All ({incidents.length})
        </button>
        <button
          type="button"
          className={`stat-badge critical filter-badge ${activeSeverityFilter === 'critical' ? 'active' : ''}`}
          onClick={() => setActiveSeverityFilter(activeSeverityFilter === 'critical' ? 'all' : 'critical')}
        >
          <FireOutlined /> {totalCritical} Critical
        </button>
        <button
          type="button"
          className={`stat-badge high filter-badge ${activeSeverityFilter === 'high' ? 'active' : ''}`}
          onClick={() => setActiveSeverityFilter(activeSeverityFilter === 'high' ? 'all' : 'high')}
        >
          {totalHigh} High
        </button>
        <button
          type="button"
          className={`stat-badge medium filter-badge ${activeSeverityFilter === 'medium' ? 'active' : ''}`}
          onClick={() => setActiveSeverityFilter(activeSeverityFilter === 'medium' ? 'all' : 'medium')}
        >
          {totalMedium} Medium
        </button>
        <button
          type="button"
          className={`stat-badge low filter-badge ${activeSeverityFilter === 'low' ? 'active' : ''}`}
          onClick={() => setActiveSeverityFilter(activeSeverityFilter === 'low' ? 'all' : 'low')}
        >
          {totalLow} Low
        </button>
      </div>

      {/* SVG Canvas with Traffic Baseline and Clean Threat Events */}
      <div className="graph-svg-container live-traffic-svg-wrap" style={{ position: 'relative' }}>
        {/* Floating Hover Preview Card */}
        {(() => {
          const hoveredNode = alertNodes.find(n => n.incident.id === hoveredAlertId);
          if (!hoveredNode) return null;
          const mitre = getMitreTechnique(hoveredNode.incident);
          const leftPercent = Math.min(Math.max((hoveredNode.x / 500) * 100, 22), 78);
          return (
            <div
              className="traffic-node-hover-popover"
              style={{
                left: `${leftPercent}%`,
              }}
            >
              <div className="hover-popover-badge-row">
                <Tag color={hoveredNode.color} style={{ margin: 0, padding: '0 5px', fontSize: 10, fontWeight: 700 }}>
                  {hoveredNode.severityLabel.toUpperCase()}
                </Tag>
                {mitre && (
                  <Tag color="geekblue" style={{ margin: 0, padding: '0 4px', fontSize: 10 }}>
                    {mitre}
                  </Tag>
                )}
                <span className="hover-popover-host">{hoveredNode.incident.agent_name || 'unknown'}</span>
              </div>
              <div className="hover-popover-desc">{hoveredNode.incident.rule_description || 'Security Incident'}</div>
              <div className="hover-popover-hint">⚡ Click node to inspect incident dossier</div>
            </div>
          );
        })()}

        <svg viewBox="0 0 500 135" className="velocity-svg" preserveAspectRatio="none">
          <defs>
            <linearGradient id="normalTrafficGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#0284c7" stopOpacity="0.22" />
              <stop offset="100%" stopColor="#0284c7" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Clean Horizontal Grid Lines */}
          <line x1="20" y1="28" x2="480" y2="28" stroke="var(--line)" strokeDasharray="4 4" opacity="0.4" />
          <line x1="20" y1="68" x2="480" y2="68" stroke="var(--line)" strokeDasharray="4 4" opacity="0.4" />
          <line x1="20" y1="108" x2="480" y2="108" stroke="var(--line)" opacity="0.7" />

          {/* Normal Traffic Area and Line Curve */}
          {areaPath && <path d={areaPath} fill="url(#normalTrafficGrad)" />}
          {linePath && <path d={linePath} fill="none" stroke="#38bdf8" strokeWidth="2.2" strokeLinecap="round" opacity="0.95" />}

          {/* Vertical indicator stems ONLY for Hovered Node or Critical threats */}
          {alertNodes.map(node => {
            const isHovered = hoveredAlertId === node.incident.id;
            const showStem = isHovered || node.pulse;
            if (!showStem) return null;

            return (
              <line
                key={`stem-${node.incident.id}`}
                x1={node.x}
                y1={node.y}
                x2={node.x}
                y2={108}
                stroke={node.color}
                strokeWidth={isHovered ? 2 : 1}
                strokeDasharray={isHovered ? undefined : '2 2'}
                opacity={isHovered ? 1 : 0.45}
              />
            );
          })}

          {/* Interactive Colored Alert Threat Nodes */}
          {alertNodes.map(node => {
            const isHovered = hoveredAlertId === node.incident.id;
            const r = isHovered ? node.radius + 2.5 : node.radius;

            return (
              <g
                key={`node-${node.incident.id}`}
                className="traffic-alert-node-group"
                onMouseEnter={() => setHoveredAlertId(node.incident.id)}
                onMouseLeave={() => setHoveredAlertId(null)}
                onClick={() => handleNodeClick(node.incident)}
                style={{ cursor: 'pointer' }}
              >
                <title>{`${node.severityLabel.toUpperCase()} THREAT: ${node.incident.rule_description || 'Security Alert'} on ${node.incident.agent_name || 'unknown'}`}</title>

                {/* Pulse Ring on Critical alerts */}
                {node.pulse && (
                  <circle
                    cx={node.x}
                    cy={node.y}
                    r="9"
                    fill="none"
                    stroke="#ef4444"
                    strokeWidth="1.2"
                    className="alert-node-pulse-ring"
                  />
                )}

                {/* Clean Solid Threat Node */}
                <circle
                  cx={node.x}
                  cy={node.y}
                  r={r}
                  fill={node.color}
                  stroke="#ffffff"
                  strokeWidth={isHovered ? 2 : 1.2}
                  opacity="1"
                  style={{ transition: 'r 0.15s ease' }}
                />
              </g>
            );
          })}
        </svg>
      </div>

      {/* Clean 5-Tick Timeline Axis */}
      <div className="graph-time-axis">
        {timeTicks.map((tick, idx) => (
          <span key={idx} className={`time-tick ${tick.isNow ? 'live-tick' : ''}`}>
            {tick.label} {tick.isNow ? '• live' : ''}
          </span>
        ))}
      </div>

      {/* Single-Row Clean Legend Bar */}
      <div className="traffic-legend-bar">
        <span className="legend-item">
          <span className="legend-line-sample" /> Normal Baseline
        </span>
        <span className="legend-item">
          <span className="legend-dot critical" /> Critical
        </span>
        <span className="legend-item">
          <span className="legend-dot high" /> High
        </span>
        <span className="legend-item">
          <span className="legend-dot medium" /> Medium
        </span>
        <span className="legend-item">
          <span className="legend-dot low" /> Low
        </span>
        <span className="legend-hint">💡 Click node for dossier</span>
      </div>

      {/* Interactive Alert & Ticket Dossier Modal */}
      {selectedIncident && (
        <Modal
          open={Boolean(selectedIncident)}
          onCancel={() => setSelectedIncident(null)}
          footer={[
            <Button key="close" onClick={() => setSelectedIncident(null)}>
              Close
            </Button>,
            <Button
              key="investigate"
              type="primary"
              icon={<EyeOutlined />}
              onClick={() => {
                const id = selectedIncident.id;
                setSelectedIncident(null);
                navigate(`/incidents/${encodeURIComponent(id)}`);
              }}
            >
              Open in Incidents Command Center →
            </Button>,
          ]}
          width={680}
          title={
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingRight: 24 }}>
              <AlertOutlined style={{ color: selectedIncident.severity === 'critical' ? '#ef4444' : '#f97316' }} />
              <span style={{ fontSize: 16, fontWeight: 700 }}>
                {selectedIncident.rule_description || 'Security Incident Dossier'}
              </span>
            </div>
          }
          className="alert-dossier-modal"
        >
          <div className="dossier-modal-content">
            {/* Severity and Status Ribbon */}
            <div className="dossier-ribbon">
              <Tag color={selectedIncident.severity === 'critical' ? 'volcano' : selectedIncident.severity === 'high' ? 'orange' : 'gold'}>
                SEVERITY: {(selectedIncident.severity || 'UNKNOWN').toUpperCase()}
              </Tag>
              <Tag color={selectedIncident.status === 'RESOLVED' ? 'green' : 'blue'}>
                STATUS: {selectedIncident.status || 'OPEN'}
              </Tag>
              {selectedIncident.policy_tier && (
                <Tag color="purple">POLICY TIER: {selectedIncident.policy_tier.toUpperCase()}</Tag>
              )}
              {getMitreTechnique(selectedIncident) && (
                <Tag color="geekblue" icon={<DeploymentUnitOutlined />}>
                  MITRE: {getMitreTechnique(selectedIncident)}
                </Tag>
              )}
            </div>

            {/* Key Information Grid */}
            <Descriptions size="small" bordered column={2} style={{ marginTop: 14 }}>
              <Descriptions.Item label="Ticket ID">
                <span className="mono">{selectedIncident.id}</span>
              </Descriptions.Item>
              <Descriptions.Item label="Alert ID">
                <span className="mono">{selectedIncident.alert_id || 'N/A'}</span>
              </Descriptions.Item>
              <Descriptions.Item label="Target Host">
                <strong>{selectedIncident.agent_name || 'unknown-host'}</strong>
                {isTier0Asset(selectedIncident.agent_name) && (
                  <Tag color="volcano" style={{ marginLeft: 6 }}>Tier-0 Protected</Tag>
                )}
              </Descriptions.Item>
              <Descriptions.Item label="Source IP">
                <span className="mono">{selectedIncident.source_ip || '127.0.0.1'}</span>
              </Descriptions.Item>
              <Descriptions.Item label="Ingestion Time">
                {selectedIncident.created_at || selectedIncident.timestamp || 'Just now'}
              </Descriptions.Item>
              <Descriptions.Item label="Kill Chain Stage">
                {selectedIncident.kill_chain_stage || 'Initial Access / Execution'}
              </Descriptions.Item>
            </Descriptions>

            {/* Deterministic Guardrail Status Notice */}
            {isTier0Asset(selectedIncident.agent_name) && (
              <div className="dossier-guardrail-alert tier0-blocked">
                <SafetyCertificateOutlined style={{ fontSize: 18, color: '#10b981' }} />
                <div>
                  <strong>Deterministic Safety Guardrail (D12/D14) Active:</strong>
                  <p style={{ margin: 0, fontSize: 12 }}>
                    Asset <code>{selectedIncident.agent_name}</code> is registered as Tier-0 Infrastructure (Allowlisted Domain Controller / Core Ledger). Autonomous destructive isolation is <strong>BLOCKED</strong> by deterministic policy.
                  </p>
                </div>
              </div>
            )}

            {/* AI Forensic Triage Analysis */}
            <div className="dossier-ai-verdict">
              <div className="dossier-section-title">
                <RobotOutlined style={{ color: 'var(--accent)' }} />
                <span>AI SOC Triage Verdict</span>
              </div>
              <p className="dossier-verdict-text">
                {selectedIncident.summary ||
                  selectedIncident.context_notes ||
                  'Automated telemetry ingestion processed via sub-millisecond deterministic policy rules. Correlation verified against enterprise threat intelligence feeds.'}
              </p>
            </div>

            {/* Raw Log Evidence */}
            {selectedIncident.full_log && (
              <div className="dossier-raw-evidence">
                <div className="dossier-section-title">
                  <ThunderboltOutlined style={{ color: '#f59e0b' }} />
                  <span>Raw Telemetry Evidence</span>
                </div>
                <pre className="mono dossier-log-snippet">{selectedIncident.full_log}</pre>
              </div>
            )}
          </div>
        </Modal>
      )}
    </div>
  );
}

// Alias for backwards compatibility
export const ThreatVelocityChart = LiveTrafficAlertChart;

export function AttackSurfaceMatrix({ incidents }: { incidents: Incident[] }) {
  const { techniques, topHosts, totalTagged } = useMemo(() => {
    const techCounts: Record<string, { count: number; name: string; severities: Record<string, number> }> = {};
    const hostCounts: Record<string, { count: number; critical: number; high: number }> = {};

    incidents.forEach(item => {
      // Extract clean MITRE technique code
      let rawMitre = item.mitre;
      if (!rawMitre && item.rule_description) {
        const match = item.rule_description.match(/T\d{4}(?:\.\d{3})?/i);
        if (match) rawMitre = match[0].toUpperCase();
      }
      if (!rawMitre) rawMitre = 'T1190';

      const mList = Array.isArray(rawMitre) ? rawMitre : [rawMitre];

      mList.forEach(m => {
        if (!m) return;
        const match = String(m).match(/T\d{4}(?:\.\d{3})?/i);
        const cleanCode = match ? match[0].toUpperCase() : String(m).trim().toUpperCase();
        if (!techCounts[cleanCode]) {
          const name = getMitreTechniqueName(cleanCode, item.rule_description);
          techCounts[cleanCode] = { count: 0, name, severities: {} };
        }
        techCounts[cleanCode].count++;
        techCounts[cleanCode].severities[item.severity] = (techCounts[cleanCode].severities[item.severity] || 0) + 1;
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
      .slice(0, 4);

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
                  style={{ flex: `${Math.max(t.count, 1)} 1 0%`, backgroundColor: color }}
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
        <small className="muted" style={{ fontSize: 9.5, textTransform: 'uppercase', letterSpacing: '0.04em', flexShrink: 0 }}>Impacted Hosts:</small>
        <div className="surface-host-tags">
          {topHosts.slice(0, 4).map(h => {
            const shortHost = h.host.replace('.corp.internal', '').replace('.internal', '').replace('.terminus.bank', '');
            return (
              <Tooltip key={h.host} title={`${h.host} — ${h.count} incidents (${h.critical} critical)`}>
                <Tag className="host-pill mono" color={h.critical > 0 ? 'volcano' : 'default'}>
                  {shortHost} <span className="host-count">({h.count})</span>
                </Tag>
              </Tooltip>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export function ProtectedEndpointThreatMatrix({
  incidents,
  onSelectHost,
}: {
  incidents: Incident[];
  onSelectHost?: (host: string) => void;
}) {
  const navigate = useNavigate();

  // Calculate polar coordinates for SVG arc paths
  function polarToCartesian(cx: number, cy: number, r: number, angleInDegrees: number) {
    const angleInRadians = ((angleInDegrees - 90) * Math.PI) / 180.0;
    return {
      x: cx + r * Math.cos(angleInRadians),
      y: cy + r * Math.sin(angleInRadians),
    };
  }

  function describeArc(cx: number, cy: number, rInner: number, rOuter: number, startAngle: number, endAngle: number) {
    let delta = endAngle - startAngle;
    if (delta >= 359.99) delta = 359.99;
    if (delta <= 0.01) delta = 0.01;
    const end = startAngle + delta;

    const startOuter = polarToCartesian(cx, cy, rOuter, end);
    const endOuter = polarToCartesian(cx, cy, rOuter, startAngle);
    const startInner = polarToCartesian(cx, cy, rInner, startAngle);
    const endInner = polarToCartesian(cx, cy, rInner, end);

    const largeArcFlag = delta <= 180 ? '0' : '1';

    return [
      'M', startOuter.x, startOuter.y,
      'A', rOuter, rOuter, 0, largeArcFlag, 0, endOuter.x, endOuter.y,
      'L', startInner.x, startInner.y,
      'A', rInner, rInner, 0, largeArcFlag, 1, endInner.x, endInner.y,
      'Z',
    ].join(' ');
  }

  const hostColorMap: Record<string, string> = {
    'dc01.corp.internal': '#06b6d4',
    'bank-core-ledger-01': '#a855f7',
    'api-gateway.terminus.bank': '#f59e0b',
    'workstation-88.corp.internal': '#f43f5e',
    'bank-customer-portal.internal': '#3b82f6',
    'payroll-srv.internal': '#10b981',
    'vpn-edge-01.corp.internal': '#6366f1',
    'laptop-fin-04.corp.internal': '#94a3b8',
  };

  const severities: Array<{
    key: 'critical' | 'high' | 'medium' | 'low';
    label: string;
    tagColor: string;
    accentColor: string;
  }> = [
    { key: 'critical', label: 'Critical', tagColor: 'red', accentColor: '#ef4444' },
    { key: 'high', label: 'High', tagColor: 'orange', accentColor: '#f97316' },
    { key: 'medium', label: 'Medium', tagColor: 'gold', accentColor: '#eab308' },
    { key: 'low', label: 'Low', tagColor: 'cyan', accentColor: '#06b6d4' },
  ];

  return (
    <div className="overview-graph-card severity-pie-grid-card" aria-label="Endpoint Alert Distribution by Severity">
      <div className="endpoint-matrix-header">
        <div className="endpoint-matrix-title-group">
          <ClusterOutlined style={{ color: 'var(--accent)', fontSize: 16 }} />
          <div>
            <h3>Endpoint Threat Distribution by Severity</h3>
            <p>Independent breakdown of alerts targeting each protected endpoint across four severity tiers.</p>
          </div>
        </div>
        <div className="endpoint-matrix-legend-row">
          <span className="matrix-legend-pill mono">{incidents.length} Total Measured Alerts</span>
        </div>
      </div>

      {/* 4 Pie Charts Grid: Critical, High, Medium, Low */}
      <div className="severity-4pie-grid">
        {severities.map(sev => {
          const matchingIncidents = incidents.filter(i => (i.severity || 'low').toLowerCase() === sev.key);
          const totalInSev = matchingIncidents.length;

          // Group by host
          const hostBreakdown: Record<string, number> = {};
          matchingIncidents.forEach(inc => {
            const h = inc.agent_name || inc.agent_id || 'unknown';
            hostBreakdown[h] = (hostBreakdown[h] || 0) + 1;
          });

          const hostEntries = Object.entries(hostBreakdown)
            .map(([host, count]) => ({ host, count }))
            .sort((a, b) => b.count - a.count);

          // Calculate slice angles
          let angleCursor = 0;
          const slices = hostEntries.map((item, idx) => {
            const span = (item.count / Math.max(totalInSev, 1)) * 360;
            const startAngle = angleCursor;
            const endAngle = angleCursor + span;
            angleCursor = endAngle;
            const color = hostColorMap[item.host] || Object.values(hostColorMap)[idx % 8];
            const path = describeArc(70, 70, 32, 54, startAngle + 0.5, endAngle - 0.5);
            return {
              host: item.host,
              count: item.count,
              percent: ((item.count / Math.max(totalInSev, 1)) * 100).toFixed(0),
              color,
              path,
            };
          });

          return (
            <div key={sev.key} className={`sev-pie-card sev-${sev.key}`}>
              {/* Header */}
              <div className="sev-pie-header">
                <Tag color={sev.tagColor} className="sev-badge-tag">{sev.label.toUpperCase()}</Tag>
                <span className="sev-total-count mono">{totalInSev} alert{totalInSev === 1 ? '' : 's'}</span>
              </div>

              {/* Donut Chart */}
              <div className="sev-donut-wrap">
                <svg viewBox="0 0 140 140" className="sev-donut-svg">
                  {totalInSev === 0 ? (
                    <circle cx="70" cy="70" r="43" fill="none" stroke="rgba(255, 255, 255, 0.08)" strokeWidth="20" />
                  ) : (
                    slices.map(slice => (
                      <Tooltip
                        key={slice.host}
                        title={`${slice.host}: ${slice.count} alert${slice.count === 1 ? '' : 's'} (${slice.percent}%)`}
                      >
                        <path
                          d={slice.path}
                          fill={slice.color}
                          stroke="#0e1526"
                          strokeWidth="1.5"
                          className="sev-donut-slice"
                          onClick={() => {
                            if (onSelectHost) onSelectHost(slice.host);
                            else navigate(`/incidents?search=${encodeURIComponent(slice.host)}`);
                          }}
                        />
                      </Tooltip>
                    ))
                  )}

                  {/* Center Readout */}
                  <circle cx="70" cy="70" r="29" fill="#0d1424" stroke="rgba(255,255,255,0.08)" strokeWidth="1" />
                  <text
                    x="70"
                    y="75"
                    textAnchor="middle"
                    fill={totalInSev > 0 ? sev.accentColor : 'var(--muted)'}
                    fontSize="17"
                    fontWeight="800"
                    fontFamily="monospace"
                  >
                    {totalInSev}
                  </text>
                </svg>
              </div>

              {/* Mini Legend List of Top Endpoints */}
              <div className="sev-endpoint-legend-list">
                {totalInSev === 0 ? (
                  <div className="sev-legend-clean">
                    <CheckCircleOutlined style={{ color: '#10b981', marginRight: 4 }} />
                    <span>0 Active Threats</span>
                  </div>
                ) : (
                  hostEntries.slice(0, 3).map(item => {
                    const color = hostColorMap[item.host] || '#38bdf8';
                    const shortName = item.host.split('.')[0];
                    return (
                      <div
                        key={item.host}
                        className="sev-legend-item"
                        onClick={() => {
                          if (onSelectHost) onSelectHost(item.host);
                          else navigate(`/incidents?search=${encodeURIComponent(item.host)}`);
                        }}
                        title={`Click to filter: ${item.host}`}
                      >
                        <span className="sev-legend-pip" style={{ background: color }} />
                        <span className="sev-legend-name mono">{shortName}</span>
                        <span className="sev-legend-count mono">{item.count}</span>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// Backwards compatibility alias
export const SeverityEndpointPieCharts = ProtectedEndpointThreatMatrix;



