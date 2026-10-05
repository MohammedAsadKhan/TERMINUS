import { useEffect, useState } from 'react';
import {
  Alert,
  App,
  Avatar,
  Button,
  Card,
  Descriptions,
  Divider,
  Form,
  Input,
  InputNumber,
  Modal,
  Progress,
  Radio,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
} from 'antd';
import {
  ApiOutlined,
  CheckCircleOutlined,
  CopyOutlined,
  DeleteOutlined,
  ExperimentOutlined,
  KeyOutlined,
  LinkOutlined,
  LockOutlined,
  PlusOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
  SaveOutlined,
  SendOutlined,
  SettingOutlined,
  TeamOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, body } from '../api';
import { useSession } from '../context';
import { Code, date, ErrorPanel, Loading, PageTitle } from '../components';
import { IngestModal } from './ingest-modal';
import ModelSettings from './model-settings';
import type { Membership } from '../types';

export default function Settings({ section = 'settings' }: { section?: 'organization' | 'settings' }) {
  const { user, orgId, detail } = useSession();
  const query = useQueryClient();
  const { message, modal } = App.useApp();
  const [ingest, setIngest] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [activeTab, setActiveTab] = useState('model');
  const [form] = Form.useForm();
  const [configForm] = Form.useForm();

  const canWrite = detail?.role === 'admin';

  // Fetch full live platform configuration
  const configQuery = useQuery({
    queryKey: ['platform-config', orgId],
    queryFn: () => api<Record<string, any>>('/settings/config', orgId),
    enabled: canWrite,
  });

  // Populate config form when loaded
  useEffect(() => {
    if (configQuery.data) {
      const d = configQuery.data;
      configForm.setFieldsValue({
        llm_provider: d.llm?.provider || 'groq',
        llm_base_url: d.llm?.base_url || '',
        llm_model: d.llm?.model || 'openai/gpt-oss-20b',
        llm_api_key: '',
        llm_temperature: d.llm?.temperature ?? 0.2,
        llm_max_tokens: d.llm?.max_tokens ?? 4096,
        enable_react_forensics: d.llm?.enable_react_forensics ?? true,
        enable_deobfuscation: d.llm?.enable_deobfuscation ?? true,
        enable_cti_lookup: d.llm?.enable_cti_lookup ?? true,
        wazuh_url: d.siem?.wazuh_url || '',
        wazuh_user: d.siem?.wazuh_user || '',
        wazuh_password: '',
        polling_interval_sec: d.siem?.polling_interval_sec ?? 30,
        virustotal_api_key: '',
        abuseipdb_api_key: '',
        otx_api_key: '',
        cti_cache_ttl_hours: d.cti?.cache_ttl_hours ?? 24,
        jira_url: d.ticketing?.jira_url || '',
        jira_user: d.ticketing?.jira_user || '',
        jira_token: '',
        jira_project: d.ticketing?.jira_project || 'SEC',
        slack_webhook: '',
        sms_to: d.ticketing?.sms_to || '9364992155',
        twilio_sid: '',
        twilio_token: '',
        twilio_from: '',
        containment_mode: d.containment?.mode || 'human_in_the_loop',
        protected_subnets: d.containment?.protected_subnets || '10.0.0.0/8, 192.168.1.0/24, 127.0.0.0/8',
        policy_ignore_threshold: d.containment?.policy_ignore_threshold ?? 5,
        policy_triage_threshold: d.containment?.policy_triage_threshold ?? 9,
        policy_escalate_threshold: d.containment?.policy_escalate_threshold ?? 10,
      });
    }
  }, [configQuery.data, configForm]);

  // Mutation to save settings
  const saveConfig = useMutation({
    mutationFn: (values: any) => {
      // Filter out empty strings so existing secrets are not blanked
      const payload: Record<string, any> = {};
      Object.entries(values).forEach(([k, v]) => {
        if (v !== '' && v !== undefined) {
          payload[k] = v;
        }
      });
      return api('/settings/config', orgId, body('POST', payload));
    },
    onSuccess: () => {
      query.invalidateQueries({ queryKey: ['platform-config', orgId] });
      query.invalidateQueries({ queryKey: ['system'] });
      message.success('Platform configuration saved and applied.');
    },
    onError: (err: Error) => message.error(`Failed to save configuration: ${err.message}`),
  });

  // Mutation to test connection
  const testConn = useMutation({
    mutationFn: (payload: { service: string; target_url?: string; api_key?: string; model?: string }) =>
      api<{ success: boolean; latency_ms: number; message: string }>('/settings/test-connection', orgId, body('POST', payload)),
    onSuccess: res => {
      message.success(`[${res.latency_ms}ms] ${res.message}`);
    },
    onError: (err: Error) => message.error(`Connection failed: ${err.message}`),
  });

  const add = useMutation({
    mutationFn: (values: { user_id: string; role: string }) => api(`/orgs/${orgId}/members`, orgId, body('POST', values)),
    onSuccess: () => {
      query.invalidateQueries({ queryKey: ['org', orgId] });
      setAddOpen(false);
      form.resetFields();
      message.success('Member added');
    },
  });

  const license = useMutation({
    mutationFn: (values: { token: string }) => api(`/orgs/${orgId}/license`, orgId, body('POST', values)),
    onSuccess: () => {
      query.invalidateQueries({ queryKey: ['org', orgId] });
      message.success('License activated');
    },
    onError: error => message.error(error.message),
  });

  async function role(member: Membership, value: string) {
    try {
      await api(`/orgs/${orgId}/members/${member.user_id}`, orgId, body('PATCH', { role: value }));
      query.invalidateQueries({ queryKey: ['org', orgId] });
      message.success('Role updated');
    } catch (error) {
      message.error((error as Error).message);
    }
  }

  function remove(member: Membership) {
    modal.confirm({
      title: `Remove ${member.user?.display_name || member.user_id}?`,
      content: 'This removes their access to this organization.',
      okText: 'Remove member',
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          await api(`/orgs/${orgId}/members/${member.user_id}`, orgId, body('DELETE'));
          query.invalidateQueries({ queryKey: ['org', orgId] });
        } catch (error) {
          message.error((error as Error).message);
          throw error;
        }
      },
    });
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // ORGANIZATION VIEW
  // ─────────────────────────────────────────────────────────────────────────────
  if (section === 'organization') {
    return (
      <>
        <PageTitle
          eyebrow="GOVERN / ORGANIZATION"
          title="A shared space. Clear access."
          description="Manage the people who can investigate and administer this organization."
          actions={
            <Button type="primary" icon={<PlusOutlined />} disabled={!canWrite} onClick={() => { add.reset(); setAddOpen(true); }}>
              Add member
            </Button>
          }
        />
        <div className="settings-grid">
          <section className="panel org-profile">
            <span className="source-icon"><TeamOutlined /></span>
            <h2>{detail?.organization.name}</h2>
            <Typography.Paragraph className="mono muted" copyable>{orgId}</Typography.Paragraph>
            <Descriptions
              column={1}
              size="small"
              items={[
                { key: 'created', label: 'Created', children: date(detail?.organization.created_at) },
                { key: 'role', label: 'Your role', children: <Tag color="blue">{detail?.role.toUpperCase()}</Tag> },
              ]}
            />
          </section>
          <section className="panel">
            <div className="eyebrow">LICENSED CAPACITY</div>
            <h2>Room for your team.</h2>
            <div className="seat-count">
              {detail?.members.length || 0}
              <span> / {detail?.license?.max_seats || '—'} seats</span>
            </div>
            <Progress
              percent={detail?.license ? Math.min(100, Math.round((detail.members.length / detail.license.max_seats) * 100)) : 0}
              showInfo={false}
              strokeColor="#e2e8f0"
            />
            <p className="muted">
              {detail?.license?.tier.toUpperCase() || 'No valid license'} ·{' '}
              {detail?.license ? `Expires ${date(detail.license.expires_at)}` : 'See Settings & license'}
            </p>
          </section>
        </div>
        <section className="panel table-panel">
          <div className="panel-heading">
            <h2>Organization members</h2>
            <Tag>{detail?.members.length || 0} MEMBERS</Tag>
          </div>
          <Table<Membership>
            rowKey="user_id"
            dataSource={detail?.members}
            pagination={false}
            columns={[
              {
                title: 'MEMBER',
                render: (_, person) => (
                  <Space>
                    <Avatar shape="square">{person.user?.display_name[0]}</Avatar>
                    <span className="incident-link">
                      <strong>
                        {person.user?.display_name || person.user_id}
                        {person.user_id === user.user_id && <Tag className="you-tag">YOU</Tag>}
                      </strong>
                      <small>{person.user?.email || 'User not found'}</small>
                    </span>
                  </Space>
                ),
              },
              {
                title: 'ROLE',
                dataIndex: 'role',
                width: 140,
                render: (value: string, person) => (
                  <Select
                    aria-label={`Role of ${person.user?.display_name || person.user_id}`}
                    value={value}
                    disabled={!canWrite}
                    options={['admin', 'member', 'viewer'].map(r => ({ value: r, label: r.toUpperCase() }))}
                    onChange={v => void role(person, v)}
                    style={{ width: 130 }}
                  />
                ),
              },
              {
                title: 'USER ID',
                dataIndex: 'user_id',
                render: (value: string) => <Typography.Text className="mono" copyable>{value}</Typography.Text>,
              },
              {
                title: '',
                width: 44,
                render: (_, person) => (
                  <Button
                    danger
                    type="text"
                    aria-label={`Remove ${person.user?.display_name || person.user_id}`}
                    icon={<DeleteOutlined />}
                    disabled={!canWrite}
                    onClick={() => remove(person)}
                  />
                ),
              },
            ]}
          />
        </section>
        <div className="role-guide">
          <div><Tag color="red">ADMIN</Tag><p>Manage access, licenses, API keys, and platform policies.</p></div>
          <div><Tag color="blue">MEMBER</Tag><p>Submit alerts, investigate root causes, and execute containment.</p></div>
          <div><Tag color="default">VIEWER</Tag><p>Review live telemetry, incident dossiers, and executive reports.</p></div>
        </div>
        <Modal
          title="Add an existing user"
          open={addOpen}
          onCancel={() => setAddOpen(false)}
          onOk={() => form.submit()}
          okText="Add member"
          confirmLoading={add.isPending}
        >
          <p className="muted">Enter the unique User ID of a registered analyst to provision membership and assign access controls.</p>
          <Form form={form} layout="vertical" initialValues={{ role: 'member' }} onFinish={values => add.mutate(values)}>
            <Form.Item name="user_id" label="User ID" rules={[{ required: true, whitespace: true }]}>
              <Input placeholder="usr-…" />
            </Form.Item>
            <Form.Item name="role" label="Role">
              <Select options={['member', 'viewer', 'admin'].map(value => ({ value, label: value.toUpperCase() }))} />
            </Form.Item>
            {add.error && <Alert type="error" title={add.error.message} />}
          </Form>
        </Modal>
      </>
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // MAIN PLATFORM SETTINGS & APPLICATION CONFIGURATION
  // ─────────────────────────────────────────────────────────────────────────────
  const cfg = configQuery.data;

  return (
    <>
      <PageTitle
        eyebrow="GOVERN / SETTINGS"
        title="Platform Configuration &amp; API Keys"
        description="Manage AI engine providers, API keys, SIEM connectors, threat intelligence feeds, and autonomous containment guardrails."
        actions={activeTab === 'model' ? undefined :
          <Space>
            <Button
              icon={<ReloadOutlined spin={configQuery.isFetching} />}
              onClick={() => void configQuery.refetch()}
            >
              Refresh
            </Button>
            <Button
              type="primary"
              icon={<SaveOutlined />}
              disabled={!canWrite}
              loading={saveConfig.isPending}
              onClick={() => configForm.submit()}
            >
              Save Changes
            </Button>
          </Space>
        }
      />

      {canWrite && configQuery.isPending ? (
        <Loading />
      ) : canWrite && configQuery.error ? (
        <ErrorPanel error={configQuery.error} retry={() => void configQuery.refetch()} />
      ) : (
        <Form
          form={configForm}
          layout="vertical"
          onFinish={values => saveConfig.mutate(values)}
          requiredMark={false}
          className="settings-form"
          component={activeTab === 'model' ? false : 'form'}
        >
          <Tabs
            activeKey={activeTab}
            onChange={setActiveTab}
            className="settings-tabs"
            items={[
              {
                key: 'model',
                label: <span><ApiOutlined /> Model gateway</span>,
                children: <ModelSettings key={orgId} />,
              },
              // ─── TAB 1: AI & LLM ENGINE ──────────────────────────────────
              {
                key: 'ai',
                label: <span><ThunderboltOutlined /> AI Forensics Engine</span>,
                children: (
                  <div className="settings-section-card">
                    <div className="settings-section-header">
                      <div>
                        <h3>AI Model &amp; Reasoning Parameters</h3>
                        <p className="muted">Configure the LLM endpoint that drives autonomous triage, script de-obfuscation, and Copilot investigations.</p>
                      </div>
                      <Button
                        icon={<ExperimentOutlined />}
                        loading={testConn.isPending}
                        onClick={() => {
                          const values = configForm.getFieldsValue();
                          testConn.mutate({
                            service: 'llm',
                            target_url: values.llm_base_url,
                            api_key: values.llm_api_key,
                            model: values.llm_model,
                          });
                        }}
                      >
                        Test LLM Connection
                      </Button>
                    </div>

                    <div className="settings-form-grid">
                      <Form.Item name="llm_model" label="AI Model Identifier" tooltip="Model name accepted by the API endpoint">
                        <Select
                          showSearch
                          options={[
                            { value: 'openai/gpt-oss-20b', label: 'openai/gpt-oss-20b (Groq LPU Engine - Recommended)' },
                            { value: 'gpt-4o', label: 'gpt-4o (OpenAI Enterprise)' },
                            { value: 'gpt-4o-mini', label: 'gpt-4o-mini (OpenAI Fast Triage)' },
                            { value: 'claude-3-7-sonnet', label: 'claude-3-7-sonnet (Anthropic Reasoning)' },
                            { value: 'llama-3.3-70b-versatile', label: 'llama-3.3-70b-versatile (Meta / Groq)' },
                            { value: 'ollama/llama3.3', label: 'ollama/llama3.3 (Local Air-Gapped Host)' },
                          ]}
                        />
                      </Form.Item>

                      <Form.Item name="llm_base_url" label="API Base URL Endpoint" tooltip="Compatible with OpenAI / Groq / Ollama / vLLM API formats">
                        <Input placeholder="https://api.groq.com/openai/v1" />
                      </Form.Item>
                    </div>

                    <div className="settings-form-grid">
                      <Form.Item
                        name="llm_api_key"
                        label="LLM API Key"
                        extra={cfg?.llm?.has_api_key ? `Current Key: ${cfg.llm.api_key_masked} (Leave empty to keep existing key)` : 'No API key currently set. In-memory demo fallback active.'}
                      >
                        <Input.Password placeholder="gsk_... or sk-..." prefix={<KeyOutlined />} />
                      </Form.Item>

                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                        <Form.Item name="llm_temperature" label="Temperature" tooltip="Lower values yield deterministic SOC verdicts">
                          <InputNumber min={0} max={1.5} step={0.05} style={{ width: '100%' }} />
                        </Form.Item>
                        <Form.Item name="llm_max_tokens" label="Max Output Tokens">
                          <InputNumber min={512} max={16384} step={512} style={{ width: '100%' }} />
                        </Form.Item>
                      </div>
                    </div>

                    <Divider style={{ margin: '12px 0 18px' }} />

                    <h4>Forensic Reasoning Capabilities</h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 10 }}>
                      <div className="toggle-row">
                        <div>
                          <strong>Autonomous ReAct Forensics</strong>
                          <p className="muted">Allow the agent to autonomously query SIEM logs, IOC databases, and attack topology graphs.</p>
                        </div>
                        <Form.Item name="enable_react_forensics" valuePropName="checked" noStyle>
                          <Switch />
                        </Form.Item>
                      </div>

                      <div className="toggle-row">
                        <div>
                          <strong>Automatic Payload De-obfuscation</strong>
                          <p className="muted">Automatically unpack Base64, Hex, URL-encoded commands, and strip cloud secrets before analysis.</p>
                        </div>
                        <Form.Item name="enable_deobfuscation" valuePropName="checked" noStyle>
                          <Switch />
                        </Form.Item>
                      </div>

                      <div className="toggle-row">
                        <div>
                          <strong>Real-Time CTI Intelligence Enrichment</strong>
                          <p className="muted">Correlate extracted IOCs (IPs, hashes, domains) against VirusTotal and AlienVault OTX knowledge base.</p>
                        </div>
                        <Form.Item name="enable_cti_lookup" valuePropName="checked" noStyle>
                          <Switch />
                        </Form.Item>
                      </div>
                    </div>
                  </div>
                ),
              },

              // ─── TAB 2: SIEM & TELEMETRY ─────────────────────────────────
              {
                key: 'siem',
                label: <span><ApiOutlined /> SIEM &amp; Ingestion</span>,
                children: (
                  <div className="settings-section-card">
                    <div className="settings-section-header">
                      <div>
                        <h3>Wazuh SIEM Manager &amp; Ingestion Pipeline</h3>
                        <p className="muted">Connect your Wazuh manager API for live host inventory, agent statuses, and real-time rule telemetry.</p>
                      </div>
                      <Space>
                        <Button
                          icon={<SendOutlined />}
                          onClick={() => setIngest(true)}
                        >
                          Simulate Alert
                        </Button>
                        <Button
                          icon={<ExperimentOutlined />}
                          loading={testConn.isPending}
                          onClick={() => {
                            const values = configForm.getFieldsValue();
                            testConn.mutate({
                              service: 'wazuh',
                              target_url: values.wazuh_url,
                            });
                          }}
                        >
                          Test Wazuh Connection
                        </Button>
                      </Space>
                    </div>

                    <div className="settings-form-grid">
                      <Form.Item name="wazuh_url" label="Wazuh Manager API Endpoint">
                        <Input placeholder="https://wazuh.soc.internal:55000" prefix={<LinkOutlined />} />
                      </Form.Item>

                      <Form.Item name="polling_interval_sec" label="Live Polling Sync Interval">
                        <Select
                          options={[
                            { value: 5, label: '5 seconds (High Frequency / Testing)' },
                            { value: 15, label: '15 seconds (Standard SOC)' },
                            { value: 30, label: '30 seconds (Balanced - Recommended)' },
                            { value: 60, label: '60 seconds (Low Bandwidth)' },
                          ]}
                        />
                      </Form.Item>
                    </div>

                    <div className="settings-form-grid">
                      <Form.Item name="wazuh_user" label="API Username">
                        <Input placeholder="wazuh-api" />
                      </Form.Item>

                      <Form.Item
                        name="wazuh_password"
                        label="API Password"
                        extra={cfg?.siem?.has_wazuh_password ? 'Password configured (Leave blank to keep current)' : 'No password set'}
                      >
                        <Input.Password placeholder="Enter Wazuh API password" prefix={<LockOutlined />} />
                      </Form.Item>
                    </div>

                    <Divider style={{ margin: '12px 0 18px' }} />

                    <h4>Direct Ingestion Webhook Endpoint</h4>
                    <p className="muted">Forward alerts directly from Wazuh `ossec.conf` or external SIEM forwarders using authenticated JSON webhooks:</p>
                    <Code>{`curl -X POST '${window.location.origin}/wazuh' \\\n  -H 'Authorization: Bearer <SESSION_TOKEN>' \\\n  -H 'X-Org-ID: ${orgId}' \\\n  -H 'Content-Type: application/json' \\\n  -d '{"id":"test-001","rule":{"id":100100,"level":12,"description":"Privilege Escalation"},"agent":{"name":"db-core-01"},"full_log":"sudo: exploit attempt"}'`}</Code>
                  </div>
                ),
              },

              // ─── TAB 3: THREAT INTELLIGENCE (CTI) ────────────────────────
              {
                key: 'cti',
                label: <span><SafetyCertificateOutlined /> Threat Intel (CTI)</span>,
                children: (
                  <div className="settings-section-card">
                    <div className="settings-section-header">
                      <div>
                        <h3>Cyber Threat Intelligence (CTI) API Keys</h3>
                        <p className="muted">Provide API keys for automated indicator reputation checks, malware hash lookups, and adversary infrastructure correlation.</p>
                      </div>
                    </div>

                    <div className="settings-form-grid">
                      <Form.Item
                        name="virustotal_api_key"
                        label="VirusTotal API Key"
                        extra={cfg?.cti?.has_virustotal_key ? `Configured: ${cfg.cti.virustotal_key_masked}` : 'Free or Enterprise API key for hash & domain telemetry'}
                      >
                        <Input.Password placeholder="Enter VirusTotal API key" prefix={<KeyOutlined />} />
                      </Form.Item>

                      <Form.Item
                        name="abuseipdb_api_key"
                        label="AbuseIPDB API Key"
                        extra={cfg?.cti?.has_abuseipdb_key ? `Configured: ${cfg.cti.abuseipdb_key_masked}` : 'IP reputation and reported malicious confidence scores'}
                      >
                        <Input.Password placeholder="Enter AbuseIPDB API key" prefix={<KeyOutlined />} />
                      </Form.Item>
                    </div>

                    <div className="settings-form-grid">
                      <Form.Item
                        name="otx_api_key"
                        label="AlienVault OTX Key"
                        extra={cfg?.cti?.has_otx_key ? `Configured: ${cfg.cti.otx_key_masked}` : 'Open Threat Exchange adversary campaign intelligence'}
                      >
                        <Input.Password placeholder="Enter AlienVault OTX API key" prefix={<KeyOutlined />} />
                      </Form.Item>

                      <Form.Item name="cti_cache_ttl_hours" label="CTI Cache Expiration (Hours)" tooltip="Prevent duplicate API consumption for known indicators">
                        <InputNumber min={1} max={168} style={{ width: '100%' }} />
                      </Form.Item>
                    </div>
                  </div>
                ),
              },

              // ─── TAB 4: TICKETING & NOTIFICATIONS ────────────────────────
              {
                key: 'notifications',
                label: <span><SendOutlined /> Ticketing &amp; Alerts</span>,
                children: (
                  <div className="settings-section-card">
                    <div className="settings-section-header">
                      <div>
                        <h3>Jira Ticketing &amp; Urgent Alert Dispatch</h3>
                        <p className="muted">Synchronize incidents with enterprise issue tracking and broadcast high-severity escalations.</p>
                      </div>
                      <Space>
                        <Button
                          icon={<ExperimentOutlined />}
                          loading={testConn.isPending}
                          onClick={() => {
                            const values = configForm.getFieldsValue();
                            testConn.mutate({
                              service: 'jira',
                              target_url: values.jira_url,
                            });
                          }}
                        >
                          Test Jira
                        </Button>
                        <Button
                          icon={<SendOutlined />}
                          loading={testConn.isPending}
                          onClick={() => {
                            const values = configForm.getFieldsValue();
                            testConn.mutate({
                              service: 'slack',
                              target_url: values.slack_webhook,
                            });
                          }}
                        >
                          Test Slack
                        </Button>
                      </Space>
                    </div>

                    <div className="settings-form-grid">
                      <Form.Item name="jira_url" label="Jira Instance URL">
                        <Input placeholder="https://yourcompany.atlassian.net" prefix={<LinkOutlined />} />
                      </Form.Item>

                      <Form.Item name="jira_project" label="Jira Project Key">
                        <Input placeholder="SEC" />
                      </Form.Item>
                    </div>

                    <div className="settings-form-grid">
                      <Form.Item name="jira_user" label="Jira Service User Email">
                        <Input placeholder="soc-automation@yourcompany.com" />
                      </Form.Item>

                      <Form.Item
                        name="jira_token"
                        label="Jira API Token"
                        extra={cfg?.ticketing?.has_jira_token ? `Token set: ${cfg.ticketing.jira_token_masked}` : 'Atlassian API token with issue create permissions'}
                      >
                        <Input.Password placeholder="Paste Jira API token" prefix={<KeyOutlined />} />
                      </Form.Item>
                    </div>

                    <Divider style={{ margin: '12px 0 18px' }} />

                    <h4>Urgent Notification Webhooks</h4>
                    <div className="settings-form-grid">
                      <Form.Item
                        name="slack_webhook"
                        label="Slack Incident Webhook URL"
                        extra={cfg?.ticketing?.slack_webhook_configured ? `Active: ${cfg.ticketing.slack_webhook_masked}` : 'Incoming webhook for Tier-1 SOC broadcast channel'}
                      >
                        <Input.Password placeholder="https://hooks.slack.com/services/..." prefix={<LinkOutlined />} />
                      </Form.Item>

                      <Form.Item name="sms_to" label="On-Call SMS Notification Number">
                        <Input placeholder="9364992155" prefix={<ThunderboltOutlined />} />
                      </Form.Item>
                    </div>
                  </div>
                ),
              },

              // ─── TAB 5: CONTAINMENT & SAFETY GUARDRAILS ─────────────────
              {
                key: 'containment',
                label: <span><LockOutlined /> Containment &amp; Guardrails</span>,
                children: (
                  <div className="settings-section-card">
                    <div className="settings-section-header">
                      <div>
                        <h3>Autonomous Containment &amp; Blast Radius Policies</h3>
                        <p className="muted">Control active response execution boundaries, blast radius limits, and deterministic triage rule levels.</p>
                      </div>
                    </div>

                    <Form.Item name="containment_mode" label="Containment Execution Mode">
                      <Radio.Group style={{ width: '100%' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                          <Card size="small" className="mode-card">
                            <Radio value="observation_only">
                              <strong>Observation Only</strong>
                              <p className="muted" style={{ fontSize: 11, margin: '4px 0 0' }}>Proposes actions without executing containment scripts.</p>
                            </Radio>
                          </Card>
                          <Card size="small" className="mode-card">
                            <Radio value="human_in_the_loop">
                              <strong>Human in the Loop (Default)</strong>
                              <p className="muted" style={{ fontSize: 11, margin: '4px 0 0' }}>Requires explicit analyst review and confirmation in console.</p>
                            </Radio>
                          </Card>
                          <Card size="small" className="mode-card">
                            <Radio value="autonomous">
                              <strong>Autonomous Active Response</strong>
                              <p className="muted" style={{ fontSize: 11, margin: '4px 0 0' }}>Automatically isolates confirmed compromised endpoints &amp; blocks attacker IPs.</p>
                            </Radio>
                          </Card>
                        </div>
                      </Radio.Group>
                    </Form.Item>

                    <Form.Item
                      name="protected_subnets"
                      label="Protected Subnets &amp; Critical Asset Whitelist"
                      tooltip="Comma-separated CIDRs or hostnames that guardrails will NEVER isolate or block"
                    >
                      <Input.TextArea rows={2} placeholder="10.0.0.0/8, 192.168.1.0/24, 127.0.0.0/8, domain-controller-01, core-banking" />
                    </Form.Item>

                    <Divider style={{ margin: '12px 0 18px' }} />

                    <h4>Deterministic Triage Engine Thresholds</h4>
                    <p className="muted" style={{ marginBottom: 14 }}>Alerts below Level 5 are ignored; Level 5–9 triggers forensic triage; Level 10+ or MITRE tags trigger immediate escalation.</p>

                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
                      <Form.Item name="policy_ignore_threshold" label="IGNORE Threshold (< Level)">
                        <InputNumber min={1} max={15} style={{ width: '100%' }} />
                      </Form.Item>
                      <Form.Item name="policy_triage_threshold" label="TRIAGE Upper Bound (Level)">
                        <InputNumber min={1} max={15} style={{ width: '100%' }} />
                      </Form.Item>
                      <Form.Item name="policy_escalate_threshold" label="ESCALATE Threshold (≥ Level)">
                        <InputNumber min={1} max={15} style={{ width: '100%' }} />
                      </Form.Item>
                    </div>
                  </div>
                ),
              },

              // ─── TAB 6: LICENSE & GOVERNANCE ─────────────────────────────
              {
                key: 'license',
                label: <span><SettingOutlined /> License &amp; System</span>,
                children: (
                  <div className="settings-section-card">
                    <div className="settings-grid">
                      <section className="panel" style={{ background: 'var(--bg-panel)' }}>
                        <div className="eyebrow">LICENSE ENTITLEMENT</div>
                        <h2>Enterprise Cryptographic Entitlement</h2>
                        {detail?.license_error && <Alert type="error" title={detail.license_error} />}
                        <p className="muted">HMAC-signed license tokens define organization tier entitlements and maximum seat allocations.</p>
                        <Space wrap style={{ marginBottom: 14 }}>
                          {detail?.license?.features.map(f => (
                            <Tag key={f} color="cyan" icon={<CheckCircleOutlined />}>
                              {f.replaceAll('_', ' ').toUpperCase()}
                            </Tag>
                          ))}
                        </Space>
                        <Form layout="vertical" onFinish={values => license.mutate(values)}>
                          <Form.Item name="token" label="Activate New License Token" rules={[{ required: true }]}>
                            <Input.TextArea rows={3} disabled={!canWrite} placeholder="Paste HMAC-signed license token string..." />
                          </Form.Item>
                          <Button type="primary" htmlType="submit" icon={<KeyOutlined />} disabled={!canWrite} loading={license.isPending}>
                            Activate License
                          </Button>
                        </Form>
                      </section>

                      <section className="panel" style={{ background: 'var(--bg-panel)' }}>
                        <div className="eyebrow">ACTIVE ACCOUNT SESSION</div>
                        <h2>{user.display_name}</h2>
                        <Descriptions
                          column={1}
                          size="small"
                          items={[
                            { key: 'email', label: 'Email', children: user.email },
                            {
                              key: 'id',
                              label: 'User ID',
                              children: (
                                <Button
                                  type="text"
                                  icon={<CopyOutlined />}
                                  onClick={() => {
                                    void navigator.clipboard.writeText(user.user_id);
                                    message.success('User ID copied');
                                  }}
                                >
                                  {user.user_id}
                                </Button>
                              ),
                            },
                            { key: 'session', label: 'Session Type', children: 'HttpOnly secure cookie · 12-hour expiration' },
                          ]}
                        />
                      </section>
                    </div>
                  </div>
                ),
              },
            ]}
          />
        </Form>
      )}
      <IngestModal open={ingest} close={() => setIngest(false)} />
    </>
  );
}
