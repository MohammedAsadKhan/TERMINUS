// File: settings.tsx
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Manage saved console configuration and distinguish it from verified connectivity or enforced containment.

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

// Serves two routes: Organization (members, seats, roles) and Platform settings (the model gateway plus saved server
// configuration). Platform values are saved configuration only; they do not verify a provider, prove ingestion or
// enforce containment, as the page text says. The configuration query runs only for admins.
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

  // Fetch the configuration currently held by this server process.
  const configQuery = useQuery({
    queryKey: ['platform-config', orgId],
    queryFn: () => api<Record<string, any>>('/settings/config', orgId),
    enabled: canWrite,
  });

  // Secret fields always load blank because the API returns only masked values and has_* flags. The fallbacks apply when
  // the server omits a value.
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

  // Blank fields are left out of the request so an untouched secret keeps its stored value; the side effect is that a
  // field cannot be cleared to empty from this form.
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
      message.success('Configuration saved for this server process. External connectivity was not verified.');
    },
    onError: (err: Error) => message.error(`Failed to save configuration: ${err.message}`),
  });

  // The current endpoint reports configuration state only; never present it as a passed connectivity test.
  const testConn = useMutation({
    mutationFn: (payload: { service: string; target_url?: string; api_key?: string; model?: string }) =>
      api<{ success: boolean; latency_ms: number; message: string }>('/settings/test-connection', orgId, body('POST', payload)),
    onSuccess: res => {
      const text = `[${res.latency_ms}ms] ${res.message}`;
      if (res.success) message.success(text);
      else message.warning(text);
    },
    onError: (err: Error) => message.error(`Connection check failed: ${err.message}`),
  });

  // Adds an existing registered user, identified by user id, to the organization.
  const add = useMutation({
    mutationFn: (values: { user_id: string; role: string }) => api(`/orgs/${orgId}/members`, orgId, body('POST', values)),
    onSuccess: () => {
      query.invalidateQueries({ queryKey: ['org', orgId] });
      setAddOpen(false);
      form.resetFields();
      message.success('Member added');
    },
  });

  // Submits a signed license token; the server validates it and any error is shown as a message.
  const license = useMutation({
    mutationFn: (values: { token: string }) => api(`/orgs/${orgId}/license`, orgId, body('POST', values)),
    onSuccess: () => {
      query.invalidateQueries({ queryKey: ['org', orgId] });
      message.success('License activated');
    },
    onError: error => message.error(error.message),
  });

  // Changes a member's role; the member list reloads on success and the server's error is shown otherwise.
  async function role(member: Membership, value: string) {
    try {
      await api(`/orgs/${orgId}/members/${member.user_id}`, orgId, body('PATCH', { role: value }));
      query.invalidateQueries({ queryKey: ['org', orgId] });
      message.success('Role updated');
    } catch (error) {
      message.error((error as Error).message);
    }
  }

  // Removes the membership only. On failure the error is shown and rethrown so the confirmation dialog stays open.
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
  // The organization route returns here; the hooks above run for both views so hook order stays the same.
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
          <div><Tag color="blue">MEMBER</Tag><p>Submit alerts and review stored investigation records.</p></div>
          <div><Tag color="default">VIEWER</Tag><p>Review stored telemetry, incident dossiers, and executive reports.</p></div>
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
  // Masked values and has_* flags only; stored secrets are never returned to the browser.
  const cfg = configQuery.data;

  // The model gateway tab has its own save controls, so the shared form renders as a plain wrapper there (component={false}).
  // The other tabs share one form, and Save configuration submits their values together.
  return (
    <>
      <PageTitle
        eyebrow="GOVERN / SETTINGS"
        title="Platform Configuration &amp; API Keys"
        description="Manage model, SIEM, threat-intelligence, and notification settings. Saved values configure this server process; they do not verify a provider, prove ingestion, or authorize containment."
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
              Save configuration
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
                        <p className="muted">Configure the LLM endpoint used by the legacy investigation and Copilot paths. Saving does not contact a provider or verify a credential.</p>
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
                        Check LLM configuration
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
                        extra={cfg?.llm?.has_api_key ? `Current Key: ${cfg.llm.api_key_masked} (Leave empty to keep existing key)` : 'No model key configured. Investigations run offline; no provider request is made.'}
                      >
                        <Input.Password placeholder="gsk_... or sk-..." prefix={<KeyOutlined />} />
                      </Form.Item>

                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                        <Form.Item name="llm_temperature" label="Temperature" tooltip="Stored preference; model behavior and provider access are not verified here.">
                          <InputNumber min={0} max={1.5} step={0.05} style={{ width: '100%' }} />
                        </Form.Item>
                        <Form.Item name="llm_max_tokens" label="Max Output Tokens">
                          <InputNumber min={512} max={16384} step={512} style={{ width: '100%' }} />
                        </Form.Item>
                      </div>
                    </div>

                    <Divider style={{ margin: '12px 0 18px' }} />

                    <h4>Stored forensic preferences</h4>
                    <Alert
                      className="context-alert"
                      type="info"
                      showIcon
                      title="These switches do not control live behavior"
                      description="Values are saved to this server process. The current investigation path does not read them, so they do not enable autonomous tool use, de-obfuscation, or threat-intelligence lookups."
                    />
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 10 }}>
                      <div className="toggle-row">
                        <div>
                          <strong>ReAct forensics preference</strong>
                          <p className="muted">Stored preference. No autonomous tool loop is started from this switch.</p>
                        </div>
                        <Form.Item name="enable_react_forensics" valuePropName="checked" noStyle>
                          <Switch />
                        </Form.Item>
                      </div>

                      <div className="toggle-row">
                        <div>
                          <strong>Payload de-obfuscation preference</strong>
                          <p className="muted">Stored preference. De-obfuscation support in the legacy path is not controlled here.</p>
                        </div>
                        <Form.Item name="enable_deobfuscation" valuePropName="checked" noStyle>
                          <Switch />
                        </Form.Item>
                      </div>

                      <div className="toggle-row">
                        <div>
                          <strong>Threat-intelligence lookup preference</strong>
                          <p className="muted">Stored preference. Provider keys and reputation lookups are not verified or executed from this page.</p>
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
                        <p className="muted">Save a Wazuh manager endpoint for configuration. This console does not read host inventory, agent health, or rule telemetry from that URL.</p>
                      </div>
                      <Space>
                        <Button
                          icon={<SendOutlined />}
                          onClick={() => setIngest(true)}
                        >
                          Synthetic test alert
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
                          Check Wazuh configuration
                        </Button>
                      </Space>
                    </div>

                    <div className="settings-form-grid">
                      <Form.Item name="wazuh_url" label="Wazuh Manager API Endpoint">
                        <Input placeholder="https://wazuh.soc.internal:55000" prefix={<LinkOutlined />} />
                      </Form.Item>

                      <Form.Item name="polling_interval_sec" label="Requested polling interval">
                        <Select
                          options={[
                            { value: 5, label: '5 seconds' },
                            { value: 15, label: '15 seconds' },
                            { value: 30, label: '30 seconds (default)' },
                            { value: 60, label: '60 seconds' },
                          ]}
                        />
                      </Form.Item>
                    </div>
                    <Alert
                      className="context-alert"
                      type="info"
                      showIcon
                      title="Polling preference only"
                      description="The current service stores this value but does not start a polling loop from the console."
                    />

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

                    <h4>Source-bound Wazuh intake</h4>
                    <p className="muted">A Wazuh integrator can post to the source endpoint with the server-side key configured by <code>TERMINUS_WAZUH_WEBHOOK_KEY</code> (at least 32 characters), bound to one organization by <code>TERMINUS_WAZUH_WEBHOOK_ORG</code>. Missing or mismatched keys are rejected, and the raw receipt is hashed. Manual console submissions use the synthetic test alert button above and are recorded as operator submissions, not Wazuh-origin events.</p>
                    <Code>{`curl -X POST '${window.location.origin}/sources/wazuh' \\\n  -H 'X-Terminus-Source-Key: <configured-source-key>' \\\n  -H 'Content-Type: application/json' \\\n  -d '{"id":"test-001","rule":{"id":100100,"level":12,"description":"Privilege Escalation"},"agent":{"name":"db-core-01"},"full_log":"sudo: exploit attempt"}'`}</Code>
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
                        <p className="muted">Store indicator-lookup keys for this server process. The console does not verify these keys or run reputation lookups from this page.</p>
                      </div>
                    </div>
                    <Alert
                      className="context-alert"
                      type="info"
                      showIcon
                      title="Stored credentials only"
                      description="Saving a key does not make a provider request. A configured key is not evidence of provider access or successful enrichment."
                    />

                    <div className="settings-form-grid">
                      <Form.Item
                        name="virustotal_api_key"
                        label="VirusTotal API Key"
                        extra={cfg?.cti?.has_virustotal_key ? `Configured: ${cfg.cti.virustotal_key_masked}` : 'Stored for connector configuration; not verified here'}
                      >
                        <Input.Password placeholder="Enter VirusTotal API key" prefix={<KeyOutlined />} />
                      </Form.Item>

                      <Form.Item
                        name="abuseipdb_api_key"
                        label="AbuseIPDB API Key"
                        extra={cfg?.cti?.has_abuseipdb_key ? `Configured: ${cfg.cti.abuseipdb_key_masked}` : 'Stored for connector configuration; not verified here'}
                      >
                        <Input.Password placeholder="Enter AbuseIPDB API key" prefix={<KeyOutlined />} />
                      </Form.Item>
                    </div>

                    <div className="settings-form-grid">
                      <Form.Item
                        name="otx_api_key"
                        label="AlienVault OTX Key"
                        extra={cfg?.cti?.has_otx_key ? `Configured: ${cfg.cti.otx_key_masked}` : 'Stored for connector configuration; not verified here'}
                      >
                        <Input.Password placeholder="Enter AlienVault OTX API key" prefix={<KeyOutlined />} />
                      </Form.Item>

                      <Form.Item name="cti_cache_ttl_hours" label="CTI cache expiration (hours)" tooltip="Stored preference; no live lookup path currently reads it.">
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
                        <p className="muted">Save ticketing and notification connector values. Saving does not create a ticket or send a message.</p>
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
                          Check Jira configuration
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
                          Check Slack configuration
                        </Button>
                      </Space>
                    </div>
                    <Alert
                      className="context-alert"
                      type="info"
                      showIcon
                      title="Connector configuration only"
                      description="These fields are stored for this server process. Saving does not contact Jira, Slack, or Twilio, and a successful save is not a delivery receipt."
                    />

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

                    <h4>Notification connector values</h4>
                    <div className="settings-form-grid">
                      <Form.Item
                        name="slack_webhook"
                        label="Slack incident webhook URL"
                        extra={cfg?.ticketing?.slack_webhook_configured ? `Configured: ${cfg.ticketing.slack_webhook_masked}` : 'Stored webhook; no notification is sent from this page'}
                      >
                        <Input.Password placeholder="https://hooks.slack.com/services/..." prefix={<LinkOutlined />} />
                      </Form.Item>

                      <Form.Item name="sms_to" label="SMS notification number (stored)" extra="Requires a configured Twilio connector on the server; no SMS is sent from this page.">
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
                        <h3>Containment Policy Preferences (Not Enforced)</h3>
                        <p className="muted">These values configure this server process only. The console does not authorize or execute containment, and generic isolate/block actions return 501.</p>
                      </div>
                    </div>
                    <Alert
                      className="context-alert"
                      type="warning"
                      showIcon
                      title="No response is executed from these settings"
                      description="A real response requires a separate scoped proposal, approval, and response worker. Changing this mode does not isolate a host or block an address."
                    />

                    <Form.Item name="containment_mode" label="Containment mode preference">
                      <Radio.Group style={{ width: '100%' }}>
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                          <Card size="small" className="mode-card">
                            <Radio value="observation_only">
                              <strong>Observation only</strong>
                              <p className="muted" style={{ fontSize: 11, margin: '4px 0 0' }}>Stored preference. No action is proposed or executed from this page.</p>
                            </Radio>
                          </Card>
                          <Card size="small" className="mode-card">
                            <Radio value="human_in_the_loop">
                              <strong>Human in the loop (default)</strong>
                              <p className="muted" style={{ fontSize: 11, margin: '4px 0 0' }}>Stored preference. Any real response still needs a separate approval and worker.</p>
                            </Radio>
                          </Card>
                          <Card size="small" className="mode-card">
                            <Radio value="autonomous">
                              <strong>Autonomous preference (inactive)</strong>
                              <p className="muted" style={{ fontSize: 11, margin: '4px 0 0' }}>Stored preference only. This build does not automatically isolate endpoints or block IPs.</p>
                            </Radio>
                          </Card>
                        </div>
                      </Radio.Group>
                    </Form.Item>

                    <Form.Item
                      name="protected_subnets"
                      label="Protected subnets preference"
                      tooltip="Stored list; the console does not enforce it today."
                    >
                      <Input.TextArea rows={2} placeholder="10.0.0.0/8, 192.168.1.0/24, 127.0.0.0/8, domain-controller-01, core-banking" />
                    </Form.Item>

                    <Divider style={{ margin: '12px 0 18px' }} />

                    <h4>Triage threshold preferences (not applied)</h4>
                    <p className="muted" style={{ marginBottom: 14 }}>Stored values only. The current policy engine uses its own server-side thresholds; these fields are not read during evaluation.</p>

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
                            { key: 'session', label: 'Session Type', children: 'HttpOnly cookie · SameSite=Strict · 12-hour expiry' },
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
