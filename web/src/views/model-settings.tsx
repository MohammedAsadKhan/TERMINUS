import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Descriptions,
  Empty,
  Input,
  Modal,
  Popconfirm,
  Select,
  Skeleton,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
} from 'antd';
import {
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  ReloadOutlined,
  SaveOutlined,
} from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, api, body } from '../api';
import { useSession } from '../context';
import './model-settings.css';

type Provider = 'openai' | 'anthropic' | 'gemini' | 'openrouter' | 'deepseek' | 'local' | 'openai_compatible';
type Classification = 'local_only' | 'approved_cloud' | 'redacted_cloud';
type Area = 'alert_handling' | 'investigation' | 'infrastructure' | 'applications_data' | 'response_improvement';

interface Connection {
  org_id: string;
  connection_id: string;
  name: string;
  provider: Provider;
  base_url: string | null;
  models: string[];
  enabled: boolean;
  credential_configured: boolean;
  credential_mask: '********' | null;
  version: number;
  updated_at: string;
  verification_status: 'unverified';
}

interface Status {
  credential_storage_ready: boolean;
  registered_connections: number;
  live_validation: string;
  setup_required: string[];
}

interface Grant {
  role: string;
  area: Area | null;
  connection_id: string;
  connection_version: number;
  models: string[];
  classifications: Classification[];
}

interface Policy {
  org_id: string;
  version: number;
  grants: Grant[];
  enabled: boolean;
}

interface Budget {
  window_key: string;
  limit_micro_usd: number;
  limit_tokens: number | null;
  version: number;
}

interface Usage {
  window_key: string;
  limit_micro_usd: number | null;
  limit_tokens: number | null;
  known_cost_micro_usd: number;
  unknown_cost_count: number;
  ambiguous_exposure_micro_usd: number;
  reserved_exposure_micro_usd: number;
  exposure_micro_usd: number;
  remaining_micro_usd: number | null;
  over_limit: boolean;
}

interface Price {
  connection_id: string;
  model: string;
  input_per_mtok_micro_usd: number;
  output_per_mtok_micro_usd: number;
  cached_input_per_mtok_micro_usd: number | null;
  reasoning_per_mtok_micro_usd: number | null;
  version: number;
}

interface ConnectionDraft {
  name: string;
  provider: Provider;
  base_url: string;
  models: string[];
  enabled: boolean;
  apiKey: string;
  credentialAction: 'keep' | 'replace' | 'clear';
}

const PROVIDERS: Array<{ value: Provider; label: string }> = [
  { value: 'openai', label: 'OpenAI' },
  { value: 'anthropic', label: 'Anthropic' },
  { value: 'gemini', label: 'Gemini' },
  { value: 'openrouter', label: 'OpenRouter' },
  { value: 'deepseek', label: 'DeepSeek' },
  { value: 'local', label: 'Local endpoint' },
  { value: 'openai_compatible', label: 'OpenAI-compatible endpoint' },
];
const CLOUD_PROVIDERS = new Set<Provider>(['openai', 'anthropic', 'gemini', 'openrouter', 'deepseek']);
const ROLES = ['triage', 'identity', 'endpoint', 'network', 'response_planner', 'verification', 'evidence_reporting', 'application_api', 'main_orchestrator', 'area_orchestrator'];
const AREAS: Area[] = ['alert_handling', 'investigation', 'infrastructure', 'applications_data', 'response_improvement'];
const CLASSIFICATIONS: Classification[] = ['local_only', 'approved_cloud', 'redacted_cloud'];

const emptyConnection = (): ConnectionDraft => ({
  name: '', provider: 'openai', base_url: '', models: [], enabled: false, apiKey: '', credentialAction: 'keep',
});
const friendly = (value: string) => value.replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase());
const requestMessage = (error: unknown) => error instanceof Error ? error.message : 'The request could not be completed.';
const conflictMessage = (error: unknown) => error instanceof ApiError && error.status === 409
  ? 'This request conflicts with the saved configuration. Refresh, then check the record version, connection name, endpoint, and credential choice before retrying.'
  : requestMessage(error);
const optionalInteger = (value: string) => value.trim() === '' ? null : Number(value);
const requiredInteger = (value: string) => Number(value);
const validInteger = (value: string, optional = false) => (optional && value.trim() === '') || /^\d+$/.test(value.trim());
const usd = (microUsd: number | null) => microUsd === null
  ? 'Unknown'
  : new Intl.NumberFormat(undefined, { style: 'currency', currency: 'USD', minimumFractionDigits: 2, maximumFractionDigits: 6 }).format(microUsd / 1_000_000);

async function optional<T>(path: string, orgId: string): Promise<T | null> {
  try {
    return await api<T>(path, orgId);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return <label className="model-field"><span>{label}</span>{children}{hint && <small>{hint}</small>}</label>;
}

export default function ModelSettings() {
  const { orgId, detail } = useSession();
  const queryClient = useQueryClient();
  const canWrite = detail?.role === 'admin';
  const windowKey = new Date().toISOString().slice(0, 10);
  const [connectionOpen, setConnectionOpen] = useState(false);
  const [editing, setEditing] = useState<Connection | null>(null);
  const [connectionDraft, setConnectionDraft] = useState<ConnectionDraft>(emptyConnection);
  const [policyDraft, setPolicyDraft] = useState<{ enabled: boolean; grants: Grant[] }>({ enabled: true, grants: [] });
  const [budgetDraft, setBudgetDraft] = useState({ limit: '', tokens: '' });
  const [priceTarget, setPriceTarget] = useState({ connectionId: '', model: '' });
  const [priceDraft, setPriceDraft] = useState({ input: '', output: '', cached: '', reasoning: '' });

  const status = useQuery({
    queryKey: ['model-settings-status', orgId],
    queryFn: () => api<Status>('/model-settings/status', orgId),
    enabled: Boolean(orgId),
  });
  const connections = useQuery({
    queryKey: ['model-connections', orgId],
    queryFn: () => api<Connection[]>('/model-connections', orgId),
    enabled: Boolean(orgId),
  });
  const policy = useQuery({
    queryKey: ['model-policy', orgId],
    queryFn: () => optional<Policy>('/model-settings/policy', orgId),
    enabled: Boolean(orgId),
  });
  const budget = useQuery({
    queryKey: ['model-budget', orgId, windowKey],
    queryFn: () => optional<Budget>(`/model-settings/budget/${windowKey}`, orgId),
    enabled: Boolean(orgId),
  });
  const usage = useQuery({
    queryKey: ['model-usage', orgId, windowKey],
    queryFn: () => api<Usage>(`/model-settings/usage/${windowKey}`, orgId),
    enabled: Boolean(orgId),
  });
  const price = useQuery({
    queryKey: ['model-price', orgId, priceTarget.connectionId, priceTarget.model],
    queryFn: () => optional<Price>(`/model-settings/prices/${encodeURIComponent(priceTarget.connectionId)}/${encodeURIComponent(priceTarget.model)}`, orgId),
    enabled: Boolean(orgId && priceTarget.connectionId && priceTarget.model),
  });

  const selectedPriceConnection = useMemo(
    () => connections.data?.find(item => item.connection_id === priceTarget.connectionId),
    [connections.data, priceTarget.connectionId],
  );

  useEffect(() => {
    setConnectionOpen(false);
    setEditing(null);
    setConnectionDraft(emptyConnection());
    setPolicyDraft({ enabled: true, grants: [] });
    setBudgetDraft({ limit: '', tokens: '' });
    setPriceTarget({ connectionId: '', model: '' });
    setPriceDraft({ input: '', output: '', cached: '', reasoning: '' });
  }, [orgId]);

  useEffect(() => {
    setPolicyDraft(policy.data
      ? { enabled: policy.data.enabled, grants: policy.data.grants.map(grant => ({ ...grant, models: [...grant.models], classifications: [...grant.classifications] })) }
      : { enabled: true, grants: [] });
  }, [orgId, policy.dataUpdatedAt]);

  useEffect(() => {
    setBudgetDraft(budget.data
      ? { limit: String(budget.data.limit_micro_usd), tokens: budget.data.limit_tokens === null ? '' : String(budget.data.limit_tokens) }
      : { limit: '', tokens: '' });
  }, [orgId, budget.dataUpdatedAt]);

  useEffect(() => {
    setPriceDraft(price.data
      ? {
        input: String(price.data.input_per_mtok_micro_usd),
        output: String(price.data.output_per_mtok_micro_usd),
        cached: price.data.cached_input_per_mtok_micro_usd === null ? '' : String(price.data.cached_input_per_mtok_micro_usd),
        reasoning: price.data.reasoning_per_mtok_micro_usd === null ? '' : String(price.data.reasoning_per_mtok_micro_usd),
      }
      : { input: '', output: '', cached: '', reasoning: '' });
  }, [orgId, priceTarget.connectionId, priceTarget.model, price.dataUpdatedAt]);

  function closeConnection() {
    setConnectionOpen(false);
    setEditing(null);
    setConnectionDraft(emptyConnection());
    connectionSave.reset();
  }

  function openConnection(item?: Connection) {
    connectionSave.reset();
    setEditing(item || null);
    setConnectionDraft(item ? {
      name: item.name,
      provider: item.provider,
      base_url: item.base_url || '',
      models: [...item.models],
      enabled: item.enabled,
      apiKey: '',
      credentialAction: 'keep',
    } : emptyConnection());
    setConnectionOpen(true);
  }

  const connectionSave = useMutation({
    mutationFn: ({ tenant, payload, id }: { tenant: string; payload: Record<string, unknown>; id?: string }) =>
      api<Connection>(id ? `/model-connections/${encodeURIComponent(id)}` : '/model-connections', tenant, body(id ? 'PATCH' : 'POST', payload)),
    onSuccess: (_record, variables) => {
      void queryClient.invalidateQueries({ queryKey: ['model-connections', variables.tenant] });
      void queryClient.invalidateQueries({ queryKey: ['model-settings-status', variables.tenant] });
      if (variables.tenant === orgId) closeConnection();
    },
  });

  const connectionDelete = useMutation({
    mutationFn: ({ tenant, item }: { tenant: string; item: Connection }) =>
      api<void>(`/model-connections/${encodeURIComponent(item.connection_id)}?expected_version=${item.version}`, tenant, body('DELETE')),
    onSuccess: (_record, variables) => {
      void queryClient.invalidateQueries({ queryKey: ['model-connections', variables.tenant] });
      void queryClient.invalidateQueries({ queryKey: ['model-settings-status', variables.tenant] });
    },
  });

  const policySave = useMutation({
    mutationFn: ({ tenant, payload }: { tenant: string; payload: Record<string, unknown> }) =>
      api<Policy>('/model-settings/policy', tenant, body('PUT', payload)),
    onSuccess: (record, variables) => {
      queryClient.setQueryData(['model-policy', variables.tenant], record);
      if (variables.tenant === orgId) setPolicyDraft({ enabled: record.enabled, grants: record.grants });
    },
  });

  const budgetSave = useMutation({
    mutationFn: ({ tenant, payload }: { tenant: string; payload: Record<string, unknown> }) =>
      api<Budget>(`/model-settings/budget/${windowKey}`, tenant, body('PUT', payload)),
    onSuccess: (record, variables) => {
      queryClient.setQueryData(['model-budget', variables.tenant, windowKey], record);
      void queryClient.invalidateQueries({ queryKey: ['model-usage', variables.tenant, windowKey] });
    },
  });

  const priceSave = useMutation({
    mutationFn: ({ tenant, connectionId, model, payload }: { tenant: string; connectionId: string; model: string; payload: Record<string, unknown> }) =>
      api<Price>(`/model-settings/prices/${encodeURIComponent(connectionId)}/${encodeURIComponent(model)}`, tenant, body('PUT', payload)),
    onSuccess: (record, variables) => {
      queryClient.setQueryData(['model-price', variables.tenant, variables.connectionId, variables.model], record);
    },
  });

  function submitConnection() {
    const name = connectionDraft.name.trim();
    const baseUrl = connectionDraft.base_url.trim();
    const apiKey = connectionDraft.apiKey;
    if (!name || connectionDraft.models.length === 0) return;
    if (!CLOUD_PROVIDERS.has(connectionDraft.provider) && !baseUrl) return;
    if (connectionDraft.credentialAction === 'replace' && apiKey.trim() === '') return;
    const payload: Record<string, unknown> = {
      name,
      provider: connectionDraft.provider,
      models: connectionDraft.models,
      enabled: connectionDraft.enabled,
    };
    if (!CLOUD_PROVIDERS.has(connectionDraft.provider)) payload.base_url = baseUrl;
    if (editing) payload.expected_version = editing.version;
    if (connectionDraft.credentialAction === 'replace') payload.api_key = apiKey;
    if (connectionDraft.credentialAction === 'clear') payload.api_key = null;
    connectionSave.mutate({ tenant: orgId, id: editing?.connection_id, payload });
  }

  function updateGrant(index: number, patch: Partial<Grant>) {
    setPolicyDraft(current => ({ ...current, grants: current.grants.map((grant, itemIndex) => itemIndex === index ? { ...grant, ...patch } : grant) }));
  }

  function addGrant() {
    const connection = connections.data?.[0];
    if (!connection) return;
    setPolicyDraft(current => ({
      ...current,
      grants: [...current.grants, {
        role: 'triage', area: null, connection_id: connection.connection_id, connection_version: connection.version,
        models: connection.models.slice(0, 1), classifications: ['redacted_cloud'],
      }],
    }));
  }

  function submitPolicy() {
    const currentConnections = new Map((connections.data || []).map(item => [item.connection_id, item]));
    const grants = policyDraft.grants.map(grant => {
      const connection = currentConnections.get(grant.connection_id);
      return { ...grant, connection_version: connection?.version || grant.connection_version };
    });
    policySave.mutate({ tenant: orgId, payload: { expected_version: policy.data?.version || 0, enabled: policyDraft.enabled, grants } });
  }

  function refresh() {
    void Promise.all([
      queryClient.invalidateQueries({ queryKey: ['model-settings-status', orgId] }),
      queryClient.invalidateQueries({ queryKey: ['model-connections', orgId] }),
      queryClient.invalidateQueries({ queryKey: ['model-policy', orgId] }),
      queryClient.invalidateQueries({ queryKey: ['model-budget', orgId, windowKey] }),
      queryClient.invalidateQueries({ queryKey: ['model-usage', orgId, windowKey] }),
      queryClient.invalidateQueries({ queryKey: ['model-price', orgId] }),
    ]);
  }

  const connectionError = connections.error || status.error;
  const connectionValid = connectionDraft.name.trim() !== ''
    && connectionDraft.models.length > 0
    && (CLOUD_PROVIDERS.has(connectionDraft.provider) || connectionDraft.base_url.trim() !== '')
    && (connectionDraft.credentialAction !== 'replace' || connectionDraft.apiKey.trim() !== '');
  const budgetValid = validInteger(budgetDraft.limit) && validInteger(budgetDraft.tokens, true);
  const priceValid = validInteger(priceDraft.input) && validInteger(priceDraft.output)
    && validInteger(priceDraft.cached, true) && validInteger(priceDraft.reasoning, true);

  return (
    <div className="model-settings" data-testid="model-settings">
      <section className="model-gateway-intro">
        <div>
          <div className="eyebrow">MODEL GATEWAY</div>
          <h2>Routes, policy, and cost controls</h2>
          <p>Register approved endpoints and define which agent roles may use them. Saving configuration does not contact a provider or verify a credential.</p>
        </div>
        <Button icon={<ReloadOutlined spin={status.isFetching || connections.isFetching} />} onClick={refresh}>Refresh gateway</Button>
      </section>

      {!canWrite && <Alert className="model-alert" type="info" showIcon title="Read-only access" description="Only administrators can change model connections, policy, budgets, or manual rates." />}
      {status.isPending ? <Skeleton active paragraph={{ rows: 2 }} /> : status.error ? <Alert className="model-alert" type="error" showIcon title="Gateway status unavailable" description={requestMessage(status.error)} /> : status.data && (
        <div className="model-status-grid">
          <div className="model-status-item"><span>Credential storage</span><strong>{status.data.credential_storage_ready ? 'Ready' : 'Setup required'}</strong><Tag color={status.data.credential_storage_ready ? 'blue' : 'gold'}>{status.data.credential_storage_ready ? 'ENCRYPTED' : 'SERVER ACTION'}</Tag></div>
          <div className="model-status-item"><span>Registered connections</span><strong className="model-number">{status.data.registered_connections}</strong><Tag>CONFIGURED</Tag></div>
          <div className="model-status-item"><span>Provider validation</span><strong>Not established</strong><Tag>UNVERIFIED</Tag></div>
        </div>
      )}
      {status.data && !status.data.credential_storage_ready && (
        <Alert className="model-alert" type="warning" showIcon title="Encrypted credential storage needs a server master key" description={status.data.setup_required.join(' ') || 'Configure the model credential key in every server and specialist process before saving provider keys.'} />
      )}

      <section className="model-section" aria-labelledby="connections-title">
        <div className="model-section-heading">
          <div><h3 id="connections-title">Connections</h3><p>Credentials remain write only. The registry returns a fixed mask and never recovers the stored value.</p></div>
          <Button type="primary" icon={<PlusOutlined />} disabled={!canWrite} onClick={() => openConnection()}>Add connection</Button>
        </div>
        {connectionError && <Alert className="model-alert" type="error" showIcon title="Connections unavailable" description={requestMessage(connectionError)} />}
        {connectionDelete.error && <Alert className="model-alert" type="error" showIcon title="Connection was not deleted" description={conflictMessage(connectionDelete.error)} />}
        {connections.isPending ? <Skeleton active paragraph={{ rows: 4 }} /> : connections.data?.length ? (
          <Table<Connection>
            rowKey="connection_id"
            pagination={false}
            dataSource={connections.data}
            scroll={{ x: 840 }}
            columns={[
              { title: 'CONNECTION', render: (_, item) => <div className="model-primary-cell"><strong>{item.name}</strong><small>{PROVIDERS.find(provider => provider.value === item.provider)?.label || item.provider} · v{item.version}</small></div> },
              { title: 'ENDPOINT', dataIndex: 'base_url', render: value => <Typography.Text className="model-endpoint" ellipsis={{ tooltip: value }}>{value}</Typography.Text> },
              { title: 'MODELS', render: (_, item) => <Space size={[4, 4]} wrap>{item.models.slice(0, 3).map(model => <Tag key={model}>{model}</Tag>)}{item.models.length > 3 && <Tag>+{item.models.length - 3}</Tag>}</Space> },
              { title: 'STATE', render: (_, item) => <Space size={4} wrap><Tag color={item.enabled ? 'blue' : 'default'}>{item.enabled ? 'ENABLED' : 'DISABLED'}</Tag><Tag>{item.verification_status.toUpperCase()}</Tag>{item.credential_configured && <Tag>KEY STORED</Tag>}</Space> },
              { title: '', width: 92, render: (_, item) => <Space size={2}>
                <Button type="text" aria-label={`Edit ${item.name}`} icon={<EditOutlined />} disabled={!canWrite} onClick={() => openConnection(item)} />
                <Popconfirm title={`Delete ${item.name}?`} description="Policy grants or rates may still reference this version." okText="Delete" okButtonProps={{ danger: true }} disabled={!canWrite} onConfirm={() => connectionDelete.mutate({ tenant: orgId, item })}>
                  <Button type="text" danger aria-label={`Delete ${item.name}`} icon={<DeleteOutlined />} disabled={!canWrite} />
                </Popconfirm>
              </Space> },
            ]}
          />
        ) : !connections.error && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No model connections are registered for this organization." />}
      </section>

      <section className="model-section" aria-labelledby="policy-title">
        <div className="model-section-heading">
          <div><h3 id="policy-title">Routing and data policy</h3><p>Each grant binds a role to the current connection version, an allowed model pool, and permitted evidence classifications.</p></div>
          <Space><span className="model-inline-switch"><span>Policy enabled</span><Switch aria-label="Policy enabled" checked={policyDraft.enabled} disabled={!canWrite} onChange={enabled => setPolicyDraft(current => ({ ...current, enabled }))} /></span><Button icon={<PlusOutlined />} disabled={!canWrite || !connections.data?.length} onClick={addGrant}>Add grant</Button></Space>
        </div>
        {policy.error && <Alert className="model-alert" type="error" showIcon title="Policy unavailable" description={requestMessage(policy.error)} />}
        {policySave.error && <Alert className="model-alert" type="error" showIcon title="Policy was not saved" description={conflictMessage(policySave.error)} />}
        {policy.isPending || connections.isPending ? <Skeleton active paragraph={{ rows: 4 }} /> : (
          <>
            {policy.data === null && <Alert className="model-alert" type="info" showIcon title="No model policy has been saved" description="Administrators can create the first policy. Until then, no model access is granted by this registry." />}
            <div className="model-grants">
              {policyDraft.grants.map((grant, index) => {
                const connection = connections.data?.find(item => item.connection_id === grant.connection_id);
                const stale = connection && connection.version !== grant.connection_version;
                return <article className="model-grant" key={`${index}-${grant.role}-${grant.connection_id}`}>
                  <div className="model-grant-index">{String(index + 1).padStart(2, '0')}</div>
                  <div className="model-grant-fields">
                    <Field label="Agent role"><Select aria-label={`Grant ${index + 1} role`} value={grant.role} disabled={!canWrite} options={ROLES.map(value => ({ value, label: friendly(value) }))} onChange={role => updateGrant(index, { role, area: role === 'area_orchestrator' ? (grant.area || 'alert_handling') : null })} /></Field>
                    <Field label="Area" hint={grant.role === 'area_orchestrator' ? undefined : 'Only area orchestrators have an area scope.'}><Select aria-label={`Grant ${index + 1} area`} value={grant.area || undefined} disabled={!canWrite || grant.role !== 'area_orchestrator'} placeholder="Not applicable" options={AREAS.map(value => ({ value, label: friendly(value) }))} onChange={area => updateGrant(index, { area })} /></Field>
                    <Field label="Connection" hint={connection ? `Policy v${grant.connection_version} · current v${connection.version}${stale ? ' (will update on save)' : ''}` : 'Connection unavailable'}><Select aria-label={`Grant ${index + 1} connection`} value={grant.connection_id} disabled={!canWrite} options={(connections.data || []).map(item => ({ value: item.connection_id, label: `${item.name} · v${item.version}` }))} onChange={connectionId => { const next = connections.data?.find(item => item.connection_id === connectionId); if (next) updateGrant(index, { connection_id: connectionId, connection_version: next.version, models: next.models.slice(0, 1) }); }} /></Field>
                    <Field label="Allowed models"><Select mode="multiple" aria-label={`Grant ${index + 1} allowed models`} value={grant.models} disabled={!canWrite || !connection} options={(connection?.models || []).map(value => ({ value, label: value }))} onChange={models => updateGrant(index, { models, connection_version: connection?.version || grant.connection_version })} /></Field>
                    <Field label="Evidence classifications"><Select mode="multiple" aria-label={`Grant ${index + 1} evidence classifications`} value={grant.classifications} disabled={!canWrite} options={CLASSIFICATIONS.map(value => ({ value, label: friendly(value) }))} onChange={classifications => updateGrant(index, { classifications })} /></Field>
                  </div>
                  <Button className="model-grant-remove" type="text" danger aria-label={`Remove grant ${index + 1}`} icon={<DeleteOutlined />} disabled={!canWrite} onClick={() => setPolicyDraft(current => ({ ...current, grants: current.grants.filter((_, itemIndex) => itemIndex !== index) }))} />
                </article>;
              })}
              {policyDraft.grants.length === 0 && <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="No role grants in this policy." />}
            </div>
            <div className="model-save-row"><span>{policy.data ? `Editing policy version ${policy.data.version}` : 'Creating the first policy version'}</span><Button type="primary" icon={<SaveOutlined />} disabled={!canWrite} loading={policySave.isPending} onClick={submitPolicy}>Save policy</Button></div>
          </>
        )}
      </section>

      <div className="model-finance-grid">
        <section className="model-section" aria-labelledby="budget-title">
          <div className="model-section-heading"><div><h3 id="budget-title">Daily budget</h3><p>UTC window {windowKey}. Money is stored as integer micro-USD.</p></div>{budget.data && <Tag>VERSION {budget.data.version}</Tag>}</div>
          {budget.error && <Alert className="model-alert" type="error" showIcon title="Budget unavailable" description={requestMessage(budget.error)} />}
          {budgetSave.error && <Alert className="model-alert" type="error" showIcon title="Budget was not saved" description={conflictMessage(budgetSave.error)} />}
          {budget.data === null && !budget.isPending && <Alert className="model-alert" type="info" title="No daily budget is configured" description="Enter an explicit limit to create one. No limit is inferred." />}
          <div className="model-form-grid">
            <Field label="Limit (micro-USD)" hint="1,000,000 micro-USD = $1.00"><Input aria-label="Daily limit in micro-USD" inputMode="numeric" value={budgetDraft.limit} disabled={!canWrite} onChange={event => setBudgetDraft(current => ({ ...current, limit: event.target.value }))} placeholder="Required integer" /></Field>
            <Field label="Token limit" hint="Optional; blank stores no token limit"><Input aria-label="Daily token limit" inputMode="numeric" value={budgetDraft.tokens} disabled={!canWrite} onChange={event => setBudgetDraft(current => ({ ...current, tokens: event.target.value }))} placeholder="Optional integer" /></Field>
          </div>
          <div className="model-save-row"><span>{budgetDraft.limit && validInteger(budgetDraft.limit) ? `${usd(requiredInteger(budgetDraft.limit))} configured limit` : 'Enter a whole number of micro-USD'}</span><Button type="primary" icon={<SaveOutlined />} disabled={!canWrite || !budgetValid} loading={budgetSave.isPending} onClick={() => budgetSave.mutate({ tenant: orgId, payload: { expected_version: budget.data?.version || 0, limit_micro_usd: requiredInteger(budgetDraft.limit), limit_tokens: optionalInteger(budgetDraft.tokens) } })}>Save budget</Button></div>
        </section>

        <section className="model-section" aria-labelledby="usage-title">
          <div className="model-section-heading"><div><h3 id="usage-title">Usage ledger</h3><p>Configured-rate estimates for {windowKey}; these are not verified provider invoice charges.</p></div>{usage.data?.over_limit && <Tag color="red">OVER LIMIT</Tag>}</div>
          {usage.isPending ? <Skeleton active paragraph={{ rows: 3 }} /> : usage.error ? <Alert className="model-alert" type="error" showIcon title="Usage unavailable" description={requestMessage(usage.error)} /> : usage.data && <Descriptions column={2} size="small" items={[
            { key: 'known', label: 'Known estimated cost', children: usd(usage.data.known_cost_micro_usd) },
            { key: 'remaining', label: 'Remaining configured budget', children: usd(usage.data.remaining_micro_usd) },
            { key: 'exposure', label: 'Total exposure', children: usd(usage.data.exposure_micro_usd) },
            { key: 'reserved', label: 'Reserved exposure', children: usd(usage.data.reserved_exposure_micro_usd) },
            { key: 'ambiguous', label: 'Ambiguous exposure', children: usd(usage.data.ambiguous_exposure_micro_usd) },
            { key: 'unknown', label: 'Unknown-cost records', children: <Tag color={usage.data.unknown_cost_count ? 'gold' : 'default'}>{usage.data.unknown_cost_count}</Tag> },
          ]} />}
          {usage.data && usage.data.unknown_cost_count > 0 && <Alert className="model-alert" type="warning" showIcon title="Some usage has unknown cost" description="Unknown cost is reported separately and is not treated as zero." />}
        </section>
      </div>

      <section className="model-section" aria-labelledby="prices-title">
        <div className="model-section-heading"><div><h3 id="prices-title">Manual model rates</h3><p>Configure integer micro-USD rates per one million tokens. The gateway does not assume provider prices.</p></div>{price.data && <Tag>VERSION {price.data.version}</Tag>}</div>
        <div className="model-price-picker">
          <Field label="Connection"><Select aria-label="Price connection" value={priceTarget.connectionId || undefined} placeholder="Choose a connection" options={(connections.data || []).map(item => ({ value: item.connection_id, label: item.name }))} onChange={connectionId => setPriceTarget({ connectionId, model: '' })} /></Field>
          <Field label="Model"><Select aria-label="Price model" value={priceTarget.model || undefined} disabled={!selectedPriceConnection} placeholder="Choose a registered model" options={(selectedPriceConnection?.models || []).map(value => ({ value, label: value }))} onChange={model => setPriceTarget(current => ({ ...current, model }))} /></Field>
        </div>
        {price.isFetching && priceTarget.model ? <Skeleton active paragraph={{ rows: 2 }} /> : price.error ? <Alert className="model-alert" type="error" showIcon title="Rate unavailable" description={requestMessage(price.error)} /> : priceTarget.model ? (
          <>
            {price.data === null && <Alert className="model-alert" type="info" title="No manual rate is configured" description="Enter explicit rates for this connection and model. Values are not populated from public price lists." />}
            {priceSave.error && <Alert className="model-alert" type="error" showIcon title="Rate was not saved" description={conflictMessage(priceSave.error)} />}
            <div className="model-price-grid">
              <Field label="Input / MTok (micro-USD)"><Input aria-label="Input rate per million tokens in micro-USD" inputMode="numeric" value={priceDraft.input} disabled={!canWrite} onChange={event => setPriceDraft(current => ({ ...current, input: event.target.value }))} placeholder="Required integer" /></Field>
              <Field label="Output / MTok (micro-USD)"><Input aria-label="Output rate per million tokens in micro-USD" inputMode="numeric" value={priceDraft.output} disabled={!canWrite} onChange={event => setPriceDraft(current => ({ ...current, output: event.target.value }))} placeholder="Required integer" /></Field>
              <Field label="Cached input / MTok" hint="Optional"><Input aria-label="Cached input rate per million tokens in micro-USD" inputMode="numeric" value={priceDraft.cached} disabled={!canWrite} onChange={event => setPriceDraft(current => ({ ...current, cached: event.target.value }))} placeholder="Unknown" /></Field>
              <Field label="Reasoning / MTok" hint="Optional"><Input aria-label="Reasoning rate per million tokens in micro-USD" inputMode="numeric" value={priceDraft.reasoning} disabled={!canWrite} onChange={event => setPriceDraft(current => ({ ...current, reasoning: event.target.value }))} placeholder="Unknown" /></Field>
            </div>
            <div className="model-save-row"><span>These configured rates drive internal ledger estimates.</span><Button type="primary" icon={<SaveOutlined />} disabled={!canWrite || !priceValid} loading={priceSave.isPending} onClick={() => priceSave.mutate({ tenant: orgId, connectionId: priceTarget.connectionId, model: priceTarget.model, payload: { expected_version: price.data?.version || 0, input_per_mtok_micro_usd: requiredInteger(priceDraft.input), output_per_mtok_micro_usd: requiredInteger(priceDraft.output), cached_input_per_mtok_micro_usd: optionalInteger(priceDraft.cached), reasoning_per_mtok_micro_usd: optionalInteger(priceDraft.reasoning) } })}>Save rate</Button></div>
          </>
        ) : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="Choose a connection and model to view its manual rate." />}
      </section>

      <Modal title={editing ? `Edit ${editing.name}` : 'Add model connection'} open={connectionOpen} onCancel={closeConnection} onOk={submitConnection} okText={editing ? 'Save connection' : 'Add connection'} okButtonProps={{ disabled: !connectionValid }} confirmLoading={connectionSave.isPending} destroyOnHidden>
        <div className="model-modal-fields">
          <Alert type="info" showIcon title="Configuration only" description="TERMINUS will store this configuration without making a provider request. Enabled does not mean verified or connected." />
          <Field label="Connection name"><Input aria-label="Connection name" value={connectionDraft.name} onChange={event => setConnectionDraft(current => ({ ...current, name: event.target.value }))} placeholder="SOC model gateway" maxLength={80} /></Field>
          <Field label="Provider"><Select aria-label="Provider" value={connectionDraft.provider} options={PROVIDERS} onChange={provider => setConnectionDraft(current => ({ ...current, provider, base_url: CLOUD_PROVIDERS.has(provider) ? '' : current.base_url }))} /></Field>
          {!CLOUD_PROVIDERS.has(connectionDraft.provider) && <Field label="Base URL" hint={connectionDraft.provider === 'local' ? 'Local endpoints may use HTTP on localhost or a private IP.' : 'OpenAI-compatible endpoints require HTTPS.'}><Input aria-label="Base URL" value={connectionDraft.base_url} onChange={event => setConnectionDraft(current => ({ ...current, base_url: event.target.value }))} placeholder={connectionDraft.provider === 'local' ? 'http://localhost:11434/v1' : 'https://models.example.com/v1'} /></Field>}
          <Field label="Registered model IDs" hint="Type a model ID and press Enter. At least one is required."><Select mode="tags" aria-label="Registered model IDs" tokenSeparators={[',']} value={connectionDraft.models} onChange={models => setConnectionDraft(current => ({ ...current, models }))} placeholder="model-name" /></Field>
          <Field label="Credential action"><Select aria-label="Credential action" value={connectionDraft.credentialAction} options={[
            { value: 'keep', label: editing ? 'Keep stored credential' : 'No credential' },
            { value: 'replace', label: 'Replace credential' },
            ...(editing ? [{ value: 'clear', label: 'Clear credential' }] : []),
          ]} onChange={credentialAction => setConnectionDraft(current => ({ ...current, credentialAction: credentialAction as ConnectionDraft['credentialAction'], apiKey: '' }))} /></Field>
          {connectionDraft.credentialAction === 'replace' && <Field label="API key" hint="Write only. It is sent once for encrypted storage and is never echoed back."><Input.Password aria-label="API key" autoComplete="new-password" value={connectionDraft.apiKey} onChange={event => setConnectionDraft(current => ({ ...current, apiKey: event.target.value }))} placeholder="Enter a new key" /></Field>}
          {connectionDraft.credentialAction === 'clear' && <Alert type="warning" showIcon title="The stored credential will be removed" description="Saving sends an explicit null credential. This cannot be recovered from the registry." />}
          <label className="model-enabled-row"><span><strong>Enabled for policy selection</strong><small>This is configuration state, not proof of connectivity.</small></span><Switch aria-label="Connection enabled" checked={connectionDraft.enabled} onChange={enabled => setConnectionDraft(current => ({ ...current, enabled }))} /></label>
          {connectionSave.error && <Alert type="error" showIcon title="Connection was not saved" description={conflictMessage(connectionSave.error)} />}
        </div>
      </Modal>
    </div>
  );
}
