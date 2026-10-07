import { useState } from 'react';
import { Alert, App, Button, Drawer, Form, Input, Modal, Select, Space, Table, Tabs, Tag, Typography } from 'antd';
import { DeleteOutlined, EyeOutlined, PlayCircleOutlined, PlusOutlined, ReloadOutlined, SafetyCertificateOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, useParams } from 'react-router-dom';
import { api, body } from '../api';
import { useSession } from '../context';
import { date, ErrorPanel, PageTitle } from '../components';
import { ASSET_KINDS, type Asset, type AssetCriticality, type AssetExposure } from '../asset-types';

type Fields = {
  name: string;
  locator?: string;
  notes?: string;
  agent_id?: string;
  hostname?: string;
  criticality?: AssetCriticality;
  owner?: string;
  environment?: string;
  exposure?: AssetExposure;
};

type RepoScan = {
  scan_id: string;
  trigger: string;
  commit_sha?: string;
  status: string;
  started_at: string;
  finished_at?: string;
  error?: string;
  stats?: {
    total_findings?: number;
    secrets_count?: number;
    dependencies_count?: number;
    suspicious_count?: number;
    components_count?: number;
  };
};

type RepoFinding = {
  finding_id: string;
  category: string;
  rule: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  file?: string;
  line?: number;
  commit_sha?: string;
  preview?: string;
  status: string;
  first_seen: string;
  last_seen: string;
  details?: Record<string, unknown>;
};

type RepoComponent = {
  ecosystem: string;
  name: string;
  version: string;
  source_file: string;
};

export default function Assets() {
  const { kind } = useParams();
  const category = ASSET_KINDS.find(item => item.kind === kind);
  const { orgId, detail } = useSession();
  const queryClient = useQueryClient();
  const { message, modal } = App.useApp();
  const [open, setOpen] = useState(false);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [search, setSearch] = useState('');
  const [form] = Form.useForm<Fields>();
  const canWrite = detail?.role === 'admin';

  const assets = useQuery({ queryKey: ['assets', orgId], queryFn: () => api<Asset[]>('/assets', orgId) });

  const save = useMutation({
    mutationFn: (values: Fields) => api<Asset>('/assets', orgId, body('POST', { ...values, kind })),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['assets', orgId] });
      setOpen(false);
      form.resetFields();
      message.success('Asset registered');
    },
  });

  const triggerScan = useMutation({
    mutationFn: (assetId: string) => api<{ status: string; scan_id: string }>(`/assets/${encodeURIComponent(assetId)}/scan`, orgId, body('POST', {})),
    onSuccess: () => {
      message.success('Repository scan queued');
      void queryClient.invalidateQueries({ queryKey: ['assets', orgId] });
      if (selectedAsset) {
        void queryClient.invalidateQueries({ queryKey: ['repo-scans', orgId, selectedAsset.asset_id] });
        void queryClient.invalidateQueries({ queryKey: ['repo-findings', orgId, selectedAsset.asset_id] });
        void queryClient.invalidateQueries({ queryKey: ['repo-components', orgId, selectedAsset.asset_id] });
      }
    },
    onError: (err: Error) => {
      message.error(err.message || 'Failed to trigger scan');
    },
  });

  const updateFinding = useMutation({
    mutationFn: ({ findingId, status }: { findingId: string; status: string }) =>
      api<RepoFinding>(`/repo-findings/${encodeURIComponent(findingId)}`, orgId, body('PATCH', { status })),
    onSuccess: () => {
      message.success('Finding status updated');
      if (selectedAsset) {
        void queryClient.invalidateQueries({ queryKey: ['repo-findings', orgId, selectedAsset.asset_id] });
      }
    },
  });

  const scans = useQuery({
    queryKey: ['repo-scans', orgId, selectedAsset?.asset_id],
    queryFn: () => (selectedAsset ? api<RepoScan[]>(`/assets/${encodeURIComponent(selectedAsset.asset_id)}/scans`, orgId) : Promise.resolve([])),
    enabled: Boolean(selectedAsset && selectedAsset.kind === 'repository'),
  });

  const findings = useQuery({
    queryKey: ['repo-findings', orgId, selectedAsset?.asset_id],
    queryFn: () => (selectedAsset ? api<RepoFinding[]>(`/assets/${encodeURIComponent(selectedAsset.asset_id)}/findings`, orgId) : Promise.resolve([])),
    enabled: Boolean(selectedAsset && selectedAsset.kind === 'repository'),
  });

  const components = useQuery({
    queryKey: ['repo-components', orgId, selectedAsset?.asset_id],
    queryFn: () => (selectedAsset ? api<RepoComponent[]>(`/assets/${encodeURIComponent(selectedAsset.asset_id)}/components`, orgId) : Promise.resolve([])),
    enabled: Boolean(selectedAsset && selectedAsset.kind === 'repository'),
  });

  function remove(asset: Asset) {
    modal.confirm({
      title: `Remove ${asset.name} from inventory?`,
      content: 'This removes its inventory record. It does not change the actual resource.',
      okText: 'Remove record',
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          await api(`/assets/${encodeURIComponent(asset.asset_id)}`, orgId, body('DELETE'));
          await queryClient.invalidateQueries({ queryKey: ['assets', orgId] });
          if (selectedAsset?.asset_id === asset.asset_id) setSelectedAsset(null);
        } catch (error) {
          message.error((error as Error).message);
          throw error;
        }
      },
    });
  }

  function renderCoverageTag(coverage: string) {
    switch (coverage) {
      case 'scanned':
        return <Tag color="success">Scanned</Tag>;
      case 'stale':
        return <Tag color="warning">Stale scan</Tag>;
      case 'never_scanned':
        return <Tag color="processing">Never scanned</Tag>;
      case 'scan_failed':
        return <Tag color="error">Scan failed</Tag>;
      default:
        return <Tag color="default">Not connected</Tag>;
    }
  }

  function renderCriticalityTag(crit?: AssetCriticality | null) {
    if (!crit) return <Tag color="default">Unclassified</Tag>;
    switch (crit) {
      case 'tier0':
        return <Tag color="red">Tier 0 (Core)</Tag>;
      case 'tier1':
        return <Tag color="volcano">Tier 1 (High)</Tag>;
      case 'tier2':
        return <Tag color="orange">Tier 2 (Medium)</Tag>;
      case 'tier3':
        return <Tag color="blue">Tier 3 (Standard)</Tag>;
      default:
        return <Tag color="default">{crit}</Tag>;
    }
  }

  function renderSeverityTag(sev: string) {
    switch (sev) {
      case 'critical':
        return <Tag color="red">CRITICAL</Tag>;
      case 'high':
        return <Tag color="volcano">HIGH</Tag>;
      case 'medium':
        return <Tag color="orange">MEDIUM</Tag>;
      case 'low':
        return <Tag color="blue">LOW</Tag>;
      default:
        return <Tag color="default">INFO</Tag>;
    }
  }

  if (!category) return <Navigate to="/assets/repository" replace />;
  const rows = (assets.data || []).filter(
    asset =>
      asset.kind === kind &&
      `${asset.name} ${asset.locator ?? ''} ${asset.notes ?? ''} ${asset.hostname ?? ''} ${asset.owner ?? ''}`
        .toLowerCase()
        .includes(search.toLowerCase())
  );

  return (
    <>
      <PageTitle
        eyebrow="ASSETS / INVENTORY"
        title={category.label}
        description={`Register ${category.label.toLowerCase()} in this organization's defense inventory.`}
        actions={
          <Space wrap>
            <Button icon={<ReloadOutlined />} onClick={() => void assets.refetch()}>
              Refresh
            </Button>
            <Button
              type="primary"
              icon={<PlusOutlined />}
              disabled={!canWrite}
              onClick={() => {
                save.reset();
                form.resetFields();
                setOpen(true);
              }}
            >
              Add {category.singular}
            </Button>
          </Space>
        }
      />
      <Alert
        className="context-alert"
        type="info"
        showIcon
        title="Inventory registration & guardrail tiering"
        description="Registered assets are saved to this workspace. High-criticality tiers (Tier 0 / Tier 1) enforce blast-radius guardrails against automated containment."
      />
      <ErrorPanel error={assets.error} retry={() => void assets.refetch()} />
      <section className="panel asset-inventory" aria-label={`${category.label} inventory`}>
        <div className="asset-inventory-toolbar">
          <strong>{rows.length} registered</strong>
          <Input.Search
            aria-label="Search assets"
            placeholder="Search name, hostname, or locator"
            value={search}
            onChange={event => setSearch(event.target.value)}
            allowClear
          />
        </div>
        <Table<Asset>
          rowKey="asset_id"
          dataSource={rows}
          loading={assets.isPending}
          scroll={{ x: 860 }}
          pagination={{ pageSize: 10, hideOnSinglePage: true }}
          locale={{ emptyText: `No ${category.label.toLowerCase()} registered. Add an asset to begin your inventory.` }}
          columns={[
            {
              title: 'Name',
              dataIndex: 'name',
              render: (value: string, record: Asset) => (
                <Space orientation="vertical" size={2}>
                  <strong>{value}</strong>
                  {record.owner && <Typography.Text type="secondary" style={{ fontSize: 11 }}>Owner: {record.owner}</Typography.Text>}
                </Space>
              ),
            },
            {
              title: 'Criticality',
              dataIndex: 'criticality',
              render: (value?: AssetCriticality | null) => renderCriticalityTag(value),
            },
            {
              title: 'Identifier / Host',
              render: (_: unknown, record: Asset) => (
                <Space orientation="vertical" size={2}>
                  <span>{record.locator || record.hostname || '—'}</span>
                  {record.agent_id && <Typography.Text type="secondary" style={{ fontSize: 11 }}>Agent: {record.agent_id}</Typography.Text>}
                </Space>
              ),
            },
            {
              title: 'Coverage',
              render: (_: unknown, record: Asset) => renderCoverageTag(record.coverage),
            },
            {
              title: 'Registered',
              dataIndex: 'created_at',
              render: (value: string) => date(value),
            },
            {
              title: 'Actions',
              key: 'actions',
              render: (_: unknown, asset: Asset) => (
                <Space>
                  {asset.kind === 'repository' && (
                    <>
                      <Button
                        size="small"
                        icon={<PlayCircleOutlined />}
                        loading={triggerScan.isPending && triggerScan.variables === asset.asset_id}
                        onClick={() => triggerScan.mutate(asset.asset_id)}
                      >
                        Scan now
                      </Button>
                      <Button
                        size="small"
                        icon={<EyeOutlined />}
                        onClick={() => setSelectedAsset(asset)}
                      >
                        Security Details
                      </Button>
                    </>
                  )}
                  <Button
                    type="text"
                    danger
                    icon={<DeleteOutlined />}
                    aria-label={`Remove ${asset.name}`}
                    disabled={!canWrite}
                    onClick={() => remove(asset)}
                  />
                </Space>
              ),
            },
          ]}
        />
      </section>

      {/* Register Asset Modal */}
      <Modal
        title={`Register ${category.singular}`}
        open={open}
        onCancel={() => setOpen(false)}
        footer={null}
        destroyOnHidden
      >
        <Form form={form} layout="vertical" onFinish={values => save.mutate(values)} requiredMark={false}>
          <Form.Item name="name" label="Asset Name" rules={[{ required: true, whitespace: true, max: 200 }]}>
            <Input autoFocus maxLength={200} placeholder="e.g. Production Payment Gateway" />
          </Form.Item>
          <Form.Item
            name="locator"
            label="Identifier / URL"
            rules={[{ max: 500 }]}
            extra={category.kind === 'repository' ? 'Must be an https:// URL on an allowlisted host (e.g. github.com).' : 'Keep credentials and secrets in the provider configuration.'}
          >
            <Input maxLength={500} placeholder={category.hint} />
          </Form.Item>
          <Form.Item name="criticality" label="Criticality Tier (Guardrails)">
            <Select
              allowClear
              placeholder="Select criticality tier"
              options={[
                { value: 'tier0', label: 'Tier 0 — Mission Critical (Automated containment prohibited)' },
                { value: 'tier1', label: 'Tier 1 — High (Requires admin override for containment)' },
                { value: 'tier2', label: 'Tier 2 — Medium (Standard automated containment)' },
                { value: 'tier3', label: 'Tier 3 — Standard Workstation / Sandbox' },
              ]}
            />
          </Form.Item>
          <Space orientation="horizontal" style={{ width: '100%' }} styles={{ item: { flex: 1 } }}>
            <Form.Item name="hostname" label="Hostname">
              <Input maxLength={255} placeholder="e.g. dc01.corp.internal" />
            </Form.Item>
            <Form.Item name="agent_id" label="Wazuh Agent ID">
              <Input maxLength={100} placeholder="e.g. 001" />
            </Form.Item>
          </Space>
          <Space orientation="horizontal" style={{ width: '100%' }} styles={{ item: { flex: 1 } }}>
            <Form.Item name="owner" label="Owner / Team">
              <Input maxLength={200} placeholder="e.g. secops@example.com" />
            </Form.Item>
            <Form.Item name="environment" label="Environment">
              <Input maxLength={100} placeholder="e.g. production, staging" />
            </Form.Item>
          </Space>
          <Form.Item name="notes" label="Notes" rules={[{ max: 2000 }]}>
            <Input.TextArea rows={2} maxLength={2000} placeholder="Operational context and contact notes" />
          </Form.Item>
          {save.error && <Alert type="error" showIcon title={save.error.message} style={{ marginBottom: 16 }} />}
          <Button type="primary" htmlType="submit" loading={save.isPending} block>
            Register asset
          </Button>
        </Form>
      </Modal>

      {/* Repository Security Drawer */}
      <Drawer
        title={
          <Space>
            <SafetyCertificateOutlined />
            <span>Repository Security — {selectedAsset?.name}</span>
          </Space>
        }
        width={820}
        open={Boolean(selectedAsset)}
        onClose={() => setSelectedAsset(null)}
        extra={
          selectedAsset && (
            <Button
              type="primary"
              icon={<PlayCircleOutlined />}
              loading={triggerScan.isPending}
              onClick={() => triggerScan.mutate(selectedAsset.asset_id)}
            >
              Scan now
            </Button>
          )
        }
      >
        <Alert
          type="warning"
          showIcon
          style={{ marginBottom: 16 }}
          message="Static scan results. Not proof of safety."
          description="Secret detection and dependency analysis are performed via static analysis. Bounded sandbox prevents code execution."
        />

        <Tabs
          defaultActiveKey="findings"
          items={[
            {
              key: 'findings',
              label: `Findings (${findings.data?.length ?? 0})`,
              children: (
                <Table<RepoFinding>
                  rowKey="finding_id"
                  dataSource={findings.data || []}
                  loading={findings.isPending}
                  pagination={{ pageSize: 8 }}
                  locale={{ emptyText: 'No open findings detected.' }}
                  columns={[
                    {
                      title: 'Severity',
                      dataIndex: 'severity',
                      width: 100,
                      render: (value: string) => renderSeverityTag(value),
                    },
                    {
                      title: 'Rule & Category',
                      render: (_: unknown, item: RepoFinding) => (
                        <Space orientation="vertical" size={2}>
                          <strong>{item.rule}</strong>
                          <Tag>{item.category}</Tag>
                        </Space>
                      ),
                    },
                    {
                      title: 'Location & Preview',
                      render: (_: unknown, item: RepoFinding) => (
                        <Space orientation="vertical" size={2}>
                          <code>{item.file ? `${item.file}${item.line ? `:${item.line}` : ''}` : 'Tree root'}</code>
                          {item.preview && <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#dc2626' }}>{item.preview}</span>}
                        </Space>
                      ),
                    },
                    {
                      title: 'Status',
                      dataIndex: 'status',
                      width: 130,
                      render: (statusVal: string, item: RepoFinding) => (
                        <Select
                          size="small"
                          value={statusVal}
                          disabled={!canWrite}
                          style={{ width: 120 }}
                          onChange={newStatus => updateFinding.mutate({ findingId: item.finding_id, status: newStatus })}
                          options={[
                            { value: 'open', label: 'Open' },
                            { value: 'acknowledged', label: 'Acknowledged' },
                            { value: 'false_positive', label: 'False positive' },
                            { value: 'resolved', label: 'Resolved' },
                          ]}
                        />
                      ),
                    },
                  ]}
                />
              ),
            },
            {
              key: 'components',
              label: `SBOM Components (${components.data?.length ?? 0})`,
              children: (
                <Table<RepoComponent>
                  rowKey={(r) => `${r.ecosystem}-${r.name}-${r.version}-${r.source_file}`}
                  dataSource={components.data || []}
                  loading={components.isPending}
                  pagination={{ pageSize: 8 }}
                  locale={{ emptyText: 'No manifest components extracted.' }}
                  columns={[
                    { title: 'Package', dataIndex: 'name', render: (v: string) => <strong>{v}</strong> },
                    { title: 'Ecosystem', dataIndex: 'ecosystem', width: 110, render: (v: string) => <Tag color="cyan">{v}</Tag> },
                    { title: 'Version', dataIndex: 'version', width: 120, render: (v: string) => <code>{v}</code> },
                    { title: 'Source Manifest', dataIndex: 'source_file' },
                  ]}
                />
              ),
            },
            {
              key: 'scans',
              label: `Scan History (${scans.data?.length ?? 0})`,
              children: (
                <Table<RepoScan>
                  rowKey="scan_id"
                  dataSource={scans.data || []}
                  loading={scans.isPending}
                  pagination={{ pageSize: 5 }}
                  columns={[
                    {
                      title: 'Status',
                      dataIndex: 'status',
                      render: (statusVal: string) => {
                        if (statusVal === 'completed') return <Tag color="success">COMPLETED</Tag>;
                        if (statusVal === 'running') return <Tag color="processing">RUNNING</Tag>;
                        if (statusVal === 'failed') return <Tag color="error">FAILED</Tag>;
                        return <Tag color="default">{statusVal.toUpperCase()}</Tag>;
                      },
                    },
                    { title: 'Trigger', dataIndex: 'trigger' },
                    { title: 'Commit', dataIndex: 'commit_sha', render: (v?: string) => (v ? <code>{v.slice(0, 8)}</code> : '—') },
                    {
                      title: 'Findings',
                      render: (_: unknown, r: RepoScan) => r.stats?.total_findings ?? '—',
                    },
                    { title: 'Started', dataIndex: 'started_at', render: (v: string) => date(v) },
                  ]}
                />
              ),
            },
          ]}
        />
      </Drawer>
    </>
  );
}
