import { useState } from 'react';
import { Alert, App, Button, Form, Input, Modal, Space, Table, Tag } from 'antd';
import { DeleteOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, useParams } from 'react-router-dom';
import { api, body } from '../api';
import { useSession } from '../context';
import { date, ErrorPanel, PageTitle } from '../components';
import { ASSET_KINDS, type Asset } from '../asset-types';

type Fields = { name: string; locator?: string; notes?: string };

export default function Assets() {
  const { kind } = useParams();
  const category = ASSET_KINDS.find(item => item.kind === kind);
  const { orgId, detail } = useSession();
  const queryClient = useQueryClient();
  const { message, modal } = App.useApp();
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [form] = Form.useForm<Fields>();
  const canWrite = detail?.role === 'admin';
  const assets = useQuery({ queryKey: ['assets', orgId], queryFn: () => api<Asset[]>('/assets', orgId) });
  const save = useMutation({
    mutationFn: (values: Fields) => api<Asset>('/assets', orgId, body('POST', { ...values, kind })),
    onSuccess: () => { void queryClient.invalidateQueries({ queryKey: ['assets', orgId] }); setOpen(false); form.resetFields(); message.success('Asset registered'); },
  });

  function remove(asset: Asset) {
    modal.confirm({
      title: `Remove ${asset.name} from inventory?`,
      content: 'This removes its inventory record. It does not change the actual resource.',
      okText: 'Remove record', okButtonProps: { danger: true },
      onOk: async () => {
        try { await api(`/assets/${encodeURIComponent(asset.asset_id)}`, orgId, body('DELETE')); await queryClient.invalidateQueries({ queryKey: ['assets', orgId] }); }
        catch (error) { message.error((error as Error).message); throw error; }
      },
    });
  }

  if (!category) return <Navigate to="/assets/repository" replace />;
  const rows = (assets.data || []).filter(asset => asset.kind === kind && `${asset.name} ${asset.locator ?? ''} ${asset.notes ?? ''}`.toLowerCase().includes(search.toLowerCase()));

  return <>
    <PageTitle eyebrow="ASSETS / INVENTORY" title={category.label} description={`Register ${category.label.toLowerCase()} in this organization's defense inventory.`} actions={<Space wrap>
      <Button icon={<ReloadOutlined />} onClick={() => void assets.refetch()}>Refresh</Button>
      <Button type="primary" icon={<PlusOutlined />} disabled={!canWrite} onClick={() => { save.reset(); form.resetFields(); setOpen(true); }}>Add {category.singular}</Button>
    </Space>} />
    <Alert className="context-alert" type="info" showIcon title="Inventory registration" description="Registered assets are saved to this workspace. Monitoring and protection require a connected collector or provider; registration alone does not enable either." />
    <ErrorPanel error={assets.error} retry={() => void assets.refetch()} />
    <section className="panel asset-inventory" aria-label={`${category.label} inventory`}>
      <div className="asset-inventory-toolbar"><strong>{rows.length} registered</strong><Input.Search aria-label="Search assets" placeholder="Search name or identifier" value={search} onChange={event => setSearch(event.target.value)} allowClear /></div>
      <Table<Asset> rowKey="asset_id" dataSource={rows} loading={assets.isPending} scroll={{ x: 760 }} pagination={{ pageSize: 10, hideOnSinglePage: true }} locale={{ emptyText: `No ${category.label.toLowerCase()} registered. Add an asset to begin your inventory.` }} columns={[
        { title: 'Name', dataIndex: 'name', render: (value: string) => <strong>{value}</strong> },
        { title: 'Identifier', dataIndex: 'locator', render: (value: string) => value || '—' },
        { title: 'Coverage', render: () => <Tag color="default">Not connected</Tag> },
        { title: 'Notes', dataIndex: 'notes', render: (value: string) => value || '—' },
        { title: 'Registered', dataIndex: 'created_at', render: (value: string) => date(value) },
        { title: '', key: 'actions', render: (_: unknown, asset: Asset) => <Button type="text" danger icon={<DeleteOutlined />} aria-label={`Remove ${asset.name}`} disabled={!canWrite} onClick={() => remove(asset)} /> },
      ]} />
    </section>
    <Modal title={`Register ${category.singular}`} open={open} onCancel={() => setOpen(false)} footer={null} destroyOnHidden>
      <Form form={form} layout="vertical" onFinish={values => save.mutate(values)} requiredMark={false}>
        <Form.Item name="name" label="Name" rules={[{ required: true, whitespace: true, max: 200 }]}><Input autoFocus maxLength={200} /></Form.Item>
        <Form.Item name="locator" label="Identifier" rules={[{ max: 500 }]} extra="Use an identifier only. Keep credentials and secrets in the provider's secure configuration."><Input maxLength={500} placeholder={category.hint} /></Form.Item>
        <Form.Item name="notes" label="Notes" rules={[{ max: 2000 }]}><Input.TextArea rows={3} maxLength={2000} /></Form.Item>
        {save.error && <Alert type="error" showIcon title={save.error.message} />}
        <Button type="primary" htmlType="submit" loading={save.isPending} block>Register asset</Button>
      </Form>
    </Modal>
  </>;
}
