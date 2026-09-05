import { Alert, Button, Empty, Skeleton, Tag, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import type { ReactNode } from 'react';

export function PageTitle({ eyebrow, title, description, actions }: { eyebrow: string; title: string; description: string; actions?: ReactNode }) {
  return <div className="page-title"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div><div className="page-actions">{actions}</div></div>;
}
export function ErrorPanel({ error, retry }: { error: Error | null; retry?: () => void }) {
  return error ? <Alert type="error" showIcon title="Unable to load this view" description={error.message} action={retry && <Button icon={<ReloadOutlined />} onClick={retry}>Retry</Button>} /> : null;
}
export function Loading() { return <div className="panel"><Skeleton active paragraph={{ rows: 6 }} /></div>; }
export function EmptyPanel({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return <Empty className="empty-state" description={<><strong>{title}</strong><p>{description}</p></>}>{action}</Empty>;
}
const severityColors: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' };
export function Severity({ value }: { value: string }) { return <Tag className="severity" color={severityColors[value] || 'default'}>{value.toUpperCase()}</Tag>; }
export function Status({ value }: { value: string }) { return <Tag color={value === 'RESOLVED' || value === 'active' ? 'green' : value === 'INVESTIGATING' ? 'blue' : 'default'}>{value.replaceAll('_', ' ')}</Tag>; }
export function date(value?: string) { if (!value) return 'Not recorded'; const d = new Date(value); return Number.isNaN(d.valueOf()) ? 'Invalid timestamp' : d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
export function Stat({ label, value, note, accent }: { label: string; value: ReactNode; note: string; accent?: string }) {
  return <div className={`stat-card ${accent || ''}`}><span>{label}</span><strong>{value}</strong><small>{note}</small></div>;
}
export function Code({ children }: { children: string }) { return <Typography.Paragraph className="code-block" copyable={{ text: children }}><pre>{children}</pre></Typography.Paragraph>; }
