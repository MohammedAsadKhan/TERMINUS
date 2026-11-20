// File: components.tsx
// Author: Team LARP
// Date: 2026-11-19 (comments revised)
// Version: 0.1.0
// Purpose: Provide shared controls and loading, error, and empty states.

import { Alert, Button, Empty, Skeleton, Tag, Typography } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import type { ReactNode } from 'react';

// Standard page header (eyebrow, title, description, optional action buttons) used by every console view.
export function PageTitle({ eyebrow, title, description, actions }: { eyebrow: string; title: string; description: string; actions?: ReactNode }) {
  return <header className="page-title"><div className="page-title-copy"><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div><div className="page-actions">{actions}</div></header>;
}
// Shows a failed request as an alert with an optional Retry button; renders nothing when there is no error.
export function ErrorPanel({ error, retry }: { error: Error | null; retry?: () => void }) {
  return error ? <Alert type="error" showIcon title="Unable to load this view" description={error.message} action={retry && <Button icon={<ReloadOutlined />} onClick={retry}>Retry</Button>} /> : null;
}
// Placeholder skeleton shown while a view's data is loading.
export function Loading() { return <div className="panel"><Skeleton active paragraph={{ rows: 6 }} /></div>; }
// Explicit empty state so an empty result is never mistaken for a loading or failed one.
export function EmptyPanel({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return <Empty className="empty-state" description={<><strong>{title}</strong><p>{description}</p></>}>{action}</Empty>;
}
// Tag colors for severity labels; unrecognized severities fall back to the default tag color.
const severityColors: Record<string, string> = { critical: 'red', high: 'orange', medium: 'gold', low: 'blue' };
// Severity tag, shown uppercase.
export function Severity({ value }: { value: string }) { return <Tag className="severity" color={severityColors[value] || 'default'}>{value.toUpperCase()}</Tag>; }
// Incident or agent status tag; underscores are shown as spaces and unrecognized states use the neutral color.
export function Status({ value }: { value: string }) { return <Tag color={value === 'RESOLVED' || value === 'active' ? 'green' : value === 'INVESTIGATING' ? 'blue' : value === 'WAITING_SPECIALIST' ? 'gold' : 'default'}>{value.replaceAll('_', ' ')}</Tag>; }
// Formats an ISO timestamp for display; missing and unparsable values get distinct labels instead of a fake date.
export function date(value?: string) { if (!value) return 'Not recorded'; const d = new Date(value); return Number.isNaN(d.valueOf()) ? 'Invalid timestamp' : d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
// Summary tile with a label, value and explanatory note.
export function Stat({ label, value, note, accent }: { label: string; value: ReactNode; note: string; accent?: string }) {
  return <div className={`stat-card ${accent || ''}`}><span>{label}</span><strong>{value}</strong><small>{note}</small><i aria-hidden="true" /></div>;
}
// Read-only code block with a copy-to-clipboard control.
export function Code({ children }: { children: string }) { return <Typography.Paragraph className="code-block" copyable={{ text: children }}><pre>{children}</pre></Typography.Paragraph>; }
