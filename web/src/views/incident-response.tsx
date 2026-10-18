import { useState } from 'react';
import { Alert, App, Button, Input, InputNumber, Modal, Space, Tag } from 'antd';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, body } from '../api';
import { useSession } from '../context';
import { date, ErrorPanel } from '../components';

type Proposal = { suggested_steps?: string[]; proposal_id: string; digest: string; title: string; action: string; origin: string; rationale: string; capability: string; source_ip: string | null; target_ip: string | null; agent_id: string | null; duration_seconds: number; cooldown_seconds: number; max_actions: number; impact: string; verification: string; recovery: string; exclusions: string[]; evidence: { id: string; task_id: string }[]; decision: { decision: string; note: string } | null };
type ResponseView = { operation_id: string | null; proposals: Proposal[]; authorizations: {authorization_id: string; mode: string; expires_at: string; revoked_at: string | null}[]; intents: {intent_id: string; proposal_id: string; state: string}[]; events: {id: number; state: string; detail: string; created_at: string; intent_id: string | null; proposal_id: string | null}[] };

export default function IncidentResponse({ incidentId, timelineOnly = false }: { incidentId: string; timelineOnly?: boolean }) {
  const { orgId, detail } = useSession();
  const { message } = App.useApp();
  const [review, setReview] = useState<{proposal: Proposal; decision: string} | null>(null);
  const [note, setNote] = useState('');
  const [revision, setRevision] = useState<Proposal | null>(null);
  const [duration, setDuration] = useState(60);
  const base = `/incidents/${encodeURIComponent(incidentId)}/response`;
  const state = useQuery({queryKey: ['live-response', orgId, incidentId], queryFn: () => api<ResponseView>(base, orgId), refetchInterval: 2000});
  const update = useMutation({mutationFn: ({path, payload}: {path: string; payload?: unknown}) => api<ResponseView>(base + path, orgId, body('POST', payload ?? {})), onSuccess: () => { setReview(null); setRevision(null); setNote(''); void state.refetch(); message.success('Response decision recorded. Execution and verification are reported separately.'); }, onError: (error: Error) => message.error(error.message)});
  const admin = detail?.role === 'admin';
  const active = state.data?.authorizations?.filter(a => !a.revoked_at && new Date(a.expires_at).getTime() > Date.now()) || [];
  const proposal = state.data?.proposals?.[0];
  return <section aria-label="Incident response" className="work-detail-content">
    <h3>{timelineOnly ? 'Response activity' : 'Response decision'}</h3>
    {state.error && <ErrorPanel error={state.error} retry={() => void state.refetch()} />}
    {!timelineOnly && <>
      <Space wrap><Button disabled={!admin || update.isPending} onClick={() => update.mutate({path: '/refresh'})}>Prepare / refresh recommendation</Button>{active.length > 0 && <Button danger disabled={!admin || update.isPending} onClick={() => update.mutate({path: '/stop'})}>Stop autonomy / queued authorization</Button>}</Space>
      {active.map(a => <Alert key={a.authorization_id} type="info" title={a.mode === 'autonomy' ? 'Autonomy enabled for this incident' : 'One action authorized'} description={`Expires ${date(a.expires_at)} or at incident closure. Stopping prevents new dispatches; existing timed effects still expire.`} />)}
      {!proposal && <p>No response proposal recorded. Prepare a recommendation to review available capabilities.</p>}
      {proposal && <article>
        <h3>{proposal.title} <Tag>{proposal.capability}</Tag></h3>
        <p>{proposal.rationale}</p>
        {!!proposal.suggested_steps?.length && <ul>{proposal.suggested_steps.map((step,index) => <li key={index}>{step}</li>)}</ul>}
        <dl className="work-fields">
          <div><dt>Origin</dt><dd>{proposal.origin} recommendation · live telemetry is separate from simulation</dd></div>
          <div><dt>Action</dt><dd>{proposal.action}</dd></div>
          <div><dt>Target</dt><dd>{proposal.target_ip || 'Review evidence'} {proposal.agent_id && `(agent ${proposal.agent_id})`}</dd></div>
          {proposal.source_ip && <div><dt>Source / duration</dt><dd>{proposal.source_ip} / {proposal.duration_seconds} seconds</dd></div>}
          <div><dt>Impact</dt><dd>{proposal.impact}</dd></div><div><dt>Verification</dt><dd>{proposal.verification}</dd></div><div><dt>Recovery</dt><dd>{proposal.recovery}</dd></div>
        </dl>
        <p>Evidence: {proposal.evidence.length ? proposal.evidence.map(e => <a key={e.id} href={`/console/agents?incident_id=${encodeURIComponent(incidentId)}&task_id=${encodeURIComponent(e.task_id)}`} title={`Task ${e.task_id}`}><code>{e.id}</code> </a>) : 'No cited evidence'}</p>
        {proposal.capability !== 'Ready' && <Alert type="warning" title={proposal.capability === 'Unsupported action' ? proposal.recovery : proposal.capability} description="Approval and autonomy are unavailable until this capability and its evidence are ready. You may reject or defer the recommendation." />}
        {proposal.decision && <p>Latest decision: <strong>{proposal.decision.decision}</strong> {proposal.decision.note}</p>}
        <Space wrap>{['approve','autonomy','reject','defer'].map(decision => <Button key={decision} type={decision === 'approve' ? 'primary' : 'default'} disabled={!admin || update.isPending || (!!proposal.decision && proposal.decision.decision !== 'defer') || (['approve','autonomy'].includes(decision) && (proposal.capability !== 'Ready' || active.length > 0))} onClick={() => {setReview({proposal,decision});setNote('');}}>{({approve:'Approve once',autonomy:'Enable autonomy for this incident',reject:'Reject',defer:'Defer'} as Record<string,string>)[decision]}</Button>)}</Space>
        {proposal.action === 'response.wazuh_ip_block' && <Button disabled={!admin || update.isPending} onClick={() => { setRevision(proposal); setDuration(proposal.duration_seconds); }}>Revise duration</Button>}
        {state.data!.proposals.length > 1 && <details><summary>Previous proposal revisions ({state.data!.proposals.length - 1})</summary>{state.data!.proposals.slice(1).map(p => <p key={p.proposal_id}><code>{p.proposal_id}</code> — {p.decision?.decision || 'No decision'} — {p.capability}</p>)}</details>}
      </article>}
    </>}
    {state.data?.operation_id && <p>Operation task: <code>{state.data.operation_id}</code></p>}
    {state.data?.intents?.map(i => <p key={i.intent_id}><Tag color={i.state === 'verified_blocked' ? 'processing' : undefined}>{i.state.replaceAll('_',' ')}</Tag> Intent <code>{i.intent_id}</code></p>)}
    <ol aria-label="Response timeline">{state.data?.events?.map(e => <li key={e.id}><strong>{e.state.replaceAll('_',' ')}</strong> · {date(e.created_at)}<p>{e.detail}</p>{e.intent_id && <code>{e.intent_id}</code>}</li>)}</ol>
    <Modal open={!!revision} title="Create a response revision" okText="Save new revision" confirmLoading={update.isPending} onCancel={() => setRevision(null)} onOk={() => revision && update.mutate({path:`/${revision.proposal_id}/revision`,payload:{digest:revision.digest,duration_seconds:duration}})}>
      <p>This revokes prior authorization. A human-authored revision requires approval by a different administrator.</p>
      <InputNumber aria-label="Block duration in seconds" min={30} max={120} value={duration} onChange={value => setDuration(Number(value) || 60)} /> seconds
    </Modal>
    <Modal open={!!review} title={review?.decision === 'autonomy' ? 'Review incident autonomy scope' : review?.decision === 'approve' ? 'Approve this exact response once' : review?.decision === 'reject' ? 'Reject recommendation' : 'Defer recommendation'} okText={review?.decision === 'autonomy' ? 'Enable incident autonomy' : review?.decision === 'approve' ? 'Authorize and queue' : 'Save decision'} confirmLoading={update.isPending} okButtonProps={{disabled: review?.decision === 'reject' && !note.trim()}} onCancel={() => setReview(null)} onOk={() => review && update.mutate({path:`/${review.proposal.proposal_id}/decision`,payload:{digest:review.proposal.digest,decision:review.decision,note}})}>
      {review && <><p>{review.proposal.impact}</p>{review.decision === 'autonomy' && <><p>Only {review.proposal.action}, source {review.proposal.source_ip}, target {review.proposal.target_ip}, agent {review.proposal.agent_id}.</p><p>30 minutes or incident closure. Maximum {review.proposal.max_actions} actions, {review.proposal.cooldown_seconds}s cooldown, {review.proposal.duration_seconds}s per block. Requires three fresh failures within 120 seconds.</p><p>Excluded: {review.proposal.exclusions.join(', ')}. New targets/actions require another decision.</p></>}<p>{review.proposal.verification} {review.proposal.recovery}</p><Input.TextArea aria-label="Decision note" placeholder={review.decision === 'reject' ? 'Required rejection reason' : 'Optional decision note'} value={note} maxLength={2000} onChange={e => setNote(e.target.value)} /><p>Authorizing does not mean the action has executed or been verified.</p></>}
    </Modal>
  </section>;
}
