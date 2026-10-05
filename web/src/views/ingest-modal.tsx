import { useState } from 'react';
import { Alert, App, Button, Input, Modal } from 'antd';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api, body } from '../api';
import { useSession } from '../context';
import { createTestAlert, randomTestTopic, TEST_TOPICS, type TestTopic } from '../test-alerts';
import './ingest-modal.css';

export function IngestModal({ open, close }: { open: boolean; close: () => void }) {
  const { orgId } = useSession();
  const query = useQueryClient();
  const { message } = App.useApp();
  const [topic, setTopic] = useState<TestTopic | 'random'>('ssh');
  const [generated, setGenerated] = useState(() => createTestAlert('ssh'));
  const [custom, setCustom] = useState<string | null>(null);
  function regenerate(nextTopic: TestTopic | 'random' = topic) {
    setGenerated(createTestAlert(nextTopic === 'random' ? randomTestTopic() : nextTopic));
    setCustom(null);
  }
  const mutation = useMutation({
    mutationFn: async () => {
      let value: unknown;
      try { value = custom === null ? generated : JSON.parse(custom); } catch { throw new Error('The payload must be valid JSON.'); }
      return api('/wazuh', orgId, body('POST', value));
    },
    onSuccess: () => { void query.invalidateQueries({ queryKey: ['incidents', orgId] }); void query.invalidateQueries({ queryKey: ['investigation-network-stable', orgId] }); message.success('Test alert submitted'); close(); regenerate(); },
  });
  return <Modal title="Submit a test alert" className="test-alert-modal" open={open} onCancel={close} okText="Submit alert" onOk={() => mutation.mutate()} confirmLoading={mutation.isPending} width={660} destroyOnHidden>
    <p className="muted">These examples are synthetic and use documentation IP addresses. Submitting one runs this organization's configured pipeline; notification channels may receive it.</p>
    <label className="field-label" htmlFor="test-alert-topic">Test topic</label>
    <select id="test-alert-topic" className="test-alert-topic-select" value={topic} onChange={event => {
      const value = event.target.value as TestTopic | 'random';
      setTopic(value);
      regenerate(value);
      mutation.reset();
    }}>
      <option value="random">Surprise me — random topic</option>
      {TEST_TOPICS.map(item => <option key={item.id} value={item.id}>{item.label} · {item.area}</option>)}
    </select>
    <p className="muted">Prepared: {generated.rule.description} · MITRE {generated.rule.mitre.id}</p>
    <Button size="small" onClick={() => regenerate()} disabled={mutation.isPending}>Regenerate details</Button>
    <label className="field-label">Alert payload <span>Editable JSON</span></label><Input.TextArea aria-label="Alert JSON" rows={9} className="mono" value={custom ?? JSON.stringify(generated, null, 2)} onChange={event => setCustom(event.target.value)} />
    {mutation.error && <Alert type="error" showIcon title={mutation.error.message} className="form-alert" />}
  </Modal>;
}
