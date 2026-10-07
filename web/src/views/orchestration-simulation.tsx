import { useEffect, useState } from 'react';
import { Alert, Button, InputNumber, Select, Space, Tag } from 'antd';
import OperationMap, { type OperationNode } from './operation-map';

import { SIMULATION_SCENARIOS } from './simulation-scenarios';

export default function OrchestrationSimulation() {
  const [scenarioId, setScenarioId] = useState('ssh');
  const scenario = SIMULATION_SCENARIOS.find(item => item.id === scenarioId)!;
  const events = [
    ['main', 'Main orchestrator', '', `Synthetic alert received: ${scenario.alert}`],
    ['area', `${scenario.area} orchestrator`, 'main', 'Assigning triage, investigation, and response planning. Execution waits for a decision.'],
    ['triage', 'Triage specialist', 'area', 'Reading sample alerts, deduplicating, and scoping the affected asset.'],
    ['identity', scenario.specialist, 'area', scenario.review],
    ['triage', 'Triage specialist', 'area', `Sample finding: ${scenario.finding}`],
    ['identity', scenario.specialist, 'area', `${scenario.evidence}: ${scenario.finding}`],
    ['response', 'Response planner', 'area', 'Checking exclusions, duration, expected impact, and undo requirements.'],
    ['response', 'Response planner', 'area', `Proposal ready: ${scenario.recommendation}. Waiting for your decision.`],
  ];
  const [step, setStep] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [selected, setSelected] = useState('main');
  const [duration, setDuration] = useState(300);
  const [decision, setDecision] = useState('');
  const [execution, setExecution] = useState(0);
  useEffect(() => {
    if (!playing || step >= events.length) return;
    const timer = window.setTimeout(() => setStep(value => value + 1), 1800);
    return () => window.clearTimeout(timer);
  }, [playing, step]);
  useEffect(() => {
    if (decision !== 'approved' || execution >= 3) return;
    const timer = window.setTimeout(() => setExecution(value => value + 1), 1800);
    return () => window.clearTimeout(timer);
  }, [decision, execution]);
  const nodes: OperationNode[] = [...new Set(events.slice(0, step).map(event => event[0]))].map(id => {
    const records = events.slice(0, step).filter(event => event[0] === id);
    const last = records.at(-1)!;
    return { id, label: last[1], parent: last[2] || null, activity: last[3], status: step >= 8 ? (id === 'response' && !decision ? 'waiting' : 'completed') : records.length > 1 && ['triage', 'identity'].includes(id) ? 'completed' : 'running' };
  });
  function reset() { setPlaying(false); setStep(0); setDecision(''); setExecution(0); setSelected('main'); setDuration(300); }
  return <section className="simulation-console" aria-label="Orchestration simulation">
    <Alert type="info" showIcon title="Simulation · scripted demonstration" description="Local sample evidence only. No model requests, network calls, notifications, or firewall changes. Separate from recorded investigations; resets when you leave this page." />
    <div className="simulation-toolbar">
      <Button type="primary" disabled={step >= events.length} onClick={() => setPlaying(!playing)}>{playing && step < events.length ? 'Pause simulation' : step ? 'Resume simulation' : 'Run orchestration simulation'}</Button>
      <Button onClick={reset}>Reset / replay</Button><Select aria-label="Simulation scenario" value={scenarioId} style={{ minWidth: 260 }} options={SIMULATION_SCENARIOS.map(item => ({ value: item.id, label: item.label }))} onChange={value => { reset(); setScenarioId(value); }} /><Tag>Synthetic {scenario.label}</Tag><span>{step} / {events.length} investigation events</span>
    </div>
    <OperationMap nodes={nodes} onSelect={setSelected} />
    {step > 0 && <section className="simulation-detail"><h3>{nodes.find(node => node.id === selected)?.label || 'Operation activity'}</h3>
      <ol className="simulation-log" aria-live="polite">{events.slice(0, step).filter(event => event[0] === selected).map((event, index) => <li key={index}>{event[3]}</li>)}</ol>
      <details><summary>Full simulated activity timeline</summary><ol className="simulation-log">{events.slice(0, step).map((event, index) => <li key={index}><strong>{event[1]}:</strong> {event[3]}</li>)}</ol></details>
    </section>}
    {step >= events.length && <section className="simulation-response" aria-label="Response decision">
      <Tag color="warning">Simulated recommendation</Tag><h2>{scenario.recommendation}</h2>
      <p><strong>Sample evidence:</strong> {scenario.evidence}. {scenario.finding}</p>
      <p><strong>Expected impact:</strong> {scenario.impact}</p>
      <div>Duration in seconds: <InputNumber aria-label="Simulated block duration" min={30} max={900} precision={0} value={duration} disabled={!!decision} onChange={value => setDuration(value ?? 300)} />.</div>
      <p><strong>Undo plan:</strong> {scenario.undo}</p>
      {!decision ? <Space wrap><Button type="primary" onClick={() => { setDecision('approved'); setExecution(1); }}>Approve simulated action</Button><Button onClick={() => setDecision('investigate')}>Keep investigating</Button><Button onClick={() => setDecision('dismissed')}>Dismiss recommendation</Button></Space> : <>
        <p role="status">{decision === 'approved' ? execution === 1 ? `Simulated execution: applying ${duration}-second response. ${scenario.recommendation}.` : execution === 2 ? 'Simulated verification: independently checking the response effect and legitimate service access.' : `Simulated verification complete: ${scenario.verification} No real action occurred.` : decision === 'undone' ? `Simulated undo complete: ${scenario.undo}` : decision === 'investigate' ? 'Further investigation requested. No simulated action approved.' : 'Recommendation dismissed. No simulated action approved.'}</p>
        {decision === 'approved' && execution === 3 && <Button onClick={() => setDecision('undone')}>Undo simulated block</Button>}
      </>}
    </section>}
  </section>;
}
