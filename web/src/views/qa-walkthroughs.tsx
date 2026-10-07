import { Button, Tag } from 'antd';
import { Link } from 'react-router-dom';
import { TEST_TOPICS } from '../test-alerts';
import './qa-walkthroughs.css';
import OrchestrationSimulation from './orchestration-simulation';

const walkthroughs = [
  {
    title: '1. Synthetic alert to incident',
    path: '/',
    action: 'Open Overview',
    steps: 'Record the current incident count. Choose a test topic, inspect its payload, and submit it. Open the resulting incident and compare the rule, host, time, source IP, and raw log.',
    evidence: 'Save the alert ID, incident ID, expected result, observed result, and any missing fields.',
  },
  {
    title: '2. Investigation and activity',
    path: '/incidents',
    action: 'Open Incidents',
    steps: 'Inspect the evidence and activity tabs. Check whether a task or specialist run actually exists. A ticket status change alone is not a verified response.',
    evidence: 'Record task/run IDs, evidence citations, status transitions, and any action outcome.',
  },
  {
    title: '3. Specialist execution',
    path: '/agents',
    action: 'Open Agents',
    steps: 'Inspect task activity, execution state, and help ownership. Separate configured catalog entries from recorded specialist runs.',
    evidence: 'Record the task ID, run ID, result state, errors, and whether evidence was saved.',
  },
  {
    title: '4. Workflow simulation',
    path: '/workflows',
    action: 'Open Workflows',
    steps: 'Run the dry-run simulation and inspect its trace. This checks workflow structure; it does not dispatch a live response.',
    evidence: 'Record the trace, chosen branch, and any failed or skipped step.',
  },
  {
    title: '5. Connector checks',
    path: '/settings',
    action: 'Open Settings',
    steps: 'Check configured Wazuh, model, and notification connections with their own test controls. Confirm the target, credential scope, received data, and any error before calling a connector live.',
    evidence: 'Record the endpoint or provider, test time, response, and downstream incident or task ID.',
  },
] as const;

export default function QaWalkthroughs() {
  return <div className="qa-page">
    <header className="qa-header">
      <div className="eyebrow">QA · Misha Stegall, Test Manager</div>
      <h1>Test walkthroughs</h1>
      <p>Use these paths to explore the current console and record what actually happened. The sample alert is synthetic; live source and response connectivity need separate evidence.</p>
    </header>

    <section className="qa-note" aria-label="Current verification status">
      <strong>Current checkpoint</strong>
      <p>The local API and console have started successfully, the production console builds, and browser fixture and focused backend tests pass. Those checks do not establish a live Wazuh, model, notification, or response connection.</p>
    </section>

    <div className="qa-grid">
      {walkthroughs.map(item => <section className="qa-card" key={item.title}>
        <h2>{item.title}</h2>
        <p>{item.steps}</p>
        <div className="qa-evidence"><strong>Record:</strong> {item.evidence}</div>
        <Button type="primary"><Link to={item.path}>{item.action}</Link></Button>
      </section>)}
    </div>

    <section className="qa-note"><h2>6. Orchestration and response simulation</h2><p>Inspect spawned agents, edit the recommendation duration, and choose whether to approve the simulated response.</p><OrchestrationSimulation /></section>

    <section className="qa-topics">
      <h2>Sample alert topics</h2>
      <p>Use the topic dropdown on Overview, or submit a random example with one click. Each sample has a new ID and timestamp and is labeled synthetic.</p>
      <div className="qa-topic-list">{TEST_TOPICS.map(topic => <Tag key={topic.id}>{topic.label} · {topic.area}</Tag>)}</div>
    </section>

    <section className="qa-note" aria-label="Next connectivity goal">
      <strong>Next goal: prove the connections end to end</strong>
      <p>Validate Wazuh source authentication and real event ingestion; model requests and saved evaluations; specialist task dispatch and durable results; notification delivery; and approved response execution with independent effect and recovery checks. Keep negative cases and repeat runs in the evidence log.</p>
    </section>
  </div>;
}
