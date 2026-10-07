import { expect, test, type Page, type Route } from '@playwright/test';

const browserChannel = process.env.TERMINUS_PLAYWRIGHT_CHANNEL;
test.use(browserChannel ? { channel: browserChannel } : {});

const now = '2026-10-04T16:30:00Z';
const task = {
  org_id: 'org-blue',
  incident_id: 'inc-opaque-X7',
  task_id: 'task-peer-A9',
  parent_task_id: 'task-help-area-B4',
  area: 'investigation',
  role: 'network',
  objective: 'Investigate lateral traffic from the affected endpoint.',
  status: 'waiting',
  priority: 80,
  idempotency_key: 'opaque-key',
  created_at: now,
  updated_at: now,
  started_at: now,
  completed_at: null,
};
const schedulerJob = { job_id: 'job-opaque-41', role: 'network', status: 'waiting', attempt: 2, max_attempts: 3, worker_id: 'worker-blue-7', run_id: 'run-opaque-C2', available_at: now, recovery_reason: 'WAITING_SPECIALIST' };
const specialistResult = {
  status: 'insufficient_telemetry',
  role: 'network',
  tool_calls: [{ tool_id: 'network.flows', status: 'unavailable', error_code: 'service_not_configured', evidence_count: 1 }],
  evidence_ids: ['ev-shared-9'],
  findings: [{ claim: 'The endpoint contacted a lateral network peer.', evidence_ids: ['ev-shared-9'] }],
  gaps: [{ code: 'tool_unavailable', tool_id: 'network.flows', detail: 'Flow service is not configured.' }],
  model: {
    connection_id: 'conn-prod-opaque',
    model: 'security-reasoner',
    route_id: 'route-policy-3',
    reservation_id: 'reservation-opaque-8',
    usage: { input_tokens: 685, output_tokens: 83, total_tokens: 768 },
    cost_known: false,
    cost_micro_usd: null,
  },
  execution_mode: 'tools_and_model',
};
const evidence = {
  org_id: 'org-blue', incident_id: task.incident_id, task_id: task.task_id,
  evidence_id: 'ev-shared-9', source: 'endpoint.events', source_timestamp: now,
  collected_at: now, content: { event: 'bounded fixture' }, content_ref: null, content_hash: 'a'.repeat(64), created_at: now,
};
const run = {
  org_id: 'org-blue', incident_id: task.incident_id, task_id: task.task_id,
  run_id: 'run-opaque-C2', agent_id: null, model_connection_id: 'conn-prod-opaque', model_name: 'security-reasoner',
  status: 'completed', created_at: now, updated_at: now, started_at: now, completed_at: now, result: specialistResult, error: null,
};
const failedRun = {
  ...run, run_id: 'run-failed-B1', status: 'failed', result: null,
  error: 'Execution error; inspect protected diagnostics',
};
const helpOwnership = {
  help_request_id: 'help-opaque-H6', incident_id: task.incident_id, state: 'incomplete', reason_code: 'insufficient_telemetry',
  requester_task_id: 'task-requester-Q1', requester_role: 'endpoint', requester_area: 'investigation', target_role: 'network', responsible_area: 'investigation',
  delegated_task_id: 'task-help-area-B4', peer_task_id: task.task_id, objective: 'Check network adjacency.', expected_evidence_kinds: ['network_flow'],
  shared_evidence_ids: ['ev-shared-9'], result: specialistResult,
};

function json(route: Route, value: unknown, status = 200) {
  return route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
}

async function mockConsole(page: Page, role: 'admin' | 'member' | 'viewer' = 'member', completed = false) {
  let cancelled = false;
  const visibleTask = () => ({ ...task, status: cancelled ? 'cancelled' : completed ? 'completed' : task.status });
  const visibleJob = () => ({ ...schedulerJob, status: completed ? 'completed' : schedulerJob.status, worker_id: completed ? null : schedulerJob.worker_id });
  await page.addInitScript(() => localStorage.clear());
  await page.route('**/*', route => {
    const request = route.request();
    const url = new URL(request.url());
    if (!['http:', 'https:'].includes(url.protocol) || !url.pathname.startsWith('/')) return route.continue();
    if (url.pathname === '/auth/me') return json(route, { user_id: 'user-1', email: 'analyst@example.test', display_name: 'Morgan', created_at: now });
    if (url.pathname === '/orgs') return json(route, [{ org_id: 'org-blue', name: 'Blue Team', created_at: now }]);
    if (url.pathname === '/orgs/current') return json(route, { organization: { org_id: 'org-blue', name: 'Blue Team', created_at: now }, role, members: [], license: null, license_error: null });
    if (url.pathname === '/system') return json(route, { version: 'test', storage: 'sqlite', transport: 'fixture', llm_mode: 'fixture', llm_model: 'fixture', live_response: false, workflow_execution: true, integrations: [] });
    if (url.pathname === '/assets') return json(route, []);
    if (url.pathname === '/agents') return json(route, [{ id: 'agent-1', name: 'Forensic investigator', role_description: 'Examines endpoint evidence', master_prompt: 'Use cited evidence.', status: 'active', incidents_processed: 3, created_at: now }]);
    if (url.pathname === '/orchestration/tasks' && request.method() === 'GET') return json(route, { items: [{ task: visibleTask(), scheduler_job: visibleJob() }], limit: 20, offset: 0 });
    if (url.pathname === `/orchestration/tasks/${task.task_id}/cancel` && request.method() === 'POST') { cancelled = true; return json(route, { task: { ...task, status: 'cancelled' } }); }
    if (url.pathname === `/orchestration/tasks/${task.task_id}`) return json(route, { task: visibleTask(), scheduler_job: visibleJob(), runs: [failedRun, run], evidence: [], help_requests: [], actions: [], child_records_limit: 200, child_records_may_be_truncated: false });
    if (url.pathname === `/orchestration/incidents/${task.incident_id}/tree`) return json(route, {
      org_id: 'org-blue', incident_id: task.incident_id, aggregate_status: 'incomplete', incident_closed: false, planned_areas: ['investigation'], gaps: ['Help result has gaps'],
      roots: [{ ...task, task_id: 'task-root-R1', parent_task_id: null, role: 'main_orchestrator', objective: 'Coordinate investigation.', status: 'completed', aggregate_status: 'incomplete', children: [{ ...task, task_id: 'task-help-area-B4', parent_task_id: 'task-root-R1', role: 'area_orchestrator', help_request_id: 'help-opaque-H6', aggregate_status: 'incomplete', help_ownership: [helpOwnership], children: [{ ...task, aggregate_status: 'incomplete', help_ownership: [] }] }] }],
    });
    if (url.pathname === `/orchestration/tasks/${task.task_id}/help-context`) return json(route, { ...helpOwnership, shared_evidence: [evidence] });
    if (url.pathname === '/orchestration/catalog') return json(route, { note: 'Execution is planned for a future release.', items: [
      { specialty_id: 'network_forensics', name: 'Network Forensics', area: 'investigation', core_role: 'network', availability: 'planned', release: 'future', execution_available: false, status_label: 'Planned' },
      { specialty_id: 'endpoint_triage', name: 'Endpoint Triage', area: 'alert_handling', core_role: 'triage', availability: 'planned', release: 'future', execution_available: false, status_label: 'Planned' },
      { specialty_id: 'future_hunting', name: 'Future Hunting', area: 'investigation', core_role: null, availability: 'future', release: 'future', execution_available: false, status_label: 'Planned — unavailable in 1.0' },
    ] });
    return route.continue();
  });
  return { wasCancelled: () => cancelled };
}

test('shows durable execution, analysis gaps, provenance, help context, and the planned catalog', async ({ page }) => {
  await mockConsole(page, 'member', true);
  await page.goto('/console/agents');

  await expect(page.getByRole('heading', { name: 'Follow every admitted investigation.' })).toBeVisible();
  await expect(page.getByText('Auto-refreshes every 2 seconds')).toBeVisible();
  await page.getByRole('button', { name: /network.*Investigate lateral traffic/ }).click();

  await expect(page.getByRole('heading', { name: 'Execution and analysis' })).toBeVisible();
  await expect(page.getByText('Insufficient telemetry', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('The endpoint contacted a lateral network peer.')).toBeVisible();
  await expect(page.getByText('Attempt 1')).toBeVisible();
  await expect(page.getByText('Attempt 2')).toBeVisible();
  await expect(page.getByText('2 of 3')).toBeVisible();
  await expect(page.getByText('Lease released after execution')).toBeVisible();
  await page.getByRole('button', { name: /Attempt 1/ }).click();
  await expect(page.getByText('Run error')).toBeVisible();
  await page.getByRole('button', { name: /Attempt 2/ }).click();
  await expect(page.getByText('768 tokens')).toBeVisible();
  await expect(page.getByText('Unknown — provider did not report')).toHaveCount(1);
  await expect(page.getByText('endpoint → network')).toBeVisible();
  await expect(page.getByText('ev-shared-9').first()).toBeVisible();
  await expect(page.getByText('Network Forensics')).toBeVisible();
  await expect(page.getByText('Future Hunting')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Network Forensics', exact: true })).toBeDisabled();
  await expect(page.getByText('future specialties', { exact: true })).toHaveCount(0);
});

test('supports operator cancellation and preserves the saved configuration workspace', async ({ page }) => {
  const fixture = await mockConsole(page, 'member');
  await page.goto('/console/agents');
  await page.getByRole('button', { name: /network.*Investigate lateral traffic/ }).click();

  await page.getByRole('button', { name: 'Cancel task' }).click();
  await expect.poll(fixture.wasCancelled).toBe(true);

  await page.getByRole('tab', { name: 'Saved configurations' }).click();
  await expect(page.getByRole('heading', { name: 'Define your investigation team.' })).toBeVisible();
  await expect(page.getByText('Forensic investigator')).toBeVisible();
  await expect(page.getByRole('button', { name: 'New agent' })).toBeDisabled();
});

test('keeps task cancellation visible but unavailable to viewers', async ({ page }) => {
  const fixture = await mockConsole(page, 'viewer');
  await page.goto('/console/agents');
  await page.getByRole('button', { name: /network.*Investigate lateral traffic/ }).click();

  await expect(page.getByRole('button', { name: 'Cancel task' })).toBeDisabled();
  expect(fixture.wasCancelled()).toBe(false);
});

test('groups incident work into an operation with spawned agents and a recorded activity timeline', async ({ page }) => {
  await mockConsole(page, 'member', true);
  await page.goto('/console/agents');
  await expect(page.getByRole('combobox', { name: 'Group agent activity' })).toBeVisible();
  await page.getByRole('button', { name: /network.*Investigate lateral traffic/ }).click();
  const operation = page.getByRole('region', { name: 'Operation overview' });
  await expect(operation.getByRole('heading', { name: 'Coordinate investigation.' })).toBeVisible();
  await expect(operation.getByText('Specialists spawned')).toBeVisible();
  await expect(operation.getByRole('button', { name: /main orchestrator/ })).toBeVisible();
  await expect(operation.getByRole('button', { name: /network.*Inspect activity/ })).toBeVisible();
  await operation.getByRole('button', { name: /network.*Inspect activity/ }).click();
  await expect(page.getByRole('heading', { name: 'Activity timeline' })).toBeVisible();
  await expect(page.getByText('Model analysis recorded', { exact: true })).toBeVisible();
  await page.screenshot({ path: 'test-results/agent-operation-overview.png', fullPage: false });
});


test('fresh simulation pauses for approval, verifies, undoes, and resets without writes', async ({ page }) => {
  await mockConsole(page, 'member');
  const writes: string[] = [];
  page.on('request', request => { if (request.method() !== 'GET') writes.push(request.url()); });
  await page.clock.install();
  await page.goto('/console/qa');
  await page.getByRole('button', { name: 'Run orchestration simulation', exact: true }).click();
  for (let i = 0; i < 8; i++) await page.clock.runFor(1900);
  await expect(page.getByRole('button', { name: 'Approve simulated action' })).toBeVisible();
  await expect(page.getByText('Simulated execution:', { exact: false })).toHaveCount(0);
  await page.getByRole('spinbutton', { name: 'Simulated block duration' }).fill('60');
  await page.getByRole('button', { name: 'Approve simulated action' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'applying 60-second response' })).toBeVisible();
  await page.clock.runFor(1900);
  await page.clock.runFor(1900);
  await page.getByRole('button', { name: 'Undo simulated block' }).click();
  await expect(page.getByText('Simulated undo complete:', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Reset / replay' }).click();
  await expect(page.getByRole('button', { name: 'Run orchestration simulation', exact: true })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Approve simulated action' })).toHaveCount(0);
  expect(writes).toEqual([]);
});


test('simulation can pause and dismiss without approving a response', async ({ page }) => {
  await mockConsole(page, 'member');
  await page.clock.install();
  await page.goto('/console/qa');
  await page.getByRole('button', { name: 'Run orchestration simulation', exact: true }).click();
  await page.clock.runFor(1900);
  await page.getByRole('button', { name: 'Pause simulation', exact: true }).click();
  await page.clock.runFor(10000);
  await expect(page.getByText('1 / 8 investigation events')).toBeVisible();
  await page.getByRole('button', { name: 'Resume simulation', exact: true }).click();
  for (let i = 0; i < 7; i++) await page.clock.runFor(1900);
  await page.getByRole('button', { name: 'Dismiss recommendation', exact: true }).click();
  await expect(page.getByText('Recommendation dismissed. No simulated action approved.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Undo simulated block' })).toHaveCount(0);
});

test('all non-SSH scenarios show distinct recommendations and reset on switching', async ({ page }) => {
  await mockConsole(page, 'member');
  await page.clock.install();
  await page.goto('/console/qa');
  const scenarios = [
    ['Ransomware-like file changes', 'Temporarily isolate training-workstation-02', 'SIM-EV-FILES-01'],
    ['Suspicious remote access', 'Temporarily restrict source 198.51.100.242', 'SIM-EV-FLOW-01'],
    ['Unexpected admin account change', 'Temporarily suspend training-user-04 privileged access', 'SIM-EV-ACCOUNT-01'],
    ['Application exploit probe', 'Temporarily block the probe source at training-api-05', 'SIM-EV-REQUEST-01'],
    ['Unusual outbound data transfer', 'Temporarily restrict egress to 203.0.113.44', 'SIM-EV-EGRESS-01'],
  ];
  for (const [label, proposal, evidence] of scenarios) {
    await page.getByRole('combobox', { name: 'Simulation scenario' }).click();
    await page.getByTitle(label, { exact: true }).click();
    await expect(page.getByRole('button', { name: 'Approve simulated action' })).toHaveCount(0);
    await page.getByRole('button', { name: 'Run orchestration simulation', exact: true }).click();
    for (let i = 0; i < 8; i++) await page.clock.runFor(1900);
    await expect(page.getByRole('heading', { name: proposal, exact: true })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Response decision' })).toContainText(evidence);
    await page.getByRole('button', { name: 'Keep investigating', exact: true }).click();
    await expect(page.getByText('Further investigation requested. No simulated action approved.')).toBeVisible();
  }
});
