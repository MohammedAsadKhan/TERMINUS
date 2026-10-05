import { expect, test, type Route } from '@playwright/test';

const browserChannel = process.env.TERMINUS_PLAYWRIGHT_CHANNEL;
test.use(browserChannel ? { channel: browserChannel } : {});

function json(route: Route, value: unknown) {
  return route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) });
}

test('submits a random synthetic alert or a selected topic with distinct evidence', async ({ page }) => {
  const submitted: Array<Record<string, any>> = [];
  await page.addInitScript(() => localStorage.clear());
  await page.route('**/*', route => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === '/auth/me') return json(route, { user_id: 'user-1', email: 'analyst@example.test', display_name: 'Morgan', created_at: '2026-10-05T00:00:00Z' });
    if (path === '/orgs') return json(route, [{ org_id: 'org-training', name: 'Training SOC', created_at: '2026-10-05T00:00:00Z' }]);
    if (path === '/orgs/current') return json(route, { organization: { org_id: 'org-training', name: 'Training SOC', created_at: '2026-10-05T00:00:00Z' }, role: 'admin', members: [], license: null, license_error: null });
    if (path === '/system') return json(route, { version: 'test', storage: 'sqlite', transport: 'fixture', llm_mode: 'fixture', llm_model: '', live_response: false, workflow_execution: false, integrations: [] });
    if (path === '/assets' || path === '/incidents' || path === '/agents/actions') return json(route, []);
    if (path === '/investigation/graph/network') return json(route, { total_events: 0, shown_events: 0, events: [] });
    if (path === '/wazuh' && request.method() === 'POST') {
      submitted.push(request.postDataJSON());
      return json(route, { status: 'accepted' });
    }
    return route.continue();
  });

  await page.goto('/console/');
  await page.getByRole('button', { name: 'Add random test alert' }).click();
  await expect.poll(() => submitted.length).toBe(1);
  expect(submitted[0].rule.description).toMatch(/^\[SYNTHETIC\]/);
  expect(submitted[0].full_log).toMatch(/^SYNTHETIC TEST EVENT:/);
  expect(submitted[0].data.srcip).toMatch(/^198\.51\.100\./);

  await page.getByRole('button', { name: 'Choose test alert' }).click();
  await page.getByLabel('Test topic').selectOption('exfiltration');
  await expect(page.getByLabel('Test topic')).toHaveValue('exfiltration');
  await expect(page.getByText(/Prepared: \[SYNTHETIC\] Unusual outbound data transfer/)).toBeVisible();
  await expect(page.getByLabel('Alert JSON')).toHaveValue(/\[SYNTHETIC\] Unusual outbound data transfer/);
  await page.getByRole('button', { name: 'Submit alert', exact: true }).click();
  await expect.poll(() => submitted.length).toBe(2);
  expect(submitted[1].rule.description).toBe('[SYNTHETIC] Unusual outbound data transfer');
  expect(submitted[1].rule.mitre.id).toBe('T1041');
  expect(submitted[1].id).not.toBe(submitted[0].id);

  await page.getByRole('button', { name: 'QA walkthroughs' }).click();
  const qaNavigation = page.getByRole('navigation', { name: 'Main navigation' });
  await expect(qaNavigation.getByRole('button').first()).toHaveText(/QA walkthroughs/);
  await expect(page.getByRole('heading', { name: 'Test walkthroughs' })).toBeVisible();
  await expect(page.getByRole('heading', { name: '5. Connector checks' })).toBeVisible();
  await page.getByRole('link', { name: 'Open Incidents' }).click();
  await expect(page.getByRole('heading', { name: 'Incidents Command Center' })).toBeVisible();
});
