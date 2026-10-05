import { expect, test, type Page, type Route } from '@playwright/test';
import { spawn, type ChildProcess } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const port = 4187;
const origin = `http://127.0.0.1:${port}`;
let server: ChildProcess;

const browserChannel = process.env.TERMINUS_PLAYWRIGHT_CHANNEL;
test.use(browserChannel ? { channel: browserChannel } : {});

const originalConnection = {
  org_id: 'org-alpha',
  connection_id: 'conn-1',
  name: 'Primary OpenAI',
  provider: 'openai',
  base_url: 'https://api.openai.com/v1',
  models: ['openai/gpt-4.1', 'gpt-4o-mini'],
  enabled: true,
  credential_configured: true,
  credential_mask: '********',
  version: 2,
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-01T00:00:00Z',
  verification_status: 'unverified',
};

async function waitForServer() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(origin);
      if (response.ok) return;
    } catch { /* server is still starting */ }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  throw new Error('Vite did not start');
}

test.beforeAll(async () => {
  const webRoot = fileURLToPath(new URL('..', import.meta.url));
  server = spawn(process.execPath, ['node_modules/vite/bin/vite.js', '--host', '127.0.0.1', '--port', String(port), '--strictPort'], {
    cwd: webRoot,
    stdio: 'ignore',
  });
  await waitForServer();
});

test.afterAll(() => server?.kill());

async function fulfill(route: Route, json: unknown, status = 200) {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(json) });
}

async function mockConsole(page: Page, role: 'admin' | 'viewer', handler?: (route: Route, pathname: string) => Promise<boolean>) {
  await page.route(`${origin}/**`, async route => {
    const request = route.request();
    const url = new URL(request.url());
    const pathname = url.pathname;
    if (handler && await handler(route, pathname)) return;
    if (pathname === '/auth/me') return fulfill(route, { user_id: 'user-1', email: 'analyst@example.test', display_name: 'Morgan Lee', created_at: '2026-01-01T00:00:00Z' });
    if (pathname === '/orgs') return fulfill(route, [{ org_id: 'org-alpha', name: 'Alpha SOC', created_at: '2026-01-01T00:00:00Z' }]);
    if (pathname === '/orgs/current') return fulfill(route, { organization: { org_id: 'org-alpha', name: 'Alpha SOC', created_at: '2026-01-01T00:00:00Z' }, role, members: [], license: null, license_error: null });
    if (pathname === '/system') return fulfill(route, { version: 'test', storage: 'sqlite', transport: 'local', llm_mode: 'configured', llm_model: '', live_response: false, workflow_execution: false, integrations: [] });
    if (pathname === '/assets') return fulfill(route, []);
    if (pathname === '/incidents') return fulfill(route, []);
    if (pathname === '/agents/actions') return fulfill(route, []);
    if (pathname === '/investigation/graph/network') return fulfill(route, { total_events: 0, shown_events: 0, events: [] });
    if (pathname === '/settings/config') return fulfill(route, { llm: {}, siem: {}, cti: {}, ticketing: {}, containment: {} });
    if (pathname === '/model-settings/status') return fulfill(route, { credential_storage_ready: true, registered_connections: 1, live_validation: 'not established by configuration', setup_required: [] });
    if (pathname === '/model-connections') return fulfill(route, [originalConnection]);
    if (pathname === '/model-settings/policy') return fulfill(route, { detail: 'Model settings record not found' }, 404);
    if (pathname.includes('/model-settings/budget/')) return fulfill(route, { detail: 'Model settings record not found' }, 404);
    if (pathname.includes('/model-settings/usage/')) return fulfill(route, { org_id: 'org-alpha', window_key: '2026-10-04', limit_micro_usd: null, limit_tokens: null, known_cost_micro_usd: 0, unknown_cost_count: 1, ambiguous_exposure_micro_usd: 250000, reserved_exposure_micro_usd: 0, exposure_micro_usd: 250000, remaining_micro_usd: null, over_limit: false });
    if (pathname.startsWith('/model-settings/prices/')) return fulfill(route, { detail: 'Model settings record not found' }, 404);
    if (request.resourceType() === 'document' || pathname.startsWith('/src/') || pathname.startsWith('/@') || pathname.startsWith('/node_modules/') || pathname.startsWith('/console/src/') || pathname.startsWith('/console/@') || pathname.startsWith('/console/node_modules/') || pathname === '/favicon.ico') return route.continue();
    return fulfill(route, { detail: `Unexpected test request: ${request.method()} ${pathname}` }, 500);
  });
  await page.goto(`${origin}/console/settings`);
  await expect(page.getByTestId('model-settings')).toBeVisible();
}

test('creates a write-only credential, preserves it on blank edit, and clears it only with explicit null', async ({ page }) => {
  let connections: Array<Record<string, unknown>> = [{ ...originalConnection }];
  const posts: Record<string, unknown>[] = [];
  const patches: Record<string, unknown>[] = [];
  await mockConsole(page, 'admin', async (route, pathname) => {
    const request = route.request();
    if (pathname === '/model-connections' && request.method() === 'GET') {
      await fulfill(route, connections);
      return true;
    }
    if (pathname === '/model-connections' && request.method() === 'POST') {
      const payload = request.postDataJSON() as Record<string, unknown>;
      posts.push(payload);
      const created = { ...originalConnection, connection_id: 'conn-2', name: payload.name, models: payload.models, version: 1, credential_configured: true, enabled: payload.enabled };
      connections = [...connections, created];
      await fulfill(route, created, 201);
      return true;
    }
    if (pathname === '/model-connections/conn-2' && request.method() === 'PATCH') {
      const payload = request.postDataJSON() as Record<string, unknown>;
      patches.push(payload);
      const current = connections.find(item => item.connection_id === 'conn-2')!;
      const updated = { ...current, ...payload, credential_configured: payload.api_key === null ? false : true, credential_mask: payload.api_key === null ? null : '********', version: Number(current.version) + 1 };
      delete updated.api_key;
      delete updated.expected_version;
      connections = connections.map(item => item.connection_id === 'conn-2' ? updated : item);
      await fulfill(route, updated);
      return true;
    }
    return false;
  });

  await page.getByRole('button', { name: 'Add connection' }).click();
  const modal = page.locator('.ant-modal');
  await modal.getByLabel('Connection name').fill('Incident reasoning');
  await modal.getByLabel('Registered model IDs').fill('gpt-4.1-mini');
  await modal.getByLabel('Registered model IDs').press('Enter');
  await modal.getByLabel('Credential action').click();
  await page.getByText('Replace credential', { exact: true }).last().click();
  await modal.getByLabel('API key').fill('sk-test-secret-value');
  await modal.getByLabel('Connection enabled').click();
  await modal.getByRole('button', { name: 'Add connection', exact: true }).click();
  await expect(page.getByText('Incident reasoning')).toBeVisible();
  expect(posts[0]).toMatchObject({ name: 'Incident reasoning', api_key: 'sk-test-secret-value', enabled: true, models: ['gpt-4.1-mini'] });
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain('sk-test-secret-value');
  await expect(page.getByText('sk-test-secret-value')).toHaveCount(0);

  await page.getByRole('button', { name: 'Edit Incident reasoning' }).click();
  await modal.getByRole('button', { name: 'Save connection' }).click();
  await expect(modal).toBeHidden();
  expect(patches[0]).toMatchObject({ expected_version: 1, name: 'Incident reasoning' });
  expect(patches[0]).not.toHaveProperty('api_key');

  await page.getByRole('button', { name: 'Edit Incident reasoning' }).click();
  await modal.getByLabel('Credential action').click();
  await page.getByText('Clear credential', { exact: true }).last().click();
  await expect(modal.getByText('The stored credential will be removed')).toBeVisible();
  await modal.getByRole('button', { name: 'Save connection' }).click();
  await expect(modal).toBeHidden();
  expect(patches[1]).toMatchObject({ expected_version: 2, api_key: null });
});

test('uses current connection and record versions for policy, budget, and explicit manual rates', async ({ page }) => {
  const writes: Array<{ path: string; payload: Record<string, unknown> }> = [];
  await mockConsole(page, 'admin', async (route, pathname) => {
    const request = route.request();
    if (pathname === '/model-settings/policy' && request.method() === 'GET') {
      await fulfill(route, { org_id: 'org-alpha', version: 3, enabled: true, grants: [{ role: 'triage', area: null, connection_id: 'conn-1', connection_version: 1, models: ['openai/gpt-4.1'], classifications: ['redacted_cloud'] }] });
      return true;
    }
    if (pathname === '/model-settings/policy' && request.method() === 'PUT') {
      const payload = request.postDataJSON() as Record<string, unknown>;
      writes.push({ path: pathname, payload });
      await fulfill(route, { org_id: 'org-alpha', version: 4, ...payload, grants: payload.grants });
      return true;
    }
    if (pathname.includes('/model-settings/budget/') && request.method() === 'PUT') {
      const payload = request.postDataJSON() as Record<string, unknown>;
      writes.push({ path: pathname, payload });
      await fulfill(route, { window_key: pathname.split('/').at(-1), version: 1, limit_micro_usd: payload.limit_micro_usd, limit_tokens: payload.limit_tokens });
      return true;
    }
    if (pathname.startsWith('/model-settings/prices/') && request.method() === 'PUT') {
      const payload = request.postDataJSON() as Record<string, unknown>;
      writes.push({ path: pathname, payload });
      await fulfill(route, { org_id: 'org-alpha', connection_id: 'conn-1', model: 'openai/gpt-4.1', version: 1, ...payload });
      return true;
    }
    return false;
  });

  await expect(page.getByText('Policy v1 · current v2 (will update on save)')).toBeVisible();
  await page.getByRole('button', { name: 'Save policy' }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0].payload).toMatchObject({ expected_version: 3, enabled: true });
  expect((writes[0].payload.grants as Array<Record<string, unknown>>)[0]).toMatchObject({ connection_id: 'conn-1', connection_version: 2, models: ['openai/gpt-4.1'], classifications: ['redacted_cloud'] });

  await page.getByLabel('Daily limit in micro-USD').fill('12500000');
  await page.getByLabel('Daily token limit').fill('900000');
  await page.getByRole('button', { name: 'Save budget' }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect(writes[1].payload).toEqual({ expected_version: 0, limit_micro_usd: 12500000, limit_tokens: 900000 });

  await page.getByLabel('Price connection').click();
  await page.getByText('Primary OpenAI', { exact: true }).last().click();
  await page.getByLabel('Price model').click();
  await page.getByText('openai/gpt-4.1', { exact: true }).last().click();
  await expect(page.getByText('No manual rate is configured')).toBeVisible();
  await page.getByLabel('Input rate per million tokens in micro-USD', { exact: true }).fill('1750000');
  await page.getByLabel('Output rate per million tokens in micro-USD', { exact: true }).fill('7200000');
  await page.getByRole('button', { name: 'Save rate' }).click();
  await expect.poll(() => writes.length).toBe(3);
  expect(writes[2].payload).toEqual({ expected_version: 0, input_per_mtok_micro_usd: 1750000, output_per_mtok_micro_usd: 7200000, cached_input_per_mtok_micro_usd: null, reasoning_per_mtok_micro_usd: null });
  await expect(page.getByText(/not verified provider invoice charges/i)).toBeVisible();
  await expect(page.getByText(/Unknown cost is reported separately and is not treated as zero/i)).toBeVisible();
});

test('keeps the gateway readable and all mutations disabled for viewers', async ({ page }) => {
  const mutationRequests: string[] = [];
  await mockConsole(page, 'viewer', async (route, pathname) => {
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(route.request().method())) mutationRequests.push(`${route.request().method()} ${pathname}`);
    return false;
  });

  await expect(page.getByText('Read-only access')).toBeVisible();
  await expect(page.getByText('Primary OpenAI')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Add connection' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Save policy' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Save budget' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Edit Primary OpenAI' })).toBeDisabled();
  expect(mutationRequests).toEqual([]);
});

test('discards an unsaved tenant draft when the organization changes', async ({ page }) => {
  const writes: Array<{ tenant: string | undefined; payload: unknown }> = [];
  await page.route(`${origin}/**`, async route => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    const tenant = request.headers()['x-org-id'];
    if (pathname === '/auth/me') return fulfill(route, { user_id: 'user-1', email: 'analyst@example.test', display_name: 'Morgan Lee', created_at: '2026-01-01T00:00:00Z' });
    if (pathname === '/orgs') return fulfill(route, [
      { org_id: 'org-alpha', name: 'Alpha SOC', created_at: '2026-01-01T00:00:00Z' },
      { org_id: 'org-beta', name: 'Beta SOC', created_at: '2026-01-02T00:00:00Z' },
    ]);
    if (pathname === '/orgs/current') return fulfill(route, { organization: { org_id: tenant, name: tenant === 'org-beta' ? 'Beta SOC' : 'Alpha SOC', created_at: '2026-01-01T00:00:00Z' }, role: 'admin', members: [], license: null, license_error: null });
    if (pathname === '/system') return fulfill(route, { version: 'test', storage: 'sqlite', transport: 'local', llm_mode: 'configured', llm_model: '', live_response: false, workflow_execution: false, integrations: [] });
    if (pathname === '/assets') return fulfill(route, []);
    if (pathname === '/incidents') return fulfill(route, []);
    if (pathname === '/agents/actions') return fulfill(route, []);
    if (pathname === '/investigation/graph/network') return fulfill(route, { total_events: 0, shown_events: 0, events: [] });
    if (pathname === '/settings/config') return fulfill(route, { llm: {}, siem: {}, cti: {}, ticketing: {}, containment: {} });
    if (pathname === '/model-settings/status') return fulfill(route, { credential_storage_ready: true, registered_connections: tenant === 'org-alpha' ? 1 : 0, live_validation: 'not established by configuration', setup_required: [] });
    if (pathname === '/model-connections') return fulfill(route, tenant === 'org-alpha' ? [originalConnection] : []);
    if (pathname === '/model-settings/policy') return fulfill(route, { detail: 'Model settings record not found' }, 404);
    if (pathname.includes('/model-settings/budget/')) {
      if (request.method() === 'PUT') {
        writes.push({ tenant, payload: request.postDataJSON() });
        return fulfill(route, { detail: 'Unexpected write' }, 500);
      }
      return tenant === 'org-alpha'
        ? fulfill(route, { window_key: '2026-10-04', limit_micro_usd: 1000000, limit_tokens: null, version: 1 })
        : fulfill(route, { detail: 'Model settings record not found' }, 404);
    }
    if (pathname.includes('/model-settings/usage/')) return fulfill(route, { org_id: tenant, window_key: '2026-10-04', limit_micro_usd: tenant === 'org-alpha' ? 1000000 : null, limit_tokens: null, known_cost_micro_usd: 0, unknown_cost_count: 0, ambiguous_exposure_micro_usd: 0, reserved_exposure_micro_usd: 0, exposure_micro_usd: 0, remaining_micro_usd: tenant === 'org-alpha' ? 1000000 : null, over_limit: false });
    if (request.resourceType() === 'document' || pathname.startsWith('/src/') || pathname.startsWith('/@') || pathname.startsWith('/node_modules/') || pathname.startsWith('/console/src/') || pathname.startsWith('/console/@') || pathname.startsWith('/console/node_modules/') || pathname === '/favicon.ico') return route.continue();
    return fulfill(route, []);
  });

  await page.goto(`${origin}/console/settings`);
  await expect(page.getByLabel('Daily limit in micro-USD')).toHaveValue('1000000');
  await page.getByLabel('Daily limit in micro-USD').fill('7777777');
  await page.getByRole('button', { name: 'Account and organization menu' }).click();
  const betaOrganization = page.getByRole('menuitem', { name: 'Beta SOC' });
  await expect(betaOrganization).toBeVisible();
  await betaOrganization.click();
  await expect(page.locator('.sidebar-workspace strong')).toHaveText('Beta SOC');
  const settingsNavigation = page.locator('.console-sidebar button.nav-item').filter({ hasText: /^Settings$/ });
  await expect(settingsNavigation).toBeVisible();
  await settingsNavigation.click();

  await expect(page).toHaveURL(`${origin}/console/settings`);
  await expect(page.getByLabel('Daily limit in micro-USD')).toHaveValue('');
  await expect(page.getByRole('button', { name: 'Save budget' })).toBeDisabled();
  expect(writes).toEqual([]);
});
