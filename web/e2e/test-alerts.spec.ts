// File: test-alerts.spec.ts
// Author: Team LARP
// Date: 2026-11-12
// Version: 0.1.0
// Purpose: Exercise the discoverable synthetic alert tool in the current Settings workspace.

import { expect, test, type Route } from '@playwright/test';

const browserChannel = process.env.TERMINUS_PLAYWRIGHT_CHANNEL;
test.use(browserChannel ? { channel: browserChannel } : {});

function json(route: Route, value: unknown) {
  return route.fulfill({ contentType: 'application/json', body: JSON.stringify(value) });
}

test('submits a random synthetic alert or a selected topic from Settings with distinct evidence', async ({ page }) => {
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
    if (path === '/settings/config') return json(route, {
      llm: { base_url: '', model: 'openai/gpt-oss-20b', has_api_key: false, api_key_masked: '', temperature: 0.2, max_tokens: 4096, enable_react_forensics: true, enable_deobfuscation: true, enable_cti_lookup: true },
      siem: { wazuh_url: '', wazuh_user: '', has_wazuh_password: false, polling_interval_sec: 30 },
      cti: { has_virustotal_key: false, virustotal_key_masked: '', has_abuseipdb_key: false, abuseipdb_key_masked: '', has_otx_key: false, otx_key_masked: '', cache_ttl_hours: 24 },
      ticketing: { jira_url: '', jira_user: '', jira_project: 'SEC', has_jira_token: false, jira_token_masked: '', slack_webhook_configured: false, slack_webhook_masked: '', sms_to: '', twilio_configured: false },
      containment: { mode: 'human_in_the_loop', protected_subnets: '', policy_ignore_threshold: 5, policy_triage_threshold: 9, policy_escalate_threshold: 10 },
    });
    if (path === '/model-settings/status') return json(route, { credential_storage_ready: true, registered_connections: 0, live_validation: 'not_established', setup_required: [] });
    if (path === '/model-connections') return json(route, []);
    if (path === '/model-settings/policy') return json(route, null);
    if (path.startsWith('/model-settings/budget/')) return json(route, null);
    if (path.startsWith('/model-settings/usage/')) return json(route, { window_key: 'test', limit_micro_usd: null, limit_tokens: null, known_cost_micro_usd: 0, unknown_cost_count: 0, ambiguous_exposure_micro_usd: 0, reserved_exposure_micro_usd: 0, exposure_micro_usd: 0, remaining_micro_usd: null, over_limit: false });
    if (path === '/wazuh' && request.method() === 'POST') {
      submitted.push(request.postDataJSON());
      return json(route, { status: 'accepted' });
    }
    return route.continue();
  });

  await page.goto('/console/settings');
  await expect(page.getByRole('heading', { name: 'Platform Configuration & API Keys' })).toBeVisible();
  await page.getByRole('tab', { name: /SIEM & Ingestion/ }).click();

  await page.getByRole('button', { name: 'Synthetic test alert' }).click();
  const dialog = page.getByRole('dialog', { name: 'Submit a test alert' });
  await expect(dialog).toBeVisible();
  await expect(dialog.getByText(/These examples are synthetic and use documentation IP addresses/)).toBeVisible();
  await page.getByLabel('Test topic').selectOption('random');
  await page.getByRole('button', { name: 'Submit alert', exact: true }).click();
  await expect.poll(() => submitted.length).toBe(1);
  expect(submitted[0].rule.description).toMatch(/^\[SYNTHETIC\]/);
  expect(submitted[0].full_log).toMatch(/^SYNTHETIC TEST EVENT:/);
  expect(submitted[0].data.srcip).toMatch(/^198\.51\.100\./);

  await expect(dialog).toBeHidden();
  await page.getByRole('button', { name: 'Synthetic test alert' }).click();
  await page.getByLabel('Test topic').selectOption('exfiltration');
  await expect(page.getByLabel('Test topic')).toHaveValue('exfiltration');
  await expect(page.getByText(/Prepared: \[SYNTHETIC\] Unusual outbound data transfer/)).toBeVisible();
  await expect(page.getByLabel('Alert JSON')).toHaveValue(/\[SYNTHETIC\] Unusual outbound data transfer/);
  await page.getByRole('button', { name: 'Submit alert', exact: true }).click();
  await expect.poll(() => submitted.length).toBe(2);
  expect(submitted[1].rule.description).toBe('[SYNTHETIC] Unusual outbound data transfer');
  expect(submitted[1].rule.mitre.id).toBe('T1041');
  expect(submitted[1].data.srcip).toMatch(/^198\.51\.100\./);
  expect(submitted[1].id).not.toBe(submitted[0].id);
});
