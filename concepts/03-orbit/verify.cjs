const { chromium } = require('../../web/node_modules/@playwright/test');
const path = require('path');
(async () => {
  const browser = await chromium.launch({ headless: true });
  const errors = [];
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  page.on('pageerror', e => errors.push(e.message));
  await page.goto('file://' + path.resolve(__dirname, 'index.html').replaceAll('\\', '/'));
  await page.screenshot({ path: path.resolve(__dirname, 'preview.png'), fullPage: true });
  for (const id of ['overview','incidents','reports','agents','workflows','integrations','organization','settings']) {
    await page.locator(`.navbtn[data-nav="${id}"]`).click();
    if (!(await page.locator(`#${id}`).evaluate(e => e.classList.contains('active')))) throw new Error(`Nav failed: ${id}`);
  }
  await page.locator('.navbtn[data-nav="overview"]').click();
  await page.locator('#alertSearch').fill('PowerShell');
  if ((await page.locator('.alert-row').count()) !== 1) throw new Error('Search failed');
  await page.locator('#alertSearch').fill('');
  await page.locator('#severityFilter').selectOption('critical');
  if ((await page.locator('.alert-row').count()) !== 2) throw new Error('Severity filter failed');
  await page.locator('#severityFilter').selectOption('all');
  await page.locator('[data-alert="INC-1041"]').click();
  if (!(await page.locator('#dTitle').textContent()).includes('PowerShell')) throw new Error('Selection failed');
  await page.locator('[data-dtab="raw"]').click();
  if (!(await page.locator('pre.raw').textContent()).includes('92057')) throw new Error('Raw tab failed');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.locator('#menu').click();
  await page.locator('.navbtn[data-nav="settings"]').click();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (overflow > 1) throw new Error(`Mobile overflow: ${overflow}`);
  if (errors.length) throw new Error(`Page errors: ${errors.join(' | ')}`);
  console.log('PASS: eight navigation sections, search, severity filter, selected dossier, raw tab, mobile nav, no mobile overflow, no page errors.');
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
