import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    ...(process.env.TERMINUS_PLAYWRIGHT_CHANNEL
      ? { channel: process.env.TERMINUS_PLAYWRIGHT_CHANNEL }
      : {}),
  },
  webServer: {
    command: 'npm run dev -- --port 4173 --strictPort',
    url: 'http://127.0.0.1:4173/console/',
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
