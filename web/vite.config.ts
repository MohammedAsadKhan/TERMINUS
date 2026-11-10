// File: vite.config.ts
// Author: Team LARP
// Date: 2026-11-09
// Version: 0.1.0
// Purpose: Build the console into FastAPI static assets and proxy API requests during development.

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/console/',
  build: {
    outDir: '../src/terminus/server/static/console',
    emptyOutDir: true,
    rollupOptions: { output: { manualChunks: (id: string) => id.includes('@xyflow') ? 'flow' : undefined } },
  },
  server: {
    proxy: Object.fromEntries(
      ['/auth', '/orgs', '/incidents', '/agents', '/assets', '/workflows', '/reports', '/settings', '/wazuh', '/system', '/metrics', '/health', '/copilot', '/stream']
        .map(path => [path, {
          target: 'http://127.0.0.1:8000',
          changeOrigin: true,
          // Local development uses a separate frontend origin. Keep forwarded
          // writes same-origin with the backend's browser security check.
          headers: { origin: 'http://127.0.0.1:8000' },
        }]),
    ),
  },
});
