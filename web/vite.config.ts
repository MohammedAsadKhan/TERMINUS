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
      ['/auth', '/orgs', '/incidents', '/agents', '/workflows', '/reports', '/wazuh', '/system', '/metrics', '/health']
        .map(path => [path, 'http://127.0.0.1:8000']),
    ),
  },
});
