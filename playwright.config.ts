import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 12_000 },
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:5173',
    browserName: 'chromium',
    ...(process.platform === 'win32' ? { channel: 'msedge' } : {}),
    screenshot: 'only-on-failure'
  },
  webServer: [
    {
      command: 'npx tsx server/index.ts',
      url: 'http://127.0.0.1:3001/api/health',
      env: { DATA_DIR: '.data/e2e', APP_ORIGIN: 'http://localhost:5173', NODE_ENV: 'test', PORT: '3001' },
      reuseExistingServer: false,
      timeout: 60_000
    },
    {
      command: 'npx vite --host 127.0.0.1',
      url: 'http://localhost:5173',
      reuseExistingServer: false,
      timeout: 60_000
    }
  ]
});
