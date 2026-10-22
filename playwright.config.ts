import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  testIgnore: /verification-platform-(demo|vite)\.spec\.ts$/,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 12_000 },
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:5174',
    browserName: 'chromium',
    ...(process.platform === 'win32' ? { channel: 'msedge' } : {}),
    screenshot: 'only-on-failure',
  },
  webServer: [
    {
      command: 'npx tsx server/index.ts',
      url: 'http://127.0.0.1:3002/api/health',
      env: {
        PORTKEY_LOAD_DOTENV: 'false',
        DATABASE_URL: '',
        DATA_DIR: process.env.PORTKEY_E2E_DATA_DIR || '.data/e2e-private-inbox',
        APP_ORIGIN: 'http://localhost:5174',
        HOST: '127.0.0.1',
        TRUST_PROXY_HOPS: '0',
        NODE_ENV: 'test',
        PORT: '3002',
      },
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: 'npx vite --force --host 127.0.0.1 --port 5174',
      url: 'http://localhost:5174',
      env: { API_ORIGIN: 'http://127.0.0.1:3002' },
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});
