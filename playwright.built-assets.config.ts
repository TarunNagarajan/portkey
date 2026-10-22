import { defineConfig } from '@playwright/test';

export default defineConfig({
  metadata: { builtAssets: true },
  testDir: './e2e',
  testMatch: /(?:workshop-proof-admission|reusable-credential-admission)\.spec\.ts$/,
  workers: 1,
  timeout: 180_000,
  expect: { timeout: 12_000 },
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:5175',
    browserName: 'chromium',
    ...(process.platform === 'win32' ? { channel: 'msedge' } : {}),
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'npx tsx scripts/built-assets-smoke-server.ts',
    url: 'http://127.0.0.1:5175/api/health',
    env: { PORTKEY_BUILT_ASSETS_PORT: '5175' },
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
