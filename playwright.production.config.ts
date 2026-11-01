import { defineConfig } from '@playwright/test';
export default defineConfig({ outputDir: 'test-results/production', testDir: './e2e', testMatch: ['credential.spec.ts', 'key-lifecycle.spec.ts'], workers: 1, timeout: 240_000,
  expect: { timeout: 12_000 }, use: { baseURL: 'https://localhost:5443', ignoreHTTPSErrors: true, browserName: 'chromium' },
  webServer: { command: 'node scripts/productionProxy.mjs', url: 'https://localhost:5443/api/health', ignoreHTTPSErrors: true, timeout: 60_000 },
});
