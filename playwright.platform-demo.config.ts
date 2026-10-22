import { defineConfig } from '@playwright/test';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

const dataDirectory = resolve(tmpdir(), `portkey-platform-demo-${randomUUID()}`);
process.env.PORTKEY_PLATFORM_DEMO_DATA_DIR = dataDirectory;

export default defineConfig({
  metadata: { builtAssets: true, isolatedDemoData: dataDirectory },
  testDir: './e2e',
  testMatch: /verification-platform-demo\.spec\.ts$/,
  workers: 1,
  timeout: 240_000,
  expect: { timeout: 20_000 },
  reporter: 'list',
  use: {
    browserName: 'chromium',
    ...(process.platform === 'win32' ? { channel: 'msedge' } : {}),
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'npx tsx scripts/platform-demo.ts',
    url: 'http://127.0.0.1:5300/platform-demo/ready',
    env: { PORTKEY_PLATFORM_DEMO_DATA_DIR: dataDirectory },
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
