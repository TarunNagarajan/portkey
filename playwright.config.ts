import { defineConfig } from '@playwright/test';
export function localTestConfig(apiPort = 3002, webPort = 5174) {
  const origin = `http://localhost:${webPort}`;
  return defineConfig({
    outputDir: 'test-results/e2e',
    testDir: './e2e', testIgnore: ['**/large-file.spec.ts', '**/compatibility.spec.ts'],
    workers: 1, timeout: 60_000, expect: { timeout: 12_000 }, reporter: 'list',
    use: { baseURL: origin, browserName: 'chromium', screenshot: 'only-on-failure',
      ...(process.platform === 'win32' ? { channel: 'msedge' } : {}) },
    webServer: [{ command: 'npx tsx server/index.ts', url: `http://127.0.0.1:${apiPort}/api/health`,
      env: { DATA_DIR: `.data/e2e-${process.pid}-${Date.now()}`, APP_ORIGIN: origin, NODE_ENV: 'test', PORT: String(apiPort) },
      reuseExistingServer: false, timeout: 60_000,
    }, { command: `npx vite --host 127.0.0.1 --port ${webPort}`, url: origin,
      env: { API_ORIGIN: `http://127.0.0.1:${apiPort}` }, reuseExistingServer: false, timeout: 60_000 }],
  });
}
export default localTestConfig();
