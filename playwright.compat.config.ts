import { defineConfig } from '@playwright/test';
import { localTestConfig } from './playwright.config.js';
const base = localTestConfig(3004, 5175);
export default defineConfig({ ...base, outputDir: 'test-results/compat', testIgnore: [], testMatch: ['compatibility.spec.ts', 'credential.spec.ts'],
  projects: ['chromium', 'firefox', 'webkit'].map(name => ({ name, use: { browserName: name as 'chromium' | 'firefox' | 'webkit' } })),
});
