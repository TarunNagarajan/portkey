import { defineConfig } from '@playwright/test';
import { localTestConfig } from './playwright.config.js';
const base = localTestConfig(3005, 5176);
export default defineConfig({ ...base, outputDir: 'test-results/large', testIgnore: [], testMatch: 'large-file.spec.ts', timeout: 900_000 });
