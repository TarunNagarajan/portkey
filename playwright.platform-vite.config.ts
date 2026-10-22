import { defineConfig } from "@playwright/test";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";

const dataDirectory = resolve(
  tmpdir(),
  `portkey-platform-vite-${randomUUID()}`,
);

export default defineConfig({
  metadata: { isolatedPlatformViteData: dataDirectory },
  testDir: "./e2e",
  testMatch: /verification-platform-vite\.spec\.ts$/,
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  reporter: "list",
  use: {
    baseURL: "http://localhost:5175",
    browserName: "chromium",
    ...(process.platform === "win32" ? { channel: "msedge" } : {}),
    screenshot: "only-on-failure",
  },
  webServer: [
    {
      command: "npx tsx server/index.ts",
      url: "http://127.0.0.1:3003/api/health",
      env: {
        PORTKEY_LOAD_DOTENV: "false",
        DATABASE_URL: "",
        DATA_DIR: dataDirectory,
        APP_ORIGIN: "http://localhost:5175",
        HOST: "127.0.0.1",
        TRUST_PROXY_HOPS: "0",
        NODE_ENV: "test",
        PORT: "3003",
      },
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: "npx vite --force --host 127.0.0.1 --port 5175",
      url: "http://localhost:5175",
      env: { API_ORIGIN: "http://127.0.0.1:3003" },
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});
