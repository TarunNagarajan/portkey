import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import express from "express";
import { chromium, expect } from "@playwright/test";
import { resolve } from "node:path";
import { createServer, type Server } from "node:http";
import { openDatabase } from "../server/database.js";
import { migrate } from "../server/migrations.js";
import { createApp } from "../server/app.js";

const walletOrigin = "http://localhost:5300";
const appOrigin = "http://localhost:5310";
const databaseUrl = process.env.PORTKEY_SDK_EXAMPLE_DATABASE_URL;
assert.ok(
  databaseUrl,
  "PORTKEY_SDK_EXAMPLE_DATABASE_URL must name a disposable PostgreSQL database.",
);
assert.match(
  databaseUrl,
  /^postgres:\/\/[^@/]+@(?:127\.0\.0\.1|localhost):\d+\/[^/?]+$/,
  "SDK example acceptance is limited to a local PostgreSQL database.",
);
assert.match(
  new URL(databaseUrl).pathname.slice(1),
  /(?:test|sdk)/i,
  "SDK example database name must contain test or sdk.",
);

const root = process.cwd();
const example = resolve(root, "examples/relying-party");
const artifacts = resolve(root, "dist/client");
const db = await openDatabase();
let wallet: Server | undefined;
let relyingParty: ChildProcess | undefined;
let browser: Awaited<ReturnType<typeof chromium.launch>> | undefined;
let pgPool: import("pg").Pool | undefined;
const acceptanceSchema = `sdk_acceptance_${randomUUID().replaceAll("-", "")}`;
let acceptanceSchemaCreated = false;
let callbackPayload: { code?: string; state?: string } | undefined;
let sawBrowserHelper = false;
let cleaned = false;

const closeServer = (server?: Server) =>
  server
    ? new Promise<void>((resolveClose) => server.close(() => resolveClose()))
    : Promise.resolve();
const stopChild = async (child?: ChildProcess) => {
  if (!child || child.exitCode !== null) return;
  child.kill("SIGTERM");
  await new Promise<void>((resolveExit) => {
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      resolveExit();
    }, 5_000);
    child.once("exit", () => { clearTimeout(timeout); resolveExit(); });
  });
};
async function cleanup() {
  if (cleaned) return;
  cleaned = true;
  await browser?.close().catch(() => undefined);
  await stopChild(relyingParty);
  await closeServer(wallet);
  await db.close().catch(() => undefined);
  if (pgPool) {
    if (acceptanceSchemaCreated)
      await pgPool
        .query(`DROP SCHEMA IF EXISTS "${acceptanceSchema}" CASCADE`)
        .catch(() => undefined);
    await pgPool.end().catch(() => undefined);
  }
  const curve = (
    globalThis as typeof globalThis & {
      curve_bn128?: { terminate: () => Promise<void> };
    }
  ).curve_bn128;
  if (curve) await curve.terminate().catch(() => undefined);
}
process.once("SIGINT", () => {
  void cleanup().finally(() => {
    process.exitCode = 130;
  });
});
process.once("SIGTERM", () => {
  void cleanup().finally(() => {
    process.exitCode = 143;
  });
});

async function postWallet<T extends object>(
  path: string,
  cookie: string,
  csrf: string,
  body: unknown = {},
  method = "POST",
): Promise<T> {
  const response = await fetch(`${walletOrigin}/api${path}`, {
    method,
    headers: {
      Origin: walletOrigin,
      Cookie: cookie,
      "X-CSRF-Token": csrf,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  const value = (await response.json().catch(() => null)) as
    | (T & { error?: { message?: string } })
    | null;
  assert.ok(
    response.ok,
    value?.error?.message ??
      `Portkey setup endpoint failed with ${response.status}.`,
  );
  assert.ok(value && typeof value === "object");
  return value as T;
}

try {
  await migrate(db);
  const portkey = createApp(db, {
    origin: walletOrigin,
    secure: false,
    geocoding: false,
    rateLimiting: false,
  });
  const demoHost = express();
  demoHost.use(portkey);
  demoHost.use(express.static(artifacts, { index: false }));
  demoHost.get("/{*path}", (_req, res) =>
    res.sendFile(resolve(artifacts, "index.html")),
  );
  wallet = createServer(demoHost);
  await new Promise<void>((resolveListen, rejectListen) => {
    wallet!.once("error", rejectListen);
    wallet!.listen(5300, "127.0.0.1", resolveListen);
  });

  const sessionResponse = await fetch(`${walletOrigin}/api/session`, {
    method: "POST",
    headers: { Origin: walletOrigin },
    signal: AbortSignal.timeout(10_000),
  });
  assert.equal(sessionResponse.status, 200);
  const ownerCookie = (sessionResponse.headers.get("set-cookie") ?? "").split(";", 1)[0];
  const { csrfToken } = (await sessionResponse.json()) as {
    csrfToken: string;
  };
  assert.ok(ownerCookie && csrfToken);
  const group = await postWallet<{ id: string }>(
    "/credential-groups",
    ownerCookie,
    csrfToken,
    {
      name: "SDK acceptance members",
      description: "Temporary local acceptance group.",
    },
  );
  const invitations = await postWallet<{
    enrollments: Array<{ token: string }>;
  }>(
    `/credential-groups/${group.id}/enrollments`,
    ownerCookie,
    csrfToken,
    { count: 1 },
  );
  const contract = await postWallet<{
    id: string;
    digest: string;
  }>(
    "/platform/contracts",
    ownerCookie,
    csrfToken,
    {
      name: "SDK acceptance contract",
      issuerLabel: "Local acceptance issuer",
      description: "Temporary proof contract.",
      groupIds: [group.id],
    },
  );
  const registration = await postWallet<{
    id: string;
    apiKey: string;
  }>(
    "/platform/apps",
    ownerCookie,
    csrfToken,
    {
      name: "SDK relying party acceptance",
      origin: appOrigin,
      redirectUris: [`${appOrigin}/portkey/callback`],
    },
  );
  const challengeResult = await postWallet<{ challenge: string }>(
    `/platform/apps/${registration.id}/domain-challenge`,
    ownerCookie,
    csrfToken,
    {},
  );
  const sessionSecret = randomBytes(32).toString("base64url");
  pgPool = new (await import("pg")).Pool({ connectionString: databaseUrl, max: 3 });
  assert.match(acceptanceSchema, /^sdk_acceptance_[a-f0-9]{32}$/);
  await pgPool.query(`CREATE SCHEMA "${acceptanceSchema}"`);
  acceptanceSchemaCreated = true;

  relyingParty = spawn(
    process.execPath,
    ["--env-file-if-exists=.env", "src/server.js"],
    {
      cwd: example,
      env: {
        ...process.env,
        APP_ORIGIN: appOrigin,
        PORTKEY_ORIGIN: walletOrigin,
        PORTKEY_APP_ID: registration.id,
        PORTKEY_APP_KEY: registration.apiKey,
        PORTKEY_DOMAIN_CHALLENGE: challengeResult.challenge,
        PORTKEY_CONTRACT_ID: contract.id,
        PORTKEY_CONTRACT_VERSION: "1",
        PORTKEY_CONTRACT_DIGEST: contract.digest,
        DATABASE_URL: databaseUrl,
        DATABASE_SCHEMA: acceptanceSchema,
        SESSION_SECRET: sessionSecret,
        PORT: "5310",
        TRUST_PROXY_HOPS: "1",
      },
      stdio: ["ignore", "ignore", "pipe"],
    },
  );
  let startupLog = "";
  relyingParty.stderr?.on("data", (chunk: Buffer) => {
    startupLog = (startupLog + chunk.toString()).slice(-2_000);
  });
  const readyDeadline = Date.now() + 20_000;
  while (Date.now() < readyDeadline) {
    if (relyingParty.exitCode !== null) throw new Error(`Relying-party example exited during startup: ${startupLog}`);
    try {
      const response = await fetch(
        `${appOrigin}/.well-known/portkey-app.json`,
        { signal: AbortSignal.timeout(500) },
      );
      if (response.ok) break;
    } catch { /* waiting for the listener */ }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
  }
  const wellKnown = await fetch(`${appOrigin}/.well-known/portkey-app.json`);
  assert.equal(wellKnown.status, 200);
  assert.deepEqual(await wellKnown.json(), { appId: registration.id, challenge: challengeResult.challenge });
  await postWallet(
    `/platform/apps/${registration.id}/verify-domain`,
    ownerCookie,
    csrfToken,
    {},
  );
  await postWallet(
    `/platform/apps/${registration.id}/trust`,
    ownerCookie,
    csrfToken,
    { contracts: [{ contractId: contract.id, version: 1 }] },
    "PUT",
  );

  browser = await chromium.launch({
    headless: true,
    timeout: 30_000,
    ...(process.platform === "win32" ? { channel: "msedge" as const } : {}),
  });
  const context = await browser.newContext();
  const page = await context.newPage();
  page.setDefaultTimeout(90_000);
  page.setDefaultNavigationTimeout(30_000);
  let startHeaders:
    | { origin?: string; fetchSite?: string; resourceType?: string }
    | undefined;
  let startScriptLoaded = false;
  let startScriptText = "";
  const browserErrors: string[] = [];
  const consoleErrors: string[] = [];
  page.on("pageerror", (error) => browserErrors.push(error.name));
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  await page.addInitScript(() => {
    const replace = history.replaceState.bind(history);
    history.replaceState = (...args) => {
      const hadCallbackFragment = location.hash.includes("code=") || location.hash.includes("state=");
      const result = replace(...args);
      if (hadCallbackFragment && !location.hash)
        sessionStorage.setItem("sdk_callback_fragment_cleared", "yes");
      return result;
    };
  });
  page.on("request", (request) => {
    if (request.url() === `${appOrigin}/start`) {
      void request.allHeaders().then((headers) => {
        startHeaders = {
          origin: headers.origin,
          fetchSite: headers["sec-fetch-site"],
          resourceType: request.resourceType(),
        };
      });
    }
    if (request.url() === `${appOrigin}/portkey/callback` && request.method() === "POST") {
      try {
        callbackPayload = request.postDataJSON() as {
          code?: string;
          state?: string;
        };
      } catch {
        /* The browser assertion reports an invalid callback payload. */
      }
    }
  });
  page.on("response", async (response) => {
    if (response.url() === `${appOrigin}/start.js`) {
      startScriptLoaded = response.ok();
      startScriptText = await response.text().catch(() => "");
    }
    if (response.url() === `${appOrigin}/callback-helper.js`)
      sawBrowserHelper = response.ok();
  });
  await page.goto(`${walletOrigin}/credentials/${group.id}#enroll=${invitations.enrollments[0].token}`);
  await page.getByRole("button", { name: "Save credential in this browser" }).click();
  await expect(page.getByText("Credential saved and enrolled in this browser.")).toBeVisible();

  await page.goto(appOrigin);
  await page.getByRole("button", { name: "Continue with Portkey" }).click();
  try {
    await expect(page).toHaveURL(
      new RegExp(`^${walletOrigin.replaceAll(".", "\\.")}\\/prove\\/`),
      { timeout: 10_000 },
    );
  } catch {
    const message = await page.locator("body").innerText();
    throw new Error(
      `Relying-party start failed (script=${startScriptLoaded}, source=${startScriptText.slice(0, 120)}, headers=${JSON.stringify(startHeaders)}, browserErrors=${browserErrors.join(",")}, consoleErrors=${consoleErrors.join(" | ")}): ${message}`,
    );
  }
  await page.getByRole("button", { name: "Prove membership and continue" }).click();
  await expect(
    page.getByText("Your membership was verified.", { exact: false }),
  ).toBeVisible({ timeout: 90_000 });
  await page.getByRole("button", { name: "Return to application" }).click();
  await expect(page.getByRole("heading", { name: "Eligibility confirmed" })).toBeVisible({ timeout: 20_000 });
  assert.ok(
    sawBrowserHelper,
    "The browser must load the packaged callback helper from the same-origin route.",
  );
  assert.ok(
    callbackPayload?.code && callbackPayload.state,
    "The browser callback must post one-use code and state to the relying party.",
  );
  const fragmentWasCleared = await page.evaluate(() => sessionStorage.getItem("sdk_callback_fragment_cleared"));
  assert.equal(
    fragmentWasCleared,
    "yes",
    "The callback helper must clear the fragment before leaving the callback page.",
  );
  const replay = await page.evaluate(async (payload) => {
    const csrf = await fetch("/csrf", { credentials: "same-origin" }).then(
      (response) => response.json(),
    );
    const response = await fetch("/portkey/callback", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "content-type": "application/json",
        "x-csrf-token": csrf.token,
      },
      body: JSON.stringify(payload),
    });
    return response.status;
  }, callbackPayload);
  assert.equal(replay, 400, "A consumed callback must not be exchangeable again.");
  await context.close();
  await browser.close();
  browser = undefined;
  console.log(
    "SDK example acceptance passed: packed SDK installed, browser helper loaded, proof receipt verified, and callback replay rejected.",
  );
} finally {
  await cleanup();
}
