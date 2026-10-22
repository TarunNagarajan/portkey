import { expect, test, type BrowserContext, type Page } from "@playwright/test";
import { randomBytes } from "node:crypto";

const walletOrigin = "http://127.0.0.1:5300";
const relyingApps = [
  { origin: "http://northstar.localhost:5301", title: "Northstar Learning" },
  { origin: "http://fieldnote.localhost:5302", title: "Fieldnote Community" },
] as const;
async function checkApplication(
  page: Page,
  context: BrowserContext,
  app: (typeof relyingApps)[number],
  injectWrongState: boolean,
) {
  await page.goto(app.origin);
  await expect(page.getByRole("heading", { name: app.title })).toBeVisible();
  if (injectWrongState) {
    await page
      .getByRole("link", { name: "Review the public Portkey contract" })
      .click();
    await expect(
      page.getByRole("heading", { name: "Demonstration membership" }),
    ).toBeVisible();
    await expect(page.getByText("Portkey sample issuer")).toBeVisible();
    await expect(
      page.getByRole("link", { name: "Download JSON manifest" }),
    ).toHaveAttribute("href", /v1\/contracts\/.+\/versions\/1/);
    await page.setViewportSize({ width: 390, height: 844 });
    const pageWidths = await page.evaluate(() => ({
      content: document.documentElement.scrollWidth,
      viewport: window.innerWidth,
    }));
    expect(pageWidths.content).toBeLessThanOrEqual(pageWidths.viewport);
    await page.screenshot({
      path: "C:/Users/ultim/Documents/Codex/outputs/verification-platform/mobile-contract.png",
      fullPage: true,
    });
  }
  await page.goto(app.origin);
  await page.getByRole("button", { name: "Continue with Portkey" }).click();
  await expect(page).toHaveURL(
    new RegExp(`^${walletOrigin.replaceAll(".", "\\.")}\/prove\/`),
  );
  await expect(
    page.getByRole("heading", { name: "Membership check" }),
  ).toBeVisible();
  await expect(page.getByText(app.title, { exact: true })).toBeVisible();
  expect(await page.locator("iframe").count()).toBe(0);
  if (injectWrongState) {
    await page.screenshot({
      path: "C:/Users/ultim/Documents/Codex/outputs/verification-platform/mobile-consent.png",
      fullPage: true,
    });
  }
  await page
    .getByRole("button", { name: "Prove membership and continue" })
    .click();
  await expect(
    page.getByText("Your membership was verified.", { exact: false }),
  ).toBeVisible({ timeout: 90_000 });

  let legitimateCallback = "";
  if (injectWrongState) {
    await page.route(
      "**/api/platform/wallet/proof-requests/*/return",
      async (route) => {
        const upstream = await route.fetch();
        const payload = (await upstream.json()) as { redirectUrl: string };
        legitimateCallback = payload.redirectUrl;
        const tampered = new URL(payload.redirectUrl);
        const parameters = new URLSearchParams(tampered.hash.slice(1));
        parameters.set("state", randomBytes(32).toString("base64url"));
        tampered.hash = parameters.toString();
        await route.fulfill({
          response: upstream,
          body: JSON.stringify({
            ...payload,
            redirectUrl: tampered.toString(),
          }),
        });
      },
    );
  }
  await page.getByRole("button", { name: "Return to application" }).click();
  if (injectWrongState) {
    await expect(
      page.getByText("This result belongs to a different application session."),
    ).toBeVisible();
    await page.unroute("**/api/platform/wallet/proof-requests/*/return");
    expect(legitimateCallback).toContain("#code=");

    const otherSession = await context.browser()!.newContext();
    const injectedPage = await otherSession.newPage();
    await injectedPage.goto(legitimateCallback);
    await expect(
      injectedPage.getByText(
        "The application could not confirm the result. Start again.",
      ),
    ).toBeVisible();
    await injectedPage.goto(`${app.origin}/benefit`);
    await expect(
      injectedPage.getByRole("heading", { name: "Session unavailable" }),
    ).toBeVisible();
    await otherSession.close();

    await page.goto(app.origin);
    await page.goto(legitimateCallback);
  }
  await expect(page).toHaveURL(`${app.origin}/`);
  await expect(
    page.getByText("Access is available in this application session", {
      exact: false,
    }),
  ).toBeVisible();
  await page.getByRole("link", { name: "Open the protected area" }).click();
  await expect(
    page.getByRole("heading", { name: "Membership confirmed" }),
  ).toBeVisible();

  const replayUrl = legitimateCallback;
  if (replayUrl) {
    await page.goto(replayUrl);
    await expect(
      page.getByText("This application request expired. Start again."),
    ).toBeVisible();
    await page.goto(`${app.origin}/benefit`);
    await expect(
      page.getByRole("heading", { name: "Membership confirmed" }),
    ).toBeVisible();
  }
}

async function checkContractDraftPreservation(page: Page) {
  await page.goto(`${walletOrigin}/credential-groups`);
  await page.getByLabel("Group name").fill("Portal draft group");
  await page.getByRole("button", { name: "Create group" }).click();
  await expect(
    page.getByText("Portal draft group", { exact: true }),
  ).toBeVisible();

  await page.goto(`${walletOrigin}/platform`);
  await expect(
    page.getByRole("heading", { name: "Verification platform" }),
  ).toBeVisible();
  const createForm = page.locator(".platform-form").first();
  async function createContract(name: string) {
    await createForm.getByLabel("Contract name").fill(name);
    await createForm.getByLabel("Issuer label").fill("Portal draft issuer");
    await createForm
      .getByLabel("Eligibility statement")
      .fill(`${name} eligibility`);
    await createForm.getByLabel("Portal draft group").check();
    await createForm.getByRole("button", { name: "Publish version 1" }).click();
    await expect(
      page.locator("article.platform-item").filter({ hasText: name }),
    ).toBeVisible();
  }
  await createContract("Draft preservation one");
  await createContract("Draft preservation two");

  const first = page
    .locator("article.platform-item")
    .filter({ hasText: "Draft preservation one" });
  const second = page
    .locator("article.platform-item")
    .filter({ hasText: "Draft preservation two" });
  await first.getByText("Publish another version").click();
  await second.getByText("Publish another version").click();
  const firstForm = first.locator("details form");
  const secondForm = second.locator("details form");
  await firstForm
    .getByLabel("Eligibility statement")
    .fill("Published update draft");
  await firstForm.locator('input[type="checkbox"]').check();
  await secondForm
    .getByLabel("Eligibility statement")
    .fill("Keep this unsaved draft");
  await secondForm.locator('input[type="checkbox"]').check();
  await firstForm.getByRole("button", { name: "Publish next version" }).click();
  await expect(first.getByText("Version 2", { exact: false })).toBeVisible();
  await expect(secondForm.getByLabel("Eligibility statement")).toHaveValue(
    "Keep this unsaved draft",
  );
  await expect(secondForm.locator('input[type="checkbox"]')).toBeChecked();
  await expect(firstForm.getByLabel("Eligibility statement")).toHaveValue("");

  await page.getByLabel("Application name").fill("Portal mobile example");
  await page
    .getByLabel("Application origin")
    .fill("https://portal-mobile.example");
  await page.getByLabel("Callback path").fill("/callback");
  await page.getByRole("button", { name: "Register application" }).click();
  const application = page
    .locator("article.platform-item")
    .filter({ hasText: "Portal mobile example" });
  await expect(application).toBeVisible();
  await application
    .getByRole("button", { name: "Create domain check" })
    .click();
  await expect(page.getByText('"challenge"', { exact: false })).toBeVisible();
  await page.screenshot({
    path: "C:/Users/ultim/Documents/Codex/outputs/verification-platform/mobile-portal.png",
    fullPage: true,
  });
}

test("one enrollment unlocks two different RP backends through Portkey consent and strict built CSP", async ({
  page,
  context,
}) => {
  test.setTimeout(240_000);
  const externalTraffic: Array<{ url: string; body: string; cookie: string }> =
    [];
  const walletProofBodies: string[] = [];
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("request", (request) => {
    const url = new URL(request.url());
    const body = request.postData() ?? "";
    const headers = request.headers();
    if (relyingApps.some((app) => url.origin === app.origin))
      externalTraffic.push({
        url: request.url(),
        body,
        cookie: headers.cookie ?? "",
      });
    if (url.origin === walletOrigin && url.pathname.endsWith("/prove"))
      walletProofBodies.push(body);
  });

  const readinessResponse = await page.request.get(
    `${walletOrigin}/platform-demo/ready`,
  );
  expect(readinessResponse.ok()).toBeTruthy();
  const readiness = (await readinessResponse.json()) as {
    applications: Array<{ name: string; origin: string }>;
  };
  expect(readiness.applications).toEqual(
    relyingApps.map(({ origin, title }) => ({ name: title, origin })),
  );

  const walletResponse = await page.goto(walletOrigin);
  expect(walletResponse?.headers()["content-security-policy"]).toContain(
    "default-src 'self'",
  );
  const csp = walletResponse?.headers()["content-security-policy"] ?? "";
  const scriptPolicy =
    csp
      .split(";")
      .map((directive) => directive.trim())
      .find((directive) => directive.startsWith("script-src ")) ?? "";
  expect(scriptPolicy).toContain("'self'");
  expect(scriptPolicy).toContain("'wasm-unsafe-eval'");
  expect(scriptPolicy).not.toContain("'unsafe-inline'");
  expect(scriptPolicy).not.toContain("'unsafe-eval'");
  await expect(page.getByRole("heading", { name: "Your rooms" })).toBeVisible();

  await page.goto(relyingApps[0].origin);
  await page
    .getByRole("link", { name: "Get the issuer’s demo enrollment link" })
    .click();
  await expect(
    page.getByRole("heading", { name: "Portkey demonstration members" }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Save credential in this browser" })
    .click();
  await expect(
    page.getByText("Credential saved and enrolled in this browser."),
  ).toBeVisible();
  const walletCredentials = await page.evaluate(
    async () =>
      new Promise<
        Array<{ groupId: string; commitment: string; privateKey: string }>
      >((resolve, reject) => {
        const request = indexedDB.open("portkey-reusable-credentials", 1);
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
          const database = request.result;
          const read = database
            .transaction("credentials")
            .objectStore("credentials")
            .getAll();
          read.onsuccess = () => {
            database.close();
            resolve(read.result);
          };
          read.onerror = () => {
            database.close();
            reject(read.error);
          };
        };
      }),
  );
  expect(walletCredentials).toHaveLength(1);

  await checkApplication(page, context, relyingApps[0], true);
  await checkApplication(page, context, relyingApps[1], false);
  await checkContractDraftPreservation(page);

  const emptyContext = await context.browser()!.newContext();
  const emptyWalletPage = await emptyContext.newPage();
  await emptyWalletPage.goto(relyingApps[0].origin);
  await emptyWalletPage
    .getByRole("button", { name: "Continue with Portkey" })
    .click();
  await expect(emptyWalletPage).toHaveURL(
    new RegExp(`^${walletOrigin.replaceAll(".", "\\.")}\/prove\/`),
  );
  await emptyWalletPage
    .getByRole("button", { name: "Prove membership and continue" })
    .click();
  await expect(
    emptyWalletPage.getByText(
      "This browser has no saved credential accepted by this contract.",
      { exact: false },
    ),
  ).toBeVisible();
  await emptyWalletPage.goto(`${relyingApps[0].origin}/benefit`);
  await expect(
    emptyWalletPage.getByRole("heading", { name: "Access is not available" }),
  ).toBeVisible();
  await emptyContext.close();

  for (const app of relyingApps) {
    await page.goto(app.origin);
    const bundle = await page.evaluate(async () =>
      (await fetch("/app.js")).text(),
    );
    expect(bundle).not.toContain("pk_live_");
    const databaseNames = await page.evaluate(async () =>
      (await indexedDB.databases()).map((database) => database.name),
    );
    expect(databaseNames).not.toContain("portkey-reusable-credentials");
    const localStorageValues = await page.evaluate(() =>
      Object.entries(localStorage).flat().join(" "),
    );
    expect(localStorageValues).not.toContain(walletCredentials[0].privateKey);
    expect(localStorageValues).not.toContain(walletCredentials[0].commitment);
  }

  expect(walletProofBodies.length).toBe(2);
  const proofNullifiers: string[] = [];
  for (const body of walletProofBodies) {
    const proofRequest = JSON.parse(body) as {
      proof?: Record<string, unknown>;
    };
    expect(Object.keys(proofRequest).sort()).toEqual([
      "capability",
      "challengeId",
      "proof",
    ]);
    expect(Object.keys(proofRequest.proof ?? {}).sort()).toEqual([
      "merkleTreeDepth",
      "merkleTreeRoot",
      "message",
      "nullifier",
      "points",
      "scope",
    ]);
    if (typeof proofRequest.proof?.nullifier === "string") {
      proofNullifiers.push(proofRequest.proof.nullifier);
    }
    expect(body).not.toContain(walletCredentials[0].groupId);
    expect(body).not.toContain(walletCredentials[0].privateKey);
    expect(proofRequest.proof).not.toHaveProperty("commitment");
    expect(proofRequest.proof).not.toHaveProperty("groupId");
    expect(proofRequest.proof).not.toHaveProperty("privateKey");
  }
  expect(externalTraffic.some((item) => item.body.includes("pk_live_"))).toBe(
    false,
  );
  expect(externalTraffic.some((item) => item.url.includes("pk_live_"))).toBe(
    false,
  );
  for (const credentialValue of [
    walletCredentials[0].groupId,
    walletCredentials[0].commitment,
    walletCredentials[0].privateKey,
    ...proofNullifiers,
  ]) {
    expect(
      externalTraffic.some((item) =>
        `${item.url}\n${item.body}\n${item.cookie}`.includes(credentialValue),
      ),
    ).toBe(false);
  }
  expect(
    externalTraffic.some((item) => item.cookie.includes("portkey_session")),
  ).toBe(false);
  expect(
    externalTraffic.some((item) =>
      item.body.includes(walletCredentials[0].commitment),
    ),
  ).toBe(false);
  expect(pageErrors).toEqual([]);
});
