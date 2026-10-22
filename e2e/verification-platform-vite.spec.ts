import { expect, test } from "@playwright/test";

test("cold Vite origin proxies issuer controls, contract manifests and JWKS", async ({
  page,
}) => {
  await page.goto("/credential-groups");
  await expect(
    page.getByRole("heading", { name: "Credential groups" }),
  ).toBeVisible();
  await page.getByLabel("Group name").fill("Cold Vite issuer group");
  await page.getByRole("button", { name: "Create group" }).click();
  await expect(
    page.getByText("Cold Vite issuer group", { exact: true }),
  ).toBeVisible();

  await page.goto("/platform");
  await expect(
    page.getByRole("heading", { name: "Verification platform" }),
  ).toBeVisible();
  const issuerForm = page.locator(".platform-form").first();
  await issuerForm.getByLabel("Contract name").fill("Cold Vite contract");
  await issuerForm.getByLabel("Issuer label").fill("Cold Vite issuer");
  await issuerForm
    .getByLabel("Eligibility statement")
    .fill("A genuine issuer contract published through the UI.");
  await issuerForm.getByLabel("Cold Vite issuer group").check();
  await issuerForm.getByRole("button", { name: "Publish version 1" }).click();
  const contract = page
    .locator("article.platform-item")
    .filter({ hasText: "Cold Vite contract" });
  await expect(contract).toBeVisible();

  const publicPage = page.waitForEvent("popup");
  await contract.getByRole("link", { name: "Public contract" }).click();
  const publicContract = await publicPage;
  await expect(
    publicContract.getByRole("heading", { name: "Cold Vite contract" }),
  ).toBeVisible();
  await expect(
    publicContract.getByText("Cold Vite issuer group", { exact: true }),
  ).toBeVisible();
  const manifestLink = publicContract.getByRole("link", {
    name: "Download JSON manifest",
  });
  const manifestPath = await manifestLink.getAttribute("href");
  expect(manifestPath).toMatch(/^\/v1\/contracts\/.+\/versions\/1$/);
  const manifest = await publicContract.evaluate(async (path) => {
    const response = await fetch(path);
    return { status: response.status, body: await response.json() };
  }, manifestPath!);
  expect(manifest.status).toBe(200);
  expect(manifest.body).toMatchObject({
    name: "Cold Vite contract",
    issuerLabel: "Cold Vite issuer",
    version: 1,
    adapter: "semaphore-membership-v1",
    proofDepth: 10,
  });
  const jwks = await publicContract.evaluate(async () => {
    const response = await fetch("/v1/.well-known/jwks.json");
    return { status: response.status, body: await response.json() };
  });
  expect(jwks.status).toBe(200);
  expect(jwks.body.keys).toHaveLength(1);
  expect(jwks.body.keys[0]).toMatchObject({
    alg: "Ed25519",
    crv: "Ed25519",
    kty: "OKP",
    use: "sig",
  });
  expect(jwks.body.keys[0].kid).toMatch(/^portkey-[0-9a-f-]{36}$/);

  await publicContract.close();
  await page.getByLabel("Application name").fill("Cold Vite application");
  await page.getByLabel("Application origin").fill("https://cold-vite.example");
  await page.getByLabel("Callback path").fill("/callback");
  await page.getByRole("button", { name: "Register application" }).click();
  const application = page
    .locator("article.platform-item")
    .filter({ hasText: "Cold Vite application" });
  await expect(application).toBeVisible();
  await application
    .getByRole("button", { name: "Create domain check" })
    .click();
  await expect(page.getByText('"challenge"', { exact: false })).toBeVisible();
});
