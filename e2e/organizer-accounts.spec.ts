import { expect, test, type Page, type CDPSession } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

type StoredCredential = {
  credentialId: string;
  isResidentCredential: boolean;
  rpId: string;
  privateKey: string;
  signCount: number;
  userHandle?: string;
};

async function addAuthenticator(page: Page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send(
    "WebAuthn.addVirtualAuthenticator",
    {
      options: {
        protocol: "ctap2",
        transport: "internal",
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
      },
    },
  );
  return { cdp, authenticatorId };
}

async function exportCredentials(cdp: CDPSession, authenticatorId: string) {
  const result = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  return result.credentials as StoredCredential[];
}

async function importCredentials(
  cdp: CDPSession,
  authenticatorId: string,
  credentials: StoredCredential[],
) {
  for (const credential of credentials) {
    await cdp.send("WebAuthn.addCredential", { authenticatorId, credential });
  }
}

test("organizer passkeys preserve adopted ownership across login and recovery", async ({
  page,
  browser,
}) => {
  test.setTimeout(180_000);
  const ownedContexts = new Set<import("@playwright/test").BrowserContext>();
  const authenticators: { cdp: CDPSession; id: string }[] = [];
  let originalSessionCookie:
    | {
        name: string;
        value: string;
        domain: string;
        path: string;
        expires: number;
        httpOnly: boolean;
        secure: boolean;
        sameSite: "Strict" | "Lax" | "None";
      }
    | undefined;

  try {
    const firstAuth = await addAuthenticator(page);
    authenticators.push({ cdp: firstAuth.cdp, id: firstAuth.authenticatorId });

    await page.goto("/");
    await page.getByLabel("Room title").fill("Persistent organizer room");
    await page.getByRole("button", { name: "Create draft" }).click();
    await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
    const roomPath = new URL(page.url()).pathname;
    const roomId = roomPath.split("/").at(-1)!;
    await page.getByRole("link", { name: "Account" }).click();
    await expect(
      page.getByRole("heading", { name: "Keep organizer access" }),
    ).toBeVisible();
    await expect(page.getByText(/This browser has 1 room/)).toBeVisible();
    await page.getByLabel(/I want to secure this browser/).check();
    await page.getByLabel("Passkey label").fill("First authenticator");
    await page
      .getByRole("button", { name: "Create account with passkey" })
      .click();
    await expect(
      page.getByRole("dialog", { name: "Save your recovery key" }),
    ).toBeVisible();
    const recoveryKey = (
      await page.locator(".recovery-panel code").innerText()
    ).trim();
    expect(recoveryKey).toMatch(/^pk_recovery_[0-9a-f-]+\.[A-Za-z0-9_-]{43}$/);
    await page.getByRole("button", { name: "I saved it" }).click();
    await expect(
      page.getByRole("heading", { name: "Organizer account active" }),
    ).toBeVisible();

    const initialCredential = (
      await exportCredentials(firstAuth.cdp, firstAuth.authenticatorId)
    )[0];
    expect(initialCredential).toBeTruthy();
    const firstCookies = await page.context().cookies();
    const originalCookie = firstCookies.find(
      (cookie) => cookie.name.includes("session") && cookie.httpOnly,
    );
    expect(originalCookie).toBeTruthy();
    originalSessionCookie = originalCookie;
    await page.getByRole("button", { name: "Sign out" }).click();
    await expect(
      page.getByRole("heading", { name: "Keep organizer access" }),
    ).toBeVisible();
    const formerOwnerList = await page.request.get("/api/rooms");
    expect(formerOwnerList.ok()).toBeTruthy();
    const formerOwnerRooms = await formerOwnerList.json();
    expect(
      formerOwnerRooms.some((room: { id: string }) => room.id === roomId),
    ).toBe(false);

    const secondContext = await browser.newContext();
    ownedContexts.add(secondContext);
    const secondPage = await secondContext.newPage();
    const secondAuth = await addAuthenticator(secondPage);
    authenticators.push({
      cdp: secondAuth.cdp,
      id: secondAuth.authenticatorId,
    });
    await importCredentials(secondAuth.cdp, secondAuth.authenticatorId, [
      initialCredential,
    ]);
    await secondPage.goto("/account");
    await secondPage
      .getByRole("button", { name: "Sign in with passkey" })
      .click();
    await expect(
      secondPage.getByRole("heading", { name: "Organizer account active" }),
    ).toBeVisible();
    const oldCredential = (
      await exportCredentials(secondAuth.cdp, secondAuth.authenticatorId)
    )[0];
    expect(oldCredential).toBeTruthy();
    await secondPage.goto("/");
    await expect(
      secondPage.getByText("Persistent organizer room", { exact: true }),
    ).toBeVisible();
    const ownerDetails = await secondPage.request.get(`/api/rooms/${roomId}`);
    expect(ownerDetails.ok()).toBeTruthy();

    const activeContext = await browser.newContext();
    ownedContexts.add(activeContext);
    const activePage = await activeContext.newPage();
    const activeAuth = await addAuthenticator(activePage);
    authenticators.push({
      cdp: activeAuth.cdp,
      id: activeAuth.authenticatorId,
    });
    await importCredentials(activeAuth.cdp, activeAuth.authenticatorId, [
      oldCredential,
    ]);
    await activePage.goto("/account");
    await activePage
      .getByRole("button", { name: "Sign in with passkey" })
      .click();
    await expect(
      activePage.getByRole("heading", { name: "Organizer account active" }),
    ).toBeVisible();
    const currentOldCredential = (
      await exportCredentials(activeAuth.cdp, activeAuth.authenticatorId)
    )[0];
    expect(currentOldCredential).toBeTruthy();

    await secondAuth.cdp.send("WebAuthn.removeVirtualAuthenticator", {
      authenticatorId: secondAuth.authenticatorId,
    });
    const replacementAuth = await addAuthenticator(secondPage);
    authenticators.push({
      cdp: replacementAuth.cdp,
      id: replacementAuth.authenticatorId,
    });
    await secondPage.goto("/account");
    await secondPage.getByRole("button", { name: "Sign out" }).click();
    await expect(
      secondPage.getByRole("heading", { name: "Keep organizer access" }),
    ).toBeVisible();
    await secondPage.goto("/account");
    await secondPage.getByText("Recover an account", { exact: true }).click();
    const recoveryDetails = secondPage.locator("details").filter({
      has: secondPage.getByRole("button", { name: "Replace passkeys" }),
    });
    await recoveryDetails.locator("input").fill(recoveryKey);
    await recoveryDetails
      .getByRole("button", { name: "Replace passkeys" })
      .click();
    await expect(
      secondPage.getByRole("heading", { name: "Save your recovery key" }),
    ).toBeVisible();
    const replacementRecoveryKey = (
      await secondPage.locator(".recovery-panel code").innerText()
    ).trim();
    expect(replacementRecoveryKey).not.toBe(recoveryKey);
    await secondPage.getByRole("button", { name: "I saved it" }).click();
    await expect(
      secondPage.getByRole("heading", { name: "Organizer account active" }),
    ).toBeVisible();

    await activePage.goto("/account");
    await expect(
      activePage.getByRole("heading", { name: "Keep organizer access" }),
    ).toBeVisible();
    const revokedStatus = await activePage.request.get("/api/account/status");
    expect((await revokedStatus.json()).signedIn).toBe(false);

    const oldLoginContext = await browser.newContext();
    ownedContexts.add(oldLoginContext);
    const oldLoginPage = await oldLoginContext.newPage();
    const oldLoginAuth = await addAuthenticator(oldLoginPage);
    authenticators.push({
      cdp: oldLoginAuth.cdp,
      id: oldLoginAuth.authenticatorId,
    });
    await importCredentials(oldLoginAuth.cdp, oldLoginAuth.authenticatorId, [
      currentOldCredential,
    ]);
    await oldLoginPage.goto("/account");
    await oldLoginPage
      .getByRole("button", { name: "Sign in with passkey" })
      .click();
    await expect(oldLoginPage.getByRole("alert")).toContainText(
      /could not be verified/i,
    );

    const recoveredCredential = (
      await exportCredentials(
        replacementAuth.cdp,
        replacementAuth.authenticatorId,
      )
    )[0];
    expect(recoveredCredential).toBeTruthy();
    const recoveredLoginContext = await browser.newContext();
    ownedContexts.add(recoveredLoginContext);
    const recoveredLoginPage = await recoveredLoginContext.newPage();
    const recoveredLoginAuth = await addAuthenticator(recoveredLoginPage);
    authenticators.push({
      cdp: recoveredLoginAuth.cdp,
      id: recoveredLoginAuth.authenticatorId,
    });
    await importCredentials(
      recoveredLoginAuth.cdp,
      recoveredLoginAuth.authenticatorId,
      [recoveredCredential],
    );
    await recoveredLoginPage.goto("/account");
    await recoveredLoginPage
      .getByRole("button", { name: "Sign in with passkey" })
      .click();
    await expect(
      recoveredLoginPage.getByRole("heading", {
        name: "Organizer account active",
      }),
    ).toBeVisible();
    const recoveredOwnerDetails = await recoveredLoginPage.request.get(
      `/api/rooms/${roomId}`,
    );
    expect(recoveredOwnerDetails.ok()).toBeTruthy();
    await recoveredLoginPage.setViewportSize({ width: 390, height: 844 });
    await mkdir(resolve("..", "outputs", "organizer-accounts"), {
      recursive: true,
    });
    await recoveredLoginPage.screenshot({
      path: resolve("..", "outputs", "organizer-accounts", "account-390.png"),
      fullPage: true,
    });

    const anonymousContext = await browser.newContext();
    ownedContexts.add(anonymousContext);
    if (originalSessionCookie) {
      await anonymousContext.addCookies([originalSessionCookie]);
      const anonymousPage = await anonymousContext.newPage();
      await anonymousPage.goto("/account");
      const anonymousStatus = await anonymousPage.request.get(
        "/api/account/status",
      );
      const status = await anonymousStatus.json();
      expect(status.signedIn).toBe(false);
      expect(status.preview).toBeNull();
      const denied = await anonymousPage.request.get(`/api/rooms/${roomId}`);
      expect([403, 404]).toContain(denied.status());
    }
  } finally {
    for (const authenticator of authenticators) {
      await authenticator.cdp
        .send("WebAuthn.removeVirtualAuthenticator", {
          authenticatorId: authenticator.id,
        })
        .catch(() => undefined);
      await authenticator.cdp.send("WebAuthn.disable").catch(() => undefined);
      await authenticator.cdp.detach().catch(() => undefined);
    }
    for (const context of ownedContexts)
      await context.close().catch(() => undefined);
  }
});
