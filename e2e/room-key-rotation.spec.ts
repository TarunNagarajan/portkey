import { expect, test, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

async function requestAdmission(page: Page, link: string, label: string, owner: Page) {
  await page.goto(link);
  await page.getByLabel('Your label').fill(label);
  await page.getByRole('button', { name: 'Request access' }).click();
  const row = owner.getByRole('row').filter({ hasText: label });
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Approve', exact: true }).click();
  await page.getByRole('link', { name: 'Enter room' }).click();
  await expect(page.getByRole('heading', { name: 'Shared room files' })).toBeVisible();
}

async function shareTextFile(owner: Page, name: string, contents: string) {
  await owner.getByLabel('Choose file to share').setInputFiles({
    name, mimeType: 'text/plain', buffer: Buffer.from(contents),
  });
  const fileRow = owner.locator('.file-row').filter({ hasText: name }).first();
  await expect(fileRow).toContainText(name);
  await fileRow.getByRole('button', { name: 'Share with room' }).click();
  await expect(fileRow.getByRole('button', { name: 'Verify and download' })).toBeVisible({ timeout: 30_000 });
}

async function enterApprovedRoom(page: Page, link: string) {
  await page.goto(link);
  const enter = page.getByRole('link', { name: 'Enter room' });
  await expect(enter).toBeVisible();
  await enter.click();
  await expect(page.getByRole('heading', { name: 'Shared room files' })).toBeVisible();
}

test('updated invitations restore old files and unlock new files after owner rotation', async ({ page, browser }) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await page.getByLabel('Room title').fill('Key rotation room');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  await page.getByRole('button', { name: 'Enable encrypted inbox' }).click();
  await expect(page.getByText('Encrypted inbox enabled.', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  await page.getByRole('button', { name: 'Enable shared files' }).click();
  await expect(page.getByText('Shared files enabled.', { exact: false })).toBeVisible();
  const oldInvite = await page.locator('.share-room .join-link').getAttribute('href');
  expect(oldInvite).toContain('files=');
  const inboxFingerprint = new URLSearchParams(new URL(oldInvite!).hash.slice(1)).get('key');
  expect(inboxFingerprint).toMatch(/^[a-f0-9]{64}$/);

  const oldAttendeeContext = await browser.newContext();
  const oldAttendee = await oldAttendeeContext.newPage();
  let closeNewAttendee: (() => Promise<void>) | undefined;
  try {
    await requestAdmission(oldAttendee, oldInvite!, 'Old key browser', page);
    await shareTextFile(page, 'first.txt', 'first key epoch');
    await page.getByLabel('Choose file to share').setInputFiles({
      name: 'interrupted.txt',
      mimeType: 'text/plain',
      buffer: Buffer.from('prepared before rotation'),
    });
    const interruptedPlan = page.locator('.file-row').filter({ hasText: 'interrupted.txt' }).first();
    await expect(interruptedPlan.getByRole('button', { name: 'Share with room' })).toBeVisible();

    let loseRecoveryCheck = false;
    await page.route('**/api/rooms/*/files/key', async (route) => {
      if (route.request().method() === 'GET' && loseRecoveryCheck) {
        loseRecoveryCheck = false;
        await route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: JSON.stringify({ error: { code: 'TEMPORARY', message: 'Temporary failure.' } }),
        });
        return;
      }
      await route.continue();
    });
    await page.route('**/api/rooms/*/files/key/rotate', async (route) => {
      const response = await route.fetch();
      expect(response.status()).toBe(200);
      loseRecoveryCheck = true;
      await route.abort('failed');
    });
    page.once('dialog', (dialog) => void dialog.accept());
    await page.getByRole('button', { name: 'Rotate shared-file key' }).click();
    await expect(page.getByRole('alert')).toBeVisible();
    await page.unroute('**/api/rooms/*/files/key');
    await page.unroute('**/api/rooms/*/files/key/rotate');
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Shared room files' })).toBeVisible();
    const recoveredInvite = await page.locator('.share-room .join-link').getAttribute('href');
    expect(recoveredInvite).not.toBe(oldInvite);
    await expect(page.locator('.file-row').filter({ hasText: 'first.txt' })).toBeVisible();
    const stalePlan = page.locator('.file-row').filter({ hasText: 'interrupted.txt' }).first();
    await expect(stalePlan).toContainText('encrypted with an older key; select original file again');
    await expect(stalePlan.getByRole('button', { name: 'Share with room' })).toBeDisabled();
    const updatedInvite = await page.locator('.share-room .join-link').getAttribute('href');
    expect(updatedInvite).toContain('files=');
    expect(updatedInvite).not.toBe(oldInvite);

    await shareTextFile(page, 'second.txt', 'second key epoch');
    await oldAttendee.waitForTimeout(6_000);
    await expect(oldAttendee.getByText(/organizer rotated the shared file key/i)).toBeVisible({ timeout: 15_000 });
    await expect(oldAttendee.getByText('Unavailable file')).toBeVisible();
    const unavailableFile = oldAttendee.locator('.file-row').filter({ hasText: 'Unavailable file' });
    await unavailableFile.getByRole('button', { name: 'Verify and download' }).click();
    await expect(oldAttendee.getByRole('alert')).toContainText(/updated room invitation/i);

    const newAttendeeContext = await browser.newContext();
    closeNewAttendee = () => newAttendeeContext.close();
    const newAttendee = await newAttendeeContext.newPage();
    await requestAdmission(newAttendee, updatedInvite!, 'Updated key browser', page);
    await newAttendee.evaluate(() => Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: undefined }));
    const oldDownloadPromise = newAttendee.waitForEvent('download');
    await newAttendee.locator('.file-row').filter({ hasText: 'first.txt' }).getByRole('button', { name: 'Verify and download' }).click();
    const oldDownloadPath = await (await oldDownloadPromise).path();
    expect(oldDownloadPath).toBeTruthy();
    expect(await readFile(oldDownloadPath!, 'utf8')).toBe('first key epoch');
    const newDownloadPromise = newAttendee.waitForEvent('download');
    await newAttendee.locator('.file-row').filter({ hasText: 'second.txt' }).getByRole('button', { name: 'Verify and download' }).click();
    const newDownloadPath = await (await newDownloadPromise).path();
    expect(newDownloadPath).toBeTruthy();
    expect(await readFile(newDownloadPath!, 'utf8')).toBe('second key epoch');

    await enterApprovedRoom(oldAttendee, updatedInvite!);
    await expect(oldAttendee.locator('.file-row').filter({ hasText: 'first.txt' })).toBeVisible();
    await expect(oldAttendee.locator('.file-row').filter({ hasText: 'second.txt' })).toBeVisible();
    await expect(page.getByRole('region', { name: 'Encrypted submission inbox' })).toContainText(inboxFingerprint!);
    expect(new URLSearchParams(new URL(updatedInvite!).hash.slice(1)).get('key')).toBe(inboxFingerprint);
  } finally {
    try {
      await closeNewAttendee?.();
    } finally {
      await oldAttendeeContext.close();
    }
  }
});

test('a delayed same-key rotation cannot replace a newer key cached by another owner tab', async ({ page }) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await page.getByLabel('Room title').fill('Concurrent key rotation');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  await page.getByRole('button', { name: 'Enable shared files' }).click();
  await expect(page.getByRole('button', { name: 'Rotate shared-file key' })).toBeVisible();
  const roomPath = new URL(page.url()).pathname;
  const tabB = await page.context().newPage();
  let initialInvitationB = '';
  let invitationAfterFirstRotation = '';
  let invitationAtEpochThree = '';

  let signalOldKeyFetched!: () => void;
  let releaseOldKeyResponse!: () => void;
  let signalFirstRotationCommitted!: () => void;
  let releaseFirstRotationResponse!: () => void;
  const oldKeyFetched = new Promise<void>((resolve) => { signalOldKeyFetched = resolve; });
  const oldKeyReleased = new Promise<void>((resolve) => { releaseOldKeyResponse = resolve; });
  const firstRotationCommitted = new Promise<void>((resolve) => { signalFirstRotationCommitted = resolve; });
  const firstRotationReleased = new Promise<void>((resolve) => { releaseFirstRotationResponse = resolve; });
  let heldOldKey = false;
  let heldFirstRotation = false;

  try {
    await tabB.goto(page.url());
    await expect(tabB.getByRole('button', { name: 'Rotate shared-file key' })).toBeVisible();
    initialInvitationB = (await tabB.locator('.share-room .join-link').getAttribute('href'))!;
    await tabB.route('**/api/rooms/*/files/key', async (route) => {
      if (route.request().method() === 'GET' && !heldOldKey) {
        heldOldKey = true;
        const response = await route.fetch();
        signalOldKeyFetched();
        await oldKeyReleased;
        await route.fulfill({ response });
        return;
      }
      await route.continue();
    });
    tabB.once('dialog', (dialog) => void dialog.accept());
    const rotateB = tabB.getByRole('button', { name: 'Rotate shared-file key' }).click();
    await oldKeyFetched;

    await page.route('**/api/rooms/*/files/key/rotate', async (route) => {
      if (!heldFirstRotation) {
        heldFirstRotation = true;
        const response = await route.fetch();
        expect(response.status()).toBe(200);
        signalFirstRotationCommitted();
        await firstRotationReleased;
        await route.fulfill({ response });
        return;
      }
      await route.continue();
    });
    page.once('dialog', (dialog) => void dialog.accept());
    const rotateA = page.getByRole('button', { name: 'Rotate shared-file key' }).click();
    await firstRotationCommitted;

    releaseOldKeyResponse();
    await rotateB;
    await expect(tabB.getByRole('button', { name: 'Rotate shared-file key' })).toBeEnabled();
    await expect(tabB.locator('.share-room .join-link')).not.toHaveAttribute('href', initialInvitationB);
    invitationAfterFirstRotation = (await tabB.locator('.share-room .join-link').getAttribute('href'))!;
    tabB.once('dialog', (dialog) => void dialog.accept());
    await tabB.getByRole('button', { name: 'Rotate shared-file key' }).click();
    await expect(tabB.locator('.share-room .join-link')).not.toHaveAttribute('href', invitationAfterFirstRotation);
    invitationAtEpochThree = (await tabB.locator('.share-room .join-link').getAttribute('href'))!;
    const filesKeyB = new URLSearchParams(new URL(invitationAtEpochThree).hash.slice(1)).get('files');
    expect(filesKeyB).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const keyInfoBeforeRelease = await page.request.get(`${new URL(page.url()).origin}/api${roomPath}/files/key`);
    expect(keyInfoBeforeRelease.ok()).toBe(true);
    const epochThreeInfo = await keyInfoBeforeRelease.json() as { epoch: number; fingerprint: string };
    expect(epochThreeInfo.epoch).toBe(3);
    expect(epochThreeInfo.fingerprint).toBe(
      createHash('sha256').update(Buffer.from(filesKeyB!, 'base64url')).digest('hex'),
    );

    releaseFirstRotationResponse();
    await rotateA;
    await expect(page.getByRole('alert')).toContainText(/newer shared-file key is already stored/i);
    await page.reload();
    await expect(page.getByRole('button', { name: 'Rotate shared-file key' })).toBeVisible();
    const invitationA = await page.locator('.share-room .join-link').getAttribute('href');
    const filesKeyA = new URLSearchParams(new URL(invitationA!).hash.slice(1)).get('files');
    expect(filesKeyA).toBe(filesKeyB);
    const keyInfo = await page.request.get(`${new URL(page.url()).origin}/api${roomPath}/files/key`);
    expect(keyInfo.ok()).toBe(true);
    const recoveredInfo = await keyInfo.json() as { epoch: number; fingerprint: string };
    expect(recoveredInfo).toEqual(epochThreeInfo);
    expect(invitationA).toBe(invitationAtEpochThree);
  } finally {
    releaseOldKeyResponse();
    releaseFirstRotationResponse();
    await Promise.all([
      page.unroute('**/api/rooms/*/files/key/rotate'),
      tabB.unroute('**/api/rooms/*/files/key'),
    ]);
    await tabB.close();
  }
});
