import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';

async function admitParticipant(
  browser: Browser,
  owner: Page,
  invitation: string,
  label: string,
): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({
    acceptDownloads: true,
    viewport: { width: 390, height: 844 },
  });
  await context.addInitScript(() => {
    Object.defineProperty(window, 'showSaveFilePicker', { value: undefined, configurable: true });
  });
  const page = await context.newPage();
  await page.goto(invitation);
  await page.getByLabel('Your label').fill(label);
  await page.getByRole('button', { name: 'Request access' }).click();
  await expect(page.getByText('Waiting for organizer approval. This page updates automatically.')).toBeVisible();
  const member = owner.getByRole('row').filter({ hasText: label });
  await expect(member).toBeVisible();
  await member.getByRole('button', { name: 'Approve', exact: true }).click();
  await page.getByRole('link', { name: 'Enter room' }).click();
  await expect(page.getByRole('heading', { name: 'Shared room files' })).toBeVisible();
  return { context, page };
}

test('shared room files propagate reliably to admitted participants and preserve private submissions', async ({ page, browser }) => {
  test.setTimeout(180_000);
  const contexts: BrowserContext[] = [];
  const httpTraffic: string[] = [];
  const monitor = (target: Page) => {
    target.on('request', (request) => {
      httpTraffic.push(`${request.url()}\n${request.postDataBuffer()?.toString('utf8') ?? ''}`);
    });
  };
  try {
    monitor(page);
    await page.goto('/');
    await page.getByLabel('Room title').fill('Shared file reliability');
    await page.getByRole('button', { name: 'Create draft' }).click();
    await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
    const roomPath = new URL(page.url()).pathname;

    await page.getByRole('button', { name: 'Enable encrypted inbox' }).click();
    await expect(page.getByText('Encrypted inbox enabled.', { exact: false })).toBeVisible();
    await page.getByRole('button', { name: 'Enable shared files' }).click();
    await expect(page.getByText('Shared files enabled.', { exact: false })).toBeVisible();
    await page.getByRole('button', { name: 'Open room', exact: true }).click();
    const invitation = await page.locator('.share-room .join-link').getAttribute('href');
    expect(invitation).toMatch(/#key=[a-f0-9]{64}&files=[A-Za-z0-9_-]{43}$/);
    const origin = new URL(page.url()).origin;

    const first = await admitParticipant(browser, page, invitation!, 'Publisher');
    contexts.push(first.context);
    monitor(first.page);
    const second = await admitParticipant(browser, page, invitation!, 'Second attendee');
    contexts.push(second.context);
    monitor(second.page);
    const plain = Buffer.alloc(2_306_867);
    for (let index = 0; index < plain.length; index++) plain[index] = (index * 37 + 19) % 256;
    const fixture = { name: 'room-wide-notes.bin', mimeType: 'application/octet-stream', buffer: plain };
    await first.page.locator('.room-files input[type="file"]').setInputFiles(fixture);
    await expect(first.page.getByText(/room-wide-notes\.bin/)).toBeVisible();

    const chunkUrl = `**/api${roomPath}/files/*/chunks/0`;
    let lostChunkResponse = false;
    await first.page.route(chunkUrl, async (route) => {
      if (!lostChunkResponse) {
        lostChunkResponse = true;
        const response = await route.fetch();
        expect(response.ok()).toBeTruthy();
        await route.abort('failed');
      } else await route.continue();
    });
    let lostCompleteResponse = false;
    await first.page.route(`**/api${roomPath}/files/*/complete`, async (route) => {
      if (!lostCompleteResponse) {
        lostCompleteResponse = true;
        const response = await route.fetch();
        expect(response.ok()).toBeTruthy();
        await route.abort('failed');
      } else await route.continue();
    });
    await first.page.getByRole('button', { name: 'Share with room' }).click();
    await expect(first.page.getByText('File shared with admitted room participants.')).toBeVisible({ timeout: 30_000 });
    expect(lostChunkResponse).toBe(true);
    expect(lostCompleteResponse).toBe(true);
    const ownerFilesResponse = await page.request.get(`${origin}/api${roomPath}/files`);
    expect(ownerFilesResponse.ok()).toBeTruthy();
    const ownerFiles = await ownerFilesResponse.json() as { files: Array<{ id: string }> };
    expect(ownerFiles.files).toHaveLength(1);
    const sharedFileId = ownerFiles.files[0].id;

    const secondFile = second.page.locator('.room-files .file-row').filter({ hasText: 'room-wide-notes.bin' });
    await expect(secondFile).toBeVisible({ timeout: 20_000 });
    await mkdir('test-results', { recursive: true });
    await second.page.screenshot({ path: 'test-results/shared-room-files-mobile.png', fullPage: true });
    const downloadPromise = second.page.waitForEvent('download');
    await secondFile.getByRole('button', { name: 'Verify and download' }).click();
    const downloaded = await downloadPromise;
    expect(downloaded.suggestedFilename()).toBe('room-wide-notes.bin');
    expect(await readFile((await downloaded.path())!)).toEqual(plain);
    await second.page.reload();
    const reloadedFile = second.page.locator('.room-files .file-row').filter({ hasText: 'room-wide-notes.bin' });
    await expect(reloadedFile).toBeVisible({ timeout: 20_000 });
    const reloadedDownloadPromise = second.page.waitForEvent('download');
    await reloadedFile.getByRole('button', { name: 'Verify and download' }).click();
    const reloadedDownload = await reloadedDownloadPromise;
    expect(await readFile((await reloadedDownload.path())!)).toEqual(plain);

    const originalFragment = new URL(invitation!).hash.slice(1);
    const fragmentValues = new URLSearchParams(originalFragment);
    const inboxKey = fragmentValues.get('key');
    const filesKey = fragmentValues.get('files');
    expect(inboxKey).toBeTruthy();
    expect(filesKey).toBeTruthy();
    await second.page.evaluate((hash) => { window.location.hash = hash; },
      `key=${inboxKey}&files=${filesKey}&files=${filesKey}`,
    );
    await expect(second.page.getByRole('alert')).toContainText('shared files key in this invitation is invalid');
    await expect(secondFile.getByRole('button', { name: 'Verify and download' })).toHaveCount(0);
    await second.page.evaluate((hash) => { window.location.hash = hash; }, `key=${inboxKey}&files=${filesKey}`);
    await expect(secondFile.getByRole('button', { name: 'Verify and download' })).toBeVisible();

    let tamperedDownloadStarted = false;
    second.page.on('download', () => { tamperedDownloadStarted = true; });
    await second.page.route(`**/api${roomPath}/files/${sharedFileId}/chunks/0`, async (route) => {
      const response = await route.fetch();
      const ciphertext = Buffer.from(await response.body());
      ciphertext[0] ^= 0x01;
      await route.fulfill({
        response,
        body: ciphertext,
        headers: {
          ...response.headers(),
          'x-ciphertext-sha256': createHash('sha256').update(ciphertext).digest('hex'),
        },
      });
    });
    await secondFile.getByRole('button', { name: 'Verify and download' }).click();
    await expect(second.page.getByRole('alert')).toContainText('failed authentication');
    expect(tamperedDownloadStarted).toBe(false);
    await second.page.unroute(`**/api${roomPath}/files/${sharedFileId}/chunks/0`);
    const verifiedAgain = second.page.waitForEvent('download');
    await secondFile.getByRole('button', { name: 'Verify and download' }).click();
    const verifiedDownload = await verifiedAgain;
    expect(await readFile((await verifiedDownload.path())!)).toEqual(plain);

    const privateFixture = { name: 'publisher-private-only.txt', mimeType: 'text/plain', buffer: Buffer.from('visible to publisher and organizer only') };
    await first.page.getByLabel('Choose a file (up to 250 MiB)').setInputFiles(privateFixture);
    await first.page.getByRole('button', { name: 'Submit file privately' }).click();
    await expect(first.page.getByText(/Submission accepted at/)).toBeVisible({ timeout: 30_000 });
    await expect(second.page.getByText('publisher-private-only.txt', { exact: false })).toHaveCount(0);
    const privateListResponse = await second.page.request.get(`${origin}/api${roomPath}/submissions`);
    expect(privateListResponse.ok()).toBeTruthy();
    const privateList = await privateListResponse.json() as { submissions: unknown[] };
    expect(privateList.submissions).toEqual([]);

    await first.context.close();
    const late = await admitParticipant(browser, page, invitation!, 'Late attendee');
    contexts.push(late.context);
    monitor(late.page);
    const lateFile = late.page.locator('.room-files .file-row').filter({ hasText: 'room-wide-notes.bin' });
    await expect(lateFile).toBeVisible({ timeout: 20_000 });
    const lateDownloadPromise = late.page.waitForEvent('download');
    await lateFile.getByRole('button', { name: 'Verify and download' }).click();
    const lateDownload = await lateDownloadPromise;
    expect(await readFile((await lateDownload.path())!)).toEqual(plain);

    const stranger = await browser.newContext();
    contexts.push(stranger);
    const strangerPage = await stranger.newPage();
    await strangerPage.goto(invitation!);
    await strangerPage.getByLabel('Your label').fill('Unapproved stranger');
    await strangerPage.getByRole('button', { name: 'Request access' }).click();
    const unauthorizedChunk = await stranger.request.get(`${origin}/api${roomPath}/files/${sharedFileId}/chunks/0`);
    expect(unauthorizedChunk.status()).toBe(403);

    const member = page.getByRole('row').filter({ hasText: 'Late attendee' });
    await member.getByRole('button', { name: 'Remove access' }).click();
    const chunkResponse = await late.context.request.get(`${origin}/api${roomPath}/files/${sharedFileId}/chunks/0`);
    expect(chunkResponse.status()).toBe(403);

    const ownerFile = page.locator('.room-files .file-row').filter({ hasText: 'room-wide-notes.bin' });
    await ownerFile.getByRole('button', { name: 'Delete' }).click();
    await expect(secondFile).toHaveCount(0, { timeout: 20_000 });
    const afterDelete = await page.request.get(`${origin}/api${roomPath}/files`);
    expect(afterDelete.ok()).toBeTruthy();
    const afterDeleteList = await afterDelete.json() as { files: unknown[]; activeIds: string[] };
    expect(afterDeleteList.files).toEqual([]);
    expect(afterDeleteList.activeIds).toEqual([]);

    const traffic = httpTraffic.join('\n');
    expect(traffic).not.toContain(filesKey!);
    expect(traffic).not.toContain('room-wide-notes.bin');
  } finally {
    for (const context of contexts) await context.close().catch(() => undefined);
  }
});
