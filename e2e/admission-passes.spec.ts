import { expect, test } from '@playwright/test';
import { readFile } from 'node:fs/promises';

test('pass admission is one use, preserves the inbox fingerprint, and supports encrypted files', async ({ page, browser }) => {
  test.setTimeout(120_000);
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  await page.goto('/');
  await page.getByLabel('Room title').fill('Single use workshop');
  await page.getByLabel('Admission').selectOption('pass');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  const roomPath = new URL(page.url()).pathname;
  const origin = new URL(page.url()).origin;

  await page.getByRole('button', { name: 'Enable encrypted inbox' }).click();
  await expect(page.getByText('Encrypted inbox enabled.', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Admission passes' })).toBeVisible();
  await expect(page.locator('.share-room')).toContainText('This room address shows a public preview. Admission requires a separate one use pass from you.');
  await page.getByLabel('Number of passes').fill('3');
  await page.getByRole('button', { name: 'Generate passes' }).click();
  await expect(page.getByText('New links are shown once.', { exact: false })).toBeVisible();

  const selector = page.getByLabel('Select a pass');
  await expect(selector.locator('option')).toHaveCount(3);
  const firstLink = await page.locator('.pass-selected .join-link').getAttribute('href');
  expect(firstLink).toMatch(/\/join\/[A-Za-z0-9_-]+#pass=[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]&key=[a-f0-9]{64}$/);
  const firstToken = new URL(firstLink!).hash.match(/pass=([^&]+)/)![1];
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download CSV' }).click();
  const csvDownload = await downloadEvent;
  const csv = await readFile((await csvDownload.path())!, 'utf8');
  expect(csv).toContain(firstLink!);
  expect(csv).toContain('number,url');
  expect(csv).toContain(`${origin}/join/`);
  await page.getByRole('img', { name: /QR code for admission pass/ }).screenshot({
    path: '../2026-09-25/i/outputs/Portkey_AdmissionPass_QR.png',
  });

  const metadataResponse = await page.request.get(`${origin}/api${roomPath}/passes`);
  expect(metadataResponse.ok()).toBe(true);
  const metadata = await metadataResponse.text();
  expect(metadata).not.toContain(firstToken);
  expect(metadata).not.toContain('token_digest');
  await expect(page.getByRole('img', { name: /QR code for admission pass/ })).toHaveAttribute('src', /^data:image\/png/);

  const attendeeContext = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const attendee = await attendeeContext.newPage();
  const apiUrls: string[] = [];
  attendee.on('request', (request) => apiUrls.push(request.url()));
  await attendee.goto(firstLink!);
  await expect(attendee).toHaveURL(/#pass=[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]&key=[a-f0-9]{64}$/);
  await attendee.getByLabel('Your label').fill('Mobile attendee');
  await attendee.getByRole('button', { name: 'Redeem pass' }).click();
  await expect(attendee.getByRole('link', { name: 'Enter room' })).toBeVisible();
  await expect(attendee).toHaveURL(/#key=[a-f0-9]{64}$/);
  await attendee.getByRole('link', { name: 'Enter room' }).click();
  await expect(attendee).toHaveURL((url) => url.pathname === roomPath && !url.hash.includes('pass=') && url.hash.includes('key='));
  await expect(attendee.getByRole('heading', { name: 'Encrypted submission inbox' })).toBeVisible();
  expect(apiUrls.every((url) => !url.includes(firstToken))).toBe(true);
  expect(await attendee.evaluate(() => window.location.hash.includes('pass='))).toBe(false);

  const fixture = {
    name: 'workshop notes.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('private workshop notes'),
  };
  await attendee.getByLabel('Choose a file (up to 250 MiB)').setInputFiles(fixture);
  await attendee.getByRole('button', { name: 'Submit file privately' }).click();
  await expect(attendee.getByText(/Submission accepted at/)).toBeVisible({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Refresh inbox' }).click();
  await attendee.evaluate(() => Object.defineProperty(window, 'showSaveFilePicker', {
    configurable: true,
    value: undefined,
  }));
  const fileDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Decrypt and download' }).click();
  const decrypted = await fileDownload;
  expect(await readFile((await decrypted.path())!, 'utf8')).toBe(fixture.buffer.toString());

  const otherContext = await browser.newContext({ viewport: { width: 390, height: 844 } });
  const other = await otherContext.newPage();
  await other.goto(firstLink!);
  await other.getByLabel('Your label').fill('Second browser');
  await other.getByRole('button', { name: 'Redeem pass' }).click();
  await expect(other.getByRole('alert')).toContainText('invalid, unavailable, or already used');

  await selector.selectOption({ label: 'Pass 2' });
  const secondLink = await page.locator('.pass-selected .join-link').getAttribute('href');
  expect(secondLink).toContain('#pass=');
  const secondRow = page.getByRole('row').filter({ hasText: '#2' });
  page.once('dialog', (dialog) => void dialog.accept());
  await secondRow.getByRole('button', { name: 'Revoke' }).click();
  await expect(secondRow).toContainText('revoked');
  await expect(page.locator('.pass-selected img')).toHaveCount(0);
  await other.goto(secondLink!);
  await other.getByLabel('Your label').fill('Revoked browser');
  await other.getByRole('button', { name: 'Redeem pass' }).click();
  await expect(other.getByRole('alert')).toContainText('invalid, unavailable, or already used');

  const previewLink = await page.locator('.share-room .join-link').getAttribute('href');
  await other.goto(previewLink!);
  await expect(other.getByText('This public room link does not grant access.')).toBeVisible();
  await expect(other.getByRole('button', { name: 'Request access' })).toHaveCount(0);

  await selector.selectOption({ label: 'Pass 3' });
  const thirdLink = await page.locator('.pass-selected .join-link').getAttribute('href');
  await other.goto(thirdLink!);
  await expect(other.getByRole('button', { name: 'Redeem pass' })).toBeVisible();
  await other.getByLabel('Your label').fill('Recovered browser');
  await other.getByRole('button', { name: 'Redeem pass' }).click();
  await expect(other.getByRole('link', { name: 'Enter room' })).toBeVisible();

  await page.getByRole('button', { name: 'Dismiss one-time links' }).click();
  let issueRequests = 0;
  await page.route(`**/api${roomPath}/passes`, async (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    issueRequests += 1;
    await route.fetch();
    await route.abort('failed');
  });
  await page.getByLabel('Number of passes').fill('1');
  await page.getByRole('button', { name: 'Generate passes' }).click();
  await expect(page.getByRole('alert')).toContainText('uncertain response may have created passes');
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(page.getByRole('row').filter({ hasText: '#4' })).toContainText('available');
  expect(issueRequests).toBe(1);
  await page.unroute(`**/api${roomPath}/passes`);

  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(await page.locator('.passes-panel').evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
  expect(pageErrors).toEqual([]);
  await attendeeContext.close();
  await otherContext.close();
});
