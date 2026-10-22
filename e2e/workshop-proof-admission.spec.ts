import { expect, test } from '@playwright/test';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

test('workshop proof enrollment saves locally, survives reload, enters directly, and keeps the encrypted inbox', async ({ page, browser }) => {
  test.setTimeout(180_000);
  const evidenceDirectory = resolve('..', 'outputs', 'workshop-zk');
  await mkdir(evidenceDirectory, { recursive: true });
  const pageErrors: string[] = [];
  const consoleErrors: string[] = [];
  const requestBodies: string[] = [];
  const proofBodies: string[] = [];
  const requestFailures: { url: string; errorText: string }[] = [];
  let challengeRequests = 0;
  let busyResponseInjected = false;
  let enrollmentResponseLost = false;
  let lostEnrollmentRequestUrl = '';
  page.on('pageerror', (error) => pageErrors.push(error.message));
  await page.goto('/');
  await page.getByLabel('Room title').fill('Credential proof workshop');
  await page.getByLabel('Admission').selectOption('proof');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  const roomPath = new URL(page.url()).pathname;
  await page.getByRole('button', { name: 'Enable encrypted inbox' }).click();
  await expect(page.getByText('Encrypted inbox enabled.', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Workshop credential enrollment' })).toBeVisible();
  await expect(page.getByText(/Groups of fewer than three have little cover/)).toBeVisible();
  await page.getByRole('button', { name: 'Issue enrollment links' }).click();
  const enrollmentLink = await page.locator('.proof-enrollments .join-link').getAttribute('href');
  expect(enrollmentLink).toMatch(/\/join\/[A-Za-z0-9_-]{16,}#key=[a-f0-9]{64}&enroll=[A-Za-z0-9_-]{43}$/);
  const enrollmentToken = new URLSearchParams(new URL(enrollmentLink!).hash.slice(1)).get('enroll')!;
  const enrollmentQr = page.getByRole('img', { name: /QR code for enrollment/ });
  await expect(enrollmentQr).toHaveAttribute('src', /^data:image\/png;base64,/);
  const qrSource = await enrollmentQr.getAttribute('src');
  await writeFile(join(evidenceDirectory, 'enrollment-qr.png'), Buffer.from(qrSource!.split(',')[1], 'base64'));
  await writeFile(join(evidenceDirectory, 'enrollment-url.sha256'), `${createHash('sha256').update(enrollmentLink!).digest('hex')}\n`, 'utf8');
  await page.screenshot({ path: join(evidenceDirectory, 'owner-desktop.png'), fullPage: true });

  const participantContext = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const participant = await participantContext.newPage();
  participant.on('pageerror', (error) => pageErrors.push(error.message));
  participant.on('console', (message) => { if (message.type() === 'error') consoleErrors.push(message.text()); });
  participant.on('requestfailed', (request) => requestFailures.push({ url: request.url(), errorText: request.failure()?.errorText ?? '' }));
  const assetResponses = new Map<string, { status: number; type: string }>();
  participant.on('response', (response) => {
    const name = new URL(response.url()).pathname.split('/').at(-1);
    if (name === 'semaphore-10.wasm' || name === 'semaphore-10.zkey')
      assetResponses.set(name, { status: response.status(), type: response.headers()['content-type'] ?? '' });
  });
  participant.on('request', (request) => {
    if (request.postData()) requestBodies.push(request.postData()!);
    if (request.url().includes('/proof-challenge')) challengeRequests += 1;
    if (request.url().endsWith('/prove') && request.postData()) proofBodies.push(request.postData()!);
  });
  await participant.route('**/api/join/*/prove', async (route) => {
    if (busyResponseInjected) return route.continue();
    busyResponseInjected = true;
    await route.fulfill({ status: 429, contentType: 'application/json', body: JSON.stringify({ error: { code: 'PROOF_BUSY', message: 'Proof checks are busy.' } }) });
  });
  await participant.addInitScript(() => {
    type Violation = { directive: string; blockedURI: string; sourceFile: string; line: number; originalPolicy: string };
    (window as Window & { workshopCspViolations?: Violation[] }).workshopCspViolations = [];
    window.addEventListener('securitypolicyviolation', (event) => {
      (window as Window & { workshopCspViolations?: Violation[] }).workshopCspViolations?.push({
        directive: event.violatedDirective,
        blockedURI: event.blockedURI,
        sourceFile: event.sourceFile,
        line: event.lineNumber,
        originalPolicy: event.originalPolicy,
      });
    });
  });
  await participant.route('**/api/join/*/enroll', async (route) => {
    if (enrollmentResponseLost) return route.continue();
    const response = await route.fetch();
    expect(response.status()).toBe(200);
    enrollmentResponseLost = true;
    lostEnrollmentRequestUrl = route.request().url();
    await route.abort('failed');
  });
  const documentResponse = await participant.goto(enrollmentLink!);
  const builtAssets = test.info().project.metadata.builtAssets === true;
  const cspResponse = builtAssets
    ? documentResponse
    : await participant.request.get(new URL(enrollmentLink!).origin + '/api/health');
  const csp = cspResponse?.headers()['content-security-policy'] ?? '';
  expect(cspResponse?.ok()).toBe(true);
  expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
  expect(csp).toContain("worker-src 'self' blob:");
  expect(csp).not.toContain("'unsafe-eval'");
  await expect(participant).toHaveURL(/#key=[a-f0-9]{64}&enroll=[A-Za-z0-9_-]{43}$/);
  await participant.getByRole('button', { name: 'Save workshop credential' }).click();
  await expect(participant.getByText(/enrollment request did not confirm/i)).toBeVisible();
  const nextOwnerPoll = page.waitForResponse((response) => response.request().method() === 'GET'
    && response.url().includes(`/api/rooms/${new URL(page.url()).pathname.split('/').at(-1)}/enrollments`) && response.ok());
  await nextOwnerPoll;
  await expect(page.getByText('1 enrolled', { exact: false })).toBeVisible();
  await expect(participant.getByText(/enrollment request did not confirm/i)).toBeVisible();
  const secretBeforeRetry = await participant.evaluate(async () => new Promise<string>((resolve, reject) => {
    const open = indexedDB.open('portkey-workshop-credentials', 1);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const request = open.result.transaction('identities').objectStore('identities').getAll();
      request.onsuccess = () => { const value = request.result[0]?.privateKey; open.result.close(); resolve(value); };
      request.onerror = () => reject(request.error);
    };
  }));
  await participant.unroute('**/api/join/*/enroll');
  await participant.getByRole('button', { name: 'Save or retry enrollment' }).click();
  await expect(participant.getByText(/Credential saved and enrolled/)).toBeVisible();
  await expect(participant).toHaveURL(/#key=[a-f0-9]{64}$/);
  await expect(participant.getByText(/Small groups offer little privacy/)).toBeVisible();
  expect(participant.url()).not.toContain(enrollmentToken);
  const credentialSecret = await participant.evaluate(async () => new Promise<string>((resolve, reject) => {
    const open = indexedDB.open('portkey-workshop-credentials', 1);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const request = open.result.transaction('identities').objectStore('identities').getAll();
      request.onsuccess = () => { const value = request.result[0]?.privateKey; open.result.close(); resolve(value); };
      request.onerror = () => reject(request.error);
    };
  }));
  expect(credentialSecret).toBeTruthy();
  expect(credentialSecret).toBe(secretBeforeRetry);
  expect(requestBodies.join('\n')).not.toContain(credentialSecret);
  await participant.screenshot({ path: join(evidenceDirectory, 'credential-saved-mobile.png'), fullPage: true });
  expect(await participant.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(await participant.locator('.workshop-admission').evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
  await participant.reload();
  await expect(participant.getByRole('button', { name: 'Prove membership and enter' })).toBeVisible();
  await expect(participant).toHaveURL(/#key=[a-f0-9]{64}$/);
  await participant.getByRole('button', { name: 'Prove membership and enter' }).click();
  await expect(participant).toHaveURL((url) => url.pathname === roomPath && /^#key=[a-f0-9]{64}$/.test(url.hash), { timeout: 140_000 });
  expect(challengeRequests).toBe(1);
  expect(busyResponseInjected).toBe(true);
  expect(proofBodies).toHaveLength(2);
  expect(JSON.parse(proofBodies[1])).toEqual(JSON.parse(proofBodies[0]));
  expect(assetResponses.get('semaphore-10.wasm')).toMatchObject({ status: 200, type: 'application/wasm' });
  expect(assetResponses.get('semaphore-10.zkey')?.status).toBe(200);
  expect(await participant.evaluate(() => (window as Window & { workshopCspViolations?: unknown[] }).workshopCspViolations)).toEqual([]);
  expect(requestFailures).toEqual([{ url: lostEnrollmentRequestUrl, errorText: 'net::ERR_FAILED' }]);
  expect(lostEnrollmentRequestUrl).toMatch(/\/api\/join\/[^/]+\/enroll$/);
  expect(consoleErrors.filter((message) => ![
    'Failed to load resource: net::ERR_FAILED',
    'Failed to load resource: the server responded with a status of 429 (Too Many Requests)',
  ].includes(message))).toEqual([]);
  expect(consoleErrors.filter((message) => message === 'Failed to load resource: net::ERR_FAILED').length).toBeLessThanOrEqual(1);
  expect(consoleErrors.filter((message) => message === 'Failed to load resource: the server responded with a status of 429 (Too Many Requests)').length).toBeLessThanOrEqual(1);
  await expect(participant.getByRole('heading', { name: 'Encrypted submission inbox' })).toBeVisible();
  expect(participant.url()).not.toContain('enroll=');
  expect(requestBodies.join('\n')).not.toContain(credentialSecret);
  const proofRequest = requestBodies.find((body) => body.includes('challengeId'));
  expect(proofRequest).toBeTruthy();
  expect(proofRequest).not.toContain('privateKey');
  await participant.screenshot({ path: join(evidenceDirectory, 'admitted-mobile.png'), fullPage: true });

  const fixture = { name: 'workshop notes.txt', mimeType: 'text/plain', buffer: Buffer.from('private proof workshop notes') };
  await participant.getByLabel('Choose a file (up to 250 MiB)').setInputFiles(fixture);
  await participant.getByRole('button', { name: 'Submit file privately' }).click();
  await expect(participant.getByText(/Submission accepted at/)).toBeVisible({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Refresh inbox' }).click();
  await expect(page.getByRole('button', { name: 'Decrypt and download' })).toBeVisible();
  await page.evaluate(() => Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: undefined }));
  const decryptedDownload = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Decrypt and download' }).click();
  const decrypted = await decryptedDownload;
  expect(await readFile((await decrypted.path())!, 'utf8')).toBe(fixture.buffer.toString());

  const noCredentialContext = await browser.newContext();
  const noCredential = await noCredentialContext.newPage();
  const publicPreview = new URL(enrollmentLink!);
  publicPreview.hash = '';
  await noCredential.goto(publicPreview.toString());
  await expect(noCredential.getByText(/This public room link does not grant access/)).toBeVisible();
  await expect(noCredential.getByRole('button', { name: 'Prove membership and enter' })).toHaveCount(0);
  expect(pageErrors).toEqual([]);
  await participantContext.close();
  await noCredentialContext.close();
});
