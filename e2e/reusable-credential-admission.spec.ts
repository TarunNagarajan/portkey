import { expect, test } from '@playwright/test';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

test('reusable credential enrolls once and proves privately in two rooms', async ({ page, browser }) => {
  test.setTimeout(180_000);
  const evidenceDirectory = resolve('..', 'outputs', 'private-admission-rules');
  await mkdir(evidenceDirectory, { recursive: true });
  const pageErrors: string[] = [];
  const proofBodies: string[] = [];
  page.on('pageerror', error => pageErrors.push(error.message));

  async function createGroup(name: string) {
    await page.goto('/credential-groups');
    await page.getByLabel('Group name').fill(name);
    await page.getByRole('button', { name: 'Create group' }).click();
    await expect(page.getByRole('heading', { name })).toBeVisible();
    await page.getByLabel('Number of enrollment links').fill('1');
    await page.getByRole('button', { name: 'Issue enrollment links' }).click();
    const link = page.locator('.enrollment-batch .join-link');
    await expect(link).toBeVisible();
    const enrollmentUrl = await link.getAttribute('href') as string;
    const qr = page.locator('.enrollment-qr');
    await expect(qr).toBeVisible();
    await expect(qr).toHaveAttribute('src', /^data:image\/png;base64,/);
    const qrSource = await qr.getAttribute('src');
    expect(qrSource).toMatch(/^data:image\/png;base64,/);
    const suffix = name.toLowerCase().replaceAll(/[^a-z0-9]+/g, '-');
    await writeFile(join(evidenceDirectory, `${suffix}-enrollment-qr.png`), Buffer.from(qrSource!.split(',')[1], 'base64'));
    await writeFile(join(evidenceDirectory, `${suffix}-enrollment-url.sha256`), `${createHash('sha256').update(enrollmentUrl).digest('hex')}\n`, 'utf8');
    await page.screenshot({ path: join(evidenceDirectory, `${suffix}-organizer-desktop.png`), fullPage: true });
    return { id: new URL(page.url()).pathname.split('/').at(-1)!, enrollmentUrl };
  }

  const groupA = await createGroup('Reusable attendees');
  const groupB = await createGroup('Reusable mentors');
  const participantContext = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const participant = await participantContext.newPage();
  const participantSecondTab = await participantContext.newPage();
  participant.on('pageerror', error => pageErrors.push(error.message));
  const admissionBodies: string[] = [];
  participant.on('request', request => {
    if (new URL(request.url()).pathname.endsWith('/prove') && request.postData()) proofBodies.push(request.postData()!);
    if (request.method() === 'POST' && new URL(request.url()).pathname.includes('/join/')) admissionBodies.push(request.postData() ?? '');
  });

  await participant.goto(groupA.enrollmentUrl);
  const uppercaseEnrollmentUrl = new URL(groupA.enrollmentUrl);
  uppercaseEnrollmentUrl.pathname = uppercaseEnrollmentUrl.pathname.replace(groupA.id, groupA.id.toUpperCase());
  await participantSecondTab.goto(uppercaseEnrollmentUrl.toString());
  await expect(participant.getByRole('heading', { name: 'Reusable attendees' })).toBeVisible();
  await expect(participantSecondTab.getByRole('heading', { name: 'Reusable attendees' })).toBeVisible();
  let lostEnrollmentResponse = false;
  await participant.route('**/api/credentials/*/enroll', async route => {
    if (!lostEnrollmentResponse) {
      lostEnrollmentResponse = true;
      const response = await route.fetch();
      expect(response.status()).toBe(200);
      await route.abort('failed');
      return;
    }
    await route.continue();
  });
  await Promise.all([
    participant.getByRole('button', { name: 'Save credential in this browser' }).click(),
    participantSecondTab.getByRole('button', { name: 'Save credential in this browser' }).click(),
  ]);
  await expect(participant.getByText(/If the server response was lost, retry this same link/)).toBeVisible();
  await expect(participantSecondTab.getByText(/Credential saved and enrolled in this browser/)).toBeVisible();
  await participant.unroute('**/api/credentials/*/enroll');
  await participant.getByRole('button', { name: 'Save credential in this browser' }).click();
  await expect(participant.getByText(/Credential saved and enrolled in this browser/)).toBeVisible();
  await expect(participantSecondTab).not.toHaveURL(/enroll=/);
  await expect(participant).not.toHaveURL(/enroll=/);
  await participantSecondTab.close();
  await participant.reload();
  await expect(participant.getByText('Reusable attendees', { exact: true })).toBeVisible();
  await participant.getByRole('link', { name: 'My credentials' }).click();
  await expect(participant.getByRole('heading', { name: 'Reusable attendees' })).toBeVisible();
  await expect(participant.getByText(/This credential is saved in this browser/)).toBeVisible();

  const commitment = await participant.evaluate(async groupId => new Promise<string>((resolve, reject) => {
    const open = indexedDB.open('portkey-reusable-credentials', 1);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const request = open.result.transaction('credentials').objectStore('credentials').get(groupId);
      request.onsuccess = () => { const value = request.result?.commitment ?? ''; open.result.close(); resolve(value); };
      request.onerror = () => reject(request.error);
    };
  }), groupA.id);
  expect(commitment).toMatch(/^[1-9][0-9]+$/);
  await participant.goto(groupB.enrollmentUrl);
  await participant.getByRole('button', { name: 'Save credential in this browser' }).click();
  await expect(participant.getByText(/Credential saved and enrolled in this browser/)).toBeVisible();
  const damagedGroupId = randomUUID();
  await participant.evaluate(groupId => new Promise<void>((resolve, reject) => {
    const request = indexedDB.open('portkey-reusable-credentials', 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction('credentials', 'readwrite');
      tx.objectStore('credentials').put({ version: 1, groupId, privateKey: 'damaged', commitment: '1', name: 'Damaged record' });
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    };
  }), damagedGroupId);
  await participant.evaluate(() => new Promise<void>((resolve, reject) => {
    const request = indexedDB.open('portkey-workshop-credentials', 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains('identities')) request.result.createObjectStore('identities', { keyPath: 'roomId' });
    };
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction('identities', 'readwrite');
      tx.objectStore('identities').put({ roomId: 'legacy-sentinel', privateKey: 'unchanged' });
      tx.oncomplete = () => { db.close(); resolve(); };
      tx.onerror = () => { db.close(); reject(tx.error); };
    };
  }));
  await participant.goto('/my-credentials');
  await expect(participant.getByRole('heading', { name: 'Reusable attendees' })).toBeVisible();
  await expect(participant.getByRole('heading', { name: 'Reusable mentors' })).toBeVisible();
  await expect(participant.getByRole('heading', { name: 'Damaged credential' })).toBeVisible();
  participant.once('dialog', dialog => dialog.accept());
  await participant.getByRole('button', { name: 'Reset this credential' }).click();
  await expect(participant.getByRole('heading', { name: 'Damaged credential' })).toHaveCount(0);
  const legacyCredential = await participant.evaluate(() => new Promise<string>((resolve, reject) => {
    const request = indexedDB.open('portkey-workshop-credentials', 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const get = db.transaction('identities').objectStore('identities').get('legacy-sentinel');
      get.onsuccess = () => { db.close(); resolve(get.result?.privateKey ?? ''); };
      get.onerror = () => { db.close(); reject(get.error); };
    };
  }));
  expect(legacyCredential).toBe('unchanged');
  const remainingCredentials = await participant.evaluate(() => new Promise<string[]>((resolve, reject) => {
    const request = indexedDB.open('portkey-reusable-credentials', 1);
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const get = db.transaction('credentials').objectStore('credentials').getAll();
      get.onsuccess = () => { db.close(); resolve(get.result.map((record: { groupId: string }) => record.groupId)); };
      get.onerror = () => { db.close(); reject(get.error); };
    };
  }));
  expect(remainingCredentials).not.toContain(damagedGroupId);
  expect(remainingCredentials).toContain(groupA.id);
  expect(remainingCredentials).toContain(groupB.id);

  const roomLinks: string[] = [];
  let failInitialRuleRead = true;
  await page.route('**/api/rooms/*/proof-rule', async route => {
    if (failInitialRuleRead) {
      failInitialRuleRead = false;
      await route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: { code: 'TEMPORARY_FAILURE', message: 'Temporary rule read failure.' } }),
      });
      return;
    }
    await route.continue();
  });
  for (const [index, title] of ['Reusable room one', 'Reusable room two'].entries()) {
    await page.goto('/');
    await page.getByLabel('Room title').fill(title);
    await page.getByLabel('Admission').selectOption('proof');
    await page.getByRole('button', { name: 'Create draft' }).click();
    await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/i);
    if (index === 0) {
      await expect(page.getByRole('button', { name: 'Retry loading admission source' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Save admission source' })).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'Open room', exact: true })).toBeDisabled();
      await page.getByRole('button', { name: 'Retry loading admission source' }).click();
      await expect(page.getByLabel('Reusable credential groups')).toBeVisible();
    }
    await page.getByLabel('Reusable credential groups').check();
    await page.locator('.group-choice-list input[type="checkbox"]').nth(0).check();
    await page.locator('.group-choice-list input[type="checkbox"]').nth(1).check();
    await page.getByRole('button', { name: 'Save admission source' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Admission source saved' })).toBeVisible();
    await page.getByRole('button', { name: 'Enable encrypted inbox' }).click();
    await expect(page.getByText('Encrypted inbox enabled.', { exact: false })).toBeVisible();
    await page.getByRole('button', { name: 'Open room', exact: true }).click();
    const roomLink = page.locator('.share-room .join-link');
    await expect(roomLink).toBeVisible();
    const href = await roomLink.getAttribute('href') as string;
    expect(href).toMatch(/#key=[a-f0-9]{64}$/);
    roomLinks.push(href);
    if (index === 0) {
      await expect(page.getByText(/Reusable rule: a credential from (Reusable attendees or Reusable mentors|Reusable mentors or Reusable attendees)/)).toBeVisible();
    }
  }

  const outsiderContext = await browser.newContext();
  const outsider = await outsiderContext.newPage();
  await outsider.goto(roomLinks[0]);
  await expect(outsider.getByText(/This browser has no saved credential from the accepted groups/)).toBeVisible();
  await expect(outsider.getByRole('button', { name: 'Prove membership and enter' })).toHaveCount(0);
  await outsiderContext.close();

  for (let index = 0; index < roomLinks.length; index += 1) {
    await participant.goto(roomLinks[index]);
    await expect(participant.getByRole('heading', { name: index === 0 ? 'Reusable room one' : 'Reusable room two' })).toBeVisible();
    await expect(participant.getByRole('button', { name: 'Prove membership and enter' })).toBeVisible();
    await participant.getByRole('button', { name: 'Prove membership and enter' }).click();
    await expect(participant).toHaveURL(/\/rooms\/[a-f0-9-]+#key=[a-f0-9]{64}$/i, { timeout: 140_000 });
  }

  expect(proofBodies).toHaveLength(2);
  for (const value of proofBodies) {
    const body = JSON.parse(value) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(['challengeId', 'proof']);
    expect(value).not.toContain(groupA.id);
    expect(value).not.toContain(groupB.id);
    expect(value).not.toContain('Reusable attendees');
    expect(value).not.toContain('Reusable mentors');
    expect(value).not.toContain(commitment);
    expect(value).not.toContain('privateKey');
  }
  expect(admissionBodies.filter(value => value.includes('challengeId'))).toHaveLength(2);
  const fixture = { name: 'reusable notes.txt', mimeType: 'text/plain', buffer: Buffer.from('reusable admission encrypted roundtrip') };
  await participant.getByLabel('Choose a file (up to 250 MiB)').setInputFiles(fixture);
  await participant.getByRole('button', { name: 'Submit file privately' }).click();
  await expect(participant.getByText(/Submission accepted at/)).toBeVisible({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Refresh inbox' }).click();
  await expect(page.getByRole('button', { name: 'Decrypt and download' })).toBeVisible();
  await page.evaluate(() => Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: undefined }));
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Decrypt and download' }).click();
  const download = await downloadEvent;
  expect(await readFile((await download.path())!, 'utf8')).toBe(fixture.buffer.toString());

  await participant.goto('/my-credentials');
  const mentorCard = participant.locator('section.panel').filter({ has: participant.getByRole('heading', { name: 'Reusable mentors' }) });
  participant.once('dialog', dialog => dialog.accept());
  await mentorCard.getByRole('button', { name: 'Forget this credential' }).click();
  await expect(mentorCard).toHaveCount(0);
  await expect(participant.getByRole('heading', { name: 'Reusable attendees' })).toBeVisible();
  expect(await participant.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(pageErrors).toEqual([]);
  await participant.screenshot({ path: join(evidenceDirectory, 'reusable-credential-admission-mobile.png'), fullPage: true });
  await participantContext.close();
});
