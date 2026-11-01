import { readFileSync, writeFileSync } from 'node:fs';
import { test, expect } from '@playwright/test';
import { issueCredential, type IssuerKeyFile } from '../scripts/issuerLib.js';

const issuer = JSON.parse(
  readFileSync(new URL('../fixtures/dev-issuer.json', import.meta.url), 'utf8'),
) as IssuerKeyFile;

test('a credential proof admits the holder and one credential holds one seat', async ({
  page,
  browser,
}, testInfo) => {
  test.setTimeout(240_000);

  await page.goto('/');
  await page.getByLabel('Room title').fill('Zero-knowledge seminar');
  await page.getByLabel('Require a university credential proof').check();
  await page.getByLabel('Department').selectOption({ label: 'Computer Science (CSE)' });
  await page.getByLabel('Class of').fill('2026');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);

  await expect(page.getByRole('heading', { name: 'Credential gate' })).toBeVisible();
  await expect(page.getByText(/Admits/)).toContainText('class of 2026');
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  const invite = await page.locator('.join-link').getAttribute('href');
  expect(invite).toMatch(/\/join\//);

  const credentialPath = testInfo.outputPath('credential.json');
  const credential = issueCredential(issuer, { dept: 1, year: 2026 });
  writeFileSync(credentialPath, JSON.stringify(credential));

  const studentContext = await browser.newContext({
    viewport: { width: 390, height: 844 },
    ...(browser.browserType().name() === 'firefox' ? {} : { isMobile: true }),
    hasTouch: true,
  });
  const student = await studentContext.newPage();
  const posted: string[] = [];
  student.on('request', (request) => {
    const body = request.postData();
    if (body) posted.push(body);
  });
  await student.goto(invite!);
  await expect(student.getByText(/This room admits/)).toContainText('class of 2026');
  await student.getByLabel('Your label').fill('Team Cedar');
  await student.getByLabel('Credential file').setInputFiles(credentialPath);
  await expect(student.getByText(/class of 2026/).last()).toBeVisible();
  await student.getByRole('button', { name: 'Prove eligibility & request access' }).click();

  await expect(student.getByRole('link', { name: 'Enter room' })).toBeVisible({
    timeout: 120_000,
  });
  await student.getByRole('link', { name: 'Enter room' }).click();
  await expect(student.getByText('You’re in.')).toBeVisible();
  await expect(student.getByText(/credential proof admitted this browser/)).toBeVisible();

  // The browser sends the proof, never the credential's secret or signature.
  const sent = posted.join('\n');
  expect(sent).toContain('publicSignals');
  expect(sent).not.toContain(credential.secret);
  expect(sent).not.toContain(credential.signature.S);

  const memberRow = page.getByRole('row').filter({ hasText: 'Team Cedar' });
  await expect(memberRow).toContainText('proved', { timeout: 20_000 });

  const secondContext = await browser.newContext();
  const second = await secondContext.newPage();
  await second.goto(invite!);
  await second.getByLabel('Your label').fill('Team Birch');
  await second.getByLabel('Credential file').setInputFiles(credentialPath);
  await second.getByRole('button', { name: 'Prove eligibility & request access' }).click();
  await expect(second.getByRole('alert')).toContainText('already taken the seat', {
    timeout: 120_000,
  });
});


test('a pending participant can prove eligibility after the organizer adds a gate', async ({ page, browser }, testInfo) => {
  test.setTimeout(120_000);
  await page.goto('/');
  await page.getByLabel('Room title').fill('Gate added after request');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  const invite = await page.locator('.join-link').getAttribute('href');
  const context = await browser.newContext();
  const student = await context.newPage();
  try {
    await student.goto(invite!);
    await student.getByLabel('Your label').fill('Early student');
    await student.getByRole('button', { name: 'Request access', exact: true }).click();
    await expect(student.getByRole('status')).toContainText('Waiting for organizer approval');
    await page.getByRole('button', { name: 'Require a credential', exact: true }).click();
    await page.getByLabel('Department').selectOption('1');
    await page.getByLabel('Class of').fill('2026');
    await page.getByRole('button', { name: 'Apply gate' }).click();
    await expect(student.getByLabel('Credential file')).toBeVisible();
    const path = testInfo.outputPath('early-student.json');
    writeFileSync(path, JSON.stringify(issueCredential(issuer, { dept: 1, year: 2026 })));
    await student.getByLabel('Your label').fill('Early student');
    await student.getByLabel('Credential file').setInputFiles(path);
    await student.getByRole('button', { name: 'Prove eligibility & request access' }).click();
    await expect(student.getByRole('link', { name: 'Enter room' })).toBeVisible({ timeout: 90_000 });
  } finally {
    await context.close();
  }
});

test('a student joining later downloads an earlier file while the organizer browser is closed', async ({ page, browser }, testInfo) => {
  test.setTimeout(180_000);
  await page.goto('/');
  await page.getByLabel('Room title').fill('Files for every student');
  await page.getByLabel('Require a university credential proof').check();
  await page.getByLabel('Department').selectOption('1');
  await page.getByLabel('Class of').fill('2026');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  await expect(page.locator('.join-link')).toHaveAttribute('href', /access=/);
  const invite = (await page.locator('.join-link').getAttribute('href'))!;
  await page.getByLabel('Choose a file (up to 250 MiB)').setInputFiles({ name: 'everyone.txt', mimeType: 'text/plain', buffer: Buffer.from('Earlier files for all admitted students') });
  await page.getByRole('button', { name: 'Encrypt and share with room' }).click();
  await expect(page.getByText(/All approved members can download it/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Download', exact: true })).toBeVisible();
  await page.close();
  const context = await browser.newContext();
  try {
    const student = await context.newPage();
    const requests: string[] = [];
    student.on('request', request => requests.push(request.url() + '\n' + (request.postData() ?? '')));
    await student.goto(invite);
    const credentialPath = testInfo.outputPath('late-student.json');
    writeFileSync(credentialPath, JSON.stringify(issueCredential(issuer, { dept: 1, year: 2026 })));
    await student.getByLabel('Your label').fill('Late student');
    await student.getByLabel('Credential file').setInputFiles(credentialPath);
    await student.getByRole('button', { name: 'Prove eligibility & request access' }).click();
    await student.getByRole('link', { name: 'Enter room' }).click();
    await expect(student.getByText('everyone.txt', { exact: true })).toBeVisible();
    await expect(student.getByRole('button', { name: 'Download', exact: true })).toBeVisible();
    await expect(student.getByRole('button', { name: 'Rotate encryption key' })).toHaveCount(0);
    await expect(student.getByText('Room access verification fingerprint:', { exact: false })).not.toBeVisible();
    await student.evaluate(() => Object.defineProperty(window, 'showSaveFilePicker', { configurable: true, value: undefined }));
    const event = student.waitForEvent('download');
    await student.getByRole('button', { name: 'Download', exact: true }).click();
    const file = await event;
    expect(file.suggestedFilename()).toBe('everyone.txt');
    const { readFile } = await import('node:fs/promises');
    expect(await readFile((await file.path())!, 'utf8')).toBe('Earlier files for all admitted students');
    const token = new URLSearchParams(new URL(invite).hash.slice(1)).get('access')!;
    expect(requests.join('\n')).not.toContain(token);
  } finally { await context.close(); }
});
