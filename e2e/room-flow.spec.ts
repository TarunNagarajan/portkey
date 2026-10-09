import { test, expect } from '@playwright/test';

test('organizer creates and manages a room; a mobile participant requests access', async ({ page, browser }) => {
  const failures: string[] = [];
  page.on('pageerror', error => failures.push(error.message));
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'A room for the event.' })).toBeVisible();
  await page.getByLabel('Room title').fill('Design workshop');
  await page.getByLabel('Public description').fill('Bring your draft. Use a team label to request entry.');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  const roomPath = new URL(page.url()).pathname;
  await page.getByRole('button', { name: 'Edit details' }).click();
  await page.getByLabel('Public description').fill('A temporary room for workshop participants.');
  await page.getByRole('button', { name: 'Save details' }).click();
  await expect(page.getByText('A temporary room for workshop participants.')).toBeVisible();
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  const qr = page.getByRole('img', { name: 'QR code for this room’s join link' });
  await expect(qr).toHaveAttribute('src', /^data:image\/png/);
  const link = await page.locator('.join-link').getAttribute('href');
  expect(link).toBeTruthy();

  const mobile = await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true });
  const participant = await mobile.newPage();
  participant.on('pageerror', error => failures.push(error.message));
  await participant.goto(link!);
  await participant.getByLabel('Your label').fill('Team Cedar');
  await participant.getByRole('button', { name: 'Request access' }).click();
  await expect(participant.getByRole('status')).toContainText('Waiting for organizer approval');
  const unauthorized = await mobile.request.get(`http://localhost:5173/api${roomPath}`);
  expect(unauthorized.status()).toBe(403);

  const row = page.getByRole('row').filter({ hasText: 'Team Cedar' });
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(participant.getByRole('link', { name: 'Enter room' })).toBeVisible();
  await participant.getByRole('link', { name: 'Enter room' }).click();
  await expect(participant.getByText('You have organizer-approved access', { exact: false })).toBeVisible();
  expect(await participant.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: '../outputs/Portkey_Room_Management_Desktop.png', fullPage: true });
  await participant.screenshot({ path: '../outputs/Portkey_Room_Management_Mobile.png', fullPage: true });

  await row.getByRole('button', { name: 'Remove access' }).click();
  await participant.reload();
  await expect(participant.getByText('Organizer approval is required.')).toBeVisible();
  page.once('dialog', dialog => void dialog.accept());
  await page.getByRole('button', { name: 'Close room', exact: true }).click();
  await expect(page.getByText('This room has closed. New admission is disabled.')).toBeVisible();
  await participant.goto(link!);
  await expect(participant.getByText('This room has closed.', { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText('This room has closed. New admission is disabled.')).toBeVisible();
  expect(failures).toEqual([]);
  await mobile.close();
});
