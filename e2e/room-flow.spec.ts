import { test, expect } from '@playwright/test';

test('organizer creates and manages a room; a mobile participant requests access', async ({
  page,
  browser,
}) => {
  const failures: string[] = [];
  page.on('pageerror', (error) => failures.push(error.message));
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Your rooms', exact: true })).toBeVisible();
  await page.getByLabel('Room title').fill('Design workshop');
  await page
    .getByLabel('Public description')
    .fill('Bring your draft. Use a team label to request entry.');
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

  const mobile = await browser.newContext({
    viewport: { width: 390, height: 844 },
    isMobile: true,
    hasTouch: true,
  });
  const participant = await mobile.newPage();
  participant.on('pageerror', (error) => failures.push(error.message));
  await participant.goto(link!);
  await participant.getByLabel('Your label').fill('Team Cedar');
  await participant.getByRole('button', { name: 'Request access' }).click();
  await expect(participant.getByRole('status')).toContainText('Waiting for organizer approval');
  const unauthorized = await mobile.request.get(`${new URL(page.url()).origin}/api${roomPath}`);
  expect(unauthorized.status()).toBe(403);

  const row = page.getByRole('row').filter({ hasText: 'Team Cedar' });
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(participant.getByRole('link', { name: 'Enter room' })).toBeVisible();
  await participant.getByRole('link', { name: 'Enter room' }).click();
  await expect(
    participant.getByText('You have organizer-approved access', { exact: false }),
  ).toBeVisible();
  expect(
    await participant.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
  ).toBe(true);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: '../outputs/Portkey_Room_Management_Desktop.png', fullPage: true });
  await participant.screenshot({
    path: '../outputs/Portkey_Room_Management_Mobile.png',
    fullPage: true,
  });

  await row.getByRole('button', { name: 'Remove access' }).click();
  await participant.reload();
  await expect(participant.getByText('Organizer approval is required.')).toBeVisible();
  page.once('dialog', (dialog) => void dialog.accept());
  await page.getByRole('button', { name: 'Close room', exact: true }).click();
  await expect(page.getByText('This room has closed. New admission is disabled.')).toBeVisible();
  await participant.goto(link!);
  await expect(participant.getByText('This room has closed.', { exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByText('This room has closed. New admission is disabled.')).toBeVisible();
  expect(failures).toEqual([]);
  await mobile.close();
});

test('rooms can be searched, filtered and reused for another workshop', async ({ page }) => {
  await page.goto('/');
  await page.getByLabel('Room title').fill('Photography basics');
  await page.getByLabel('Public description').fill('Lighting and composition');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  const originalPath = new URL(page.url()).pathname;
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  await page.getByRole('link', { name: 'Your rooms', exact: true }).click();
  await page.getByLabel('Room title').fill('Design sprint');
  await page.getByLabel('Public description').fill('A new brief for the next event');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  await page.getByRole('link', { name: 'Your rooms', exact: true }).click();

  const rooms = page.locator('.room-list > li');
  await expect(rooms).toHaveCount(2);
  await page.getByLabel('Search rooms').fill('lighting');
  await expect(rooms).toHaveCount(1);
  await expect(rooms.first()).toContainText('Photography basics');
  await page.getByLabel('Filter rooms by status').selectOption('draft');
  await expect(page.getByRole('heading', { name: 'No matching rooms' })).toBeVisible();
  await page.getByRole('button', { name: 'Clear filters' }).click();
  await expect(rooms).toHaveCount(2);
  await page.getByLabel('Filter rooms by status').selectOption('open');
  await expect(rooms).toHaveCount(1);
  await page.getByLabel('Filter rooms by status').selectOption('all');
  await page.screenshot({ path: '../outputs/Portkey_Workspace_Desktop.png', fullPage: true });

  await page.getByRole('link', { name: 'Use Photography basics as template', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Reuse a room' })).toBeVisible();
  await expect(page.getByLabel('Room title')).toHaveValue('Photography basics');
  await expect(page.getByLabel('Public description')).toHaveValue('Lighting and composition');
  await page.getByLabel('Room title').fill('Photography — session two');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  expect(new URL(page.url()).pathname).not.toBe(originalPath);
  await expect(page.getByRole('button', { name: 'Open room', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'No requests yet' })).toBeVisible();
  await page.getByRole('link', { name: 'Your rooms', exact: true }).click();
  await expect(rooms).toHaveCount(3);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.screenshot({ path: '../outputs/Portkey_Workspace_Mobile.png', fullPage: true });
});
