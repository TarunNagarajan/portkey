import { test, expect } from '@playwright/test';

test('submission retention is disclosed on creation and join, and historical opt-in requires confirmation', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  await expect(page.getByLabel('Room title')).toBeVisible();
  await expect(page.getByText('Encrypted private submissions and shared files are automatically removed after this deadline', { exact: false })).toBeVisible();
  await page.getByLabel('Room title').fill('Retention workflow');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  const roomId = new URL(page.url()).pathname.split('/').at(-1)!;
  await expect(page.getByText('Completed encrypted private submissions and shared files are scheduled for removal after the room deadline', { exact: false })).toBeVisible();
  const joinCode = await page.evaluate(async (id) => {
    const response = await fetch('/api/rooms/' + id);
    return (await response.json()).joinCode as string;
  }, roomId);
  await page.goto('/join/' + joinCode);
  await expect(page.getByText('Completed encrypted private submissions and shared files are scheduled for removal after this deadline', { exact: false })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  const joinCard = page.locator('.join-page');
  expect((await joinCard.boundingBox())!.width).toBeLessThanOrEqual(390);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: 'test-results/submission-retention-mobile.png', fullPage: true });

  await page.setViewportSize({ width: 1440, height: 1000 });
  let enabled = false;
  let completed = false;
  let enableCalls = 0;
  await page.route('**/api/rooms/' + roomId, async (route) => {
    const response = await route.fetch();
    const value = await response.json();
    value.submissionCleanupEnabled = enabled;
    value.submissionsPurgedAt = completed ? new Date().toISOString() : null;
    await route.fulfill({ response, json: value });
  });
  await page.route('**/api/rooms/' + roomId + '/submission-cleanup', async (route) => {
    enableCalls++;
    expect(route.request().postData()).toBe('{}');
    const response = await route.fetch();
    enabled = true;
    await route.fulfill({ response });
  });
  await page.goto('/rooms/' + roomId);
  await expect(page.getByRole('button', { name: 'Enable automatic deletion' })).toBeVisible();
  page.once('dialog', (dialog) => { void dialog.dismiss(); });
  await page.getByRole('button', { name: 'Enable automatic deletion' }).click();
  expect(enableCalls).toBe(0);
  await expect(page.getByRole('button', { name: 'Enable automatic deletion' })).toBeVisible();
  page.once('dialog', (dialog) => { void dialog.accept(); });
  await page.getByRole('button', { name: 'Enable automatic deletion' }).click();
  await expect(page.getByRole('button', { name: 'Enable automatic deletion' })).toBeHidden();
  expect(enableCalls).toBe(1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: 'test-results/submission-retention-desktop.png', fullPage: true });
  completed = true;
  await page.reload();
  await expect(page.getByText('The server removed this room’s encrypted private submissions and shared files after its deadline.', { exact: true })).toBeVisible();
  await page.goto('/?template=' + roomId + '#new-room');
  await expect(page.getByText('Encrypted private submissions and shared files are automatically removed after this deadline', { exact: false })).toBeVisible();
});
