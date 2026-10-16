import { expect, test } from '@playwright/test';

test('sharing controls stay unavailable when public config is missing or malformed', async ({ page }) => {
  let mode: 'null' | 'malformed' | 'unavailable' = 'null';
  const sessionStarts: string[] = [];
  page.on('request', request => {
    if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/session') sessionStarts.push(request.url());
  });
  await page.route('**/api/config', route => {
    if (mode === 'unavailable') return route.abort();
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: mode === 'null' ? 'null' : '{',
    });
  });
  for (const next of ['null', 'malformed', 'unavailable'] as const) {
    mode = next;
    await page.goto('/');
    await expect(page.getByRole('alert')).toContainText(/invitation address/i);
    await expect(page.getByRole('button', { name: 'Create draft' })).toHaveCount(0);
  }
  expect(sessionStarts).toEqual([]);
});

test('canonical mismatch link stays on the configured host and retains the browser fragment', async ({ page }) => {
  const sessionStarts: string[] = [];
  const requests: string[] = [];
  page.on('request', request => {
    requests.push(request.url());
    if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/session') sessionStarts.push(request.url());
  });
  await page.route('**/api/config', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ publicOrigin: 'https://portkey.onrender.com' }),
  }));
  await page.goto('http://localhost:5174//attacker.example/join/Ab_cd-1234567890?from=invite#key=secret');
  await expect(page.getByRole('heading', { name: 'Open Portkey at its configured address' })).toBeVisible();
  const href = await page.getByRole('link', { name: 'Open the configured Portkey address' }).getAttribute('href');
  expect(new URL(href!).origin).toBe('https://portkey.onrender.com');
  expect(new URL(href!).hash).toBe('#key=secret');
  expect(sessionStarts).toEqual([]);
  expect(requests.every(url => !url.includes('#key=secret'))).toBe(true);
});

test('local rooms show a concise phone-sharing notice beside invitations', async ({ page }) => {
  await page.goto('/');
  const warning = 'This local address is for this computer. Phone sharing needs a public HTTPS address.';
  await expect(page.getByText(warning, { exact: true })).toBeVisible();
  await page.getByLabel('Room title').fill('Local phone demo');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page).toHaveURL(/\/rooms\/[a-f0-9-]+$/);
  await page.getByRole('button', { name: 'Open room', exact: true }).click();
  await expect(page.locator('.share-room').getByText(warning, { exact: true })).toBeVisible();
});
