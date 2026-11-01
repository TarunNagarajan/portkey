import { test, expect } from '@playwright/test';

// Warangal, Telangana and a point far away in Hyderabad.
const warangal = { latitude: 17.9689, longitude: 79.5941 };
const hyderabad = { latitude: 17.385, longitude: 78.4867 };

test('a room restricted to an area only admits devices inside it', async ({ browser }) => {
  test.setTimeout(120_000);

  const ownerContext = await browser.newContext({
    geolocation: { ...warangal, accuracy: 100 },
    permissions: ['geolocation'],
  });
  const owner = await ownerContext.newPage();
  await owner.goto('/');
  await owner.getByLabel('Room title').fill('Warangal only');
  await owner.getByRole('button', { name: 'Create draft' }).click();
  await expect(owner).toHaveURL(/\/rooms\/[a-f0-9-]+$/);

  await owner.getByRole('button', { name: 'Set an area' }).click();
  await owner.getByRole('button', { name: 'Use my current location' }).click();
  await expect(owner.getByText('My current location', { exact: true })).toBeVisible();
  await owner.getByRole('button', { name: 'Apply area' }).click();
  await expect(owner.getByText(/Restricted to/)).toBeVisible();

  await owner.getByRole('button', { name: 'Open room', exact: true }).click();
  const invite = await owner.locator('.join-link').getAttribute('href');
  expect(invite).toMatch(/\/join\//);

  const insideContext = await browser.newContext({
    geolocation: { latitude: 17.96895, longitude: 79.59415, accuracy: 2500 },
    permissions: ['geolocation'],
  });
  const inside = await insideContext.newPage();
  await inside.goto(invite!);
  await inside.getByLabel('Your label').fill('Inside student');
  await inside.getByRole('button', { name: 'Share location & request access' }).click();
  await expect(inside.getByRole('button', { name: 'Getting precise location…' })).toBeVisible();
  // An approximate phone fix must not be submitted or clamped into an
  // apparently accurate reading. Wait for the browser to improve it.
  const pending = await insideContext.request.get(new URL('/api/join/' + new URL(invite!).pathname.split('/').pop(), invite!).href);
  expect((await pending.json()).membershipStatus).toBeNull();
  await insideContext.setGeolocation({ latitude: 17.96895, longitude: 79.59415, accuracy: 10 });
  await expect(
    inside.getByText('Waiting for organizer approval. This page updates automatically.'),
  ).toBeVisible();
  const insideRow = owner.getByRole('row').filter({ hasText: 'Inside student' });
  await expect(insideRow).toContainText('Inside');

  const outsideContext = await browser.newContext({
    geolocation: { ...hyderabad, accuracy: 10 },
    permissions: ['geolocation'],
  });
  const outside = await outsideContext.newPage();
  await outside.goto(invite!);
  await outside.getByLabel('Your label').fill('Outside student');
  await outside.getByRole('button', { name: 'Share location & request access' }).click();
  await expect(outside.getByRole('alert')).toContainText('outside this room');
});
