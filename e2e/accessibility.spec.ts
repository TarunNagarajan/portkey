import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
test('workspace, room controls and recovery form have no serious accessibility violations', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('/');
  const audit = async () => {
    const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
    expect(result.violations.filter(issue => ['serious', 'critical'].includes(issue.impact ?? ''))).toEqual([]);
  };
  await audit();
  await page.keyboard.press('Tab');
  await expect(page.getByRole('link', { name: 'Skip to content' })).toBeFocused();
  await page.getByLabel('Room title').fill('Accessible workspace');
  await page.getByRole('button', { name: 'Create draft' }).click();
  await expect(page.getByRole('button', { name: 'Open room', exact: true })).toBeVisible();
  await audit();
  await page.goto('/recover');
  await expect(page.getByLabel('Ownership recovery code')).toBeVisible();
  await audit();
});
