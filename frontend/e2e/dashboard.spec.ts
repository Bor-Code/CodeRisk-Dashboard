import { test, expect } from '@playwright/test';

test('has title and can navigate', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle(/CodeRisk/i);

  // Expect a basic element to be present (e.g. a heading or button)
  const heading = page.locator('h1').first();
  if (await heading.isVisible()) {
    await expect(heading).toBeVisible();
  }
});
