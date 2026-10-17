import { expect, test } from '@playwright/test';

test('sign-in is usable at desktop and mobile widths', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Less waste. More control.' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in to your workspace' })).toBeEnabled();
  await page.screenshot({ path: 'test-results/login-desktop.png', fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByRole('button', { name: 'Sign in to your workspace' })).toBeInViewport();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: 'test-results/login-mobile.png', fullPage: true });
});
