import { test, expect } from '@playwright/test';

test('has title', async ({ page }) => {
  await page.goto('/');

  // Expect a title "to contain" a substring.
  await expect(page).toHaveTitle(/AuthClaw/i);
});

test('login page loads and displays form', async ({ page }) => {
  await page.goto('/login');

  // Expect login button to be visible
  await expect(page.locator('text=Sign In')).toBeVisible();
});

test('dashboard requires authentication', async ({ page }) => {
  await page.goto('/');
  // Next.js uses client-side routing, so it might redirect to /login
  // Since we don't have a token, it redirects us.
  await page.waitForURL('**/login');
  expect(page.url()).toContain('/login');
});
