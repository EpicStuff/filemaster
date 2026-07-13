import { expect, test } from '@playwright/test';

test('boots the app shell and reaches the dashboard route', async ({ page }) => {
	await page.goto('/');

	await expect(page).toHaveTitle(/Portmaster/);
	await expect(page.locator('app-root')).toBeAttached();
	await expect(page).toHaveURL(/\/dashboard(?:[/?#]|$)/);
});
