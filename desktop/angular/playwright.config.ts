import { defineConfig, devices } from '@playwright/test';

const baseURL = process.env.PLAYWRIGHT_BASE_URL ?? 'http://127.0.0.1:4200';

export default defineConfig({
	testDir: './playwright',
	fullyParallel: true,
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 2 : 0,
	reporter: [
		['list'],
		['html', { open: 'never' }],
	],
	timeout: 30_000,
	expect: {
		timeout: 10_000,
	},
	use: {
		baseURL,
		screenshot: 'only-on-failure',
		trace: 'on-first-retry',
		video: 'retain-on-failure',
	},
	webServer: {
		command: 'npm run serve -- --host 0.0.0.0',
		url: baseURL,
		reuseExistingServer: !process.env.CI,
		timeout: 240_000,
	},
	projects: [
		{
			name: 'chromium',
			use: { ...devices['Desktop Chrome'] },
		},
	],
});
