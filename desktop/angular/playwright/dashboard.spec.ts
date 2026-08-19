import { expect, test, type Page } from '@playwright/test';
import path from 'path';

const repoRoot = path.resolve(__dirname, '../../..');

test('renders empty and populated file-access dashboard states', async ({ page }) => {
	test.setTimeout(60_000);
	await mockDashboard(page, false);
	await page.goto('/dashboard');
	await closeIntro(page);
	await page.locator('app-dashboard').evaluate(element => element.scrollTo(0, 0));
	await expect(page.getByText('Open and Execute Decisions over Time', { exact: true })).toBeVisible();
	await expect(page.getByText('Recently Blocked Applications', { exact: true })).toBeVisible();

	await page.unroute('**/filequery/query/batch');
	await page.unroute('**/filequery/charts/decisions');
	await page.unroute('**/filequery/mounts/activity');
	await page.unroute('**/fileaccess/mounts');
	await page.unroute('**/fileaccess/diagnostics');
	await mockDashboard(page, true);
	await page.reload();
	await closeIntro(page);
	await page.locator('app-dashboard').evaluate(element => element.scrollTo(0, 0));
	await expect(page.getByText('File Opens Blocked', { exact: true })).toBeVisible();
	await expect(page.getByText('/protected', { exact: true }).first()).toBeVisible();
	await expect(page.getByText('Sleep', { exact: true })).toBeVisible();
	await page.screenshot({ path: path.join(repoRoot, 'tmp', 'file-access-dashboard-activity-top.png') });
	await page.getByText('Protected Mounts', { exact: true }).scrollIntoViewIfNeeded();
	await page.screenshot({ path: path.join(repoRoot, 'tmp', 'file-access-dashboard-activity-details.png') });
	await page.getByText('Enforcement State', { exact: true }).scrollIntoViewIfNeeded();
	await expect(page.getByText('Decision Pipeline', { exact: true })).toBeVisible();
	await expect(page.getByText('Event Delivery', { exact: true })).toBeVisible();
	await page.screenshot({ path: path.join(repoRoot, 'tmp', 'file-access-dashboard-activity-enforcement.png') });
});

async function closeIntro(page: Page): Promise<void> {
	await page.waitForTimeout(500);
	await page.addStyleTag({ content: '.loading, .cdk-overlay-container { display: none !important; }' });
	await page.locator('.loading').evaluateAll(elements => elements.forEach(element => element.remove()));
	const connectionOverlay = page.locator('sfng-dialog-container').filter({ hasText: 'Connecting to filemaster' });
	if (await connectionOverlay.isVisible()) {
		await connectionOverlay.evaluate(element => element.remove());
	}
	const dialog = page.locator('sfng-dialog-container').filter({ hasText: 'Filemaster Protects Your Privacy' });
	if (await dialog.isVisible()) {
		await dialog.locator('svg').first().click();
		await expect(dialog).toBeHidden();
	}
}

async function mockDashboard(page: Page, active: boolean): Promise<void> {
	await page.route('**/filequery/query/batch', route => route.fulfill({ json: active ? {
		fileBlocked: [{ count: 3 }], folderBlocked: [{ count: 1 }], openAllowed: [{ count: 12 }], executeAllowed: [{ count: 4 }],
		blockedApplications: [{ profile: 'local/tail', app_name: 'Tail', count: 3 }],
		activeApplications: [{ profile: 'local/sleep', app_name: 'Sleep', count: 12 }, { profile: 'local/tail', app_name: 'Tail', count: 3 }],
	} : { fileBlocked: [], folderBlocked: [], openAllowed: [], executeAllowed: [], blockedApplications: [], activeApplications: [] } }));
	await page.route('**/filequery/charts/decisions', route => route.fulfill({ json: { results: active ? [
		{ timestamp: Math.floor(Date.now() / 1000) - 30, open_allowed: 3, open_blocked: 1, execute_allowed: 1, execute_blocked: 0 },
		{ timestamp: Math.floor(Date.now() / 1000) - 20, open_allowed: 5, open_blocked: 0, execute_allowed: 2, execute_blocked: 1 },
		{ timestamp: Math.floor(Date.now() / 1000) - 10, open_allowed: 4, open_blocked: 2, execute_allowed: 1, execute_blocked: 0 },
	] : [] } }));
	await page.route('**/filequery/mounts/activity', route => route.fulfill({ json: { results: active ? [{ mount_id: 1, mount_path: '/protected', last_activity_at: '2026-08-19T18:00:00Z', open_allowed: 12, open_blocked: 3, execute_allowed: 4, execute_blocked: 1 }] : [] } }));
	await page.route('**/fileaccess/mounts', route => route.fulfill({ json: active ? {
		coverage: 'partial', active_mount_count: 1, missing_mount_count: 1,
		mounts: [{ mount_id: 1, mount_path: '/protected', status: 'protected', reasons: [] }, { mount_id: 2, mount_path: '/pending', status: 'pending', reasons: ['scope_activation_pending'] }], pending_scopes: ['/pending'], dynamic_gaps: [],
	} : { coverage: 'unknown', active_mount_count: 0, missing_mount_count: 0, mounts: [], pending_scopes: [], dynamic_gaps: [] } }));
	await page.route('**/fileaccess/diagnostics', route => route.fulfill({ json: {
		LifecycleState: 'running', Warnings: [], Decision: { QueueDepth: 0, Workers: 4, ActiveWorkers: 4, PendingAsk: 0, QueueSaturationDenies: 0, OutstandingBudgetDenies: 0, ProfileAskBudgetDenies: 0 }, Observation: { QueueDepth: 0, QueueCapacity: 128, Dropped: 0 }, Reader: { DescriptorPressure: false, LastDecisionLatencyNanos: 1000000, LastResponseLatencyNanos: 4000000, QueueOverflowCount: 0, Fatal: false }, FailedResponseCount: 0,
	} }));
}
