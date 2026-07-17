import { spawn, type ChildProcessWithoutNullStreams } from 'child_process';
import { mkdir, readFile, rm, writeFile } from 'fs/promises';
import net from 'net';
import os from 'os';
import path from 'path';
import { expect, test, type Locator, type Page } from '@playwright/test';

const repoRoot = path.resolve(__dirname, '../../..');
const sourceMode = process.env.PLAYWRIGHT_FILEACCESS_SOURCE === 'real' ? 'real' : 'fake';

type TestCore = {
	apiPort: number;
	sourceMode: 'fake' | 'real';
	socketPath?: string;
	dataDir: string;
	watchDir: string;
	process: ChildProcessWithoutNullStreams;
	output: string[];
};

type AccessAttempt = {
	path: string;
	op: 'read' | 'write';
	command: string;
	// Fake-source mode spawns this real, long-lived process and sends its
	// PID over the socket, so the daemon resolves a real portmaster profile
	// from /proc/<pid>/exe exactly as it would for a kernel fanotify event.
	liveCmd: string;
	liveArgs: string[];
	// Expected resolved profile (binary) name, asserted in the monitor.
	appName: string;
};

test.describe.configure({ mode: 'serial' });

test('prompts for watched file write and read decisions and records them in the app', async ({ page }) => {
	test.setTimeout(180_000);

	const core = await startFilemaster(sourceMode, test.info().workerIndex);
	try {
		await page.goto(`/?api-port=${core.apiPort}`);
		await expect(page.locator('app-root')).toBeAttached();

		const target = path.join(core.watchDir, 'watched.txt');

		const writeAttempt = requestAccess({
			path: target,
			op: 'write',
			command: `echo test > ${target}`,
			liveCmd: 'sleep',
			liveArgs: ['60'],
			appName: 'sleep',
		}, core);

		await expectPromptInApp(page, core.apiPort, target, 'write');
		await page.getByRole('button', { name: 'Allow' }).click();
		await expect(writeAttempt).resolves.toMatchObject({
			verdict: 'allow',
			stdout: '',
			stderr: '',
			exitCode: 0,
		});

		await expect(await readFile(target, 'utf8')).toBe('test\n');

		// "Always allow this path" must persist a per-app File Access Rule:
		// a second event for the same profile/path proceeds without another prompt.
		await expect(requestAccess({
			path: target,
			op: 'write',
			command: `echo test > ${target}`,
			liveCmd: 'sleep',
			liveArgs: ['60'],
			appName: 'sleep',
		}, core)).resolves.toMatchObject({ verdict: 'allow', exitCode: 0 });

		const readAttempt = requestAccess({
			path: target,
			op: 'read',
			command: `cat ${target}`,
			liveCmd: 'tail',
			liveArgs: ['-f', '/dev/null'],
			appName: 'tail',
		}, core);

		await expectPromptInApp(page, core.apiPort, target, 'read');
		await page.getByRole('button', { name: 'Block' }).click();
		const readResult = await readAttempt;
		expect(readResult.verdict).toBe('deny');
		expect(readResult.stdout).toBe('');
		expect(readResult.exitCode).not.toBe(0);

		await page.goto(`/monitor?api-port=${core.apiPort}`);
		const monitorRows = page.locator('sfng-file-event-row').filter({ hasText: target });
		// Each row must carry the op AND the real resolved app name — the
		// latter proving the PID→/proc→portmaster-profile path worked end to
		// end (no synthetic/"/" fallback).
		await expect(
			monitorRows.filter({ hasText: 'Write' }).filter({ hasText: 'sleep' })
		).toHaveCount(2);
		await expect(
			monitorRows.filter({ hasText: 'Read' }).filter({ hasText: 'tail' })
		).toBeVisible();
		await expect(page.getByText('File Accesses', { exact: true })).toBeVisible();
		await expect(page.locator('sfng-netquery-line-chart svg')).toBeVisible();

		const introDialog = page.locator('sfng-dialog-container').filter({ hasText: 'Portmaster Protects Your Privacy' });
		if (await introDialog.isVisible()) {
			await introDialog.locator('svg').first().click();
			await expect(introDialog).toBeHidden();
		}

		if (process.env.PLAYWRIGHT_FILEACCESS_SCREENSHOT === 'true') {
			await page.screenshot({
				path: path.join(repoRoot, 'tmp', 'file-access-activity.png'),
				fullPage: true,
			});
		}

		await page.locator('app-network-scout').getByText('Tail', { exact: true }).click();
		await expect(page).toHaveURL(/\/app\//);
		await expect(page.getByRole('heading', { name: 'Tail' })).toBeVisible();
		await page.getByText('File Events', { exact: true }).click();
		await expect(page.locator('app-filequery-viewer sfng-file-event-row').filter({ hasText: target })).toBeVisible();
		await expect(page.locator('app-filequery-viewer sfng-netquery-line-chart svg')).toBeVisible();

		if (process.env.PLAYWRIGHT_FILEACCESS_SCREENSHOT === 'true') {
			await page.screenshot({
				path: path.join(repoRoot, 'tmp', 'app-file-access-activity.png'),
				fullPage: true,
			});
		}

		await page.goto(`/settings?api-port=${core.apiPort}`);
		await page.waitForTimeout(500);
		const settingsIntroDialog = page.locator('sfng-dialog-container').filter({ hasText: 'Portmaster Protects Your Privacy' });
		if (await settingsIntroDialog.isVisible()) {
			await settingsIntroDialog.locator('svg').first().click();
			await expect(settingsIntroDialog).toBeHidden();
		}
		const otherHeading = page.getByRole('heading', { name: 'Other' });
		await expect(otherHeading).toBeVisible();
		await expect(page.getByText('Intercept Read Syscalls', { exact: true })).toBeVisible();
		await otherHeading.scrollIntoViewIfNeeded();

		if (process.env.PLAYWRIGHT_FILEACCESS_SCREENSHOT === 'true') {
			await page.screenshot({
				path: path.join(repoRoot, 'tmp', 'settings.png'),
				fullPage: true,
			});
		}
	} finally {
		await stopFilemaster(core);
	}
});

async function startFilemaster(mode: 'fake' | 'real', workerIndex: number): Promise<TestCore> {
	const apiPort = await getFreePort();
	const root = await makeTempDir('filemaster-playwright-');
	const dataDir = path.join(root, 'data');
	const binDir = path.join(root, 'bin');
	const watchDir = path.join(root, 'watched');
	const socketPath = path.join(root, 'fake-fanotify.sock');

	await mkdir(dataDir, { recursive: true });
	await mkdir(binDir, { recursive: true });
	await mkdir(watchDir, { recursive: true });
	await writeFile(path.join(dataDir, 'config.json'), JSON.stringify({
		core: {
			devMode: true,
		},
		fileaccess: {
			watchPaths: [watchDir],
			interceptReads: true,
		},
	}, null, 2));

	const output: string[] = [];
	const env: NodeJS.ProcessEnv = {
		...process.env,
		FM_WATCH_PATHS: watchDir,
		GOMODCACHE: process.env.GOMODCACHE || path.join(os.homedir(), 'go/pkg/mod'),
		PLAYWRIGHT_WORKER_INDEX: String(workerIndex),
	};
	if (mode === 'fake') {
		env.FM_FAKE_SOCKET = socketPath;
	}

	const child = spawn(
		'go',
		[
			'run',
			...(mode === 'fake' ? ['-tags', 'filemaster_test'] : []),
			'./cmds/portmaster-core',
			'--devmode',
			'--log',
			'debug',
			'--api-address',
			`127.0.0.1:${apiPort}`,
			'--data-dir',
			dataDir,
			'--bin-dir',
			binDir,
		],
		{
			cwd: repoRoot,
			env,
		}
	);

	child.stdout.on('data', chunk => output.push(String(chunk)));
	child.stderr.on('data', chunk => output.push(String(chunk)));

	const core: TestCore = {
		apiPort,
		sourceMode: mode,
		socketPath: mode === 'fake' ? socketPath : undefined,
		dataDir: root,
		watchDir,
		process: child,
		output,
	};

	try {
		await waitFor(async () => {
			if (child.exitCode !== null) {
				throw new Error(`portmaster-core exited early with ${child.exitCode}`);
			}
			await connectAndClose(apiPort);
		}, 120_000);

		if (mode === 'fake') {
			await waitFor(async () => {
				await connectUnixAndClose(socketPath);
			}, 30_000);
		}
		return core;
	} catch (err) {
		await stopFilemaster(core);
		const cause = err instanceof Error ? err.message : String(err);
		throw new Error(
			`fake fanotify source did not become ready at ${socketPath}: ${cause}\n` +
				`portmaster-core output:\n${output.join('').slice(-12_000)}`,
		);
	}
}

async function stopFilemaster(core: TestCore) {
	if (core.process.exitCode === null) {
		core.process.kill('SIGTERM');
		await new Promise<void>(resolve => {
			const done = () => resolve();
			core.process.once('exit', done);
			setTimeout(() => {
				if (core.process.exitCode === null) {
					core.process.kill('SIGKILL');
				}
				resolve();
			}, 5_000);
		});
	}
	await rm(core.dataDir, { recursive: true, force: true });
}

async function expectPromptInApp(page: Page, apiPort: number, target: string, op: string): Promise<Locator> {
	await page.goto(`/prompt?api-port=${apiPort}`);
	const prompt = page.locator('table.custom').filter({ hasText: target }).filter({ hasText: op });
	await expect(page.getByText(target)).toBeVisible();
	await expect(page.getByRole('row', { name: new RegExp(`Op:\\s+${op}\\b`) })).toBeVisible();
	await expect(prompt).toBeVisible();
	return prompt;
}

async function requestAccess(attempt: AccessAttempt, core: TestCore) {
	if (core.sourceMode === 'real') {
		return requestRealAccess(attempt);
	}
	if (!core.socketPath) {
		throw new Error('fake file access source is missing its socket path');
	}

	// Spawn a real, long-lived process so the daemon can resolve its profile
	// from /proc/<pid>/exe — the fake source carries only the PID, exactly
	// like the kernel does. The process is killed once the verdict is in.
	const live = spawn(attempt.liveCmd, attempt.liveArgs, { stdio: 'ignore' });
	await new Promise<void>((resolve, reject) => {
		live.once('spawn', () => resolve());
		live.once('error', reject);
	});

	let verdict: string;
	try {
		verdict = await sendSocketEvent(core.socketPath, {
			pid: live.pid,
			path: attempt.path,
			op: attempt.op,
		});
	} finally {
		live.kill('SIGKILL');
	}

	if (verdict === 'deny') {
		return {
			verdict,
			stdout: '',
			stderr: `${attempt.command}: Permission denied\n`,
			exitCode: 13,
		};
	}

	if (attempt.op === 'write') {
		await writeFile(attempt.path, 'test\n');
		return {
			verdict,
			stdout: '',
			stderr: '',
			exitCode: 0,
		};
	}

	return {
		verdict,
		stdout: await readFile(attempt.path, 'utf8'),
		stderr: '',
		exitCode: 0,
	};
}

function requestRealAccess(attempt: AccessAttempt) {
	return new Promise<{
		verdict: 'allow' | 'deny';
		stdout: string;
		stderr: string;
		exitCode: number | null;
	}>((resolve, reject) => {
		const child = spawn('sh', ['-c', attempt.command], {
			stdio: ['ignore', 'pipe', 'pipe'],
		});
		let stdout = '';
		let stderr = '';

		child.stdout.on('data', chunk => {
			stdout += String(chunk);
		});
		child.stderr.on('data', chunk => {
			stderr += String(chunk);
		});
		child.on('error', reject);
		child.on('exit', code => {
			resolve({
				verdict: code === 0 ? 'allow' : 'deny',
				stdout,
				stderr,
				exitCode: code,
			});
		});
	});
}

function sendSocketEvent(socketPath: string, event: Record<string, unknown>): Promise<string> {
	return new Promise((resolve, reject) => {
		const socket = net.createConnection(socketPath);
		let data = '';

		socket.setTimeout(45_000);
		socket.on('connect', () => {
			socket.write(`${JSON.stringify(event)}\n`);
		});
		socket.on('data', chunk => {
			data += String(chunk);
			if (data.includes('\n')) {
				socket.end();
				resolve(data.trim());
			}
		});
		socket.on('timeout', () => {
			socket.destroy(new Error(`timed out waiting for verdict for ${JSON.stringify(event)}`));
		});
		socket.on('error', reject);
	});
}

function connectAndClose(port: number): Promise<void> {
	return new Promise((resolve, reject) => {
		const socket = net.createConnection({ host: '127.0.0.1', port });
		socket.setTimeout(1_000);
		socket.on('connect', () => {
			socket.end();
			resolve();
		});
		socket.on('timeout', () => {
			socket.destroy(new Error(`timed out connecting to 127.0.0.1:${port}`));
		});
		socket.on('error', reject);
	});
}

function connectUnixAndClose(socketPath: string): Promise<void> {
	return new Promise((resolve, reject) => {
		const socket = net.createConnection(socketPath);
		socket.setTimeout(1_000);
		socket.on('connect', () => {
			socket.end();
			resolve();
		});
		socket.on('timeout', () => {
			socket.destroy(new Error(`timed out connecting to ${socketPath}`));
		});
		socket.on('error', reject);
	});
}

async function waitFor(fn: () => Promise<void>, timeoutMs: number): Promise<void> {
	const started = Date.now();
	let lastError: unknown;

	while (Date.now() - started < timeoutMs) {
		try {
			await fn();
			return;
		} catch (err) {
			lastError = err;
			await new Promise(resolve => setTimeout(resolve, 250));
		}
	}

	throw lastError instanceof Error ? lastError : new Error(String(lastError));
}

function getFreePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const server = net.createServer();
		server.listen(0, '127.0.0.1', () => {
			const address = server.address();
			if (!address || typeof address === 'string') {
				server.close();
				reject(new Error('failed to allocate tcp port'));
				return;
			}
			const port = address.port;
			server.close(() => resolve(port));
		});
		server.on('error', reject);
	});
}

async function makeTempDir(prefix: string) {
	return os.tmpdir() + '/' + await import('crypto').then(({ randomUUID }) => `${prefix}${randomUUID()}`);
}
