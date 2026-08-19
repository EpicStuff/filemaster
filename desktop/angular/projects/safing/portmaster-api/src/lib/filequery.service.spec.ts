import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { Filequery, IFileQueryProfileStats } from './filequery.service';
import { PORTMASTER_HTTP_API_ENDPOINT } from './portapi.service';

describe('Filequery', () => {
	let service: Filequery;
	let http: HttpTestingController;

	beforeEach(() => {
		TestBed.configureTestingModule({
			imports: [HttpClientTestingModule],
			providers: [
				Filequery,
				{ provide: PORTMASTER_HTTP_API_ENDPOINT, useValue: 'http://filemaster.test' },
			],
		});
		service = TestBed.inject(Filequery);
		http = TestBed.inject(HttpTestingController);
	});

	afterEach(() => http.verify());

	it('uses app_name when present and falls back to the profile ID', () => {
		let stats: IFileQueryProfileStats[] = [];
		service.getProfileStats().subscribe(result => stats = result);

		const request = http.expectOne('http://filemaster.test/v1/filequery/query/batch');
		expect(request.request.method).toBe('POST');
		request.flush({
			verdicts: [
				{ profile: 'local/sleep', app_name: 'Sleep', verdict: 'allow', totalCount: 2 },
				{ profile: 'local/cat', app_name: '', verdict: 'deny', totalCount: 1 },
			],
		});

		expect(stats.find(item => item.ID === 'local/sleep')?.Name).toBe('Sleep');
		expect(stats.find(item => item.ID === 'local/cat')?.Name).toBe('local/cat');
	});

	it('loads dashboard decision, mount, and diagnostics data from the file APIs', () => {
		service.getDecisionChart().subscribe(result => expect(result[0].open_allowed).toBe(4));
		http.expectOne('http://filemaster.test/v1/filequery/charts/decisions').flush({
			results: [{ timestamp: 10, open_allowed: 4, open_blocked: 1, execute_allowed: 2, execute_blocked: 0 }],
		});

		service.getMountActivity().subscribe(result => expect(result[0].mount_path).toBe('/home'));
		http.expectOne('http://filemaster.test/v1/filequery/mounts/activity').flush({
			results: [{ mount_id: 1, mount_path: '/home', last_activity_at: '2026-08-19T00:00:00Z', open_allowed: 1, open_blocked: 0, execute_allowed: 0, execute_blocked: 0 }],
		});

		service.getProtectedMounts().subscribe(result => expect(result?.coverage).toBe('protected'));
		http.expectOne('http://filemaster.test/v1/fileaccess/mounts').flush({ coverage: 'protected', active_mount_count: 1, missing_mount_count: 0, mounts: [], pending_scopes: [], dynamic_gaps: [] });

		service.getFileAccessDiagnostics().subscribe(result => expect(result?.LifecycleState).toBe('running'));
		http.expectOne('http://filemaster.test/v1/fileaccess/diagnostics').flush({ LifecycleState: 'running' });
	});
});
