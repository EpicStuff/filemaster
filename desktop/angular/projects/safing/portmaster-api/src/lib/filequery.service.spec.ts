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
});
