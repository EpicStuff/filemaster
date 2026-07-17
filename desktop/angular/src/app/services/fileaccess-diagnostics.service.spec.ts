import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { PORTMASTER_HTTP_API_ENDPOINT } from '@safing/portmaster-api';
import { FileAccessDiagnostics, FileAccessDiagnosticsService } from './fileaccess-diagnostics.service';

describe('FileAccessDiagnosticsService', () => {
	let service: FileAccessDiagnosticsService;
	let http: HttpTestingController;

	beforeEach(() => {
		TestBed.configureTestingModule({
			imports: [HttpClientTestingModule],
			providers: [
				FileAccessDiagnosticsService,
				{ provide: PORTMASTER_HTTP_API_ENDPOINT, useValue: 'http://filemaster.test/api' },
			],
		});
		service = TestBed.inject(FileAccessDiagnosticsService);
		http = TestBed.inject(HttpTestingController);
	});

	afterEach(() => http.verify());

	it('reads the compact diagnostics endpoint over HTTP', () => {
		let diagnostics: FileAccessDiagnostics | undefined;
		service.get().subscribe(result => diagnostics = result);

		const request = http.expectOne('http://filemaster.test/api/v1/fileaccess/diagnostics');
		expect(request.request.method).toBe('GET');
		request.flush({ Decision: { Workers: 4 } });

		expect(diagnostics?.Decision.Workers).toBe(4);
	});
});
