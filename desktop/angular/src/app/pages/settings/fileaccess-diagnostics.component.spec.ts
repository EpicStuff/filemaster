import { CommonModule } from '@angular/common';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { BehaviorSubject } from 'rxjs';
import { FileAccessDiagnostics, FileAccessDiagnosticsService } from '../../services/fileaccess-diagnostics.service';
import { FileAccessDiagnosticsComponent } from './fileaccess-diagnostics.component';

describe('FileAccessDiagnosticsComponent', () => {
	let fixture: ComponentFixture<FileAccessDiagnosticsComponent>;
	let diagnostics: BehaviorSubject<FileAccessDiagnostics | null>;

	beforeEach(async () => {
		diagnostics = new BehaviorSubject<FileAccessDiagnostics | null>(healthyDiagnostics());
		await TestBed.configureTestingModule({
			imports: [CommonModule],
			declarations: [FileAccessDiagnosticsComponent],
			providers: [{
				provide: FileAccessDiagnosticsService,
				useValue: { watch: () => diagnostics },
			}],
		}).compileComponents();
		fixture = TestBed.createComponent(FileAccessDiagnosticsComponent);
		fixture.detectChanges();
	});

	it('shows a healthy running enforcement status', () => {
		expect(fixture.nativeElement.querySelector('[data-testid="fileaccess-diagnostics-healthy"]')).toBeTruthy();
		expect(fixture.nativeElement.textContent).toContain('running');
		expect(fixture.nativeElement.querySelector('[data-testid="fileaccess-diagnostics-warning"]')).toBeNull();
	});

	it('shows a degraded coverage warning', () => {
		const status = healthyDiagnostics();
		status.Mount.PartialCoverage = true;
		status.Warnings = [{ ID: 'partial_mount_coverage', Severity: 'warning', Message: 'Some mounts are not marked.' }];
		diagnostics.next(status);
		fixture.detectChanges();
		expect(fixture.nativeElement.querySelector('[data-testid="fileaccess-diagnostics-warning"]')).toBeTruthy();
		expect(fixture.nativeElement.textContent).toContain('Some mounts are not marked.');
	});

	it('lists every root Ask rollout blocker', () => {
		const status = healthyDiagnostics();
		status.RootAskGate = { Requested: true, Open: false, Reasons: ['missing systemd host verification', 'missing root benchmark'] };
		diagnostics.next(status);
		fixture.detectChanges();
		const gate = fixture.nativeElement.querySelector('[data-testid="fileaccess-root-ask-gate"]');
		expect(gate.textContent).toContain('missing systemd host verification');
		expect(gate.textContent).toContain('missing root benchmark');
	});

	it('shows dirty permanent-rule persistence failures', () => {
		const status = healthyDiagnostics();
		status.PermanentRules = {
			'local/profile': { DirtyCount: 2, PersistentFailure: true, LastError: 'disk is read-only' },
		};
		diagnostics.next(status);
		fixture.detectChanges();
		expect(fixture.nativeElement.querySelector('[data-testid="fileaccess-dirty-rules"]').textContent).toContain('2');
		expect(fixture.nativeElement.textContent).toContain('disk is read-only');
	});

	it('shows shutdown in progress', () => {
		const status = healthyDiagnostics();
		status.Shutdown.State = 1;
		status.LifecycleState = 'closing';
		status.Shutdown.Marks.Pending = true;
		diagnostics.next(status);
		fixture.detectChanges();
		expect(fixture.nativeElement.textContent).toContain('closing');
		expect(fixture.nativeElement.textContent).toContain('in progress');
	});

	it('shows an unavailable state when the endpoint is temporarily unreachable', () => {
		diagnostics.next(null);
		fixture.detectChanges();
		expect(fixture.nativeElement.querySelector('[data-testid="fileaccess-diagnostics-unavailable"]')).toBeTruthy();
	});
});

function healthyDiagnostics(): FileAccessDiagnostics {
	return {
		Mount: { ConfiguredScopes: [], CanonicalScopes: [], ActiveMountIDs: [], MissingMountIDs: [], PartialCoverage: false, LastError: '' },
		Reader: {
			DescriptorLimit: 128,
			OutstandingDescriptors: 0,
			PeakOutstandingDescriptors: 0,
			DescriptorPressure: false,
			EMFILECount: 0,
			QueueOverflowCount: 0,
			UnresolvedPathDenyCount: 0,
			Running: true,
			Exited: false,
			Degraded: false,
			Fatal: false,
			LastError: '',
			FatalError: '',
		},
		Response: { Sealed: false, Closed: false, FatalError: '' },
		FailedResponseCount: 0,
		Decision: {
			Workers: 4,
			ExpectedWorkers: 4,
			ActiveWorkers: 4,
			ExitedWorkers: 0,
			QueueDepth: 0,
			PeakQueueDepth: 0,
			Outstanding: 0,
			PendingAsk: 0,
		},
		Prompt: { Groups: 0, Events: 0, ActivePrompts: 0 },
		PermanentRules: {},
		LifecycleState: 'running',
		Shutdown: {
			State: 0,
			ReportingCompleted: false,
			FinalCleanupCompleted: false,
			DeadlineExpired: false,
			Marks: { Complete: false, Final: false, Pending: false },
			Unresolved: [],
		},
		RootAskGate: { Requested: false, Open: false, Reasons: [] },
		Warnings: [],
	};
}
