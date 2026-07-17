import { Component, OnDestroy, OnInit } from '@angular/core';
import { Subscription } from 'rxjs';
import { FileAccessDiagnostics, FileAccessDiagnosticsService } from '../../services/fileaccess-diagnostics.service';

@Component({
	selector: 'app-file-access-diagnostics',
	templateUrl: './fileaccess-diagnostics.component.html',
	styleUrls: ['./fileaccess-diagnostics.component.scss'],
})
export class FileAccessDiagnosticsComponent implements OnInit, OnDestroy {
	diagnostics: FileAccessDiagnostics | null = null;
	unavailable = false;

	private subscription = Subscription.EMPTY;

	constructor(private diagnosticsService: FileAccessDiagnosticsService) {}

	ngOnInit(): void {
		this.subscription = this.diagnosticsService.watch().subscribe(diagnostics => {
			this.unavailable = diagnostics === null;
			if (diagnostics !== null) {
				this.diagnostics = diagnostics;
			}
		});
	}

	ngOnDestroy(): void {
		this.subscription.unsubscribe();
	}

	get lifecycleState(): string {
		return this.diagnostics?.LifecycleState || 'Unavailable';
	}

	get degraded(): boolean {
		const diagnostics = this.diagnostics;
		if (diagnostics === null) {
			return this.unavailable;
		}
		return diagnostics.Mount.PartialCoverage ||
			diagnostics.Reader.Degraded ||
			diagnostics.Reader.Fatal ||
			diagnostics.Response.FatalError !== '' ||
			diagnostics.FailedResponseCount > 0 ||
			diagnostics.Warnings.length > 0;
	}

	get dirtyRuleCount(): number {
		return Object.values(this.diagnostics?.PermanentRules || {}).reduce(
			(count, status) => count + status.DirtyCount,
			0,
		);
	}

	get persistenceFailure(): string {
		return Object.values(this.diagnostics?.PermanentRules || {})
			.filter(status => status.PersistentFailure)
			.map(status => status.LastError || 'permanent rule persistence is failing')
			.join('; ');
	}
}
