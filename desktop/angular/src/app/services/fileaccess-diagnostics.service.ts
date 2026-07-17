import { HttpClient } from '@angular/common/http';
import { Inject, Injectable } from '@angular/core';
import { PORTMASTER_HTTP_API_ENDPOINT } from '@safing/portmaster-api';
import { Observable, of, timer } from 'rxjs';
import { catchError, switchMap } from 'rxjs/operators';

export interface FileAccessWarning {
	ID: string;
	Severity: string;
	Message: string;
}

export interface FileAccessDiagnostics {
	Mount: {
		ConfiguredScopes: string[];
		CanonicalScopes: string[];
		ActiveMountIDs: number[];
		MissingMountIDs: number[];
		PartialCoverage: boolean;
		LastError: string;
	};
	Reader: {
		DescriptorLimit: number;
		OutstandingDescriptors: number;
		PeakOutstandingDescriptors: number;
		DescriptorPressure: boolean;
		EMFILECount: number;
		QueueOverflowCount: number;
		UnresolvedPathDenyCount: number;
		Running: boolean;
		Exited: boolean;
		Degraded: boolean;
		Fatal: boolean;
		LastError: string;
		FatalError: string;
	};
	Response: {
		Sealed: boolean;
		Closed: boolean;
		FatalError: string;
	};
	FailedResponseCount: number;
	Decision: {
		Workers: number;
		ExpectedWorkers: number;
		ActiveWorkers: number;
		ExitedWorkers: number;
		QueueDepth: number;
		PeakQueueDepth: number;
		Outstanding: number;
		PendingAsk: number;
	};
	Prompt: {
		Groups: number;
		Events: number;
		ActivePrompts: number;
	};
	PermanentRules: Record<string, {
		DirtyCount: number;
		PersistentFailure: boolean;
		LastError?: string;
	}>;
	LifecycleState?: string;
	Shutdown: {
		State: number;
		ReportingCompleted: boolean;
		FinalCleanupCompleted: boolean;
		DeadlineExpired: boolean;
		Marks: {
			Complete: boolean;
			Final: boolean;
			Pending: boolean;
		};
		Unresolved: unknown[];
	};
	RootAskGate: {
		Requested: boolean;
		Open: boolean;
		Reasons: string[];
	};
	Warnings: FileAccessWarning[];
}

@Injectable({ providedIn: 'root' })
export class FileAccessDiagnosticsService {
	constructor(
		private http: HttpClient,
		@Inject(PORTMASTER_HTTP_API_ENDPOINT) private httpEndpoint: string,
	) {}

	get(): Observable<FileAccessDiagnostics> {
		return this.http.get<FileAccessDiagnostics>(`${this.httpEndpoint}/v1/fileaccess/diagnostics`);
	}

	watch(intervalMS = 2_000): Observable<FileAccessDiagnostics | null> {
		return timer(0, intervalMS).pipe(
			switchMap(() => this.get().pipe(catchError(() => of(null)))),
		);
	}
}
