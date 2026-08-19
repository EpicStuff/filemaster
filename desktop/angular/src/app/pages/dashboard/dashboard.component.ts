import { ChangeDetectionStrategy, ChangeDetectorRef, Component, DestroyRef, OnInit, TrackByFunction, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FileAccessDiagnostics, Filequery, MountActivity, PortapiService, ProtectedMount, ProtectedMountsResponse, QueryResult, Select } from '@safing/portmaster-api';
import { forkJoin, interval, repeat, startWith } from 'rxjs';
import { ChartConfig } from 'src/app/shared/netquery/line-chart/line-chart';

interface ApplicationActivity {
	profileID: string;
	name: string;
	count: number;
}

interface MountRow extends ProtectedMount {
	activity: MountActivity | null;
}

interface NewsCard {
	title: string;
	body: string;
	url?: string;
	footer?: string;
	progress?: { percent: number; style: string };
}

interface News { cards: NewsCard[]; }

interface DecisionChartPoint {
	timestamp: number;
	allowed: number;
	blocked: number;
}

const newsResourceIdentifier = 'intel/news.yaml';
const decisionChartConfig: ChartConfig<DecisionChartPoint> = {
	series: {
		allowed: { lineColor: 'text-green-200', areaColor: 'text-green-100 text-opacity-25' },
		blocked: { lineColor: 'text-red-200', areaColor: 'text-red-100 text-opacity-25' },
	},
	time: { from: -10 * 60 },
	tooltipFormat: point => `Allowed: ${point.allowed}\nBlocked: ${point.blocked}`,
	showDataPoints: true,
	fillEmptyTicks: { interval: 60 },
};

@Component({
	selector: 'app-dashboard',
	changeDetection: ChangeDetectionStrategy.OnPush,
	styleUrls: ['./dashboard.component.scss'],
	templateUrl: './dashboard.component.html',
})
export class DashboardPageComponent implements OnInit {
	private readonly destroyRef = inject(DestroyRef);
	private readonly cdr = inject(ChangeDetectorRef);
	private readonly filequery = inject(Filequery);
	private readonly portapi = inject(PortapiService);

	readonly decisionChartConfig = decisionChartConfig;
	fileBlocked = 0;
	folderBlocked = 0;
	recentApplications = 0;
	openAllowed = 0;
	executeAllowed = 0;
	blockedApplications: ApplicationActivity[] = [];
	activeApplications: ApplicationActivity[] = [];
	openDecisionChart: DecisionChartPoint[] = [];
	executeDecisionChart: DecisionChartPoint[] = [];
	mounts: MountRow[] = [];
	coverage: ProtectedMountsResponse | null = null;
	diagnostics: FileAccessDiagnostics | null = null;
	news?: News | 'pending' = 'pending';

	trackApplication: TrackByFunction<ApplicationActivity> = (_, application) => application.profileID;
	trackMount: TrackByFunction<MountRow> = (_, mount) => `${mount.mount_id}:${mount.mount_path}:${mount.scope_path || ''}`;

	ngOnInit(): void {
		this.portapi.getResource<News>(newsResourceIdentifier)
			.pipe(repeat({ delay: 60000 }), takeUntilDestroyed(this.destroyRef))
			.subscribe({
				next: response => {
					this.news = response;
					this.cdr.markForCheck();
				},
				error: () => {
					this.news = undefined;
					this.cdr.markForCheck();
				},
			});

		interval(10000)
			.pipe(startWith(0), takeUntilDestroyed(this.destroyRef))
			.subscribe(() => this.loadDashboard());
	}

	monitorQuery(query: string): { q: string } { return { q: query }; }

	coverageLabel(): string {
		switch (this.coverage?.coverage) {
			case 'protected': return 'Protected';
			case 'partial': return 'Partial';
			default: return 'Unknown';
		}
	}

	coverageClass(): string { return `coverage-${this.coverage?.coverage || 'unknown'}`; }

	mountLabel(mount: MountRow): string { return mount.mount_path || mount.scope_path || 'Unresolved scope'; }

	mountShieldSeverity(mount: MountRow): 'normal' | 'warning' | 'error' {
		switch (mount.status) {
			case 'protected': return 'normal';
			case 'pending': return 'warning';
			default: return 'error';
		}
	}

	mountQuery(mount: MountRow): string {
		return mount.mount_path ? `mount_path:${JSON.stringify(mount.mount_path)}` : '';
	}

	diagnosticsClass(kind: 'enforcement' | 'pipeline' | 'delivery'): string {
		if (!this.diagnostics) return 'health-warning';
		if (kind === 'enforcement') return this.diagnostics.Warnings.length || this.diagnostics.LifecycleState !== 'running' ? 'health-warning' : 'health-good';
		if (kind === 'pipeline') {
			const denied = this.diagnostics.Decision.QueueSaturationDenies + this.diagnostics.Decision.OutstandingBudgetDenies + this.diagnostics.Decision.ProfileAskBudgetDenies;
			return denied > 0 ? 'health-danger' : 'health-good';
		}
		return this.diagnostics.Reader.Fatal || this.diagnostics.Observation.Dropped > 0 || this.diagnostics.FailedResponseCount > 0 ? 'health-danger' : 'health-good';
	}

	latencyMilliseconds(): string { return this.diagnostics ? (this.diagnostics.Reader.LastResponseLatencyNanos / 1_000_000).toFixed(1) : '—'; }

	private loadDashboard(): void {
		forkJoin({
			stats: this.filequery.batch({
				fileBlocked: { query: { op: 'open', verdict: 'deny', is_dir: 'false' }, select: [{ $count: { field: '*', as: 'count' } }] as unknown as Select[] },
				folderBlocked: { query: { op: 'open', verdict: 'deny', is_dir: 'true' }, select: [{ $count: { field: '*', as: 'count' } }] as unknown as Select[] },
				openAllowed: { query: { op: 'open', verdict: 'allow' }, select: [{ $count: { field: '*', as: 'count' } }] as unknown as Select[] },
				executeAllowed: { query: { op: 'exec', verdict: 'allow' }, select: [{ $count: { field: '*', as: 'count' } }] as unknown as Select[] },
				blockedApplications: { query: { verdict: 'deny' }, select: ['profile', 'app_name', { $count: { field: '*', as: 'count' } }] as unknown as Select[], groupBy: ['profile', 'app_name'], orderBy: [{ field: 'count', desc: true }], pageSize: 12 },
				activeApplications: { select: ['profile', 'app_name', { $count: { field: '*', as: 'count' } }] as unknown as Select[], groupBy: ['profile', 'app_name'], orderBy: [{ field: 'count', desc: true }], pageSize: 12 },
			}),
			chart: this.filequery.getDecisionChart(),
			mounts: this.filequery.getProtectedMounts(),
			activity: this.filequery.getMountActivity(),
			diagnostics: this.filequery.getFileAccessDiagnostics(),
		}).pipe(takeUntilDestroyed(this.destroyRef)).subscribe(({ stats, chart, mounts, activity, diagnostics }) => {
			this.fileBlocked = this.count(stats.fileBlocked);
			this.folderBlocked = this.count(stats.folderBlocked);
			this.openAllowed = this.count(stats.openAllowed);
			this.executeAllowed = this.count(stats.executeAllowed);
			this.blockedApplications = this.applications(stats.blockedApplications);
			this.activeApplications = this.applications(stats.activeApplications);
			this.recentApplications = this.activeApplications.length;
			this.openDecisionChart = chart.map(point => ({ timestamp: point.timestamp, allowed: point.open_allowed, blocked: point.open_blocked }));
			this.executeDecisionChart = chart.map(point => ({ timestamp: point.timestamp, allowed: point.execute_allowed, blocked: point.execute_blocked }));
			this.coverage = mounts;
			this.mounts = this.combineMounts(mounts, activity);
			this.diagnostics = diagnostics;
			this.cdr.markForCheck();
		});
	}

	private count(rows: QueryResult[] | undefined): number { return Number(rows?.[0]?.['count'] || 0); }

	private applications(rows: QueryResult[] | undefined): ApplicationActivity[] {
		return (rows || []).filter(row => row['profile']).map(row => ({ profileID: String(row['profile']), name: String(row['app_name'] || row['profile']), count: Number(row['count'] || 0) }));
	}

	private combineMounts(coverage: ProtectedMountsResponse | null, activity: MountActivity[]): MountRow[] {
		const byMount = new Map(activity.map(item => [`${item.mount_id}:${item.mount_path}`, item]));
		return (coverage?.mounts || []).map(mount => ({ ...mount, activity: byMount.get(`${mount.mount_id}:${mount.mount_path}`) || null })).sort((left, right) => {
			const rank = { pending: 0, degraded: 1, protected: 2 };
			const difference = rank[left.status] - rank[right.status];
			return difference || (right.activity?.last_activity_at || '').localeCompare(left.activity?.last_activity_at || '');
		});
	}
}
