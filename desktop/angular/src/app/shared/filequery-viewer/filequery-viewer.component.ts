import { ChangeDetectionStrategy, ChangeDetectorRef, Component, DestroyRef, Input, OnInit, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Condition, FileAccessRecord, Filequery, OrderBy, Select } from '@safing/portmaster-api';
import { Datasource, DynamicItemsPaginator } from '@safing/ui';
import { BehaviorSubject, Observable, Subject } from 'rxjs';
import { debounceTime, map, switchMap } from 'rxjs/operators';
import { mergeConditions } from '../netquery/utils';
import { ChartConfig } from '../netquery/line-chart/line-chart';

const PAGE_SIZE = 25;

const freeTextFields: (keyof FileAccessRecord)[] = ['app_name', 'exe', 'path'];

export const keyTranslation: { [key: string]: string } = {
	at: 'Time',
	app_name: 'App',
	op: 'Operation',
	verdict: 'Verdict',
	path: 'File Path',
	profile: 'Profile',
	exe: 'Executable',
};

export interface ActiveFilter {
	key: string;
	value: string;
	label: string;
}

interface FilterSuggestion {
	value: string;
	count: number;
}

interface FileAccessGroup {
	key: string;
	values: Record<string, string>;
	events: FileAccessRecord[];
}

interface FileActivityChartPoint {
	timestamp: number;
	allowed: number;
	blocked: number;
}

const fileActivityChartConfig: ChartConfig<FileActivityChartPoint> = {
	series: {
		allowed: {
			lineColor: 'text-green-200',
			areaColor: 'text-green-100 text-opacity-25',
		},
		blocked: {
			lineColor: 'text-red-200',
			areaColor: 'text-red-100 text-opacity-25',
		},
	},
	time: { from: -10 * 60 },
	tooltipFormat: point => `Allowed: ${point.allowed}\nBlocked: ${point.blocked}`,
	showDataPoints: true,
	fillEmptyTicks: { interval: 60 },
};

/**
 * File-access counterpart of Portmaster's sfng-netquery-viewer.
 *
 * It deliberately uses the same paginator and accordion-row UI machinery as
 * the network activity view; only the query backend and result columns differ.
 */
@Component({
	selector: 'app-filequery-viewer',
	templateUrl: './filequery-viewer.component.html',
	changeDetection: ChangeDetectionStrategy.OnPush,
	styles: [`:host { @apply flex flex-col gap-3 pr-3 min-h-full; }`],
})
export class FilequeryViewerComponent implements OnInit {
	private destroyRef = inject(DestroyRef);
	private cdr = inject(ChangeDetectorRef);
	private filequery = inject(Filequery);

	private search$ = new Subject<void>();
	private reload$ = new BehaviorSubject<void>(undefined);

	@Input() showAppColumn = true;

	@Input()
	set filterPreset(v: string | undefined) {
		this.presetCondition = v ? { profile: v } : null;
		this.performSearch();
	}
	private presetCondition: Condition | null = null;

	readonly keyTranslation = keyTranslation;
	readonly activityChartConfig = fileActivityChartConfig;
	get orderBy(): OrderBy[] {
		const fields = [...this.selectedGroupBy, ...this.selectedOrderBy]
			.filter((field, index, values) => values.indexOf(field) === index);

		return (fields.length ? fields : ['at']).map(field => ({
			field,
			desc: field === 'at',
		}));
	}

	textSearch = '';
	selectedVerdicts: string[] = [];
	selectedFiles: string[] = [];
	selectedApps: string[] = [];
	selectedOperations: string[] = [];
	selectedGroupBy: string[] = [];
	selectedOrderBy: string[] = [];
	fileSuggestions: FilterSuggestion[] = [];
	appSuggestions: FilterSuggestion[] = [];
	loading = false;
	totalResultCount = 0;
	activityChart: FileActivityChartPoint[] = [];
	paginator!: DynamicItemsPaginator<FileAccessRecord>;
	groupedPageItems$!: Observable<FileAccessGroup[]>;

	get isGrouped(): boolean {
		return this.selectedGroupBy.length > 0;
	}

	get activeFilters(): ActiveFilter[] {
		return [
			...this.selectedVerdicts.map(value => ({ key: 'verdict', value, label: keyTranslation.verdict })),
			...this.selectedFiles.map(value => ({ key: 'path', value, label: keyTranslation.path })),
			...this.selectedApps.map(value => ({ key: 'app_name', value, label: keyTranslation.app_name })),
			...this.selectedOperations.map(value => ({ key: 'op', value, label: keyTranslation.op })),
		];
	}

	ngOnInit(): void {
		const source: Datasource<FileAccessRecord> = {
			view: (page, pageSize) => this.filequery.query({
				query: this.buildCondition(),
				orderBy: this.orderBy,
				page: page - 1,
				pageSize,
			}) as unknown as import('rxjs').Observable<FileAccessRecord[]>,
		};
		this.paginator = new DynamicItemsPaginator(source, PAGE_SIZE);
		this.groupedPageItems$ = this.paginator.pageItems$.pipe(
			map(events => this.groupPage(events)),
		);

		this.search$
			.pipe(
				debounceTime(300),
				takeUntilDestroyed(this.destroyRef),
				switchMap(() => {
					this.loading = true;
					this.cdr.markForCheck();

					return this.filequery.batch({
						total: {
							query: this.buildCondition(),
							select: [{ $count: { field: '*', as: 'totalCount' } }] as unknown as Select[],
						},
						chart: {
							query: this.buildCondition(),
							orderBy: [{ field: 'at', desc: true }],
							pageSize: 100,
						},
					});
				}),
			)
			.subscribe(results => {
				const total = (results.total?.[0]?.['totalCount'] as number) || 0;
				this.totalResultCount = total;
				const points = new Map<number, FileActivityChartPoint>();
				(results.chart || []).forEach(result => {
					const event = result as unknown as FileAccessRecord;
					const timestamp = Math.floor(new Date(event.at).getTime() / 60_000) * 60;
					const point = points.get(timestamp) || { timestamp, allowed: 0, blocked: 0 };
					if (event.verdict === 'allow') {
						point.allowed += 1;
					} else {
						point.blocked += 1;
					}
					points.set(timestamp, point);
				});
				this.activityChart = Array.from(points.values()).sort((a, b) => a.timestamp - b.timestamp);
				this.paginator.reset(total);
				this.loading = false;
				this.cdr.markForCheck();
			});

		this.reload$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => this.search$.next());
	}

	performSearch(): void {
		this.search$.next();
	}

	reload(): void {
		this.reload$.next();
	}

	onFiltersChange(): void {
		this.performSearch();
	}

	loadSuggestions(field: 'path' | 'app_name'): void {
		this.filequery.query({
			select: [field, { $count: { field: '*', as: 'count' } }] as unknown as Select[],
			groupBy: [field],
			orderBy: [{ field: 'count', desc: true }],
			pageSize: 10,
		}).subscribe(results => {
			const suggestions = results
				.map(result => ({
					value: String(result[field] || ''),
					count: Number(result['count'] || 0),
				}))
				.filter(suggestion => suggestion.value);

			if (field === 'path') {
				this.fileSuggestions = suggestions;
			} else {
				this.appSuggestions = suggestions;
			}
			this.cdr.markForCheck();
		});
	}

	toggleOperation(operation: string): void {
		this.selectedOperations = this.selectedOperations.includes(operation)
			? this.selectedOperations.filter(value => value !== operation)
			: [...this.selectedOperations, operation];
		this.performSearch();
	}

	removeFilter(filter: ActiveFilter): void {
		if (filter.key === 'verdict') {
			this.selectedVerdicts = this.selectedVerdicts.filter(value => value !== filter.value);
		} else if (filter.key === 'path') {
			this.selectedFiles = this.selectedFiles.filter(value => value !== filter.value);
		} else if (filter.key === 'app_name') {
			this.selectedApps = this.selectedApps.filter(value => value !== filter.value);
		} else if (filter.key === 'op') {
			this.selectedOperations = this.selectedOperations.filter(value => value !== filter.value);
		}
		this.performSearch();
	}

	clearFilters(): void {
		this.textSearch = '';
		this.selectedOperations = [];
		this.selectedVerdicts = [];
		this.selectedFiles = [];
		this.selectedApps = [];
		this.performSearch();
	}

	trackEvent(_: number, event: FileAccessRecord): number {
		return event.id;
	}

	trackGroup(_: number, group: FileAccessGroup): string {
		return group.key;
	}

	private groupPage(events: FileAccessRecord[]): FileAccessGroup[] {
		if (!this.isGrouped) {
			return [];
		}

		const groups = new Map<string, FileAccessGroup>();
		events.forEach(event => {
			const values = Object.fromEntries(this.selectedGroupBy.map(field => [field, String(event[field as keyof FileAccessRecord] || 'N/A')]));
			const key = this.selectedGroupBy.map(field => values[field]).join('\u0000');
			const group = groups.get(key) || { key, values, events: [] };
			group.events.push(event);
			groups.set(key, group);
		});

		return Array.from(groups.values());
	}

	private buildCondition(): Condition {
		const cond: Condition = {};

		if (this.textSearch.trim()) {
			const q = this.textSearch.trim();
			freeTextFields.forEach(f => {
				cond[f as string] = { $like: `%${q}%` };
			});
		}

		if (this.selectedOperations.length) {
			cond.op = this.selectedOperations.length === 1
				? this.selectedOperations[0]
				: { $in: this.selectedOperations };
		}

		if (this.selectedVerdicts.length) {
			cond.verdict = this.selectedVerdicts.length === 1
				? this.selectedVerdicts[0]
				: { $in: this.selectedVerdicts };
		}

		if (this.selectedFiles.length) {
			cond.path = this.selectedFiles.length === 1
				? this.selectedFiles[0]
				: { $in: this.selectedFiles };
		}

		if (this.selectedApps.length) {
			cond.app_name = this.selectedApps.length === 1
				? this.selectedApps[0]
				: { $in: this.selectedApps };
		}

		return this.presetCondition ? mergeConditions(cond, this.presetCondition) : cond;
	}
}
