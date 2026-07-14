import { ChangeDetectionStrategy, ChangeDetectorRef, Component, DestroyRef, Input, OnInit, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Condition, FileAccessRecord, Filequery, OrderBy, Select } from '@safing/portmaster-api';
import { Datasource, DynamicItemsPaginator } from '@safing/ui';
import { BehaviorSubject, Subject } from 'rxjs';
import { debounceTime, switchMap } from 'rxjs/operators';
import { mergeConditions } from '../netquery/utils';

const PAGE_SIZE = 25;

const freeTextFields: (keyof FileAccessRecord)[] = ['app_name', 'exe', 'path'];

export const keyTranslation: { [key: string]: string } = {
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
	readonly orderBy: OrderBy[] = [{ field: 'at', desc: true }];

	textSearch = '';
	activeFilters: ActiveFilter[] = [];
	loading = false;
	totalResultCount = 0;
	paginator!: DynamicItemsPaginator<FileAccessRecord>;

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
					});
				}),
			)
			.subscribe(results => {
				const total = (results.total?.[0]?.['totalCount'] as number) || 0;
				this.totalResultCount = total;
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

	addFilter(key: string, value: string): void {
		const existing = this.activeFilters.findIndex(f => f.key === key && f.value === value);
		if (existing !== -1) return;
		this.activeFilters = [
			...this.activeFilters,
			{ key, value, label: keyTranslation[key] || key },
		];
		this.performSearch();
	}

	removeFilter(filter: ActiveFilter): void {
		this.activeFilters = this.activeFilters.filter(f => f !== filter);
		this.performSearch();
	}

	clearFilters(): void {
		this.textSearch = '';
		this.activeFilters = [];
		this.performSearch();
	}

	trackEvent(_: number, event: FileAccessRecord): number {
		return event.id;
	}

	private buildCondition(): Condition {
		const cond: Condition = {};

		if (this.textSearch.trim()) {
			const q = this.textSearch.trim();
			freeTextFields.forEach(f => {
				cond[f as string] = { $like: `%${q}%` };
			});
		}

		this.activeFilters.forEach(f => {
			cond[f.key] = f.value;
		});

		return this.presetCondition ? mergeConditions(cond, this.presetCondition) : cond;
	}
}
