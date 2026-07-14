import { ChangeDetectionStrategy, ChangeDetectorRef, Component, DestroyRef, Input, OnInit, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Condition, FileAccessRecord, Filequery, OrderBy } from '@safing/portmaster-api';
import { BehaviorSubject, Subject } from 'rxjs';
import { debounceTime, switchMap } from 'rxjs/operators';
import { mergeConditions } from '../netquery/utils';

const PAGE_SIZE = 50;

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

@Component({
	selector: 'app-filequery-viewer',
	templateUrl: './filequery-viewer.component.html',
	changeDetection: ChangeDetectionStrategy.OnPush,
	styles: [`:host { @apply flex flex-col gap-3 min-h-full; }`],
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
		this._filterPreset = v || null;
		this.presetCondition = v ? { profile: v } : null;
		this.performSearch();
	}
	private _filterPreset: string | null = null;
	private presetCondition: Condition | null = null;

	readonly keyTranslation = keyTranslation;

	textSearch = '';
	activeFilters: ActiveFilter[] = [];
	loading = false;
	events: FileAccessRecord[] = [];
	hasMore = false;

	private page = 0;

	private readonly orderBy: OrderBy[] = [{ field: 'at', desc: true }];

	ngOnInit(): void {
		this.search$
			.pipe(
				debounceTime(300),
				takeUntilDestroyed(this.destroyRef),
				switchMap(() => {
					this.loading = true;
					this.page = 0;
					this.cdr.markForCheck();

					return this.filequery.query({
						query: this.buildCondition(),
						orderBy: this.orderBy,
						pageSize: PAGE_SIZE + 1,
						page: 0,
					});
				}),
			)
			.subscribe(results => {
				this.hasMore = results.length > PAGE_SIZE;
				this.events = results.slice(0, PAGE_SIZE) as unknown as FileAccessRecord[];
				this.loading = false;
				this.cdr.markForCheck();
			});

		this.reload$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => this.search$.next());
	}

	loadMore(): void {
		this.page += 1;
		this.loading = true;
		this.cdr.markForCheck();

		this.filequery.query({
			query: this.buildCondition(),
			orderBy: this.orderBy,
			pageSize: PAGE_SIZE + 1,
			page: this.page,
		}).pipe(takeUntilDestroyed(this.destroyRef)).subscribe(results => {
			this.hasMore = results.length > PAGE_SIZE;
			this.events = [
				...this.events,
				...results.slice(0, PAGE_SIZE) as unknown as FileAccessRecord[],
			];
			this.loading = false;
			this.cdr.markForCheck();
		});
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
