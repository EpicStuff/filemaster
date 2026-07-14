import { Component, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FileAccessRecord, Filequery } from '@safing/portmaster-api';
import { Subject, interval, map, merge, repeat } from 'rxjs';
import { fadeInAnimation, moveInOutListAnimation } from 'src/app/shared/animations';
import { ChartConfig } from 'src/app/shared/netquery/line-chart/line-chart';

type FileActivityChartPoint = {
	timestamp: number;
	allowed: number;
	blocked: number;
};

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

@Component({
	templateUrl: './monitor.html',
	styleUrls: ['../page.scss', './monitor.scss'],
	providers: [],
	animations: [fadeInAnimation, moveInOutListAnimation],
})
export class MonitorPageComponent {
	filequery = inject(Filequery);
	reload = new Subject<void>();
	readonly activityChartConfig = fileActivityChartConfig;

	activityChart = this.filequery.getRecentEvents(100)
		.pipe(
			repeat({ delay: () => merge(interval(1000), this.reload) }),
			map(events => {
				const points = new Map<number, FileActivityChartPoint>();
				events.forEach((event: FileAccessRecord) => {
					const timestamp = Math.floor(new Date(event.at).getTime() / 60_000) * 60;
					const point = points.get(timestamp) || { timestamp, allowed: 0, blocked: 0 };
					if (event.verdict === 'allow') {
						point.allowed += 1;
					} else {
						point.blocked += 1;
					}
					points.set(timestamp, point);
				});

				return Array.from(points.values()).sort((a, b) => a.timestamp - b.timestamp);
			}),
			takeUntilDestroyed(),
		);
}
