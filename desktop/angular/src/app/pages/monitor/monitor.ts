import { Component, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Filequery } from '@safing/portmaster-api';
import { Subject, interval, merge, repeat } from 'rxjs';
import { fadeInAnimation, moveInOutListAnimation } from 'src/app/shared/animations';

@Component({
	templateUrl: './monitor.html',
	styleUrls: ['../page.scss', './monitor.scss'],
	providers: [],
	animations: [fadeInAnimation, moveInOutListAnimation],
})
export class MonitorPageComponent {
	filequery = inject(Filequery);
	reload = new Subject<void>();

	fileEvents = this.filequery.getRecentEvents(100)
		.pipe(
			repeat({ delay: () => merge(interval(1000), this.reload) }),
			takeUntilDestroyed()
		);
}
