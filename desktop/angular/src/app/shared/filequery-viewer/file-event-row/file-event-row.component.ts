import { ChangeDetectionStrategy, Component, HostBinding, Input } from '@angular/core';
import { FileAccessRecord } from '@safing/portmaster-api';

/**
 * File-event row following Portmaster's sfng-netquery-connection-row layout.
 * The grid and responsive breakpoints are shared UI conventions; only the
 * connection-specific fields have been replaced with file-access columns.
 */
@Component({
	selector: 'sfng-file-event-row',
	templateUrl: './file-event-row.component.html',
	changeDetection: ChangeDetectionStrategy.OnPush,
	styles: [`
		:host {
			@apply w-full flex-grow gap-4 grid justify-start items-center overflow-hidden px-3;
			grid-template-columns: 5rem 1fr 4rem 4rem minmax(12rem, 2fr);
			grid-auto-rows: 1.5rem;
			--app-icon-size: 20px;
		}
		:host.without-app {
			grid-template-columns: 5rem 4rem 4rem minmax(12rem, 2fr);
		}
		:host > * { @apply overflow-hidden whitespace-nowrap text-ellipsis; }
	`],
})
export class FileEventRowComponent {
	@Input() event!: FileAccessRecord;
	@Input() showAppColumn = true;

	@HostBinding('class.without-app')
	get withoutAppColumn(): boolean {
		return !this.showAppColumn;
	}

	get opClass(): string {
		switch (this.event?.op) {
			case 'write': return 'text-yellow-400';
			case 'exec': return 'text-orange-400';
			default: return '';
		}
	}

	get verdictClass(): string {
		return this.event?.verdict === 'allow' ? 'text-green-400' : 'text-red-400';
	}
}
