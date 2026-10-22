import { ChangeDetectionStrategy, Component, Input } from '@angular/core';
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
			@apply w-full flex-grow gap-4 grid justify-start items-center overflow-hidden;
			grid-template-columns: 1fr 1fr 1fr 2rem;
			grid-auto-rows: 1.5rem;
			--app-icon-size: 20px;
		}
		:host-context(.min-width-768px) :host {
			grid-template-columns: 1fr 4rem 1fr 1fr 5rem 2rem;
		}
		:host-context(.min-width-1024px) :host {
			grid-template-columns: 1fr 4rem 1fr 1fr 5rem 2rem;
		}
		:host-context(.min-width-1280px) :host {
			grid-template-columns: 1fr 4rem 1fr 1fr 8rem 2rem;
		}
		:host > * { @apply overflow-hidden whitespace-nowrap text-ellipsis; }
	`],
})
export class FileEventRowComponent {
	@Input() event!: FileAccessRecord;
	@Input() showAppColumn = true;

	get opClass(): string {
		switch (this.event?.op) {
			case 'write': return 'text-yellow-400';
			case 'exec': return 'text-orange-400';
			default: return '';
		}
	}

	get verdictClass(): string {
		switch (this.event?.verdict) {
			case 'allow': return 'text-green-400';
			case 'would-deny': return 'text-yellow-400';
			default: return 'text-red-400';
		}
	}

	get verdictDotClass(): string {
		switch (this.event?.verdict) {
			case 'allow': return 'bg-green-400';
			case 'would-deny': return 'bg-yellow-400';
			default: return 'bg-red-400';
		}
	}

	get verdictLabel(): string {
		switch (this.event?.verdict) {
			case 'allow': return 'Allowed';
			case 'deny': return 'Blocked';
			case 'would-deny': return 'Would block';
			default: return this.event?.verdict || '';
		}
	}
}
