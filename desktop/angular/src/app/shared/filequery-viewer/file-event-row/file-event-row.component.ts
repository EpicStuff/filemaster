import { ChangeDetectionStrategy, Component, Input } from '@angular/core';
import { FileAccessRecord } from '@safing/portmaster-api';

@Component({
	selector: 'app-file-event-row',
	templateUrl: './file-event-row.component.html',
	changeDetection: ChangeDetectionStrategy.OnPush,
})
export class FileEventRowComponent {
	@Input() event!: FileAccessRecord;

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
