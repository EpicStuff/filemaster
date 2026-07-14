import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { SfngAccordionModule, SfngDropDownModule, SfngPaginationModule, SfngSelectModule } from '@safing/ui';
import { NetqueryModule } from '../netquery';
import { FileEventRowComponent } from './file-event-row/file-event-row.component';
import { FilequeryViewerComponent } from './filequery-viewer.component';

@NgModule({
	imports: [
		CommonModule,
		FormsModule,
		SfngAccordionModule,
		SfngDropDownModule,
		SfngPaginationModule,
		SfngSelectModule,
		NetqueryModule,
	],
	declarations: [
		FilequeryViewerComponent,
		FileEventRowComponent,
	],
	exports: [
		FilequeryViewerComponent,
	],
})
export class FilequeryViewerModule { }
