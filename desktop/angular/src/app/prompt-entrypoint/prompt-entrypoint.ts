import { CommonModule } from "@angular/common";
import { Component, OnInit, TrackByFunction, inject } from "@angular/core";
import { AppProfile, AppProfileService, PortapiService } from "@safing/portmaster-api";
import { catchError, combineLatest, forkJoin, map, of, switchMap } from "rxjs";
import { FileAccessPrompt, NotificationType, NotificationsService } from "../services";
import { SfngAppIconModule } from "../shared/app-icon";
import { getCurrentWindow } from '@tauri-apps/api/window';

interface Prompt {
	prompts: FileAccessPrompt[];
	profile: AppProfile | null;
}

@Component({
	standalone: true,
	selector: 'app-root',
	templateUrl: './prompt.html',
	imports: [
		CommonModule,
		SfngAppIconModule,
	]
})
export class PromptEntryPointComponent implements OnInit {
	private readonly notificationService = inject(NotificationsService);
	private readonly portapi = inject(PortapiService);
	private readonly profileService = inject(AppProfileService);

	prompts: Prompt[] = [];

	trackPrompt: TrackByFunction<FileAccessPrompt> = (_, p) => p.EventID;
	trackProfile: TrackByFunction<Prompt> = (_, p) => p.profile?._meta?.Key ?? p.prompts[0]?.EventData?.Subject?.Exe ?? '';

	ngOnInit(): void {

		this.notificationService
			.new$
			.pipe(
				map(notifs => {
					return notifs.filter(n => n.Type === NotificationType.Prompt && n.EventID.startsWith('fileaccess:'))
				}),
				switchMap(notifications => {
					// Group by profile when we have one, otherwise by the
					// requesting binary so the unknown-process bucket
					// still renders coherently.
					const distinctProfiles = new Map<string, FileAccessPrompt[]>();
					notifications.forEach(n => {
						const prof = n.EventData?.Profile;
						const key = prof && prof.ID
							? `${prof.Source}/${prof.ID}`
							: `exe/${n.EventData?.Subject?.Exe ?? 'unknown'}`;
						const arr = distinctProfiles.get(key) || [];
						arr.push(n);
						distinctProfiles.set(key, arr);
					});

					if (distinctProfiles.size === 0) {
						return of([]);
					}

					return combineLatest(Array.from(distinctProfiles.entries()).map(([key, prompts]) => {
						// Only profile-backed groups have a key the
						// AppProfileService can resolve; unknown-process
						// buckets just emit a null profile.
						if (!key.startsWith('exe/')) {
							return forkJoin({
								profile: this.profileService.getAppProfile(key).pipe(catchError(() => of(null))),
								prompts: of(Array.from(prompts)),
							});
						}
						return of({
							profile: null,
							prompts: Array.from(prompts),
						});
					}));
				})
			)
			.subscribe(result => {
				this.prompts = result;

				// show the prompt now since we're ready
				if (this.prompts.length) {
					getCurrentWindow()!.show();
				}
			})
	}

	selectAction(prompt: FileAccessPrompt, action: string) {
		prompt.SelectedActionID = action;

		this.portapi.update(prompt._meta!.Key, prompt)
			.subscribe();
	}
}
