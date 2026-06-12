import { ChangeDetectionStrategy, ChangeDetectorRef, Component, HostBinding, OnDestroy, OnInit, TrackByFunction } from '@angular/core';
import { AppProfile, AppProfileService, deepClone, setAppSetting } from '@safing/portmaster-api';
import { combineLatest, forkJoin, Observable, Subscription } from 'rxjs';
import { map, switchMap } from 'rxjs/operators';
import { Action, FileAccessPrompt, NotificationsService, NotificationType } from 'src/app/services';
import { moveInOutAnimation, moveInOutListAnimation } from 'src/app/shared/animations';
import { ActionIndicatorService } from '../action-indicator';

// ProfilePrompts extends an application profile with prompt
// information mainly used for paginagtion.
interface ProfilePrompts extends AppProfile {
	promptsLimited: FileAccessPrompt[];
	prompts: FileAccessPrompt[];
	showAll: boolean;
}

// Number of prompts to display per application profile
// before we start to paginate the list of prompts.
const PromptLimit = 3;

@Component({
	selector: 'app-prompt-list',
	templateUrl: './prompt-list.component.html',
	styleUrls: [
		'./prompt-list.component.scss'
	],
	changeDetection: ChangeDetectionStrategy.OnPush,
	animations: [
		moveInOutAnimation,
		moveInOutListAnimation
	]
})
export class PromptListComponent implements OnInit, OnDestroy {
	profiles: ProfilePrompts[] = [];

	/**
	 * @private
	 * Sets "empty" class on the host element if no prompts are displayed
	 */
	@HostBinding('class.empty')
	get isEmpty() {
		return this.profiles.length === 0;
	}

	// Subscription to new prompts and profile updates.
	private subscription = Subscription.EMPTY;

	constructor(
		private changeDetectorRef: ChangeDetectorRef,
		private profileService: AppProfileService,
		public notifService: NotificationsService,
		public uai: ActionIndicatorService
	) { }

	trackPrompts: TrackByFunction<FileAccessPrompt> = this.notifService.trackBy;

	ngOnInit() {
		// filter the stream of all notifications to only emit
		// file-access prompts (fileaccess:<op> prefix).
		const prompts$: Observable<FileAccessPrompt[]> = this.notifService
			.new$
			.pipe(
				map(notifs => notifs.filter(notif => {
					return notif.Type === NotificationType.Prompt &&
						notif.EventID.startsWith('fileaccess:');
				})),
			);

		// each time the notification list is emitted make sure we have an
		// up-to-date copy of the linked application profile as well.
		const profiles$ = prompts$
			.pipe(
				switchMap(notifs => {
					// collect all profile keys in a distict set so we don't load
					// them more that once. Drop prompts without a resolved
					// profile -- the in-app list only renders per-profile groups.
					var profileKeys = new Set<string>();
					notifs.forEach(n => {
						const prof = n.EventData?.Profile;
						if (prof && prof.ID) {
							profileKeys.add(this.profileService.getKey(prof.Source, prof.ID));
						}
					});
					if (profileKeys.size === 0) {
						return forkJoin([] as Observable<AppProfile>[]).pipe(map(() => [] as AppProfile[]));
					}
					// load all of them in parallel
					return forkJoin(
						Array.from(profileKeys).map(key => this.profileService.getAppProfileFromKey(key))
					)
				})
			);

		// subscribe to updates on the prompt list and the related profiles.
		this.subscription =
			combineLatest([
				prompts$,
				profiles$,
			]).subscribe(([prompts, profiles]) => {

				let promptsByProfile = new Map<string, FileAccessPrompt[]>();

				prompts.forEach(prompt => {
					if (!prompt.EventData) {
						return;
					}

					const profileID = prompt.EventData.Profile?.ID;
					if (!profileID) {
						return;
					}

					let entries = promptsByProfile.get(profileID);
					if (!entries) {
						entries = [];
						promptsByProfile.set(profileID, entries);
					}
					entries.push(prompt);
				});

				// Convert the list of application profiles into a set of ProfilePrompts
				// objects that we can use to actually display the prompts with pagination
				// applied.
				this.profiles = profiles
					.filter(profile => !!promptsByProfile.get(profile.ID))
					.map(profile => {
						const prompts = promptsByProfile.get(profile.ID)!;
						return {
							...profile,
							showAll: prompts.length < PromptLimit,
							promptsLimited: prompts.slice(0, PromptLimit),
							prompts: prompts,
						};
					})
					.sort((a, b) => {
						if (a.ID > b.ID) {
							return 1;
						}
						if (a.ID < b.ID) {
							return -1;
						}
						return 0;
					});

				this.changeDetectorRef.markForCheck();
			})
	}

	allow(prompt: FileAccessPrompt) {
		const action = prompt.AvailableActions.find(a => a.ID === 'allow' || a.ID === 'allow-always');
		if (action) {
			this.execute(prompt, action);
		}
	}

	block(prompt: FileAccessPrompt) {
		const action = prompt.AvailableActions.find(a => a.ID === 'deny' || a.ID === 'deny-always');
		if (action) {
			this.execute(prompt, action);
		}
	}

	changeDefault(profile: ProfilePrompts, newDefault: 'permit' | 'block') {

		this.profileService
			.getAppProfile(profile.Source, profile.ID)
			.pipe(
				map(rawProfile => {
					const copy = deepClone(rawProfile);
					setAppSetting(copy.Config || {}, 'filter/defaultAction', newDefault)

					return copy
				}),
				switchMap(updatedProfile => this.profileService.saveProfile(updatedProfile)),
			)
			.subscribe({
				error: (err) => {
					this.uai.error('Failed to change App Settings', this.uai.getErrorMessage(err));
				}
			})


		setAppSetting(profile.Config || {}, 'filter/defaultAction', newDefault)
	}

	allowAll(profile: ProfilePrompts) {
		profile.prompts.forEach(prompt => this.allow(prompt));
	}

	denyAll(profile: ProfilePrompts) {
		profile.prompts.forEach(prompt => this.block(prompt));
	}

	execute(prompt: FileAccessPrompt, action: Action) {
		this.notifService.execute(prompt, action)
			.subscribe({
				error: console.error,
			});
	}

	ngOnDestroy() {
		this.subscription.unsubscribe();
	}

	/** @private - {@link TrackByFunction} for profile prompts */
	trackProfile(_: number, p: ProfilePrompts) {
		return p.ID;
	}
}
