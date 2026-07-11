import { ChangeDetectionStrategy, ChangeDetectorRef, Component, HostBinding, OnDestroy, OnInit, TrackByFunction } from '@angular/core';
import { AppProfile, AppProfileService, deepClone, setAppSetting } from '@safing/portmaster-api';
import { combineLatest, forkJoin, Observable, of, Subscription } from 'rxjs';
import { catchError, map, switchMap } from 'rxjs/operators';
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
		//
		// catchError per-lookup so a single 404 (profile auto-created
		// by the daemon but not yet persisted when the prompt arrived,
		// or stale prompt for a deleted profile) does NOT tear down
		// the whole subscription -- which is the failure shape that
		// shows up to users as "yellow badge but No Prompts panel".
		const profiles$ = prompts$
			.pipe(
				switchMap(notifs => {
					var profileKeys = new Set<string>();
					notifs.forEach(n => {
						const prof = n.EventData?.Profile;
						if (prof && prof.ID) {
							profileKeys.add(this.profileService.getKey(prof.Source, prof.ID));
						}
					});
					if (profileKeys.size === 0) {
						return of([] as AppProfile[]);
					}
					return forkJoin(
						Array.from(profileKeys).map(key =>
							this.profileService.getAppProfileFromKey(key).pipe(
								catchError(() => of(null as AppProfile | null)),
							)
						)
					).pipe(
						map(results => results.filter((p): p is AppProfile => p !== null)),
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
				let placeholders = new Map<string, ProfilePrompts>();

				const profilesByID = new Map<string, AppProfile>();
				profiles.forEach(p => profilesByID.set(p.ID, p));

				prompts.forEach(prompt => {
					if (!prompt.EventData) {
						return;
					}

					const subject = prompt.EventData.Subject;
					const profMeta = prompt.EventData.Profile;
					// Use the profile's ID when available, fall back to
					// the exe path so prompts still group when the
					// profile lookup failed (race or stale).
					const groupID = profMeta?.ID || subject?.Exe || 'unknown';

					let entries = promptsByProfile.get(groupID);
					if (!entries) {
						entries = [];
						promptsByProfile.set(groupID, entries);
					}
					entries.push(prompt);

					// If the profile didn't load, synthesise just enough
					// to render the group header so the prompt is still
					// actionable. ID intentionally matches groupID.
					// AppProfile has many fields the template doesn't
					// read in this view; cast through unknown to skip
					// the structural check.
					if (!profilesByID.has(groupID)) {
						placeholders.set(groupID, {
							ID: groupID,
							Source: profMeta?.Source || '',
							Name: profMeta?.Name || subject?.Exe || 'Unknown application',
							LinkedPath: profMeta?.LinkedPath || subject?.Exe || '',
							Config: {},
							showAll: false,
							promptsLimited: [],
							prompts: [],
						} as unknown as ProfilePrompts);
					}
				});

				const allGroups: AppProfile[] = [
					...profiles,
					...Array.from(placeholders.values()).filter(p => !profilesByID.has(p.ID)),
				];

				this.profiles = allGroups
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
