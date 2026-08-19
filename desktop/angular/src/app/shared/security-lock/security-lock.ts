import { ChangeDetectionStrategy, ChangeDetectorRef, Component, DestroyRef, Input, OnInit, inject } from "@angular/core";
import { SecurityLevel } from "@safing/portmaster-api";
import { combineLatest } from "rxjs";
import { StatusService, ModuleStateType, GetModuleState, ControlPauseStateData } from "src/app/services";
import { fadeInAnimation, fadeOutAnimation } from "../animations";

interface SecurityOption {
  level: SecurityLevel;
  displayText: string;
  class: string;
  subText?: string;
}

@Component({
  selector: 'app-security-lock',
  templateUrl: './security-lock.html',
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./security-lock.scss'],
  animations: [
    fadeInAnimation,
    fadeOutAnimation
  ]
})
export class SecurityLockComponent implements OnInit {
	private destroyRef = inject(DestroyRef);
	private forcedSeverity?: 'normal' | 'warning' | 'error';

  lockLevel: SecurityOption | null = null;

  /** The display mode for the security lock */
	@Input()
	mode: 'small' | 'full' = 'full'

	/**
	 * Overrides the global protection state when the shield represents a
	 * specific resource, such as a protected mount.
	 */
	@Input()
	set severity(value: 'normal' | 'warning' | 'error' | undefined) {
		this.forcedSeverity = value;
		if (value) {
			this.lockLevel = this.optionForSeverity(value);
			this.cdr.markForCheck();
		}
	}

  constructor(
    private statusService: StatusService,
    private cdr: ChangeDetectorRef,
  ) { }

	ngOnInit(): void {
		if (this.forcedSeverity) {
			return;
		}

		this.statusService.status$.subscribe(status => {
        // By default the lock is green and we are "Secure"
        this.lockLevel = {
          level: SecurityLevel.Normal,
          class: 'text-green-300',
          displayText: 'Secure',
        }

        // update the shield depending on the worst state.
        switch (status.WorstState.Type) {
          case ModuleStateType.Warning:
            this.lockLevel = {
              level: SecurityLevel.High,
              class: 'text-yellow-300',
              displayText: 'Warning'
            }
            break;
          case ModuleStateType.Error:
            this.lockLevel = {
              level: SecurityLevel.Extreme,
              class: 'text-red-300',
              displayText: 'Insecure'
            }
            break;
        }

        // Checking for Control:Paused state
        const pausedState = GetModuleState(status, 'Control', 'control:paused');
        if (pausedState?.Data) {
          const pauseData = pausedState.Data as ControlPauseStateData;
          if (pauseData.Interception === true) {
            this.lockLevel.displayText = 'Insecure: PAUSED';
          } else if (pauseData.SPN === true) {
            this.lockLevel.displayText = 'Secure (SPN Paused)';
          }
        }

        this.cdr.markForCheck();
		});
	}

	private optionForSeverity(severity: 'normal' | 'warning' | 'error'): SecurityOption {
		switch (severity) {
			case 'warning':
				return { level: SecurityLevel.High, class: 'text-yellow-300', displayText: 'Warning' };
			case 'error':
				return { level: SecurityLevel.Extreme, class: 'text-red-300', displayText: 'Insecure' };
			default:
				return { level: SecurityLevel.Normal, class: 'text-green-300', displayText: 'Secure' };
		}
	}
}
