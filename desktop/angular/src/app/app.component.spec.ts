import { NO_ERRORS_SCHEMA } from '@angular/core';
import { TestBed, waitForAsync } from '@angular/core/testing';
import { Overlay } from '@angular/cdk/overlay';
import { RouterTestingModule } from '@angular/router/testing';
import { PortapiService } from '@safing/portmaster-api';
import { OverlayStepper, SfngDialogService } from '@safing/ui';
import { of } from 'rxjs';
import { INTEGRATION_SERVICE } from './integration';
import { AppComponent } from './app.component';
import { ExitService } from './shared/exit-screen';
import { UIStateService } from './services';

describe('AppComponent', () => {
  beforeEach(waitForAsync(() => {
    TestBed.configureTestingModule({
      imports: [
        RouterTestingModule
      ],
      declarations: [
        AppComponent
      ],
      providers: [
        { provide: PortapiService, useValue: { connected$: of(false) } },
        { provide: ExitService, useValue: { showOverlay$: of(false) } },
        { provide: OverlayStepper, useValue: {} },
        { provide: SfngDialogService, useValue: { create: jasmine.createSpy('create') } },
        { provide: Overlay, useValue: { position: () => ({ global: () => ({ centerHorizontally: () => ({ top: () => ({}) }) }) }) } },
        { provide: UIStateService, useValue: {} },
        { provide: INTEGRATION_SERVICE, useValue: { openExternal: jasmine.createSpy('openExternal') } },
      ],
      schemas: [NO_ERRORS_SCHEMA],
    }).compileComponents();
  }));

  it('should create the app', () => {
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
  });

  it(`should have as title 'portmaster'`, () => {
    const fixture = TestBed.createComponent(AppComponent);
    const app = fixture.componentInstance;
    expect(app.title).toEqual('portmaster');
  });
});
