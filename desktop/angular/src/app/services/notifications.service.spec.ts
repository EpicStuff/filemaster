import { HttpClient } from '@angular/common/http';
import { fakeAsync, flushMicrotasks, TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { PortapiService } from '@safing/portmaster-api';
import { of, PartialObserver, Subject } from 'rxjs';
import { INTEGRATION_SERVICE } from '../integration';
import { ActionIndicatorService } from '../shared/action-indicator';
import { NotificationsService } from './notifications.service';
import { Action, Notification, NotificationState, NotificationType } from './notifications.types';

describe('NotificationsService', () => {
  let service: NotificationsService;
  let portapi: jasmine.SpyObj<PortapiService>;
  let watchAllUpdates: Subject<Notification<any>[]>;

  beforeEach(() => {
    watchAllUpdates = new Subject<Notification<any>[]>();
    portapi = jasmine.createSpyObj<PortapiService>('PortapiService', [
      'query',
      'watchAll',
      'update',
      'create',
    ]);
    portapi.watchAll.and.returnValue(watchAllUpdates);

    TestBed.configureTestingModule({
      providers: [
        NotificationsService,
        { provide: PortapiService, useValue: portapi },
        { provide: HttpClient, useValue: {} },
        { provide: Router, useValue: { navigate: jasmine.createSpy('navigate').and.returnValue(Promise.resolve(true)) } },
        {
          provide: ActionIndicatorService,
          useValue: {
            error: jasmine.createSpy('error'),
            getErrorMessgae: (err: any) => String(err),
            httpObserver: () => null,
          },
        },
        { provide: INTEGRATION_SERVICE, useValue: { openExternal: jasmine.createSpy('openExternal').and.returnValue(Promise.resolve()) } },
      ],
    });
    service = TestBed.inject(NotificationsService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should allow to query for notifications', () => {
    portapi.query.and.returnValue(of(
      {
        data: {
          EventID: 'updates:core-update-available',
          Message: 'Update available',
        },
      } as any,
      {
        data: {
          EventID: 'updates:ui-reload-required',
          Message: 'UI reload required',
        },
      } as any,
    ));

    const observer = createSpyObserver();
    service.query('updates:').subscribe(observer);

    expect(portapi.query).toHaveBeenCalledWith('notifications:all/updates:');
    expect(observer.next).toHaveBeenCalledWith([
      {
        EventID: 'updates:core-update-available',
        Message: 'Update available',
      },
      {
        EventID: 'updates:ui-reload-required',
        Message: 'UI reload required',
      },
    ]);
    expect(observer.error).not.toHaveBeenCalled();
    expect(observer.complete).toHaveBeenCalled();
  });

  describe('execute notification actions', () => {
    it('should work using a notif object', fakeAsync(() => {
      const update = new Subject<void>();
      portapi.update.and.returnValue(update);
      const observer = createSpyObserver();
      const action = notificationAction('restart', 'Restart');
      const notif = {
        EventID: 'updates:core-update-available',
        Message: 'An update is available',
        Type: NotificationType.Info,
        AvailableActions: [action],
      } as Notification;

      service.execute(notif, action).subscribe(observer);
      flushMicrotasks();

      expect(observer.error).not.toHaveBeenCalled();
      expect(portapi.update).toHaveBeenCalledWith('notifications:all/updates:core-update-available', {
        EventID: 'updates:core-update-available',
        SelectedActionID: 'restart',
      });

      update.next(undefined);
      update.complete();
      flushMicrotasks();

      expect(observer.next).toHaveBeenCalledWith(undefined);
      expect(observer.error).not.toHaveBeenCalled();
      expect(observer.complete).toHaveBeenCalled();
    }));

    it('should work using a key', fakeAsync(() => {
      const update = new Subject<void>();
      portapi.update.and.returnValue(update);
      const observer = createSpyObserver();

      service.execute('updates:core-update-available', notificationAction('restart', 'Restart')).subscribe(observer);
      flushMicrotasks();

      expect(observer.error).not.toHaveBeenCalled();
      expect(portapi.update).toHaveBeenCalledWith('notifications:all/updates:core-update-available', {
        EventID: 'updates:core-update-available',
        SelectedActionID: 'restart',
      });

      update.next(undefined);
      update.complete();
      flushMicrotasks();

      expect(observer.next).toHaveBeenCalledWith(undefined);
      expect(observer.error).not.toHaveBeenCalled();
      expect(observer.complete).toHaveBeenCalled();
    }));
  });

  describe('resolving pending actions', () => {
    it('should work using a notif object', () => {
      const update = new Subject<void>();
      portapi.update.and.returnValue(update);
      const observer = createSpyObserver();
      const notif = {
        EventID: 'updates:core-update-available',
        Message: 'An update is available',
        Type: NotificationType.Info,
        State: NotificationState.Responded,
        SelectedActionID: 'restart',
      } as Notification;

      service.resolvePending(notif, 100).subscribe(observer);

      expect(observer.error).not.toHaveBeenCalled();
      expect(portapi.update).toHaveBeenCalledWith('notifications:all/updates:core-update-available', {
        EventID: 'updates:core-update-available',
        State: NotificationState.Responded,
      });

      update.next(undefined);
      update.complete();

      expect(observer.next).toHaveBeenCalledWith(undefined);
      expect(observer.error).not.toHaveBeenCalled();
      expect(observer.complete).toHaveBeenCalled();
    });

    it('should throw on an executed notification using a notif object', () => {
      const observer = createSpyObserver();
      const notif = {
        EventID: 'updates:core-update-available',
        Message: 'An update is available',
        Type: NotificationType.Info,
        SelectedActionID: 'restart',
        State: NotificationState.Executed,
      } as Notification;

      service.resolvePending(notif).subscribe(observer);

      expect(observer.error).toHaveBeenCalled();
      expect(portapi.update).not.toHaveBeenCalled();
    });

    it('should work using a key', () => {
      const update = new Subject<void>();
      portapi.update.and.returnValue(update);
      const observer = createSpyObserver();

      service.resolvePending('updates:core-update-available', 100).subscribe(observer);

      expect(observer.error).not.toHaveBeenCalled();
      expect(portapi.update).toHaveBeenCalledWith('notifications:all/updates:core-update-available', {
        EventID: 'updates:core-update-available',
        State: NotificationState.Responded,
      });

      update.next(undefined);
      update.complete();

      expect(observer.next).toHaveBeenCalledWith(undefined);
      expect(observer.error).not.toHaveBeenCalled();
      expect(observer.complete).toHaveBeenCalled();
    });
  });

  describe('watching notifications', () => {
    it('should be possible to watch for new and action-required notifs only', () => {
      const observer = createSpyObserver();
      service.new$.subscribe(observer);

      const n1 = {
        EventID: 'new-notif-1',
        Message: 'a new notification',
        State: NotificationState.Active,
        Expires: Math.round(Date.now() / 1000) + 60 * 60,
      };
      const n2 = {
        EventID: 'new-notif-2',
        Message: 'a new notification',
        Expires: 0,
        AvailableActions: [notificationAction('action-id', 'some action')],
      };
      const expired = {
        EventID: 'new-notif-3',
        Message: 'a new notification',
        State: NotificationState.Executed,
        Expires: 100,
      };
      const pending = {
        EventID: 'new-notif-4',
        Message: 'a new notification',
        State: NotificationState.Responded,
        SelectedActionID: 'test',
      };

      watchAllUpdates.next([n1 as Notification]);
      watchAllUpdates.next([n1 as Notification, expired as Notification]);
      watchAllUpdates.next([n1 as Notification, expired as Notification, n2 as Notification]);
      watchAllUpdates.next([n1 as Notification, expired as Notification, n2 as Notification, pending as Notification]);

      expect(portapi.watchAll).toHaveBeenCalledWith('notifications:all/', undefined);
      expect(observer.complete).not.toHaveBeenCalled();
      expect(observer.error).not.toHaveBeenCalled();
      expect(observer.next).toHaveBeenCalledWith([]);
      expect(observer.next).toHaveBeenCalledWith([n1]);
      expect(observer.next).toHaveBeenCalledWith([n1, n2]);
    });
  });

  describe('creating notifications', () => {
    it('should be possible using an object', () => {
      const create = new Subject<void>();
      portapi.create.and.returnValue(create);
      const notification: Partial<Notification<any>> = {
        EventID: 'my-awesome-notification',
        AvailableActions: [
          notificationAction('action-no', 'No'),
          notificationAction('force-no', 'Hell No'),
        ],
        Message: 'Update complete, do you want to reboot?',
        Type: NotificationType.Warning,
      };

      const observer = createSpyObserver();
      service.create(notification).subscribe(observer);

      expect(observer.error).not.toHaveBeenCalled();
      expect(portapi.create).toHaveBeenCalledWith('notifications:all/my-awesome-notification', notification);

      create.next(undefined);
      create.complete();

      expect(observer.complete).toHaveBeenCalled();
      expect(observer.error).not.toHaveBeenCalled();
      expect(observer.next).toHaveBeenCalledWith(undefined);
    });

    it('should be possible using parameters', () => {
      const create = new Subject<void>();
      portapi.create.and.returnValue(create);
      const observer = createSpyObserver();

      service.create('my-param-notification', 'message', NotificationType.Prompt).subscribe(observer);

      expect(observer.error).not.toHaveBeenCalled();
      expect(portapi.create).toHaveBeenCalledWith('notifications:all/my-param-notification', {
        Type: NotificationType.Prompt,
        EventID: 'my-param-notification',
        Message: 'message',
        State: NotificationState.Active,
      });

      create.next(undefined);
      create.complete();

      expect(observer.complete).toHaveBeenCalled();
      expect(observer.error).not.toHaveBeenCalled();
      expect(observer.next).toHaveBeenCalledWith(undefined);
    });
  });
});

function notificationAction(ID: string, Text: string): Action {
  return {
    ID,
    Text,
    Type: '',
    Visibility: '',
  };
}

function createSpyObserver(): PartialObserver<any> {
  return jasmine.createSpyObj('observer', ['next', 'error', 'complete']);
}
