import { TestBed } from '@angular/core/testing';
import { PortapiService } from '@safing/portmaster-api';
import { NEVER, of } from 'rxjs';

import { StatusService } from './status.service';

describe('StatusService', () => {
  let service: StatusService;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        {
          provide: PortapiService,
          useValue: {
            qsub: jasmine.createSpy('qsub').and.returnValue(NEVER),
            get: jasmine.createSpy('get').and.returnValue(of({})),
            update: jasmine.createSpy('update').and.returnValue(of(undefined)),
          },
        },
      ],
    });
    service = TestBed.inject(StatusService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
