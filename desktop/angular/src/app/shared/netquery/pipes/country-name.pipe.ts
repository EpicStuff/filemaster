import { Pipe, PipeTransform, Injectable, inject } from '@angular/core';
import { GeoCoordinates } from '@safing/portmaster-api';

export interface CountryListResponse {
  [countryKey: string]: {
    Code: string;
    Name: string;
    Center: GeoCoordinates;
    Continent: {
      Code: string;
      Region: string;
      Name: string;
    }
  }
}

@Injectable()
export class CountryNameService {
  private map: Map<string, string> = new Map();

  constructor() {
    // The geoip backend was removed with the network stack; this pipe
    // is only reachable from the kept-for-scaffolding netquery views.
    // Don't toast the missing endpoint -- the map stays empty and the
    // pipe just falls back to the raw country code.
  }

  resolveName(code: string): string {
    return this.map.get(code) || '';
  }
}

@Pipe({
  name: 'countryName',
  pure: true,
})
export class CountryNamePipe implements PipeTransform {
  private countryService = inject(CountryNameService);

  transform(countryCode: string) {
    return this.countryService.resolveName(countryCode);
  }
}
