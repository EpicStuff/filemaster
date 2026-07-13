import { HttpClient } from "@angular/common/http";
import { Inject, Injectable } from "@angular/core";
import { Observable, of } from "rxjs";
import { catchError, map } from "rxjs/operators";
import { PORTMASTER_HTTP_API_ENDPOINT } from "./portapi.service";
import { Condition, Query, QueryResult, Select } from "./netquery.service";

export interface FileAccessRecord {
  id: number;
  at: string;
  pid: number;
  exe: string;
  path: string;
  op: string;
  verdict: string;
  profile: string;
  app_name: string;
}

export interface IFileQueryProfileStats {
  ID: string;
  Name: string;
  size: number;
  empty: boolean;
  countAllowed: number;
  countDenied: number;
}

type BatchResponse<T> = {
  [key in keyof T]: QueryResult[]
}

interface BatchRequest {
  [key: string]: Query
}

@Injectable({ providedIn: 'root' })
export class Filequery {
  constructor(
    private http: HttpClient,
    @Inject(PORTMASTER_HTTP_API_ENDPOINT) private httpAPI: string,
  ) { }

  query(query: Query): Observable<QueryResult[]> {
    return this.http.post<{ results: QueryResult[] }>(`${this.httpAPI}/v1/filequery/query`, query)
      .pipe(
        map(res => res.results || []),
        catchError(() => of([] as QueryResult[])),
      );
  }

  batch<T extends BatchRequest>(queries: T): Observable<BatchResponse<T>> {
    return this.http.post<BatchResponse<T>>(`${this.httpAPI}/v1/filequery/query/batch`, queries)
      .pipe(catchError(() => of({} as BatchResponse<T>)));
  }

  /** Returns the list of profile IDs that have any file-access events. */
  getActiveProfileIDs(): Observable<string[]> {
    return this.query({
      select: ['profile'] as unknown as Select[],
      groupBy: ['profile'],
    }).pipe(
      map(result => result.map(res => (res['profile'] as string) || '').filter(Boolean))
    );
  }

  /** Returns per-profile event counts (allow + deny) for the Apps sidebar. */
  getProfileStats(query?: Condition): Observable<IFileQueryProfileStats[]> {
    return this.batch({
      verdicts: {
        select: [
          'profile',
          'verdict',
          { $count: { field: '*', as: 'totalCount' } },
        ] as unknown as Select[],
        groupBy: ['profile', 'verdict'],
        query: query,
      },
    }).pipe(
      map(result => {
        const statsMap = new Map<string, IFileQueryProfileStats>();

        const getOrCreate = (id: string): IFileQueryProfileStats => {
          let stats = statsMap.get(id);
          if (!stats) {
            stats = { ID: id, Name: id, size: 0, empty: true, countAllowed: 0, countDenied: 0 };
            statsMap.set(id, stats);
          }
          return stats;
        };

        (result.verdicts || []).forEach((row: QueryResult) => {
          const stats = getOrCreate(row['profile'] as string);
          const count = (row['totalCount'] as number) || 0;
          stats.size += count;
          if ((row['verdict'] as unknown as string) === 'allow') {
            stats.countAllowed += count;
          } else {
            stats.countDenied += count;
          }
          stats.empty = stats.size === 0;
        });

        return Array.from(statsMap.values());
      })
    );
  }

  /** Returns recent file-access events for a given profile. */
  getEventsForProfile(profileID: string, limit = 100): Observable<FileAccessRecord[]> {
    return this.query({
      query: { profile: profileID },
      orderBy: [{ field: 'at', desc: true }],
      pageSize: limit,
    }).pipe(
      map(results => results as unknown as FileAccessRecord[])
    );
  }
}
