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
  // Protected mount the event was attributed to (backend Phase 2.5). A zero
  // mount_id with an empty mount_path means the mount was unknown.
  mount_id: number;
  mount_path: string;
  is_dir: boolean;
}

export interface FileDecisionChartPoint {
  timestamp: number;
  open_allowed: number;
  open_blocked: number;
  execute_allowed: number;
  execute_blocked: number;
}

export interface ProtectedMount {
  mount_id: number;
  mount_path: string;
  scope_path?: string;
  status: 'protected' | 'pending' | 'degraded';
  reasons: string[];
}

export interface ProtectedMountGap {
  mount_id: number;
  mount_path: string;
  affected_scopes: string[];
}

export interface ProtectedMountsResponse {
  coverage: 'protected' | 'partial' | 'unknown';
  active_mount_count: number;
  missing_mount_count: number;
  mounts: ProtectedMount[];
  pending_scopes: string[];
  dynamic_gaps: ProtectedMountGap[];
}

export interface MountActivity {
  mount_id: number;
  mount_path: string;
  last_activity_at: string;
  open_allowed: number;
  open_blocked: number;
  execute_allowed: number;
  execute_blocked: number;
}

export interface FileAccessDiagnostics {
  LifecycleState: string;
  Warnings: { Code: string; Detail: string }[];
  Decision: {
    QueueDepth: number;
    Workers: number;
    ActiveWorkers: number;
    PendingAsk: number;
    QueueSaturationDenies: number;
    OutstandingBudgetDenies: number;
    ProfileAskBudgetDenies: number;
  };
  Observation: {
    QueueDepth: number;
    QueueCapacity: number;
    Dropped: number;
  };
  Reader: {
    DescriptorPressure: boolean;
    LastDecisionLatencyNanos: number;
    LastResponseLatencyNanos: number;
    QueueOverflowCount: number;
    Fatal: boolean;
  };
  FailedResponseCount: number;
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
          'app_name',
          'verdict',
          { $count: { field: '*', as: 'totalCount' } },
        ] as unknown as Select[],
        groupBy: ['profile', 'app_name', 'verdict'],
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
          const appName = row['app_name'] as string;
          if (appName && stats.Name === stats.ID) {
            stats.Name = appName;
          }
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

  /** Returns recent file-access events across all profiles. */
  getRecentEvents(limit = 100): Observable<FileAccessRecord[]> {
    return this.query({
      orderBy: [{ field: 'at', desc: true }],
      pageSize: limit,
    }).pipe(
      map(results => results as unknown as FileAccessRecord[])
    );
  }

  getDecisionChart(): Observable<FileDecisionChartPoint[]> {
    return this.http.get<{ results: FileDecisionChartPoint[] }>(`${this.httpAPI}/v1/filequery/charts/decisions`)
      .pipe(
        map(response => response.results || []),
        catchError(() => of([] as FileDecisionChartPoint[])),
      );
  }

  getMountActivity(): Observable<MountActivity[]> {
    return this.http.get<{ results: MountActivity[] }>(`${this.httpAPI}/v1/filequery/mounts/activity`)
      .pipe(
        map(response => response.results || []),
        catchError(() => of([] as MountActivity[])),
      );
  }

  getProtectedMounts(): Observable<ProtectedMountsResponse | null> {
    return this.http.get<ProtectedMountsResponse>(`${this.httpAPI}/v1/fileaccess/mounts`)
      .pipe(catchError(() => of(null)));
  }

  getFileAccessDiagnostics(): Observable<FileAccessDiagnostics | null> {
    return this.http.get<FileAccessDiagnostics>(`${this.httpAPI}/v1/fileaccess/diagnostics`)
      .pipe(catchError(() => of(null)));
  }
}
