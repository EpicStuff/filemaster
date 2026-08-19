//go:build linux

package fileaccess

import (
	"reflect"
	"testing"
)

func TestProtectedMountStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		diagnostics FileAccessDiagnostics
		want        []ProtectedMountStatus
	}{
		{
			name: "protected mount",
			diagnostics: FileAccessDiagnostics{Mount: MountDiagnostics{
				CoverageKnown:  true,
				RequiredMounts: []RequiredMount{{MountID: 7, MountPath: "/home"}},
			}},
			want: []ProtectedMountStatus{{MountID: 7, MountPath: "/home", Status: mountStatusProtected, Reasons: []string{}}},
		},
		{
			name: "pending takes precedence over degraded",
			diagnostics: FileAccessDiagnostics{Mount: MountDiagnostics{
				CoverageKnown:          true,
				ScopeActivationPending: true,
				RequiredMounts:         []RequiredMount{{MountID: 7, MountPath: "/home"}},
				MissingMountIDs:        []int{7},
			}},
			want: []ProtectedMountStatus{{
				MountID: 7, MountPath: "/home", Status: mountStatusPending,
				Reasons: []string{"scope_activation_pending", "missing_mark"},
			}},
		},
		{
			name: "degraded reasons are mount specific and stable",
			diagnostics: FileAccessDiagnostics{
				Mount: MountDiagnostics{
					CoverageKnown:              false,
					MountNamespaceIsolated:     true,
					RequiredMounts:             []RequiredMount{{MountID: 2, MountPath: "/var"}, {MountID: 3, MountPath: "/home"}},
					MissingMountIDs:            []int{3},
					DynamicMountCoverageBreach: true,
					DynamicMountIDs:            []int{2},
				},
				Reader: ReaderDiagnostics{Fatal: true},
			},
			want: []ProtectedMountStatus{
				{MountID: 2, MountPath: "/var", Status: mountStatusDegraded, Reasons: []string{"coverage_unknown", "dynamic_coverage_breach", "mount_namespace_isolated", "reader_fatal"}},
				{MountID: 3, MountPath: "/home", Status: mountStatusDegraded, Reasons: []string{"coverage_unknown", "missing_mark", "mount_namespace_isolated", "reader_fatal"}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := protectedMountStatuses(test.diagnostics)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("protectedMountStatuses() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestProtectedMountStatusResponseIncludesCoverageAndUnresolvedScopes(t *testing.T) {
	t.Parallel()

	got := protectedMountStatusResponse(FileAccessDiagnostics{Mount: MountDiagnostics{
		CoverageKnown:  false,
		ActiveMountIDs: []int{3},
		PendingScopes:  []string{"/home"},
		DynamicMountCoverageGaps: []MountCoverageGap{{
			MountID:        9,
			MountPath:      "/mnt/data",
			AffectedScopes: []string{"/home"},
		}},
	}})
	want := ProtectedMountsResponse{
		Coverage:          "unknown",
		ActiveMountCount:  1,
		MissingMountCount: 0,
		Mounts: []ProtectedMountStatus{{
			ScopePath: "/home",
			Status:    mountStatusPending,
			Reasons:   []string{"scope_activation_pending"},
		}},
		PendingScopes: []string{"/home"},
		DynamicGaps: []ProtectedMountGap{{
			MountID:        9,
			MountPath:      "/mnt/data",
			AffectedScopes: []string{"/home"},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("protectedMountStatusResponse() = %#v, want %#v", got, want)
	}
}
