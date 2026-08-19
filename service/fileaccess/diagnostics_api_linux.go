//go:build linux

package fileaccess

import (
	"errors"
	"sort"

	"github.com/safing/portmaster/base/api"
)

// ProtectedMountStatus is the stable dashboard-oriented summary of fanotify
// coverage for one required mount.
type ProtectedMountStatus struct {
	MountID   int      `json:"mount_id"`
	MountPath string   `json:"mount_path"`
	ScopePath string   `json:"scope_path,omitempty"`
	Status    string   `json:"status"`
	Reasons   []string `json:"reasons"`
}

// ProtectedMountsResponse describes the complete current coverage state. A
// pending scope may not yet have a discoverable mount, so it is represented by
// scope_path rather than an invented mount ID or mount path.
type ProtectedMountsResponse struct {
	Coverage          string                 `json:"coverage"`
	ActiveMountCount  int                    `json:"active_mount_count"`
	MissingMountCount int                    `json:"missing_mount_count"`
	Mounts            []ProtectedMountStatus `json:"mounts"`
	PendingScopes     []string               `json:"pending_scopes"`
	DynamicGaps       []ProtectedMountGap    `json:"dynamic_gaps"`
}

type ProtectedMountGap struct {
	MountID        int      `json:"mount_id"`
	MountPath      string   `json:"mount_path"`
	AffectedScopes []string `json:"affected_scopes"`
}

const (
	mountStatusProtected = "protected"
	mountStatusPending   = "pending"
	mountStatusDegraded  = "degraded"
)

func registerFileAccessAPI() error {
	if err := api.RegisterEndpoint(api.Endpoint{
		Name:        "File Access Diagnostics",
		Description: "Returns compact fanotify coverage, pipeline, persistence, shutdown, and rollout diagnostics without sensitive descriptor identities.",
		Path:        "fileaccess/diagnostics",
		Read:        api.PermitUser,
		StructFunc: func(*api.Request) (any, error) {
			if module == nil {
				return nil, errors.New("fileaccess module is not initialized")
			}
			return module.Diagnostics(), nil
		},
	}); err != nil {
		return err
	}

	return api.RegisterEndpoint(api.Endpoint{
		Name:        "Protected Mount Status",
		Description: "Returns the current protection status for mounts required by configured file-access scopes.",
		Path:        "fileaccess/mounts",
		Read:        api.PermitUser,
		StructFunc: func(*api.Request) (any, error) {
			if module == nil {
				return nil, errors.New("fileaccess module is not initialized")
			}
			return protectedMountStatusResponse(module.Diagnostics()), nil
		},
	})
}

func protectedMountStatusResponse(diagnostics FileAccessDiagnostics) ProtectedMountsResponse {
	response := ProtectedMountsResponse{
		Coverage:          mountCoverageStatus(diagnostics),
		ActiveMountCount:  len(diagnostics.Mount.ActiveMountIDs),
		MissingMountCount: len(diagnostics.Mount.MissingMountIDs),
		Mounts:            protectedMountStatuses(diagnostics),
		PendingScopes:     append([]string(nil), diagnostics.Mount.PendingScopes...),
		DynamicGaps:       make([]ProtectedMountGap, 0, len(diagnostics.Mount.DynamicMountCoverageGaps)),
	}
	for _, gap := range diagnostics.Mount.DynamicMountCoverageGaps {
		response.DynamicGaps = append(response.DynamicGaps, ProtectedMountGap{
			MountID:        gap.MountID,
			MountPath:      gap.MountPath,
			AffectedScopes: append([]string(nil), gap.AffectedScopes...),
		})
	}
	return response
}

func mountCoverageStatus(diagnostics FileAccessDiagnostics) string {
	if !diagnostics.Mount.CoverageKnown {
		return "unknown"
	}
	if diagnostics.Mount.PartialCoverage || diagnostics.Mount.MountNamespaceIsolated || diagnostics.Reader.Fatal {
		return "partial"
	}
	return "protected"
}

func protectedMountStatuses(diagnostics FileAccessDiagnostics) []ProtectedMountStatus {
	missing := make(map[int]struct{}, len(diagnostics.Mount.MissingMountIDs))
	for _, id := range diagnostics.Mount.MissingMountIDs {
		missing[id] = struct{}{}
	}
	dynamicGaps := make(map[int]struct{}, len(diagnostics.Mount.DynamicMountIDs))
	for _, id := range diagnostics.Mount.DynamicMountIDs {
		dynamicGaps[id] = struct{}{}
	}

	statuses := make([]ProtectedMountStatus, 0, len(diagnostics.Mount.RequiredMounts))
	for _, mount := range diagnostics.Mount.RequiredMounts {
		reasons := mountStatusReasons(diagnostics, mount.MountID, missing, dynamicGaps)
		status := mountStatusProtected
		switch {
		case diagnostics.Mount.ScopeActivationPending:
			status = mountStatusPending
		case len(reasons) > 0:
			status = mountStatusDegraded
		}
		statuses = append(statuses, ProtectedMountStatus{
			MountID:   mount.MountID,
			MountPath: mount.MountPath,
			Status:    status,
			Reasons:   reasons,
		})
	}
	if len(diagnostics.Mount.RequiredMounts) == 0 {
		for _, scope := range diagnostics.Mount.PendingScopes {
			statuses = append(statuses, ProtectedMountStatus{
				ScopePath: scope,
				Status:    mountStatusPending,
				Reasons:   []string{"scope_activation_pending"},
			})
		}
	}
	sort.Slice(statuses, func(i, j int) bool {
		leftRank, rightRank := mountStatusRank(statuses[i].Status), mountStatusRank(statuses[j].Status)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if statuses[i].MountID == 0 || statuses[j].MountID == 0 {
			return statuses[i].ScopePath < statuses[j].ScopePath
		}
		return statuses[i].MountID < statuses[j].MountID
	})
	return statuses
}

func mountStatusRank(status string) int {
	switch status {
	case mountStatusPending:
		return 0
	case mountStatusDegraded:
		return 1
	default:
		return 2
	}
}

func mountStatusReasons(diagnostics FileAccessDiagnostics, mountID int, missing, dynamicGaps map[int]struct{}) []string {
	reasons := make([]string, 0, 6)
	if diagnostics.Mount.ScopeActivationPending {
		reasons = append(reasons, "scope_activation_pending")
	}
	if !diagnostics.Mount.CoverageKnown {
		reasons = append(reasons, "coverage_unknown")
	}
	if _, ok := missing[mountID]; ok {
		reasons = append(reasons, "missing_mark")
	}
	if _, ok := dynamicGaps[mountID]; ok {
		reasons = append(reasons, "dynamic_coverage_breach")
	}
	if diagnostics.Mount.MountNamespaceIsolated {
		reasons = append(reasons, "mount_namespace_isolated")
	}
	if diagnostics.Reader.Fatal {
		reasons = append(reasons, "reader_fatal")
	}
	if diagnostics.Mount.LastError != "" && len(reasons) == 0 {
		reasons = append(reasons, "reconciliation_error")
	}
	return reasons
}
